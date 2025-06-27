from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from playwright.async_api import async_playwright
import asyncio
import logging
import validators
from typing import List, Dict
import time
import json
import os
import socket
import ipaddress
from urllib.parse import urlparse

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://urljourney.netlify.app/"],  # Replace Netlify URL later
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

# Known Akamai IP ranges (simplified; use MaxMind or full list for production)
AKAMAI_IP_RANGES = [
    "23.192.0.0/11",  # Covers 23.193.114.49 from BMW headers
    "104.64.0.0/10",
    "184.24.0.0/13",
    # Add more ranges as needed: https://www.akamai.com/site/en/documents/technical-support/akamai-ip-address-ranges.pdf
]

def is_akamai_ip(ip: str) -> bool:
    """Check if an IP belongs to Akamai's network."""
    try:
        ip_addr = ipaddress.ip_address(ip)
        for cidr in AKAMAI_IP_RANGES:
            if ip_addr in ipaddress.ip_network(cidr):
                return True
    except ValueError:
        logger.debug(f"Invalid IP address: {ip}")
        return False
    return False

def resolve_ip(url: str) -> str:
    """Resolve URL to IP address."""
    hostname = urlparse(url).hostname
    try:
        return socket.gethostbyname(hostname)
    except socket.gaierror:
        logger.debug(f"Failed to resolve IP for {hostname}")
        return None

def get_server_name(headers: dict, url: str) -> str:
    """Enhanced server identification for Akamai vs. AEM (Apache) based on headers and IP."""
    headers = {k.lower(): v for k, v in headers.items()}  # Normalize header keys

    # Check Server header
    server_value = headers.get("server", "").lower()
    if server_value:
        if "akamai" in server_value or "ghost" in server_value:
            return "Akamai"
        if "apache" in server_value:
            return "Apache (AEM)"  # Assume AEM for BMW/MINI Apache servers
        return server_value.capitalize()  # Return other server names as-is

    # Check Akamai indicators
    server_timing = headers.get("server-timing", "")
    has_akamai_cache = "cdn-cache; desc=HIT" in server_timing or "cdn-cache; desc=MISS" in server_timing
    has_akamai_metric = "ak_p;" in server_timing
    has_akamai_request_id = "x-akamai-request-id" in headers
    has_akamai_transform = "x-akamai-transformed" in headers
    ip = resolve_ip(url)
    is_akamai = is_akamai_ip(ip) if ip else False  # Renamed variable to avoid conflict

    # Check AEM indicators
    has_dispatcher = "x-dispatcher" in headers or "x-aem-instance" in headers
    has_aem_paths = any(
        "/etc.clientlibs" in v for h, v in headers.items()
        if h in ["link", "baqend-tags"]
    )  # BMW-specific AEM paths; add "/mini-web" for MINI once headers are provided
    has_jsessionid = any("jsessionid" in v.lower() for h, v in headers.items() if h == "set-cookie")
    has_security_headers = headers.get("x-content-type-options") == "nosniff" or headers.get("x-frame-options")

    # Decision logic
    if has_akamai_cache or has_akamai_request_id or (has_akamai_metric and is_akamai):
        # Redirects or cached responses with strong Akamai signals
        if has_aem_paths or has_dispatcher or has_jsessionid:
            # Cached AEM content (e.g., first BMW URL)
            return "Apache (AEM)"
        return "Akamai"  # Pure Akamai redirect (e.g., second BMW URL)
    
    if has_dispatcher or has_jsessionid or (has_aem_paths and has_security_headers):
        # AEM origin response, even if proxied by Akamai
        return "Apache (AEM)"
    
    # Fallback: Use IP and weak signals
    if is_akamai and (has_akamai_transform or has_akamai_metric):
        return "Akamai"
    
    # Log headers for debugging unknown cases
    logger.debug(f"Headers for {url}: {json.dumps(headers, indent=2)}")
    return "Unknown"

async def fetch_url_with_playwright(url: str, websocket: WebSocket) -> bool:
    async with async_playwright() as playwright:
        browser = None
        try:
            logger.info(f"Launching browser for {url}")
            browser = await playwright.chromium.launch(headless=True, args=["--no-sandbox", "--disable-gpu"])
            context = await browser.new_context(
                user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                viewport={"width": 1280, "height": 720},
                extra_http_headers={
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
                }
            )
            page = await context.new_page()

            # Enable tracing for debugging
            trace_dir = "traces"
            os.makedirs(trace_dir, exist_ok=True)
            trace_path = os.path.join(trace_dir, f"trace_{int(time.time())}.zip")
            await context.tracing.start(screenshots=True, snapshots=True, sources=True)

            redirect_chain = []
            start_time = time.time()

            async def handle_request(request):
                if request.is_navigation_request():
                    logger.debug(f"Navigation request: {request.url}")

            async def handle_response(response):
                if response.request.is_navigation_request():
                    try:
                        hop = {
                            "url": response.url,
                            "status": response.status,
                            "server": get_server_name(response.headers, response.url),
                            "timestamp": time.time() - start_time
                        }
                        if not redirect_chain or redirect_chain[-1]["url"] != hop["url"]:
                            redirect_chain.append(hop)
                            logger.debug(f"Added hop: {hop}")
                    except Exception as e:
                        logger.error(f"Error processing response for {response.url}: {e}")

            page.on("request", handle_request)
            page.on("response", handle_response)

            try:
                response = await page.goto(url, timeout=60000, wait_until="domcontentloaded")
            except playwright._impl._errors.TimeoutError as timeout_error:
                logger.warning(f"Navigation timeout for {url}: {timeout_error}")
                final_url = page.url if page.url else url
                result = {
                    "originalURL": url,
                    "finalURL": final_url,
                    "redirectChain": redirect_chain,
                    "totalTime": time.time() - start_time,
                    "error": f"Navigation timed out after 60s: {str(timeout_error)}"
                }
                await context.tracing.stop(path=trace_path)
                await websocket.send_text(json.dumps(result))
                return True
            except Exception as nav_error:
                logger.error(f"Navigation error for {url}: {nav_error}")
                final_url = page.url if page.url else url
                result = {
                    "originalURL": url,
                    "finalURL": final_url,
                    "redirectChain": redirect_chain,
                    "totalTime": time.time() - start_time,
                    "error": f"Navigation failed: {str(nav_error)}"
                }
                await context.tracing.stop(path=trace_path)
                await websocket.send_text(json.dumps(result))
                return True

            final_url = page.url

            if not redirect_chain or redirect_chain[-1]["url"] != final_url:
                try:
                    hop = {
                        "url": final_url,
                        "status": response.status if response else 200,
                        "server": get_server_name(response.headers, final_url) if response else "Unknown",
                        "timestamp": time.time() - start_time
                    }
                    redirect_chain.append(hop)
                    logger.debug(f"Added final hop: {hop}")
                except Exception as e:
                    logger.error(f"Error adding final hop for {final_url}: {e}")

            if len(redirect_chain) > 10:
                logger.warning(f"Possible redirect loop detected for {url}")
                redirect_chain.append({"error": "Excessive redirects (limit: 10)"})

            result = {
                "originalURL": url,
                "finalURL": final_url,
                "redirectChain": redirect_chain,
                "totalTime": time.time() - start_time
            }
            await context.tracing.stop(path=trace_path)
            await websocket.send_text(json.dumps(result))
            return True
        except WebSocketDisconnect:
            logger.info(f"Client disconnected while processing {url}")
            return False
        except Exception as e:
            logger.error(f"Error fetching {url}: {e}")
            result = {
                "originalURL": url,
                "finalURL": None,
                "redirectChain": redirect_chain if 'redirect_chain' in locals() else [],
                "totalTime": None,
                "error": f"Failed to fetch URL: {str(e)}"
            }
            try:
                await context.tracing.stop(path=trace_path)
                await websocket.send_text(json.dumps(result))
                return True
            except WebSocketDisconnect:
                logger.info(f"Client disconnected while sending error for {url}")
                return False
            except NameError:
                # Handle case where tracing wasn't started
                await websocket.send_text(json.dumps(result))
                return True
        finally:
            if browser:
                try:
                    await browser.close()
                    logger.info(f"Browser closed for {url}")
                except Exception as e:
                    logger.error(f"Error closing browser for {url}: {e}")

async def validate_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = f"https://{url}"
    if not validators.url(url):
        raise ValueError(f"Invalid URL: {url}")
    return url

@app.websocket("/analyze")
async def analyze_urls_websocket(websocket: WebSocket):
    logger.info("WebSocket connection attempt")
    await websocket.accept()
    logger.info("WebSocket connection accepted")
    try:
        data = await websocket.receive_json()
        logger.info(f"Received data: {data}")
        urls = list(set(filter(None, data.get("urls", []))))
        if not urls:
            await websocket.send_text(json.dumps({"error": "No valid URLs provided"}))
            return

        validated_urls = []
        for url in urls:
            try:
                validated_urls.append(await validate_url(url))
            except ValueError as ve:
                logger.error(f"Validation error for {url}: {ve}")
                await websocket.send_text(json.dumps({"error": f"Invalid URL: {url}"}))

        for url in validated_urls:
            try:
                await websocket.send_text(json.dumps({"status": "processing", "url": url}))
            except WebSocketDisconnect:
                logger.info("Client disconnected before processing started")
                return

            continue_processing = await fetch_url_with_playwright(url, websocket)
            if not continue_processing:
                logger.info("Stopping URL processing due to client disconnection")
                return

            await asyncio.sleep(1)

        try:
            await websocket.send_text(json.dumps({"done": True}))
        except WebSocketDisconnect:
            logger.info("Client disconnected before sending done message")
    except WebSocketDisconnect:
        logger.info("Client disconnected during WebSocket operation")
    except ValueError as ve:
        logger.error(f"Validation error: {ve}")
        try:
            await websocket.send_text(json.dumps({"error": "Invalid input"}))
        except WebSocketDisconnect:
            logger.info("Client disconnected while sending validation error")
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        try:
            await websocket.send_text(json.dumps({"error": f"Internal server error: {str(e)}"}))
        except WebSocketDisconnect:
            logger.info("Client disconnected while sending error")
    finally:
        try:
            await websocket.close()
            logger.info("WebSocket connection closed")
        except Exception as e:
            logger.error(f"Error closing WebSocket: {e}")

@app.get("/test")
async def test():
    return {"status": "OK", "message": "Service operational"}

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8080))
    logger.info(f"Starting Uvicorn on port {port}")
    logger.info(f"Playwright browsers path: {os.getenv('PLAYWRIGHT_BROWSERS_PATH', 'Not set')}")
    uvicorn.run(app, host="0.0.0.0", port=port)