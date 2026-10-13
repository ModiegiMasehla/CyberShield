import httpx
SECURITY_HEADERS = {
    "content-security-policy": "Controls executable content sources.",
    "strict-transport-security": "Forces browsers to prefer HTTPS.",
    "x-content-type-options": "Reduces MIME-sniffing risks.",
    "x-frame-options": "Helps prevent clickjacking.",
    "referrer-policy": "Controls referrer information leakage.",
    "permissions-policy": "Restricts browser capabilities."
}
async def check_headers(url: str):
    async with httpx.AsyncClient(timeout=5, follow_redirects=True) as client:
        r = await client.get(url)
    headers = {k.lower(): v for k,v in r.headers.items()}
    rows = [{"header": h, "status": "PRESENT" if h in headers else "MISSING", "why": why} for h,why in SECURITY_HEADERS.items()]
    cookies = []
    for value in r.headers.get_list("set-cookie"):
        lower=value.lower()
        cookies.append({"secure": "secure" in lower, "httponly":"httponly" in lower, "samesite":"samesite" in lower})
    return {"url":str(r.url), "status_code":r.status_code, "https":r.url.scheme=="https", "headers":rows, "cookies":cookies, "server":headers.get("server","not disclosed")}
