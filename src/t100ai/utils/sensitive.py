import re

_IPV4_RE = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")

def mask_password(text: str) -> str:
    if not isinstance(text, str):
        text = str(text)
    # Simple masking: replace middle portion with asterisks
    if len(text) <= 4:
        return "****"[: max(1, len(text))]
    return text[:2] + "***" + text[-2:]

def mask_ip(text: str) -> str:
    if not isinstance(text, str):
        return text
    # Mask IPv4 addresses by obscuring the last octet
    if _IPV4_RE.match(text.strip()):
        parts = text.strip().split(".")
        if len(parts) == 4:
            parts[-1] = "xxx"
            return ".".join(parts)
    return text

def mask_hash(text: str) -> str:
    if not isinstance(text, str):
        return text
    # Obscure long hashes commonly used in tokens/IDs
    if len(text) > 8:
        return text[:4] + "..." + text[-4:]
    return text
