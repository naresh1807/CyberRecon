"""Domain validation shared by scope and public metadata collectors."""
import re
from .models import ValidationError

def domain(value):
    if not isinstance(value, str) or len(value) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise ValidationError("Invalid domain text.")
    try:
        value = value.strip().removesuffix(".").encode("idna").decode().lower()
    except UnicodeError:
        raise ValidationError("Enter a valid fully qualified domain, without a URL or path.") from None
    if len(value) > 253 or not re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})", value):
        raise ValidationError("Enter a valid fully qualified domain, without a URL or path.")
    return value
