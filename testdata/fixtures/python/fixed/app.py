import hashlib


def handler(request):
    value = str(request.get("value", ""))
    return hashlib.sha256(value.encode()).hexdigest()
