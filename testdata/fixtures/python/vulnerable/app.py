import hashlib
import subprocess


def handler(request):
    cmd = request.get("cmd", "")
    subprocess.call(cmd, shell=True)
    eval(request.get("expr", ""))
    return hashlib.md5(cmd.encode()).hexdigest()
