import platform
import subprocess

from fastapi import FastAPI, Request, APIRouter
from pydantic import BaseModel

# import socketio
# from firewall_control import block_ip, unblock_ip, quarantine_ip, unquarantine_ip, detect_os

router = APIRouter()



def detect_os():
    return "windows" if platform.system().lower() == "windows" else "ubuntu"

def block_ip(ip):
    if detect_os() == "windows":
        return subprocess.run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name=Block_{ip}", "dir=in", "action=block", f"remoteip={ip}"
        ], shell=True)
    else:
        return subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

def unblock_ip(ip):
    if detect_os() == "windows":
        return subprocess.run([
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name=Block_{ip}"
        ], shell=True)
    else:
        return subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])

def quarantine_ip(ip):
    if detect_os() == "windows":
        return block_ip(ip)  # simulate quarantine
    else:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "LOG", "--log-prefix", "QUARANTINE:"])
        return subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])

def unquarantine_ip(ip):
    if detect_os() == "windows":
        return unblock_ip(ip)
    else:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
        return subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "LOG", "--log-prefix", "QUARANTINE:"])
    


class IPRequest(BaseModel):
    ip: str


@router.post("/block_ip")
async def block(request: IPRequest):
    result = block_ip(request.ip)
    status = "blocked" if result.returncode == 0 else "failed"
    await sio.emit("firewall_action", {"ip": request.ip, "action": "blocked", "status": status})
    return {"ip": request.ip, "action": "block", "os": detect_os(), "status": status}


@router.post("/unblock_ip")
async def unblock(request: IPRequest):
    result = unblock_ip(request.ip)
    status = "unblocked" if result.returncode == 0 else "failed"
    await sio.emit("firewall_action", {"ip": request.ip, "action": "unblocked", "status": status})
    return {"ip": request.ip, "action": "unblock", "os": detect_os(), "status": status}


@router.post("/quarantine_ip")
async def quarantine(request: IPRequest):
    result = quarantine_ip(request.ip)
    status = "quarantined" if result.returncode == 0 else "failed"
    await sio.emit("firewall_action", {"ip": request.ip, "action": "quarantined", "status": status})
    return {"ip": request.ip, "action": "quarantine", "os": detect_os(), "status": status}


@router.post("/unquarantine_ip")
async def unquarantine(request: IPRequest):
    result = unquarantine_ip(request.ip)
    status = "unquarantined" if result.returncode == 0 else "failed"
    await sio.emit("firewall_action", {"ip": request.ip, "action": "unquarantined", "status": status})
    return {"ip": request.ip, "action": "unquarantine", "os": detect_os(), "status": status}