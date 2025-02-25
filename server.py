import functools
import json
import os
import random
from struct import pack, unpack
import ipaddress
from fcntl import ioctl
from base64 import b64encode, b64decode
import asyncio
from typing import Any, Tuple, Union

from websockets import ServerConnection
from websockets.asyncio.server import serve
from Crypto.Cipher import AES



# assign next IP address
def next_ip_address():
    for ip in ip_net.hosts():
        if ip == server_ip:
            continue
        if ip not in ip_to_ws:
            return ip
    return None


def get_next_aes():
    return AES.new(key, AES.MODE_CFB)


def open_tun(tun_name: bytes) -> Any:
    tun = open("/dev/net/tun", "r+b", buffering=0)
    LINUX_IFF_TUN = 0x0001
    LINUX_IFF_NO_PI = 0x1000
    LINUX_TUNSETIFF = 0x400454CA
    flags = LINUX_IFF_TUN | LINUX_IFF_NO_PI
    ifs = pack("16sH22s", tun_name, flags, b"")
    ioctl(tun, LINUX_TUNSETIFF, ifs)
    return tun


def read_ip_header(pkg: bytes) -> Tuple[Union[None, ipaddress.IPv4Address], Union[None, ipaddress.IPv4Address]]:
    if len(pkg) < 20:
        return None, None
    iphdr = unpack(">BBHHHBBHII", pkg[0:20])
    version = iphdr[0] >> 4
    ihl = iphdr[0] & 0xF
    if version != 4:
        return None, None
    return ipaddress.ip_address(iphdr[8]), ipaddress.ip_address(iphdr[9])


def tun_reader(tun_fd: Any) -> None:
    pkg = tun_fd.read(1500)  # mtu
    src_ip, dst_ip = read_ip_header(pkg)
    if src_ip is None or dst_ip is None:
        return
    if dst_ip not in ip_to_ws:
        return
    ws = ip_to_ws[dst_ip]
    asyncio.get_event_loop().create_task(send_package(ws, pkg))


async def send_package(ws: ServerConnection, pkg: bytes) -> None:
    encrypted_pkg = ws_to_aes[ws][0].encrypt(pkg)
    b64_pkg = b64encode(encrypted_pkg).decode("utf-8")
    await ws.send(json.dumps({"pkg": b64_pkg}))


async def client_handler(ws: ServerConnection, tun_fd: Any):
    new_ip = next_ip_address()
    if new_ip is None:
        await ws.send(json.dumps({"error": "ip address failed"}))
        return
    ws_to_ip[ws] = new_ip
    ip_to_ws[new_ip] = ws
    ws_to_aes[ws] = [get_next_aes(), get_next_aes()]
    task = asyncio.get_event_loop().create_task(tick_timer(ws))
    try:
        await ws.send(json.dumps({"ip": new_ip.__str__(), "gw": server_ip.__str__(), "iv": [
            b64encode(ws_to_aes[ws][0].iv).decode("utf-8"),
            b64encode(ws_to_aes[ws][1].iv).decode("utf-8"),
        ]}))

        print("New client is getting IP ", new_ip)
        async for msg in ws:
            json_msg = json.loads(msg)
            if 'pkg' not in json_msg:
                continue
            decoded_b64 = b64decode(json_msg['pkg'])
            decrypted_b64 = ws_to_aes[ws][1].decrypt(decoded_b64)
            src, dst = read_ip_header(decrypted_b64)
            if src is None or dst is None:
                continue
            if src != new_ip:
                continue
            print("Writing pkg from ", src, " to ", dst)
            tun_fd.write(decrypted_b64)
    except Exception as e:
        print("Client", new_ip, " has error", e)
    finally:
        print("Client", new_ip, "was disconnected")
    task.cancel()
    del ws_to_ip[ws]
    del ip_to_ws[new_ip]
    del ws_to_aes[ws]


async def tick_timer(ws: ServerConnection):
    await asyncio.sleep(1) # initial sleep
    while True:
        await asyncio.sleep(random.randint(1, 10) / 10.0)  # 0.1-1 sec
        fake_pkg = b"0" + random.randbytes(random.randint(31, 1499))
        encrypted_pkg = ws_to_aes[ws][0].encrypt(fake_pkg)
        await ws.send(json.dumps({"pkg": b64encode(encrypted_pkg).decode("utf-8")}))


async def main(tun_fd: Any):
    asyncio.get_event_loop().add_reader(tun_fd, tun_reader, tun_fd)
    handler = functools.partial(client_handler, tun_fd=tun_fd)
    async with serve(handler, "0.0.0.0", 8765) as server:
        await server.serve_forever()


key = b"BTC{S3cur3__VPN}"
interface = b"btc_vpn0"
ws_to_ip = dict()
ip_to_ws = dict()
ws_to_aes = dict()

ip_net = ipaddress.ip_network('192.168.100.0/24')
server_ip = ipaddress.ip_address('192.168.100.1')

if __name__ == '__main__':
    tun = open_tun(interface)
    os.system("sudo ip l set btc_vpn0 up")
    os.system(f"sudo ip a a dev btc_vpn0 {server_ip}/24")
    asyncio.run(main(tun))
