import json
import os
import random
import sys
from struct import pack, unpack
import ipaddress
from fcntl import ioctl
from base64 import b64encode, b64decode
import asyncio
from typing import Any, Tuple, Union

from websockets import ClientConnection
from websockets.asyncio.client import connect
from Crypto.Cipher import AES


def open_tun(tun_name: bytes) -> Any:
    tun = open("/dev/net/tun", "r+b", buffering=0)
    LINUX_IFF_TUN = 0x0001
    LINUX_IFF_NO_PI = 0x1000
    LINUX_TUNSETIFF = 0x400454CA
    flags = LINUX_IFF_TUN | LINUX_IFF_NO_PI
    ifs = pack("16sH22s", tun_name, flags, b"")
    ioctl(tun, LINUX_TUNSETIFF, ifs)
    return tun


def read_ip_header(pkg: bytes) -> Tuple[Union[None,ipaddress.IPv4Address], Union[None,ipaddress.IPv4Address]]:
    if len(pkg) < 20:
        return None, None
    iphdr = unpack(">BBHHHBBHII", pkg[0:20])
    version = iphdr[0] >> 4
    ihl = iphdr[0] & 0xF
    if version != 4:
        return None, None
    return ipaddress.ip_address(iphdr[8]), ipaddress.ip_address(iphdr[9])


def tun_reader(tunfd: Any, ws: ClientConnection, encrypt: AES) -> None:
    pkg = tunfd.read(1500)  # mtu
    src_ip, dst_ip = read_ip_header(pkg)
    if src_ip is None or dst_ip is None:
        return
    asyncio.get_event_loop().create_task(send_package(ws, pkg, encrypt))


async def send_package(ws: ClientConnection, pkg: bytes, encrypt: AES) -> None:
    _pkg = b64encode(encrypt.encrypt(pkg)).decode("utf-8")
    await ws.send(json.dumps({"pkg": _pkg}))



async def tick_timer(ws: ClientConnection, encrypt: AES) -> None:
    await asyncio.sleep(1)
    while True:
        await asyncio.sleep(random.randint(1, 10) / 10.0)  # 0.1-10 sec
        pkg = b"0" + random.randbytes(random.randint(31, 1499))
        _pkg = encrypt.encrypt(pkg)
        await ws.send(json.dumps({"pkg": b64encode(_pkg).decode("utf-8")}))


async def main(tun_fd: Any, server: str):
    async with connect(server) as ws:
        first = await ws.recv()
        data = json.loads(first)
        decrypt = AES.new(key, AES.MODE_CFB, iv=b64decode(data['iv'][0]))
        encrypt = AES.new(key, AES.MODE_CFB, iv=b64decode(data['iv'][1]))
        asyncio.get_event_loop().add_reader(tun_fd, tun_reader, tun_fd, ws, encrypt)
        asyncio.get_event_loop().create_task(tick_timer(ws, encrypt))
        os.system("sudo ip l set btc_vpn1 up")
        os.system(f"sudo ip a a dev btc_vpn1 {data['ip']}/24")
        print("I am ", data['ip'], "my server is ", data['gw'])
        while True:
            msg = await ws.recv()
            data = json.loads(msg)['pkg']
            pkg = b64decode(data)
            real_pkg = decrypt.decrypt(pkg)
            src, dst = read_ip_header(real_pkg)
            if src is None or dst is None:
                continue
            print("Reading from ", src, " to ", dst)
            tun_fd.write(real_pkg)




key = b"BTC{S3cur3__VPN}"
interface = b"btc_vpn1"
if __name__ == '__main__':
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} ws://server:port")
        exit(1)
    asyncio.run(main(open_tun(interface), sys.argv[1]))
