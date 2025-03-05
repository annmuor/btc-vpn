# BTC VPN
## This is just an example

On 6th of March I was giving a talk in Limassol called "How To Design Your Own VPN".
Here I provide a very, **very** simple example of what it could be.

Feel free to look into the code and understand the idea.

### DO NOT USE IT IN PRODUCTION

## Key features

- Uses HTTP + WebSocket as a transport layer
- Encrypts everything in AES (CFB mode, IVs are provided on the start)
- Provides fake messages to bypass traffic pattern detection
- Works with tun (Linux). Code OS X example on your own please. Utun [code sample](https://gist.github.com/whiler/295113850bd55ed4f4bf898124abe4a8)

## Client

If you see no client - it means no one have solved my task yet.
Once they do (or once I understand that nobody will) - I will upload a client as well.

## Installation (Linux)
1. Create VENV
2. Add CAP_NET_ADMIN (via setcap) to your Python if you're not r00t
3. Run server.py
4. In separate console set an IP address on tun interface (`sudo ip a a dev btcvpn0 192.168.100.1` with default settings)
5. Run client on separate device
6. Set IP address on client as well
7. ...
8. Enjoy your *modern*, **fast** VPN

## Installation (OS X)
1. Create a OSX port ...
2. ...
3. Enjoy your *modern*, **fast** VPN
