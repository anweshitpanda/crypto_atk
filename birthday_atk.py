import threading, time
from flask import Flask, request, Response # type: ignore
from crypto_impl import SimpleHashDRBG
import requests

CLIENT_HOST, CLIENT_PORT = "127.0.0.1", 65433
SERVER_HOST, SERVER_PORT = "127.0.0.1", 65432

NUM_BYTES  = 32
PREFIX_LEN = 19
MAX_ITERS  = 200_000

def seed_client(rng: SimpleHashDRBG):
    b = str(time.time_ns()).encode("utf-8")
    b = (b + b"\x00" * 32)[:32]
    rng.seed(b)

def seed_server(rng: SimpleHashDRBG):
    base = str(time.time_ns()) + str(threading.get_ident())
    b = base.encode("utf-8")
    b = (b + b"\x00" * 32)[:32]
    rng.seed(b)

def run_api(host, port, seed_func, name):
    rng = SimpleHashDRBG()
    seed_func(rng)

    app = Flask(name)
    @app.route("/random")
    def random_bytes():
        n = int(request.args.get("n_bytes", NUM_BYTES))
        return Response(rng.generate(n), mimetype="application/octet-stream")

    app.run(host=host, port=port)

def start_api(host, port, seed_func, name):
    t = threading.Thread(
        target=run_api,
        args=(host, port, seed_func, name),
        daemon=True
    )
    t.start()

def birthday_attack(client_url, server_url):
    client_seen, server_seen = {}, {}

    for _ in range(MAX_ITERS):
        c = requests.get(client_url, params={"n_bytes":NUM_BYTES}).content
        pc = c[:PREFIX_LEN]
        if pc in server_seen:
            print(f"\n collision {pc.hex()}")
            print(f" CLIENT: {c.hex()}")
            print(f" SERVER: {server_seen[pc].hex()}")
            return
        client_seen[pc] = c

        s = requests.get(server_url, params={"n_bytes":NUM_BYTES}).content
        ps = s[:PREFIX_LEN]
        if ps in client_seen:
            print(f"\n collision {ps.hex()}")
            print(f" CLIENT: {client_seen[ps].hex()}")
            print(f" SERVER: {s.hex()}")
            return
        server_seen[ps] = s

    print("[-] no collision within iteration cap")

if __name__ == "__main__":
    start_api(CLIENT_HOST, CLIENT_PORT, seed_client, "client_api")
    start_api(SERVER_HOST, SERVER_PORT, seed_server, "server_api")

    # give Flask a second to start listening
    time.sleep(1)

    client_url = f"http://{CLIENT_HOST}:{CLIENT_PORT}/random"
    server_url = f"http://{SERVER_HOST}:{SERVER_PORT}/random"
    print(f"Client @ {client_url}")
    print(f"Server @ {server_url}")
    print("Starting birthday attack…")

    birthday_attack(client_url, server_url)
