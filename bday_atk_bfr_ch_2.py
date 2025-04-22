import socket, time, base64
from crypto_impl import SimpleHashDRBG
from protocol import serialize_message, MSG_TYPE_CLIENT_HELLO, CS_DEFAULT

def pad32(b: bytes) -> bytes:
    return b.ljust(32, b'\x00')

def brute_force_seed(observed: bytes,
                     t0_ns: int,
                     window_ns: int = 2_000_000,
                     step_ns: int   =   100_000):
    drbg = SimpleHashDRBG()
    # expected length of the ASCII timestamp
    ascii_len = len(str(t0_ns))

    for delta in range(-window_ns, window_ns + 1, step_ns):
        t = t0_ns + delta
        s = str(t).encode()
        # skip if the decimal string isn't the right length
        if len(s) != ascii_len:
            continue

        seed = pad32(s)
        drbg.seed(seed)
        if drbg.generate(32) == observed:
            return t, seed

    return None, None

def attack():
    # 1) Connect as “client” to the real server
    sock = socket.create_connection(("127.0.0.1", 65432))

    # 2) Seed our DRBG exactly like the client’s time‑only fallback,
    #    generate the 32‑byte client_random, and note the timestamp.
    rng = SimpleHashDRBG()
    t0 = time.time_ns()
    seed0 = pad32(str(t0).encode("utf-8"))
    rng.seed(seed0)
    client_random = rng.generate(32)
    client_random_b64 = base64.b64encode(client_random).decode("ascii")

    # 3) Build & send a valid ClientHello
    hello = {
        "random": client_random_b64,
        "cipher_suites": [CS_DEFAULT]
    }
    raw_hello = serialize_message(MSG_TYPE_CLIENT_HELLO, hello)
    sock.sendall(raw_hello)
    print(f"[>] Sent ClientHello at {t0} ns with random={client_random_b64}")

    # 4) Brute‑force the fallback seed
    print("[*] Brute-forcing fallback seed…")
    found_t, found_seed = brute_force_seed(client_random, t0)
    if found_seed:
        print(f"[+] Seed recovered! timestamp = {found_t}")
        print(f"    seed (hex) = {found_seed.hex()}")
    else:
        print("[-] Seed not found in +/-2 ms window")

    sock.close()

if __name__ == "__main__":
    attack()