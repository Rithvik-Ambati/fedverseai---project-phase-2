"""A real multi-node blockchain: 4 Hyperledger Besu validators running QBFT consensus on localhost.

QBFT is Byzantine fault tolerant: with n = 4 validators it keeps producing blocks with 1 validator down or even
malicious (needs 2f+1 = 3 honest) and halts safely if 2 are down. The same contract / Python bridge as the Hardhat
backend runs on top; only the node software changes, and transactions are signed locally with each role's key
(Besu manages no accounts).

    python -m fedsec.besunet start      # create keys + genesis (first time) and start 4 validators
    python -m fedsec.besunet status
    python -m fedsec.besunet stop
"""
import atexit, json, os, shutil, subprocess, sys, time

from web3 import Web3

HERE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHAIN = os.path.join(HERE, "chain")
DIST = os.path.join(CHAIN, "besu-dist")
NET = os.path.join(CHAIN, "qbft")
BASE_RPC, BASE_P2P = 8550, 30310
MNEMONIC = "test test test test test test test test test test test junk"      # same dev accounts as Hardhat
N_ACCOUNTS = 60
CHAIN_ID = 1337


def besu_bin():
    for d in sorted(os.listdir(DIST)) if os.path.isdir(DIST) else []:
        p = os.path.join(DIST, d, "bin", "besu.bat" if os.name == "nt" else "besu")
        if os.path.exists(p):
            return p
    raise FileNotFoundError(f"Besu not found in {DIST}: download the release zip from github.com/hyperledger/besu and unzip it there")


def dev_accounts(n=N_ACCOUNTS):
    from eth_account import Account
    Account.enable_unaudited_hdwallet_features()
    return [Account.from_mnemonic(MNEMONIC, account_path=f"m/44'/60'/0'/0/{i}") for i in range(n)]


_SHARED = {}


class BesuNetwork:
    @classmethod
    def shared(cls):
        """One network object per Python process, so every run and the UI talk to the same validators."""
        if "net" not in _SHARED:
            _SHARED["net"] = cls()
        return _SHARED["net"]

    def __init__(self, validators=4):
        self.n = validators
        self.procs = {}
        self.logs = {}

    # ------------------------------------------------------------------ one-time network files
    def setup(self):
        if os.path.exists(os.path.join(NET, "network", "genesis.json")):
            return
        os.makedirs(NET, exist_ok=True)
        alloc = {a.address[2:]: {"balance": hex(10_000 * 10 ** 18)} for a in dev_accounts()}
        cfg = {
            "genesis": {
                "config": {"chainId": CHAIN_ID, "berlinBlock": 0, "londonBlock": 0, "zeroBaseFee": True,
                           "qbft": {"blockperiodseconds": 1, "epochlength": 30000, "requesttimeoutseconds": 4}},
                "nonce": "0x0", "timestamp": "0x58ee40ba", "gasLimit": "0x1fffffff", "difficulty": "0x1",
                "mixHash": "0x63746963616c2062797a616e74696e65206661756c7420746f6c6572616e6365",
                "coinbase": "0x0000000000000000000000000000000000000000", "alloc": alloc},
            "blockchain": {"nodes": {"generate": True, "count": self.n}},
        }
        cfg_path = os.path.join(NET, "config.json")
        json.dump(cfg, open(cfg_path, "w"), indent=1)
        out = os.path.join(NET, "network")
        if os.path.exists(out):
            shutil.rmtree(out)
        r = subprocess.run([besu_bin(), "operator", "generate-blockchain-config", f"--config-file={cfg_path}",
                            f"--to={out}", "--private-key-file-name=key"], capture_output=True, text=True, env=self._env())
        if r.returncode != 0:
            raise RuntimeError("besu config generation failed:\n" + r.stdout[-800:] + r.stderr[-800:])

    def _env(self):
        e = dict(os.environ)
        e["BESU_OPTS"] = "-Xmx640m --enable-final-field-mutation=ALL-UNNAMED"
        e["JAVA_OPTS"] = e["BESU_OPTS"]
        return e

    def _keys(self):
        kd = os.path.join(NET, "network", "keys")
        return [os.path.join(kd, d) for d in sorted(os.listdir(kd))]

    def rpc(self, i):
        return f"http://127.0.0.1:{BASE_RPC + i}"

    # ------------------------------------------------------------------ lifecycle
    def _enodes(self):
        out = []
        for i, kd in enumerate(self._keys()):
            pub = open(os.path.join(kd, "key.pub")).read().strip().removeprefix("0x")
            out.append(f"enode://{pub}@127.0.0.1:{BASE_P2P + i}")
        return out

    def start_node(self, i, bootnode=None):
        keys = self._keys()[i]
        data = os.path.join(NET, f"data{i}")
        os.makedirs(data, exist_ok=True)
        static = os.path.join(NET, f"static-nodes{i}.json")
        json.dump([e for j, e in enumerate(self._enodes()) if j != i], open(static, "w"))
        cmd = [besu_bin(), f"--data-path={data}", f"--genesis-file={os.path.join(NET, 'network', 'genesis.json')}",
               f"--node-private-key-file={os.path.join(keys, 'key')}", "--rpc-http-enabled", "--rpc-http-host=127.0.0.1",
               f"--rpc-http-port={BASE_RPC + i}", "--rpc-http-api=ETH,NET,WEB3,QBFT,ADMIN,TXPOOL",
               "--host-allowlist=*", "--rpc-http-cors-origins=*", "--p2p-host=127.0.0.1", f"--p2p-port={BASE_P2P + i}",
               "--min-gas-price=0", "--sync-mode=FULL", "--data-storage-format=FOREST", "--sync-min-peers=1",
               f"--static-nodes-file={static}", "--discovery-enabled=false"]
        self.logs[i] = open(os.path.join(NET, f"node{i}.log"), "w")
        self.procs[i] = subprocess.Popen(cmd, stdout=self.logs[i], stderr=self.logs[i], env=self._env(),
                                         creationflags=getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0))

    def start(self, timeout=180):
        self.setup()
        w3 = Web3(Web3.HTTPProvider(self.rpc(0), request_kwargs={"timeout": 5}))
        if self._up(w3):
            return self
        for i in range(self.n):
            self.start_node(i)
        atexit.register(self.stop)
        t0 = time.time()
        while time.time() - t0 < timeout:
            if self._up(w3) and w3.net.peer_count >= self.n - 1 and w3.eth.block_number >= 2:
                return self
            time.sleep(1)
        raise TimeoutError("QBFT network did not come up; see chain/qbft/node*.log")

    @staticmethod
    def _up(w3):
        try:
            return w3.is_connected()
        except Exception:
            return False

    def kill_validator(self, i):
        p = self.procs.get(i)
        if p and p.poll() is None:
            if os.name == "nt":
                subprocess.run(["taskkill", "/T", "/F", "/PID", str(p.pid)], capture_output=True)
            else:
                p.terminate()
            p.wait(timeout=20)

    def stop(self):
        for i in list(self.procs):
            self.kill_validator(i)
        self.procs.clear()

    def validators(self):
        w3 = Web3(Web3.HTTPProvider(self.rpc(0)))
        return w3.provider.make_request("qbft_getValidatorsByBlockNumber", ["latest"])["result"]

    def status(self):
        out = []
        for i in range(self.n):
            w3 = Web3(Web3.HTTPProvider(self.rpc(i), request_kwargs={"timeout": 3}))
            try:
                out.append({"node": i, "block": w3.eth.block_number, "peers": w3.net.peer_count})
            except Exception:
                out.append({"node": i, "block": None, "peers": None})
        return out


if __name__ == "__main__":
    net = BesuNetwork()
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    if cmd == "start":
        net.start()
        print("validators:", net.validators())
        print(net.status())
        print("running; press Ctrl+C to stop")
        try:
            while True:
                time.sleep(5)
        except KeyboardInterrupt:
            net.stop()
    elif cmd == "status":
        print(net.status())
    elif cmd == "stop":
        os.system("taskkill /F /IM java.exe" if os.name == "nt" else "pkill -f besu")
