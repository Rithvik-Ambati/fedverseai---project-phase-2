"""Real multi-node consensus: 4 Besu validators running QBFT (needs Java and the Besu zip unpacked in chain/besu-dist).

Takes ~3 minutes; skipped automatically when Besu is not installed.
"""
import os
import shutil
import time

import pytest

from fedsec import besunet

pytestmark = pytest.mark.skipif(
    shutil.which("java") is None or not os.path.isdir(besunet.DIST) or not os.listdir(besunet.DIST),
    reason="Java / Besu not installed")

from fedsec.federation import Config, Federation


def test_federation_survives_a_dead_validator_and_chain_halts_safely_with_two():
    f = Federation(Config(rounds=2, n_clients=4, z=2.0, local_epochs=2, chain="besu"))
    ct, net = f.contract, f.contract.network
    try:
        assert len(net.validators()) == 4
        res = f.run()
        assert res["rejected_rounds"] == 0 and ct.verify_chain() == (True, None) and not f.verify_model_history()
        heads = {s["block"] for s in net.status()}
        assert len(heads) <= 2 and max(heads) - min(heads) <= 1                  # all validators on the same chain

        # f = 1: one validator down, the network still finalises blocks and a whole federation still completes
        net.kill_validator(3)
        time.sleep(4)
        res2 = Federation(Config(rounds=1, n_clients=4, z=2.0, local_epochs=1, chain="besu")).run()
        assert res2["rejected_rounds"] == 0

        # 2 of 4 down: no quorum (needs 2f+1 = 3) -> the chain stops producing blocks (safety over liveness)
        net.kill_validator(2)
        time.sleep(6)
        h0 = net.status()[0]["block"]
        time.sleep(8)
        assert net.status()[0]["block"] == h0
    finally:
        net.stop()
