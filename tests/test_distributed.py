"""A real distributed run: 1 server process + N hospital processes, each with its own keys and chain account."""
import shutil

import pytest

pytestmark = pytest.mark.skipif(shutil.which("npx") is None, reason="Node/npx not installed")

from fedsec.dist import launch


def test_distributed_run_with_a_real_crash(tmp_path):
    res = launch.main(["--clients", "4", "--rounds", "2", "--epochs", "3", "--drop", "1:1", "--port", "9133",
                       "--out", str(tmp_path), "--timeout", "30"])
    assert res["processes"] == 5                                         # server + 4 hospitals, all separate OS processes
    h = res["history"]
    assert all(x["accepted"] and x["chain_verified"] for x in h)         # the CONTRACT verified every aggregate
    assert h[0]["dropped"] == [] and h[1]["dropped"] == [1] and h[1]["survivors"] == [0, 2, 3]
    assert h[-1]["acc"] > 0.55
    eps = res["eps"]
    assert eps["1"] < eps["0"]                                           # the crashed hospital was charged for fewer rounds
    assert (tmp_path / "client1.log").read_text().count("CRASHING") == 1
