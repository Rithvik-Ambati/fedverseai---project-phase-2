"""Security properties on the REAL chain (Solidity contract on a local Hardhat node, via web3.py).

These start `npx hardhat node` automatically; they are skipped if Node/npx is unavailable.
"""
import shutil

import pytest

pytestmark = pytest.mark.skipif(shutil.which("npx") is None, reason="Node/npx not installed")

from fedsec.accountant import eps_for
from fedsec.federation import Config, Federation


def run(**kw):
    base = dict(rounds=3, n_clients=4, dp="distributed", z=2.0, local_epochs=1, chain="evm")
    base.update(kw)
    f = Federation(Config(**base))
    return f, f.run()


def kinds(res):
    return {e["type"] for e in res["events"]}


def test_honest_run_on_real_chain():
    f, res = run()
    ct = f.contract
    assert ct.backend == "evm" and ct.w3.eth.block_number > 30           # real blocks were mined
    assert res["rejected_rounds"] == 0 and not res["events"]
    assert ct.verify_chain() == (True, None)
    assert f.verify_model_history() == []
    # epsilon recomputed ON-CHAIN agrees with the analytic accountant (within a hair, rounded up)
    assert res["eps"][0] == pytest.approx(eps_for(2.0, 3), rel=2e-3)
    assert res["eps"][0] >= eps_for(2.0, 3) - 1e-9


def test_every_action_is_a_signed_tx_from_a_distinct_account():
    f, res = run()
    ct = f.contract
    senders = {}
    for rec in ct.tx_log:
        tx = ct.w3.eth.get_transaction(rec["tx"])
        senders.setdefault(rec["method"], set()).add(tx["from"])
    assert senders["beginRound"] == {ct.server}
    assert senders["postAggregate"] == {ct.server}
    assert senders["reportAudit"] <= {ct.auditor}
    assert senders["register"] == {ct.owner}
    assert len(senders["postCommitment"]) == 4                              # one account per hospital
    assert senders["postCommitment"] <= set(ct.client_addr.values())


def test_contract_rejects_unauthorised_callers():
    f, _ = run(rounds=1)
    ct, c = f.contract, f.contract.contract.functions
    stranger = ct.client_addr[1]
    with pytest.raises(Exception):
        c.postAggregate(5, [], b"\0" * 32, b"\0" * 32, True, False).transact({"from": stranger})
    with pytest.raises(Exception):
        c.reportAudit(0, ct.client_addr[2], False, "x").transact({"from": stranger})
    with pytest.raises(Exception):
        c.register(stranger, 10 ** 18).transact({"from": stranger})
    with pytest.raises(Exception):                                         # sigma must equal the admitted noise
        c.postIntent(0, 123, b"\1" * 32, b"\2" * 32).transact({"from": ct.client_addr[0]})


def test_history_tampering_detected():
    f, _ = run()
    assert f.contract.verify_chain()[0]
    f.contract.blocks[2]["txs"][0]["args"]["round"] = 99                  # edit a recorded transaction
    ok, bad = f.contract.verify_chain()
    assert not ok and bad == 2


def test_model_registry_tampering_detected():
    f, _ = run()
    f.snapshots[1] = f.snapshots[1] + 1e-3
    assert f.verify_model_history() == [1]


def test_merkle_inclusion_proof_matches_onchain_root():
    f, _ = run()
    leaf, path, root = f.contract.inclusion_proof(1, 2)
    assert f.contract.verify_inclusion(leaf, path, root)
    assert not f.contract.verify_inclusion(b"\1" * 32, path, root)


def test_forged_input_and_server_attacks_rejected_by_contract_logic():
    for kw, expected in (
        (dict(malicious={1: "forge"}), "aggregate_verification_failed"),
        (dict(server_attack="swap_aggregate"), "aggregate_verification_failed"),
        (dict(server_attack="drop_client"), "survivor_mismatch"),
    ):
        _, res = run(rounds=2, **kw)
        assert res["rejected_rounds"] == 2 and expected in kinds(res), kw


def test_missing_noise_banned_on_chain():
    f, res = run(malicious={2: "noeps"}, audit_rate=1.0, rounds=2)
    assert 2 in res["banned"] and "audit_fail" in kinds(res)
    assert f.contract.contract.functions.clients(f.contract.client_addr[2]).call()[1] is True   # banned flag in storage
    assert not (set(res["banned"]) - {2})                                  # no honest client accused


def test_budget_enforced_by_contract():
    cap = 6.0
    _, res = run(eps_max=cap, rounds=6, z=1.5)
    assert max(res["eps"].values()) <= cap + 1e-9
    assert any(e["type"] == "refused" and "budget" in e["reason"] for e in res["events"])


def test_under_declared_noise_is_refused():
    _, res = run(n_clients=8, malicious={4: "overbudget"}, eps_max=12.0, rounds=2, z=3.0)
    assert any(e["type"] == "refused" and e["cid"] == 4 for e in res["events"]) and res["eps"][4] == 0.0


def test_stake_slash_reward_and_withdraw():
    f, res = run(n_clients=6, rounds=3, stake=1.0, slash=0.4, malicious={2: "scale"}, attack_scale=10, audit_rate=1.0,
                 local_epochs=2)
    ct = f.contract
    assert res["banned"] == [2]
    b = ct.balances()
    assert b[2]["stake"] == 0 and b["pool"] == pytest.approx(1.0)               # ban forfeits the whole stake
    ct.distribute_rewards()
    b = ct.balances()
    assert b["pool"] == 0
    assert all(b[c]["credit"] == pytest.approx(0.2) for c in (0, 1, 3, 4, 5))   # shared equally among honest clients
    before = ct.w3.eth.get_balance(ct.client_addr[0])
    ct.withdraw(0)
    assert ct.w3.eth.get_balance(ct.client_addr[0]) - before > 1.1e18          # stake + reward (minus gas)
    with pytest.raises(Exception):
        ct.withdraw(2)                                                          # the banned client has nothing to take


def test_client_without_stake_is_refused():
    from unittest import mock
    from fedsec.evmchain import EVMChain
    orig = EVMChain.deposit
    with mock.patch.object(EVMChain, "deposit", lambda self, cid, eth: None if cid == 1 else orig(self, cid, eth)):
        _, res = run(n_clients=4, rounds=2, stake=0.5, slash=0.2, local_epochs=1)
    assert any(e["type"] == "refused" and e["cid"] == 1 and "stake" in e["reason"] for e in res["events"])


def test_server_blamed_and_slashed():
    f, res = run(n_clients=4, rounds=3, stake=1.0, slash=0.3, server_attack="swap_aggregate", attribution=True,
                 attack_rounds=(1,), local_epochs=1)
    assert "server_blamed" in kinds(res)
    assert f.contract.balances()["server_bond"] == pytest.approx(0.7)
