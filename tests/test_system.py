import copy

import numpy as np
import pytest

from fedsec import merkle
from fedsec.accountant import eps_for
from fedsec.federation import Config, Federation, model_hash


def run(**kw):
    base = dict(rounds=4, n_clients=4, dp="distributed", z=2.0, local_epochs=1)
    base.update(kw)
    f = Federation(Config(**base))
    return f, f.run()


def kinds(res):
    return {e["type"] for e in res["events"]}


def test_honest_run_is_clean_and_verifiable():
    f, res = run()
    assert res["rejected_rounds"] == 0 and not res["events"]
    assert f.contract.verify_chain() == (True, None)
    assert f.verify_model_history() == []
    # privacy accounting on the contract matches an independent recomputation
    assert res["eps"][0] == pytest.approx(eps_for(2.0, 4), rel=1e-6)


def test_ledger_tampering_detected():
    f, _ = run()
    ok, _ = f.contract.verify_chain()
    assert ok
    f.contract.blocks[2]["txs"][0]["args"]["round"] = 99
    ok, bad = f.contract.verify_chain()
    assert not ok and bad == 2


def test_model_tampering_detected():
    f, _ = run()
    f.snapshots[1] = f.snapshots[1] + 1e-3
    assert f.verify_model_history() == [1]


def test_merkle_inclusion_proof_from_contract():
    f, _ = run()
    leaf, path, root = f.contract.inclusion_proof(2, 1)
    assert merkle.verify(leaf, path, root)


def test_secagg_changes_nothing_but_privacy():
    kw = dict(dp="none", ledger=False, rounds=3)
    _, a = run(secagg=True, **kw)
    _, b = run(secagg=False, **kw)
    from fedsec.model import get_flat
    assert np.allclose(get_flat(a["model"]), get_flat(b["model"]), atol=1e-5)
    assert abs(a["leak_cos"]) < 0.2 and b["leak_cos"] > 0.99   # server view: masked vs plaintext


def test_dropout_recovery():
    _, res = run(n_clients=8, dropout=0.2, rounds=5, dp="none", eps_max=float("inf"))
    assert sum(1 for h in res["history"] if not h["rejected"]) >= 3


def test_forged_masked_input_detected_by_commitment_check():
    _, res = run(malicious={1: "forge"})
    assert res["rejected_rounds"] == 4 and "aggregate_verification_failed" in kinds(res)
    _, und = run(malicious={1: "forge"}, ledger=False)
    assert und["rejected_rounds"] == 0           # undefended: silently accepted


def test_server_swapping_aggregate_detected():
    _, res = run(server_attack="swap_aggregate")
    assert res["rejected_rounds"] == 4 and "aggregate_verification_failed" in kinds(res)


def test_server_dropping_client_detected_by_survivor_check():
    _, res = run(server_attack="drop_client")
    assert res["rejected_rounds"] == 4 and "survivor_mismatch" in kinds(res)


def test_missing_noise_caught_by_audit_and_banned():
    _, res = run(malicious={2: "noeps"}, audit_rate=1.0, rounds=3)
    assert 2 in res["banned"] and "audit_fail" in kinds(res)


def test_norm_violation_caught_by_audit():
    _, res = run(n_clients=8, malicious={3: "scale"}, attack_scale=20, audit_rate=1.0, rounds=3)
    assert 3 in res["banned"]
    # honest clients are never falsely accused
    assert all(c == 3 for c in res["banned"])


def test_no_false_positives_on_honest_clients():
    _, res = run(n_clients=8, audit_rate=1.0, rounds=6)
    assert not res["banned"] and "audit_fail" not in kinds(res)


def test_privacy_budget_enforced_on_chain():
    cap = 6.0
    f, res = run(eps_max=cap, rounds=8, z=1.5)
    assert max(res["eps"].values()) <= cap + 1e-9
    assert any(e["type"] == "refused" and "budget" in e["reason"] for e in res["events"])


def test_under_declared_noise_cannot_dodge_the_budget():
    # a client declaring tiny sigma is charged a huge epsilon and refused up front
    _, res = run(n_clients=8, malicious={4: "overbudget"}, eps_max=12.0, rounds=3, z=3.0)
    refused = [e for e in res["events"] if e["type"] == "refused" and e["cid"] == 4]
    assert refused and res["eps"][4] == 0.0


def test_emergency_audit_when_aggregate_norm_implausible():
    # five boosted attackers push the *aggregate* far outside any honest range
    mal = {i: "scale" for i in range(5)}
    _, res = run(n_clients=8, malicious=mal, attack_scale=40, audit_rate=0.0, rounds=3)
    assert any(h["emergency"] for h in res["history"])
    assert set(res["banned"]) == set(mal)


def test_seeded_audit_primitives():
    import hashlib
    from fedsec.federation import check_seeded, noise_vec
    d, sigma, clip = 14, 0.5, 0.5
    seed, beacon = b"s" * 16, b"b" * 32
    clean = np.full(d, 0.1)                       # norm 0.37 <= clip
    x = clean + noise_vec(seed, beacon, sigma, d)
    h = hashlib.sha256(seed).hexdigest()
    assert check_seeded(x, seed, h, beacon, sigma, clip, d)[0]
    assert not check_seeded(x, b"t" * 16, h, beacon, sigma, clip, d)[0]        # wrong seed
    assert not check_seeded(clean, seed, h, beacon, sigma, clip, d)[0]          # noise missing
    assert not check_seeded(x, seed, h, b"c" * 32, sigma, clip, d)[0]           # noise not bound to the beacon


def test_noise_is_bound_to_committed_seed_and_beacon():
    from fedsec.federation import noise_vec
    a = noise_vec(b"s" * 16, b"b" * 32, 1.0, 14)
    assert np.array_equal(a, noise_vec(b"s" * 16, b"b" * 32, 1.0, 14))
    assert not np.array_equal(a, noise_vec(b"s" * 16, b"c" * 32, 1.0, 14))


def test_integrity_attack_window_recovers():
    # attack only in rounds 1-2: those rounds are rejected, the others go through
    _, res = run(server_attack="swap_aggregate", attack_rounds=(1, 2), rounds=5)
    rej = [h["round"] for h in res["history"] if h["rejected"]]
    assert rej == [1, 2]


# ====================================================================== new defences (adaptive gate, zk, baselines, blame)
def test_validation_gate_stops_poisoning_even_with_audits_off():
    kw = dict(n_clients=8, rounds=8, z=1.0, local_epochs=15, malicious={3: "scale"}, attack_scale=10, audit_rate=0.0)
    _, plain = run(**kw)
    _, gated = run(val_gate=True, **kw)
    assert gated["final"]["acc"] > plain["final"]["acc"] + 0.25          # rolled back + attacker found by emergency audit
    assert 3 in gated["banned"] and any(h["emergency"] for h in gated["history"])


def test_validation_gate_has_no_false_alarms_on_honest_runs():
    _, res = run(n_clients=8, rounds=8, z=1.0, local_epochs=15, val_gate=True)
    assert res["rejected_rounds"] == 0 and not res["banned"] and not any(h["emergency"] for h in res["history"])


def test_probation_audits_catch_attackers_in_round_zero():
    _, res = run(n_clients=8, rounds=3, malicious={3: "scale"}, attack_scale=10, audit_rate=0.0,
                 probation_rounds=1, probation_rate=1.0, emergency_audit=False)
    assert 3 in res["banned"]
    assert [e["round"] for e in res["events"] if e["type"] == "audit_fail"] == [0]


def test_zk_norm_proof_bans_poisoner_with_zero_audit_rate():
    _, res = run(n_clients=6, rounds=2, malicious={3: "scale"}, attack_scale=10, audit_rate=0.0, norm_proof="zk")
    assert 3 in res["banned"]
    assert any(e["type"] == "audit_fail" and "zk norm proof" in e["reason"] for e in res["events"])


def test_zk_mode_honest_clients_pass_and_label_flip_inside_bound_is_not_caught():
    _, res = run(n_clients=6, rounds=2, audit_rate=1.0, norm_proof="zk")
    assert not res["banned"] and res["rejected_rounds"] == 0
    _, lf = run(n_clients=6, rounds=2, malicious={2: "labelflip"}, audit_rate=0.0, norm_proof="zk")
    assert not lf["banned"]                                               # known limit, stated in the README


def test_zk_noise_audit_reveals_only_noise_and_catches_missing_noise():
    f, res = run(n_clients=6, rounds=2, malicious={2: "noeps"}, audit_rate=1.0, norm_proof="zk")
    assert 2 in res["banned"]
    assert any("noise" in e.get("reason", "") for e in res["events"] if e["type"] == "audit_fail")


def test_robust_aggregators_resist_signflip_but_forbid_secagg():
    kw = dict(n_clients=8, rounds=6, dp="none", ledger=False, secagg=False, local_epochs=15,
              malicious={3: "scale"}, attack_scale=10)
    _, mean = run(**kw)
    for agg in ("median", "trimmed", "krum", "multikrum"):
        _, res = run(aggregator=agg, **kw)
        assert res["final"]["acc"] > mean["final"]["acc"] + 0.3, agg
    with pytest.raises(ValueError):
        Federation(Config(aggregator="krum", secagg=True))


def test_second_dataset_trains():
    _, res = run(dataset="covtype", hidden=16, rounds=3, n_clients=4, dp="none", ledger=False, secagg=False, local_epochs=3)
    assert res["final"]["acc"] > 0.55


def test_blame_phase_bans_the_forger_and_restores_liveness():
    kw = dict(n_clients=6, rounds=6, malicious={3: "forge"}, attack_scale=10, audit_rate=0.0, attack_rounds=(1, 2, 3, 4, 5))
    _, no = run(**kw)
    _, yes = run(attribution=True, **kw)
    assert no["rejected_rounds"] == 5 and not no["banned"]
    assert yes["rejected_rounds"] == 1 and yes["banned"] == [3]
    assert "forger_identified" in kinds(yes)


def test_blame_phase_blames_the_server_when_clients_are_consistent():
    _, res = run(n_clients=6, rounds=3, server_attack="swap_aggregate", attribution=True, attack_rounds=(1, 2))
    assert "server_blamed" in kinds(res) and not res["banned"]
