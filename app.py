"""Minimal Streamlit front-end:  streamlit run app.py"""
import glob, os

import altair as alt
import pandas as pd
import streamlit as st

from fedsec.accountant import noise_for_eps
from fedsec.attacks import membership_inference
from fedsec.federation import Config, Federation

st.set_page_config(page_title="Secure Federated Intelligence Platform", layout="wide")
st.title("Secure Federated Intelligence Platform")
run_tab, ledger_tab, res_tab = st.tabs(["Run a federation", "Ledger explorer", "Experiment results"])

with run_tab:
    c1, c2, c3 = st.columns(3)
    with c1:
        n = st.slider("clients", 4, 16, 8)
        rounds = st.slider("rounds", 3, 30, 10)
        dp = st.selectbox("DP mode", ["distributed", "local", "none"])
        eps_t = st.select_slider("target epsilon (total)", [1, 2, 4, 8, 16, 32], value=8)
    with c2:
        secagg = st.checkbox("secure aggregation", True)
        ledger = st.checkbox("ledger + commitments + audits", True)
        backend = st.selectbox("ledger backend", [
            "real blockchain (Solidity on local EVM chain)",
            "real BFT network (Solidity on 4 Besu QBFT validators)",
            "simulated ledger (fast)"])
        audit = st.slider("audit rate", 0.0, 1.0, 0.25, 0.05)
        dropout = st.slider("client dropout", 0.0, 0.4, 0.0, 0.05)
        eps_cap = st.number_input("per-client epsilon budget (0 = unlimited)", 0.0, 100.0, 0.0)
    with c3:
        atk = st.selectbox("malicious client 3", ["none", "scale", "labelflip", "noeps", "forge", "overbudget"])
        satk = st.selectbox("malicious server", ["none", "swap_aggregate", "drop_client"])
        window = st.checkbox("server / forgery attacks only in rounds 3-6 (so training can recover)", True)
    with st.expander("Advanced defences"):
        a1, a2, a3 = st.columns(3)
        with a1:
            zk = st.checkbox("ZK norm proof from every hospital (no trusted auditor; slower)", False)
            gate = st.checkbox("validation gate (rollback + emergency audit)", False)
        with a2:
            onchain = st.checkbox("contract verifies the aggregate itself (real chain)", False)
            attrib = st.checkbox("blame phase (identify the forger / blame the server)", False)
        with a3:
            stake = st.number_input("stake per hospital in ETH (0 = off; real chain)", 0.0, 10.0, 0.0)
    if st.button("Run", type="primary"):
        cfg = Config(n_clients=n, rounds=rounds, dp=dp, z=noise_for_eps(eps_t, rounds), secagg=secagg, ledger=ledger,
                     audit_rate=audit, dropout=dropout, eps_max=eps_cap or float("inf"),
                     malicious={} if atk == "none" else {3: atk}, attack_scale=10,
                     server_attack="" if satk == "none" else satk,
                     attack_rounds=(3, 4, 5, 6) if (window and (satk != "none" or atk == "forge")) else (),
                     chain="besu" if "BFT" in backend else ("evm" if backend.startswith("real") else "sim"),
                     norm_proof="zk" if zk else "none", val_gate=gate, onchain_verify=onchain, attribution=attrib,
                     stake=stake, slash=stake * 0.4)
        st.session_state.pop("_tamper", None)
        with st.spinner("training and writing every round to the chain (first run also starts the local node)..."):
            f = Federation(cfg)
            res = f.run()
        st.session_state["fed"], st.session_state["res"] = f, res
        st.session_state["target_eps"] = eps_t if dp != "none" else 0
    if "res" in st.session_state:
        f, res = st.session_state["fed"], st.session_state["res"]
        h = pd.DataFrame(res["history"])
        a, b, c = st.columns(3)
        a.metric("final accuracy", f"{res['final']['acc']:.3f}")
        b.metric("max epsilon spent", f"{max(res['eps'].values()):.2f}")
        c.metric("rejected rounds", res["rejected_rounds"])
        st.line_chart(h.set_index("round")[["acc", "auc"]])
        st.subheader("Server's view of one client's update")
        st.write(f"mean cosine(similarity of what the server saw, true update) = **{res['leak_cos']:.3f}** "
                 "(1.0 = server reads the update, ~0 = masked)")
        st.subheader("Membership inference on the final model")
        st.json(membership_inference(res["model"], res["clients"]))
        st.subheader("Per-client privacy budget")
        eps_df = pd.DataFrame({"client": [str(c) for c in res["eps"]], "epsilon": list(res["eps"].values())})
        top = max(eps_df.epsilon.max(), st.session_state.get("target_eps", 0)) * 1.25 or 1.0
        bars = alt.Chart(eps_df).mark_bar(color="#1b998b").encode(
            x=alt.X("client:N", title="client (hospital)", axis=alt.Axis(labelAngle=0)),
            y=alt.Y("epsilon:Q", title="epsilon spent", scale=alt.Scale(domain=[0, top])),
            tooltip=["client", alt.Tooltip("epsilon:Q", format=".2f")])
        labels = bars.mark_text(dy=-8, color="white").encode(text=alt.Text("epsilon:Q", format=".2f"))
        layers = bars + labels
        if st.session_state.get("target_eps"):
            rule = alt.Chart(pd.DataFrame({"t": [st.session_state["target_eps"]]})).mark_rule(
                color="#f28f3b", strokeDash=[6, 4], size=2).encode(y="t:Q")
            layers = layers + rule
        st.altair_chart(layers, use_container_width=True)
        st.caption("Dashed line = the planned privacy budget for the run. Equal bars: every hospital took part in every round.")
        if res.get("events"):
            st.subheader("Security events (on-chain)")
            st.dataframe(pd.DataFrame(res["events"]), use_container_width=True)
        if res.get("banned"):
            st.warning(f"banned by reputation: {res['banned']}")

with ledger_tab:
    if "fed" in st.session_state and st.session_state["fed"].contract:
        f = st.session_state["fed"]
        c = f.contract
        real = getattr(c, "backend", "sim") == "evm"
        ok, bad = c.verify_chain()
        if real:
            st.info(f"Real EVM chain (chain id {c.w3.eth.chain_id}), contract {c.address}, "
                    f"block height {c.w3.eth.block_number}. Every action is a signed transaction from its own account "
                    f"(owner / server / auditor / one per hospital).")
        else:
            st.info("Simulated ledger (hash-chained Python log).")
        if ok:
            st.success("Chain intact: every recorded block and transaction matches what the chain holds" if real
                       else "Hash chain intact: no block has been altered")
        else:
            st.error(f"Record does not match the chain at phase {bad}: history was modified")
        if f.verify_model_history():
            st.error(f"Stored model does not match its on-chain hash in rounds {f.verify_model_history()}")
        else:
            st.success("Model history intact: every stored model matches the hash recorded on-chain")
        m1, m2, m3 = st.columns(3)
        m1.metric("real blocks mined" if real else "blocks", c.w3.eth.block_number if real else len(c.blocks))
        m2.metric("transactions", sum(len(b["txs"]) for b in c.blocks))
        m3.metric("gas used (measured)" if real else "estimated gas", f"{c.gas_total:,}")
        st.caption("Gas by contract method" + (" (measured on the EVM)" if real else " (estimate for an Ethereum-style chain)"))
        st.dataframe(pd.Series(c.gas_by_method, name="gas").sort_values(ascending=False).to_frame(),
                     use_container_width=True)
        n_show = st.slider("phases to show (newest first)", 2, len(c.blocks), min(6, len(c.blocks)))
        for blk in reversed(c.blocks[-n_show:]):
            span = f"blocks #{blk['first_block']}-#{blk['last_block']}" if real else f"block {blk['index']}"
            with st.expander(f"{span}: {blk['label']}   (hash {blk['hash'][:12]}..)"):
                st.caption(f"previous block hash: {blk['prev'][:12]}..   |   {len(blk['txs'])} transactions")
                st.dataframe(pd.DataFrame([{"method": t["method"], "gas": t["gas"],
                                            "details": ", ".join(f"{k}={v}" for k, v in t["args"].items())}
                                           for t in blk["txs"]]), use_container_width=True, hide_index=True)
        net = getattr(c, "network", None)
        if net is not None:
            st.divider()
            st.subheader("Consensus: 4 Besu validators (QBFT)")
            st.caption("QBFT keeps producing blocks with 1 validator down (3 of 4 = 2f+1) and halts safely with 2 down.")
            st.dataframe(pd.DataFrame(net.status()), hide_index=True)
            b1, b2, b3 = st.columns(3)
            if b1.button("Stop validator 3 (1 fault tolerated)"):
                net.kill_validator(3)
                st.rerun()
            if b2.button("Also stop validator 2 (no quorum: chain halts)"):
                net.kill_validator(2)
                st.rerun()
        st.divider()
        st.subheader("Tamper test")
        st.caption("Simulates an attacker editing one recorded transaction. The check at the top must turn red.")
        if st.session_state.get("_tamper"):
            if st.button("Undo the edit"):
                args, key, val = st.session_state.pop("_tamper")
                args[key] = val
                st.rerun()
        elif st.button("Edit a recorded transaction"):
            args = c.blocks[min(2, len(c.blocks) - 1)]["txs"][0]["args"]
            st.session_state["_tamper"] = (args, "round", args.get("round"))
            args["round"] = 999
            st.rerun()
    else:
        st.info("Run a federation with the ledger enabled first.")

with res_tab:
    files = sorted(glob.glob(os.path.join("results", "*.csv")))
    if not files:
        st.info("Run `python -m experiments.run_experiments all` to produce results.")
    for p in files:
        with st.expander(os.path.basename(p)):
            st.dataframe(pd.read_csv(p), use_container_width=True)
