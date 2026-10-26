"""Schematic figures for the report (architecture, ZK proof, defence coverage, QBFT network, distributed protocol)."""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Circle

NAVY, TEAL, ORANGE, RED, GREY, GREEN, LIGHT, GOLD = "#1f2a44", "#1b998b", "#f28f3b", "#d1495b", "#8d99ae", "#2e933c", "#eef1f6", "#e9c46a"


def box(ax, x, y, w, h, title, sub="", color=NAVY, tc="white", fs=11, sfs=8.5):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.08", fc=color, ec="none"))
    if sub:
        ax.text(x + w / 2, y + h * 0.64, title, ha="center", va="center", color=tc, fontsize=fs, fontweight="bold")
        ax.text(x + w / 2, y + h * 0.28, sub, ha="center", va="center", color=tc, fontsize=sfs)
    else:
        ax.text(x + w / 2, y + h / 2, title, ha="center", va="center", color=tc, fontsize=fs, fontweight="bold")


def arrow(ax, x1, y1, x2, y2, color=NAVY, lw=1.8, style="-|>", ls="-"):
    ax.annotate("", (x2, y2), (x1, y1), arrowprops=dict(arrowstyle=style, color=color, lw=lw, ls=ls))


def lane(ax, x, y, w, h, label, color):
    ax.add_patch(FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.1", fc=color, ec="none", alpha=0.10))
    ax.text(x + 0.12, y + h - 0.22, label, fontsize=12.5, fontweight="bold", color=color, va="top")


def architecture(save):
    fig, ax = plt.subplots(figsize=(16, 9))
    ax.set_xlim(0, 16); ax.set_ylim(0, 9); ax.axis("off")
    lane(ax, 0.15, 0.3, 5.1, 8.5, "HOSPITALS  (private data never leaves)", NAVY)
    lane(ax, 5.6, 3.6, 4.2, 5.2, "SERVER  (untrusted)", RED)
    lane(ax, 10.15, 0.3, 5.7, 8.5, "BLOCKCHAIN  (Solidity contract on QBFT / EVM)", TEAL)
    # hospital column
    hs = [("1  Train locally", "own patients only"), ("2  Clip + DP noise", "seed committed before beacon"),
          ("3  Commit", "Pedersen commitment on-chain"), ("4  ZK norm proof", "||update||2 <= C, no auditor"),
          ("5  Mask (SecAgg)", "pairwise masks, Shamir shares")]
    for i, (t, sub) in enumerate(hs):
        y = 7.0 - i * 1.4
        box(ax, 0.5, y, 4.4, 1.05, t, sub, NAVY if i != 3 else GREEN)
        if i < 4:
            arrow(ax, 2.7, y, 2.7, y - 0.35)
    # server column
    box(ax, 6.0, 6.9, 3.4, 1.05, "Relay encrypted shares", "cannot read them", RED)
    box(ax, 6.0, 5.5, 3.4, 1.05, "Sum masked vectors", "sees only noise", RED)
    box(ax, 6.0, 4.1, 3.4, 1.05, "Unmask + publish aggregate", "needs >= t shares", RED)
    arrow(ax, 7.7, 6.9, 7.7, 6.55); arrow(ax, 7.7, 5.5, 7.7, 5.15)
    arrow(ax, 4.9, 1.9, 6.0, 5.9, color=ORANGE)             # masked vectors to server
    # chain column
    cs = [("Admission + budget", "RDP accountant in fixed point"), ("Intents + beacon", "commit-reveal randomness"),
          ("Commitments + Merkle root", "tamper-evident log"), ("Audit selection", "keccak(beacon, root)"),
          ("verifyAggregate", "contract checks prod C = Com(agg)"), ("Stake, slash, reward", "ban forfeits stake"),
          ("Model registry", "hash per round")]
    for i, (t, sub) in enumerate(cs):
        y = 7.45 - i * 1.07
        box(ax, 10.5, y, 5.0, 0.86, t, sub, TEAL if i not in (4,) else GREEN, fs=10.5, sfs=8)
    arrow(ax, 4.9, 3.35, 10.5, 3.6, color=TEAL, ls="--")       # hospital -> chain, routed below the server box
    ax.text(7.7, 3.12, "signed transactions: intents, commitments, proof hashes", ha="center", fontsize=8.5, color=TEAL)
    arrow(ax, 9.4, 4.45, 10.5, 3.95, color=ORANGE)             # server -> chain (aggregate to verify)
    # verifier / auditor
    box(ax, 6.0, 0.5, 3.4, 2.3, "", "", GOLD, tc=NAVY)
    ax.text(7.7, 2.45, "Auditor / any verifier", ha="center", va="center", fontsize=11, fontweight="bold", color=NAVY)
    ax.text(7.7, 1.4, "verifies ZK proofs\nopens noise seeds (not data)\nblame phase\nreports to the contract",
            ha="center", va="center", fontsize=8.8, color=NAVY)
    arrow(ax, 9.4, 1.7, 10.5, 2.3, color=GOLD)
    ax.text(8.0, 8.93, "Secure Federated Intelligence Platform - system architecture", ha="center", fontsize=15, fontweight="bold", color=NAVY)
    ax.text(0.2, 0.05, "solid orange: masked data   |   dashed teal: signed transactions   |   green: zero-knowledge / on-chain verification",
            fontsize=9, color=GREY)
    save(fig, "F01_architecture")


def zk_protocol(save):
    fig, ax = plt.subplots(figsize=(15, 6.6))
    ax.set_xlim(0, 15); ax.set_ylim(0, 6.6); ax.axis("off")
    ax.text(7.5, 6.3, "Zero-knowledge proof that a committed update has L2 norm <= C", ha="center", fontsize=15, fontweight="bold", color=NAVY)
    steps = [
        ("1  Commit per coordinate", "P_i = h_i^{c_i} g^{r_i}\nA_i = u^{c_i} g^{s_i}\nQ_i = u^{c_i^2} g^{t_i}", NAVY),
        ("2  Sigma proof (same c_i)", "P_i, A_i, Q_i = A_i^{c_i} g^{tau}\nshows Q_i commits to c_i squared", NAVY),
        ("3  Sum of squares", "prod Q_i = u^{sum c_i^2} g^{sum t_i}\nslack  w = B - sum c_i^2", NAVY),
        ("4  Range proof of slack", "w = sum 2^j b_j,  D_j = u^{b_j} g^{rho_j}\nOR-proof: each bit is 0 or 1", NAVY),
        ("5  Anyone verifies", "prod P_i = Com_c   |   all Sigma proofs\nprod D_j^{2^j} = V   |   all OR-proofs", GREEN),
    ]
    for i, (t, sub, c) in enumerate(steps):
        x = 0.25 + i * 2.95
        box(ax, x, 3.1, 2.7, 2.2, "", "", c)
        ax.text(x + 1.35, 4.85, t, ha="center", va="center", color="white", fontsize=10.5, fontweight="bold")
        ax.text(x + 1.35, 3.85, sub, ha="center", va="center", color="white", fontsize=7.9)
        if i < 4:
            arrow(ax, x + 2.7, 4.2, x + 2.95, 4.2)
    ax.text(7.5, 2.55, "Result:  sum c_i^2 = B - w <= B    (soundness: discrete log;  zero knowledge: honest-verifier, Fiat-Shamir)", ha="center",
            fontsize=11.5, color=NAVY, fontweight="bold")
    facts = [("14 parameters", "0.32 s prove, 0.30 s verify, 17 KB"), ("256 parameters", "2.9 s prove, 2.4 s verify, 146 KB"),
             ("Effect", "poisoner caught in round 0 with audits at 0%"), ("Limit", "linear cost: ~19 s/hospital/round at 1,665 parameters")]
    for i, (a, b) in enumerate(facts):
        x = 0.4 + i * 3.7
        ax.add_patch(FancyBboxPatch((x, 0.35), 3.45, 1.55, boxstyle="round,pad=0.02,rounding_size=0.08", fc=LIGHT, ec=GREY, lw=1))
        ax.text(x + 1.72, 1.45, a, ha="center", fontsize=11, fontweight="bold", color=TEAL)
        ax.text(x + 1.72, 0.85, b, ha="center", fontsize=8.8, color=NAVY, wrap=True)
    save(fig, "F21_zk_proof")


ATTACKS = ["Server reads an update", "Membership inference", "Poisoning (large norm)", "Sleeper poisoning",
           "Forged masked input", "Server tampers with aggregate", "Server drops a hospital", "Client skips DP noise",
           "Under-declares noise (budget dodge)", "Over-spends privacy budget", "Rewrite ledger history", "Swap a stored model",
           "Label-flip inside the bound"]
MECH = ["Secure\naggregation", "DP noise", "Commitments +\nverify", "Survivor\ncheck", "Noise\naudit", "ZK norm\nproof",
        "Validation\ngate", "Blame\nphase", "Budget +\nstake", "Hash chain\n/ BFT"]
# 2 = primary defence, 1 = contributes / partial, 0 = no effect
COVER = [
    [2, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    [0, 2, 0, 0, 0, 0, 0, 0, 1, 0],
    [0, 0, 0, 0, 1, 2, 1, 0, 1, 0],
    [0, 0, 0, 0, 1, 2, 1, 0, 1, 0],
    [0, 0, 2, 0, 0, 0, 0, 2, 1, 0],
    [0, 0, 2, 1, 0, 0, 0, 1, 1, 1],
    [0, 0, 0, 2, 0, 0, 0, 1, 0, 1],
    [0, 0, 0, 0, 2, 0, 0, 0, 1, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 2, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 2, 0],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
    [0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
    [0, 0, 0, 0, 0, 1, 1, 0, 0, 0],
]


def coverage(save):
    import numpy as np
    from matplotlib.colors import ListedColormap
    fig, ax = plt.subplots(figsize=(13.5, 7.6))
    M = np.array(COVER)
    ax.imshow(M, cmap=ListedColormap(["#f4f5f8", "#bfe3dd", TEAL]), vmin=0, vmax=2, aspect="auto")
    ax.set_xticks(range(len(MECH))); ax.set_xticklabels(MECH, fontsize=9.5)
    ax.set_yticks(range(len(ATTACKS))); ax.set_yticklabels(ATTACKS, fontsize=10.5)
    ax.xaxis.tick_top()
    ax.set_xticks([x - 0.5 for x in range(1, len(MECH))], minor=True)
    ax.set_yticks([y - 0.5 for y in range(1, len(ATTACKS))], minor=True)
    ax.grid(which="minor", color="white", lw=2)
    ax.grid(which="major", visible=False)
    ax.tick_params(which="both", length=0)
    for i in range(M.shape[0]):
        for j in range(M.shape[1]):
            if M[i, j]:
                ax.text(j, i, "●" if M[i, j] == 2 else "○", ha="center", va="center", color="white" if M[i, j] == 2 else NAVY, fontsize=15)
    for sp in ax.spines.values():
        sp.set_visible(False)
    ax.set_title("Which defence stops which attack  (● primary defence, ○ contributes or bounds the damage)", pad=60, fontsize=13.5)
    ax.text(0, len(ATTACKS) + 0.2, "Last row: an attacker that stays inside the norm bound is only bounded, never detected (stated limit).\n"
            "Each row is backed by a test in tests/ and an experiment in results/.", fontsize=9, color=GREY, va="top")
    save(fig, "F22_defence_coverage")


def qbft(save):
    fig, ax = plt.subplots(figsize=(12.5, 6))
    ax.set_xlim(0, 12.5); ax.set_ylim(0, 6); ax.axis("off")
    ax.text(6.25, 5.65, "Real multi-node blockchain: 4 Hyperledger Besu validators, QBFT consensus", ha="center", fontsize=14.5, fontweight="bold", color=NAVY)
    pos = {0: (2.4, 3.6), 1: (5.2, 3.6), 2: (2.4, 1.5), 3: (5.2, 1.5)}
    for i, j in [(0, 1), (0, 2), (0, 3), (1, 2), (1, 3), (2, 3)]:
        arrow(ax, *pos[i], *pos[j], color=GREY, lw=1.2, style="-")
    for i, (x, y) in pos.items():
        ax.add_patch(Circle((x, y), 0.62, fc=TEAL, ec="white", lw=2))
        ax.text(x, y, f"V{i}", ha="center", va="center", color="white", fontsize=14, fontweight="bold")
    box(ax, 0.2, 2.0, 1.2, 1.1, "RPC", "web3.py", GOLD, tc=NAVY, fs=11)
    arrow(ax, 1.4, 2.8, 1.78, 3.45, color=ORANGE)
    box(ax, 7.3, 3.0, 4.9, 1.9, "", "", LIGHT)
    ax.text(9.75, 4.45, "Fault tolerance (n = 4, f = 1, quorum 2f + 1 = 3)", ha="center", fontsize=11, fontweight="bold", color=NAVY)
    ax.text(9.75, 3.55, "all 4 up        -> blocks every second, same head on every node\n1 validator killed -> federation still completes\n2 validators killed -> no quorum: chain halts (never forks)",
            ha="center", va="center", fontsize=9.3, color=NAVY)
    box(ax, 7.3, 0.5, 4.9, 2.1, "", "", LIGHT)
    ax.text(9.75, 2.15, "Measured on this machine", ha="center", fontsize=11, fontweight="bold", color=NAVY)
    ax.text(9.75, 1.35, "4 hospitals: 23 transactions, 14-19 s per round\n(1 s blocks, ~13 sequential phases)\nall 66 tests pass, incl. the kill-a-validator test",
            ha="center", va="center", fontsize=9.3, color=NAVY)
    save(fig, "F23_qbft_network")


def swimlane(save):
    fig, ax = plt.subplots(figsize=(14, 9))
    ax.set_xlim(0, 14); ax.set_ylim(0, 9.3); ax.axis("off")
    ax.text(7, 9.0, "Distributed run: one round as real messages between separate OS processes", ha="center", fontsize=14.5, fontweight="bold", color=NAVY)
    lanes = {"Hospital i": (2.0, NAVY), "Server": (7.0, RED), "Chain (contract)": (12.0, TEAL)}
    for name, (x, c) in lanes.items():
        box(ax, x - 1.15, 8.1, 2.3, 0.6, name, "", c, fs=11)
        ax.plot([x, x], [0.3, 8.1], color=c, lw=1.4, ls=":")
    H, S, C = lanes["Hospital i"][0], lanes["Server"][0], lanes["Chain (contract)"][0]
    msgs = [
        (S, C, "1  beginRound  (admission, budget check)", 7.7),
        (S, H, "2  round parameters + global model (HTTP)", 7.2),
        (H, C, "3  postIntent, revealNonce  (own account)", 6.7),
        (S, C, "4  closeReveals  ->  beacon", 6.2),
        (H, C, "5  postCommitment  (+ ZK proof hash)", 5.7),
        (S, C, "6  closeCommitments  (Merkle root)", 5.2),
        (H, S, "7  public key; encrypted shares  (server relays)", 4.7),
        (H, S, "8  masked vector;  markSubmitted on chain", 4.2),
        (S, H, "9  survivor list", 3.7),
        (H, S, "10  reveal shares (dropped: key, alive: self-mask)", 3.2),
        (S, C, "11  verifyAggregate: contract checks prod C = Com(agg)", 2.7),
        (S, C, "12  postAggregate  (survivors must equal 'submitted')", 2.2),
        (C, H, "13  result readable by everyone; budgets charged", 1.7),
    ]
    for a, b, t, y in msgs:
        col = GREEN if "verifyAggregate" in t else (ORANGE if (a, b) in ((H, S), (S, H)) else TEAL)
        arrow(ax, a, y, b, y, color=col, lw=1.7)
        ax.text((a + b) / 2, y + 0.09, t, ha="center", fontsize=8.6, color=NAVY)
    ax.text(7, 0.55, "A crashed hospital simply never sends message 8: the server recovers its masks from the Shamir shares,\nthe contract still verifies, and the hospital is charged for fewer rounds.",
            ha="center", fontsize=9.3, color=GREY)
    save(fig, "F24_distributed_protocol")
