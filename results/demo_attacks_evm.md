# Attack demo - REAL Solidity contract on a local EVM chain (clean accuracy 0.82; n=8, 10 rounds, eps<=8)

| attack | what the attacker does | undefended | defended | verdict |
|---|---|---|---|---|
| Server reads a hospital's update | honest-but-curious server inspects each submitted vector | similarity to true update = 1.00 (readable) | similarity = +0.02 (looks random) | BLOCKED by secure aggregation |
| Model poisoning (sign-flip, 10x boost) | client 3 sends a reversed, oversized update | acc 0.29  (clean 0.82) | acc 0.82; client 3 banned=True, first caught round 0 | DETECTED + EXCLUDED |
| Stealth poisoning (forged input) | client 3 shows an honest update to auditors but sends a poisoned one | acc 0.71  (silently accepted) | acc 0.82; 4 poisoned rounds rejected | DETECTED (commitment check) |
| Server tampers with the aggregate | server reverses the summed update before publishing | acc 0.73  (silently accepted) | acc 0.82; 4 rounds rejected | DETECTED (commitment check) |
| Server silently drops a hospital | server claims a live client vanished and excludes its data | acc 0.84  (hospital ignored, nobody knows) | acc 0.82; 4 rounds flagged | DETECTED (survivor check) |
| Client skips its DP noise | client 3 declares noise but adds none (leaks its own data) | undetectable (no way to check) | banned=True, caught round 0 | DETECTED (seeded-noise audit) |
| Client under-declares noise to dodge budget | client 3 declares tiny noise to look cheap | no budget enforcement | refused 10 times; spent eps = 0.0 | BLOCKED (contract admission) |
| Rewrite history on the ledger | attacker edits a past transaction (e.g. a privacy-budget record) | no audit trail to edit | chain valid before=True; after edit valid=False, broken at block 3 | DETECTED (hash chain) |
| Swap a stored model version | attacker replaces a past global model (e.g. with a backdoored one) | no way to tell | mismatching rounds before=[], after=[4] | DETECTED (model-hash registry) |
| Label-flipping (within norm bound) | two clients train on flipped labels but respect the clip bound | acc 0.80 | acc 0.81; banned=[] | NOT DETECTED - only bounded by clipping (known limitation) |
