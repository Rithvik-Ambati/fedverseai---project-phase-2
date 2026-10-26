**Experimental setup.**

| parameter            | value                                                               |
|:---------------------|:--------------------------------------------------------------------|
| model                | logistic regression (13+1 parameters); MLP (1,665) on Covertype     |
| local training       | 15 epochs SGD, lr 0.05, batch 32                                    |
| update clipping      | L2 norm C = 0.5                                                     |
| differential privacy | client-level Gaussian mechanism, RDP accountant, delta = 1e-5       |
| noise split          | distributed: sigma = zC/sqrt(h); local: sigma = zC                  |
| secure aggregation   | X25519 pairwise masks + self mask, Shamir threshold floor(n/2)+1    |
| commitments          | Pedersen vector commitments, 1024-bit Schnorr group, 256-bit order  |
| ZK norm proof        | Sigma protocols + bit-decomposition range proof (Fiat-Shamir)       |
| fixed point          | 2^20                                                                |
| audit rate           | 0.25 (default)                                                      |
| ledger               | Solidity 0.8.24 contract; Hardhat chain or Besu QBFT (4 validators) |
| seeds                | 5-20 per experiment, reported as mean ± s.d.                        |
