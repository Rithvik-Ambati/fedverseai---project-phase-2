**Ablation: final accuracy as layers are added (8 seeds).**

| layer                              |   client skips DP noise |   honest |   poisoner (sign-flip x10) |   server reverses aggregate |   stealth forger |
|:-----------------------------------|------------------------:|---------:|---------------------------:|----------------------------:|-----------------:|
| 1 FedAvg                           |                   0.820 |    0.820 |                      0.330 |                       0.810 |            0.740 |
| 2 + DP (noise)                     |                   0.810 |    0.810 |                      0.320 |                       0.710 |            0.680 |
| 3 + SecAgg                         |                   0.810 |    0.810 |                      0.320 |                       0.710 |            0.680 |
| 4 + ledger (commit, audit, verify) |                   0.810 |    0.810 |                      0.650 |                       0.800 |            0.790 |
| 5 + validation gate                |                   0.810 |    0.790 |                      0.780 |                       0.800 |            0.800 |
| 6 + blame phase                    |                   0.810 |    0.790 |                      0.780 |                       0.810 |            0.790 |
