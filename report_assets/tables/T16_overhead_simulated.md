**Per-layer overhead against number of hospitals (simulated ledger: gas is an estimate).**

|   clients | variant                  |   time_per_round_s |   bytes_per_client_round |   gas_per_round |
|----------:|:-------------------------|-------------------:|-------------------------:|----------------:|
|         4 | FedAvg                   |              0.180 |                  112.000 |           0.000 |
|         4 | +DP                      |              0.170 |                  112.000 |           0.000 |
|         4 | +DP+SecAgg               |              0.190 |                 1240.000 |           0.000 |
|         4 | +DP+SecAgg+Ledger (full) |              0.210 |                 1400.000 |     1361377.600 |
|         8 | FedAvg                   |              0.200 |                  112.000 |           0.000 |
|         8 | +DP                      |              0.210 |                  112.000 |           0.000 |
|         8 | +DP+SecAgg               |              0.280 |                 2032.000 |           0.000 |
|         8 | +DP+SecAgg+Ledger (full) |              0.320 |                 2192.000 |     2553532.800 |
|        16 | FedAvg                   |              0.270 |                  112.000 |           0.000 |
|        16 | +DP                      |              0.240 |                  112.000 |           0.000 |
|        16 | +DP+SecAgg               |              0.240 |                 3616.000 |           0.000 |
|        16 | +DP+SecAgg+Ledger (full) |              0.260 |                 3776.000 |     4824350.400 |
|        32 | FedAvg                   |              0.210 |                  112.000 |           0.000 |
|        32 | +DP                      |              0.230 |                  112.000 |           0.000 |
|        32 | +DP+SecAgg               |              0.350 |                 6784.000 |           0.000 |
|        32 | +DP+SecAgg+Ledger (full) |              0.390 |                 6944.000 |     9577608.000 |
