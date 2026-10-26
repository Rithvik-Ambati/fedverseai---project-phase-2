**Real chains with on-chain verification: Hardhat (1 node) vs Besu QBFT (4 validators).**

| backend                  |   clients |   rounds |   tx_per_round |   gas_per_round |   verify_gas_per_round |   seconds_per_round |   rejected |   acc |
|:-------------------------|----------:|---------:|---------------:|----------------:|-----------------------:|--------------------:|-----------:|------:|
| Hardhat (1 node)         |         4 |        3 |         23.000 |     4685045.333 |            1685979.000 |               1.377 |          0 | 0.779 |
| Hardhat (1 node)         |         8 |        3 |         41.667 |     6662603.667 |            1697895.333 |               0.767 |          0 | 0.684 |
| Besu QBFT (4 validators) |         4 |        3 |         23.000 |     3885528.667 |             886462.333 |              19.021 |          0 | 0.779 |
| Besu QBFT (4 validators) |         8 |        3 |         41.667 |     5960287.667 |             995579.333 |              13.695 |          0 | 0.684 |
