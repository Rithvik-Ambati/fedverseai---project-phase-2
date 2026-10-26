**Distributed run: server and hospitals as separate OS processes (one with a real crash).**

| scenario                      |   round | accepted   | chain_verified   |   survivors |   dropped |   acc |   processes |   gas_total |   wall_seconds |
|:------------------------------|--------:|:-----------|:-----------------|------------:|----------:|------:|------------:|------------:|---------------:|
| no crash                      |       0 | True       | True             |           5 |         0 | 0.593 |           6 |    10970907 |         23.075 |
| no crash                      |       1 | True       | True             |           5 |         0 | 0.797 |           6 |    10970907 |         23.075 |
| no crash                      |       2 | True       | True             |           5 |         0 | 0.810 |           6 |    10970907 |         23.075 |
| no crash                      |       3 | True       | True             |           5 |         0 | 0.831 |           6 |    10970907 |         23.075 |
| hospital 2 crashes in round 1 |       0 | True       | True             |           5 |         0 | 0.732 |           6 |    11895379 |         34.797 |
| hospital 2 crashes in round 1 |       1 | True       | True             |           4 |         1 | 0.675 |           6 |    11895379 |         34.797 |
| hospital 2 crashes in round 1 |       2 | True       | True             |           5 |         0 | 0.693 |           6 |    11895379 |         34.797 |
| hospital 2 crashes in round 1 |       3 | True       | True             |           5 |         0 | 0.710 |           6 |    11895379 |         34.797 |
