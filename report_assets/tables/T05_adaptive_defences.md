**Audit policies against persistent and sleeper poisoners.**

| scenario                       | policy                      | accuracy      | attacker banned   |   emergency audits / run |   honest exposure |   seeds |
|:-------------------------------|:----------------------------|:--------------|:------------------|-------------------------:|------------------:|--------:|
| honest                         | ZK norm proofs (audit 0%)   | 0.795 ± 0.016 | 0%                |                    0.000 |             0.000 |       8 |
| honest                         | audit 10% + validation gate | 0.807 ± 0.028 | 0%                |                    0.000 |             0.100 |      16 |
| honest                         | audit 25% + validation gate | 0.803 ± 0.022 | 0%                |                    0.000 |             0.250 |      16 |
| honest                         | audit 25% only              | 0.804 ± 0.029 | 0%                |                    0.000 |             0.270 |      16 |
| honest                         | no defence (DP+SecAgg)      | 0.807 ± 0.026 | 0%                |                    0.000 |             0.000 |      16 |
| persistent sign-flip x10       | ZK norm proofs (audit 0%)   | 0.785 ± 0.031 | 100%              |                    0.000 |             0.000 |       8 |
| persistent sign-flip x10       | audit 10% + validation gate | 0.800 ± 0.033 | 100%              |                    0.750 |             0.380 |      16 |
| persistent sign-flip x10       | audit 25% + validation gate | 0.788 ± 0.028 | 100%              |                    0.620 |             0.470 |      16 |
| persistent sign-flip x10       | audit 25% only              | 0.708 ± 0.153 | 94%               |                    0.000 |             0.270 |      16 |
| persistent sign-flip x10       | no defence (DP+SecAgg)      | 0.340 ± 0.044 | 0%                |                    0.000 |             0.000 |      16 |
| sleeper sign-flip (rounds 5-9) | ZK norm proofs (audit 0%)   | 0.800 ± 0.027 | 100%              |                    0.000 |             0.000 |       8 |
| sleeper sign-flip (rounds 5-9) | audit 10% + validation gate | 0.768 ± 0.060 | 100%              |                    0.750 |             0.300 |      16 |
| sleeper sign-flip (rounds 5-9) | audit 25% + validation gate | 0.767 ± 0.063 | 94%               |                    0.310 |             0.320 |      16 |
| sleeper sign-flip (rounds 5-9) | audit 25% only              | 0.719 ± 0.098 | 88%               |                    0.000 |             0.270 |      16 |
| sleeper sign-flip (rounds 5-9) | no defence (DP+SecAgg)      | 0.556 ± 0.089 | 0%                |                    0.000 |             0.000 |      16 |
