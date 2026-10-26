**Audit rate, audit mode and detection (20 seeds).**

| attacker      | audit_mode   |   audit_rate | accuracy      | caught   | first detection round   |   honest exposure |
|:--------------|:-------------|-------------:|:--------------|:---------|:------------------------|------------------:|
| no DP noise   | seeded       |        0.000 | 0.798 ± 0.035 | 0%       | -                       |             0.000 |
| no DP noise   | seeded       |        0.100 | 0.808 ± 0.027 | 70%      | 3.7                     |             0.090 |
| no DP noise   | seeded       |        0.250 | 0.801 ± 0.030 | 100%     | 3.1                     |             0.270 |
| no DP noise   | seeded       |        0.500 | 0.790 ± 0.033 | 100%     | 0.8                     |             0.500 |
| no DP noise   | seeded       |        1.000 | 0.784 ± 0.027 | 100%     | 0.0                     |             1.000 |
| no DP noise   | statistical  |        0.000 | 0.798 ± 0.035 | 0%       | -                       |             0.000 |
| no DP noise   | statistical  |        0.100 | 0.808 ± 0.027 | 0%       | -                       |             0.100 |
| no DP noise   | statistical  |        0.250 | 0.803 ± 0.025 | 0%       | -                       |             0.240 |
| no DP noise   | statistical  |        0.500 | 0.794 ± 0.037 | 0%       | -                       |             0.500 |
| no DP noise   | statistical  |        1.000 | 0.802 ± 0.029 | 0%       | -                       |             1.000 |
| sign-flip x10 | seeded       |        0.000 | 0.358 ± 0.057 | 0%       | -                       |             0.000 |
| sign-flip x10 | seeded       |        0.100 | 0.638 ± 0.195 | 80%      | 4.6                     |             0.110 |
| sign-flip x10 | seeded       |        0.250 | 0.720 ± 0.143 | 95%      | 2.7                     |             0.250 |
| sign-flip x10 | seeded       |        0.500 | 0.800 ± 0.025 | 100%     | 0.4                     |             0.500 |
| sign-flip x10 | seeded       |        1.000 | 0.789 ± 0.035 | 100%     | 0.0                     |             1.000 |
| sign-flip x10 | statistical  |        0.000 | 0.358 ± 0.057 | 0%       | -                       |             0.000 |
| sign-flip x10 | statistical  |        0.100 | 0.638 ± 0.202 | 80%      | 4.6                     |             0.100 |
| sign-flip x10 | statistical  |        0.250 | 0.721 ± 0.143 | 95%      | 2.7                     |             0.230 |
| sign-flip x10 | statistical  |        0.500 | 0.792 ± 0.038 | 100%     | 0.4                     |             0.490 |
| sign-flip x10 | statistical  |        1.000 | 0.787 ± 0.024 | 100%     | 0.0                     |             1.000 |
