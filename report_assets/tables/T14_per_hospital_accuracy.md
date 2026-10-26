**Accuracy on each hospital's own test set (10 seeds, epsilon = 8).**

| system                       | cleveland     | hungarian     | switzerland   | va            |
|:-----------------------------|:--------------|:--------------|:--------------|:--------------|
| FedAvg (no privacy)          | 0.828 ± 0.040 | 0.830 ± 0.027 | 0.897 ± 0.052 | 0.762 ± 0.058 |
| local DP (eps=8)             | 0.700 ± 0.072 | 0.714 ± 0.075 | 0.729 ± 0.180 | 0.664 ± 0.115 |
| ours: distributed DP (eps=8) | 0.786 ± 0.048 | 0.822 ± 0.043 | 0.852 ± 0.066 | 0.720 ± 0.068 |
