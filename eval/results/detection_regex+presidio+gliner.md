**regex,presidio,gliner** on 1000 ai4privacy/pii-masking-400k (validation) examples

- Overall recall: 86.7%
- Residual leak rate (gold values left verbatim): 12.4%
- Examples with any leak: 13.1%
- Precision (masked spans overlapping gold): 41.5%
- Masking latency p50/p95: 114.4 / 164.9 ms

| Entity | Recall | Support |
|---|---|---|
| GIVENNAME | 95.7% | 161 |
| SURNAME | 95.5% | 133 |
| CITY | 98.1% | 104 |
| USERNAME | 82.8% | 99 |
| EMAIL | 98.9% | 87 |
| TELEPHONENUM | 96.0% | 75 |
| BUILDINGNUM | 63.4% | 71 |
| ACCOUNTNUM | 81.0% | 58 |
| IDCARDNUM | 58.6% | 58 |
| ZIPCODE | 70.4% | 54 |
| DATEOFBIRTH | 88.2% | 51 |
| SOCIALNUM | 100.0% | 48 |
| STREET | 97.6% | 42 |
| TAXNUM | 92.7% | 41 |
| DRIVERLICENSENUM | 86.7% | 30 |
| PASSWORD | 10.0% | 30 |
| CREDITCARDNUMBER | 95.7% | 23 |