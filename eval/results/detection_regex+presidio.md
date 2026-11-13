**regex,presidio** on 1000 ai4privacy/pii-masking-400k (validation) examples

- Overall recall: 58.5%
- Residual leak rate (gold values left verbatim): 36.7%
- Examples with any leak: 34.3%
- Precision (masked spans overlapping gold): 44.6%
- Masking latency p50/p95: 8.7 / 14.8 ms

| Entity | Recall | Support |
|---|---|---|
| GIVENNAME | 67.1% | 161 |
| SURNAME | 61.7% | 133 |
| CITY | 68.3% | 104 |
| USERNAME | 25.3% | 99 |
| EMAIL | 98.9% | 87 |
| TELEPHONENUM | 50.7% | 75 |
| BUILDINGNUM | 16.9% | 71 |
| ACCOUNTNUM | 72.4% | 58 |
| IDCARDNUM | 53.4% | 58 |
| ZIPCODE | 29.6% | 54 |
| DATEOFBIRTH | 82.4% | 51 |
| SOCIALNUM | 95.8% | 48 |
| STREET | 14.3% | 42 |
| TAXNUM | 90.2% | 41 |
| DRIVERLICENSENUM | 60.0% | 30 |
| PASSWORD | 3.3% | 30 |
| CREDITCARDNUMBER | 87.0% | 23 |