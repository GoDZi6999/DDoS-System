# Datasets

Public intrusion-detection datasets are large and licensed by their
publishers, so they are **never committed**. Download them from the official
pages and place them as shown below; `data/raw/` and `data/processed/` are
git-ignored.

| Dataset | Role in Argus | Official page |
|---|---|---|
| **CIC-IDS2017** (`MachineLearningCSV.zip`, a few hundred MB) | Primary train/test set: benign, DDoS, PortScan, Bot, DoS | <https://www.unb.ca/cic/datasets/ids-2017.html> |
| **CIC-DDoS2019** (CSV files; tens of GB in total, a subset of attack files is enough) | Wider DDoS coverage: SYN, UDP, DNS/NTP/LDAP reflection, … | <https://www.unb.ca/cic/datasets/ddos-2019.html> |
| UNSW-NB15 | Cross-dataset generalisation check only | <https://research.unsw.edu.au/projects/unsw-nb15-dataset> |
| CSE-CIC-IDS2018 | Optional larger-scale evaluation | <https://www.unb.ca/cic/datasets/ids-2018.html> |

## Layout

Keep the publishers' original file names: the Phase 4 loaders rely on them.

```
data/
  raw/                         git-ignored
    cic-ids2017/MachineLearningCVE/*.csv
    cic-ddos2019/<day>/*.csv
    unsw-nb15/*.csv
  processed/                   git-ignored; cleaned output of the ML pipeline
  samples/                     committed: tiny files only (a short PCAP for the
                               replay demo, a small CSV used by tests)
```

## Known data issues (handled in Phase 4)

- CIC CSVs contain `Infinity`/`NaN` in rate columns (`Flow Bytes/s`,
  `Flow Packets/s`), duplicate rows, and column names with leading spaces.
- Flows from one attack run are near-duplicates, so a random row split inflates
  scores; Argus splits by time/session instead.
- CIC-IDS2017 has documented flow-construction and labelling errors
  (Engelen et al., 2021); results are reported with that caveat.

## Citations

- I. Sharafaldin, A. H. Lashkari, A. A. Ghorbani, "Toward Generating a New
  Intrusion Detection Dataset and Intrusion Traffic Characterization",
  ICISSP 2018. (CIC-IDS2017, CSE-CIC-IDS2018)
- I. Sharafaldin, A. H. Lashkari, S. Hakak, A. A. Ghorbani, "Developing
  Realistic Distributed Denial of Service (DDoS) Attack Dataset and Taxonomy",
  ICCST 2019. (CIC-DDoS2019)
- N. Moustafa, J. Slay, "UNSW-NB15: a comprehensive data set for network
  intrusion detection systems", MilCIS 2015.
- G. Engelen, V. Rimmer, W. Joosen, "Troubleshooting an Intrusion Detection
  Dataset: the CICIDS2017 Case Study", IEEE S&P Workshops 2021.
