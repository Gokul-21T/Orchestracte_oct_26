# Ghost Data Still Exists audit agent

This submission uses a deterministic evidence and policy engine. It resolves request emails against current identities and identity-change history, indexes the supplied evidence corpus, applies the configured deletion treatment, and emits ordered findings, remediation, and verification objects.

## Run

From the repository root, with Python 3.10 or newer:

```powershell
python code/main.py
```

The script reads the participant-facing CSV files and `dataset/evidence/`, then writes `output.csv` in the repository root. Use `--dataset PATH`, `--requests PATH`, and `--output PATH` to select alternate inputs or an output destination.

## Evaluation

Run the public-sample evaluation from the repository root:

```powershell
python code/evaluation/main.py
```

The evaluation compares status, step fields, and full array sequence against `dataset/sample_output.csv`; it also executes three synthetic checks. Reports in `code/evaluation/` describe the final run, measurements, limitations, and model usage. The prediction run uses no hosted model, so it makes zero model calls and incurs no model token or API cost.

## Evidence handling

The engine reads structured JSON and SQLite-compatible SQL snapshots, parses plain-text operational logs and PDF text, and opens each PNG evidence file. Evidence later than `audit_at` is excluded using the evidence manifest capture time. Workflow claims are not used as proof. PII extraction from screenshots depends on optional `pytesseract`; without it, the PNG is opened but its text is not OCR-indexed.
