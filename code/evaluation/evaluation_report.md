# Evaluation report

## Public sample results

The evaluation workflow in `main.py` compares generated output against all 32 rows in `dataset/sample_output.csv` and measures status accuracy, step precision and recall, field accuracy, and exact ordered sequence accuracy. The latest run reported:

| Measure | Result |
|---|---:|
| Case status accuracy | 26 / 32 (81.25%) |
| Exact case status and ordered step sequence | 0 / 32 (0%) |
| Expected step objects | 193 |
| Predicted step objects | 129 |
| Matched step objects | 70 |
| Step precision | 54.26% |
| Step recall | 36.27% |
| Position-based field accuracy | 49.56% (680 / 1,372) |

Field accuracy compares all seven output fields at each array position and counts missing or extra rows as mismatches. Sequence accuracy requires exact object equality and order for a case. This is a deliberately strict public-sample check; evidence source choice and dataset-specific identifier correlations account for many sequence mismatches.

## Additional evaluation cases

Three synthetic checks are run by `main.py` and passed in the latest evaluation:

1. A request only asking for a data copy is classified as not authorizing deletion.
2. A Japanese request using 削除 is recognized as an erasure request.
3. An enabled integration connector is classified as an active flow requiring disablement.

## Failures found and improvements made

- The initial evidence reader missed pipe-delimited handover entries and JSON payloads embedded in structured logs. It was extended to parse these formats and to keep their timestamps and evidence IDs.
- Identity resolution now includes historical email, name, phone, and hash values, including computed hashes for prior email addresses.
- Evidence is filtered by the manifest capture time at the case cutoff. Reported workflow statuses and activity outcomes do not establish record state.
- Public-sample evaluation still shows missed or misclassified cases and incomplete record coverage. Exact sequence accuracy remains zero. A principal limitation is screenshot OCR: images are opened, but OCR only runs when `pytesseract` is installed. The current environment did not provide it. Resource links that cannot be joined from evidence remain uncertain, so the engine does not invent findings for them.

## Reproduce

From the repository root run `python code/evaluation/main.py`. The evaluator uses the public sample only; it does not feed sample labels into predictions. The full evaluation set is generated separately with `python code/main.py`.
