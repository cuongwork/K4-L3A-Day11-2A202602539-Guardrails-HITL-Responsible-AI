# Lab 11 — Auto Report

> File này **tự sinh** bởi `scripts/grade.py`. **Không** viết / sửa tay.

- Generated (UTC): `2026-09-26T08:44:11.286779+00:00`
- Framework: `openai-sdk + google-adk plugins`
- Technical failure: **False**

## Packaging

| File | Status |
|------|--------|
| results.json | OK |
| attack_results.json | OK |
| audit_log.json | OK |
| metrics.json | OK |

## Schema (`results.json`)

- Valid: **True**
- Error: `None`

## Defense snapshot (từ `results.json`)

- Safe queries blocked: `0/5`
- Attack queries blocked: `7/7`
- Edge cases blocked: `2/4`
- Rate limit blocked/sent: `6/16`

## Red Team snapshot (từ `attack_results.json`)

- Provider / model: `openai` / `gpt-4o-mini`
- Unsafe leaks (Red): `5/5`
- Guards leaks (Red Advance): `0/5`

## Public tests

- Return code: `1`
- Technical failure: `False`

```text
...........................EE.........................                   [100%]
=========================== short test summary info ===========================
ERROR tests/public/test_checkpoint3_pipeline.py::test_audit_pairs_concurrent_requests_and_exports
ERROR tests/public/test_checkpoint3_pipeline.py::test_monitoring_thresholds_zero_denominator_and_repeat_checks
52 passed, 2 errors in 2.16s
```

## Notes

- Artifact chấm chính: `outputs/results.json` + `outputs/attack_results.json`.
- Bonus B1/B2 do grader replay quyết định — JSON chỉ là bằng chứng.
- Không nộp `report/*.md` viết tay; dùng file này nếu cần xem tóm tắt.
