# Scoring

Implemented in `src/secscope/core/scoring.py`, unit-tested in `tests/unit/test_scoring.py`.
All numbers below are the defaults (SPEC §9); weights are configurable in Settings with a
"reset to default" action.

## Penalty scores (security, dependencies, quality)

```
score = max(0, 100 − Σ penalty(f))
penalty(f) = severity_weight(f) × confidence_factor(f) × repeat_factor(f)
```

| Severity | weight | | Confidence | factor |
|---|---|---|---|---|
| critical | 25 | | confirmed | 1.0 |
| high | 10 | | high | 0.8 |
| medium | 4 | | medium | 0.5 |
| low | 1 | | low | 0.25 |
| info | 0 | | | |

`repeat_factor` is 1.0 for the most severe finding of a `rule_id` and 0.25 for every further
finding of the same rule (finding the same mistake 40 times should not zero the score).

- **Security**: findings with category `security`, except `SCA-*`.
- **Dependencies**: `SCA-*` security findings (vulnerable packages, typosquats, install scripts).
- **Quality**: findings with category `quality` (accessibility, console errors, code quality).

A sub-score exists only if a contributing module ran; e.g. a URL-only scan has no dependency
score rather than a misleading 100.

## SEO and resilience

Computed by the SEO (M6) and load/resilience (M7) modules and documented there.

## Overall score and grade

Weighted mean of the available sub-scores with weights security 45 %, SEO 20 %, resilience
20 %, quality 10 %, dependencies 5 %. If a sub-score is missing, its weight is redistributed
proportionally over the others; the report shows the effective weights.

Grades: A ≥ 90, B ≥ 80, C ≥ 70, D ≥ 60, F < 60. **A confirmed critical finding caps the grade
at D** regardless of the numeric score.
