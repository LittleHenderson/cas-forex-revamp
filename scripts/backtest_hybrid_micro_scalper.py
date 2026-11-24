"""CLI entrypoint for Phase 1 Hybrid Micro-Scalping & Sideways Pivot Replay ($0.00 live risk).

Usage:
  python scripts/backtest_hybrid_micro_scalper.py --fetch-live-data out_data.json
  python scripts/backtest_hybrid_micro_scalper.py --dataset out_data.json --out report.json
  python scripts/backtest_hybrid_micro_scalper.py --synthetic-stress --out synthetic_report.json
"""
from __future__ import annotations

import argparse
from decimal import Decimal
import json
import pathlib
import sys

_SRC_ROOT = pathlib.Path(__file__).resolve().parents[1] / "src"
if str(_SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(_SRC_ROOT))

from cas_forex_revamp.futures.hybrid_micro_scalper import (
    SUPPORTED_MICRO_ROOTS,
    build_synthetic_three_regime_dataset,
    evaluate_phase1_matrix,
    fetch_real_cme_m1_dataset,
)


def _write_json_atomic(path_str: str, payload: dict[str, object]) -> pathlib.Path:
    out_path = pathlib.Path(path_str).resolve()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    raw = json.dumps(payload, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    out_path.write_bytes(raw)
    return out_path


def _print_summary(report: dict[str, object]) -> None:
    verdict = report.get("phase1_verdict")
    reasons = report.get("phase1_reasons")
    beats = report.get("beats_swing_only_at_500ms")
    print(f"PHASE1_VERDICT={verdict} BEATS_SWING={beats} REASONS={reasons}")
    runs = report.get("runs")
    if isinstance(runs, dict):
        for label, item in runs.items():
            if not isinstance(item, dict):
                continue
            summ = item.get("summary") or {}
            sh = item.get("shields_and_gates") or {}
            print(
                f"  {label}: trades={summ.get('closed_trades')} wr={summ.get('win_rate_pct')}% "
                f"pf={summ.get('net_profit_factor')} net=${summ.get('net_pnl_usd')} "
                f"fees=${summ.get('total_fees_usd')} dd={summ.get('max_drawdown_pct')}% "
                f"kills={sh.get('breakout_kills')} valve_p99={sh.get('valve_p99_ms')}ms"
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Phase 1 Hybrid Micro-Scalp & Sideways Pivot Replay")
    parser.add_argument("--fetch-live-data", default="", help="Write captured 7d 1m real CME futures JSON to path")
    parser.add_argument("--dataset", default="", help="Path to offline M1 dataset JSON")
    parser.add_argument("--synthetic-stress", action="store_true", help="Run deterministic 3-regime synthetic stress dataset")
    parser.add_argument("--out", default="", help="Output JSON report path")
    parser.add_argument("--equity", default="5000.00", help="Starting practice equity in USD (Decimal string)")
    parser.add_argument("--range-window", default="7d", help="Yahoo fetch range window (e.g. 5d or 7d)")
    args = parser.parse_args(argv)

    if args.fetch_live_data:
        dataset = fetch_real_cme_m1_dataset(roots=SUPPORTED_MICRO_ROOTS, range_window=args.range_window)
        written = _write_json_atomic(args.fetch_live_data, dataset)
        print(f"FETCHED_DATASET={written} SHA256={dataset['dataset_sha256']} META={json.dumps(dataset['meta'])}")
        return 0

    if args.dataset and args.synthetic_stress:
        raise SystemExit("Pass either --dataset or --synthetic-stress, not both")
    if not args.dataset and not args.synthetic_stress:
        raise SystemExit("Specify one of --fetch-live-data, --dataset, or --synthetic-stress")

    if args.dataset:
        dataset_doc = json.loads(pathlib.Path(args.dataset).read_text(encoding="utf-8"))
    else:
        dataset_doc = build_synthetic_three_regime_dataset()

    report = evaluate_phase1_matrix(dataset_doc, starting_equity_usd=Decimal(str(args.equity)))
    _print_summary(report)
    if args.out:
        written = _write_json_atomic(args.out, report)
        print(f"WROTE_REPORT={written} SHA256={report['report_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
