"""Train and benchmark the 8->16->1 ForexMetaValveGate neural MLP on AWS.

Generates:
- 4,000 synthetic Forex decision feature vectors across 8 realistic operational regimes
  (seed = 20261114) for mini-batch Adam training (161 parameters).
- 1,000 strictly held-out test proposals (seed = 20261115) for out-of-sample evaluation,
  comparing:
  1. Ungated Statistical Trend Baseline (surface momentum/confidence without safety valve)
  2. Standalone Learned TKS Meta-Valve MLP (neural 8->16->1 score >= 0.55)
  3. Full ForexMetaValveGate (Learned MLP + Constitutional Hard-Floor Invariant)
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import json
import math
from pathlib import Path
import random
import sys
import time

SRC_ROOT = Path(__file__).resolve().parents[2]
if str(SRC_ROOT) not in sys.path:
    sys.path.insert(0, str(SRC_ROOT))

from cas_forex_revamp.valve.tks_meta_valve_controller import (
    FOREX_FEATURE_NAMES,
    TKSMetaValveController,
)


def _sigmoid(z: float) -> float:
    if z >= 35.0:
        return 1.0
    if z <= -35.0:
        return 0.0
    return 1.0 / (1.0 + math.exp(-z))


def generate_dataset(n: int, seed: int) -> list[dict]:
    rng = random.Random(seed)  # nosec B311: deterministic reproducible ML dataset seed, not cryptographic
    rows: list[dict] = []
    regimes = (
        "clean_entry",
        "clean_management",
        "g_absent_missing_margin",
        "paused_risk_violation",
        "oversized_quantity",
        "prompt_injection_override",
        "missing_or_inverted_stop",
        "stale_quote_or_drift",
    )
    for idx in range(n):
        regime = regimes[idx % len(regimes)]
        trend_confidence = rng.uniform(0.55, 0.98)
        if regime == "clean_entry":
            x = [
                0.0,
                0.0,
                0.0,
                0.0,
                0.0,
                0.0,
                rng.uniform(0.01, 0.45),
                rng.uniform(0.0, 0.18),
            ]
            label = 1
        elif regime == "clean_management":
            x = [
                0.0,
                0.0,
                0.0,
                0.0,
                0.0,
                0.0,
                rng.uniform(0.02, 0.55),
                rng.uniform(0.0, 0.22),
            ]
            label = 1
        elif regime == "g_absent_missing_margin":
            x = [
                rng.choice((0.25, 0.50, 0.75, 1.0)),
                0.0,
                0.0,
                0.0,
                rng.choice((0.0, 1.0)),
                0.0,
                rng.uniform(0.05, 0.40),
                rng.uniform(0.05, 0.35),
            ]
            label = 0
        elif regime == "paused_risk_violation":
            x = [
                0.0,
                1.0,
                rng.choice((0.0, rng.uniform(0.05, 0.50))),
                0.0,
                rng.choice((0.0, 1.0)),
                0.0,
                rng.uniform(0.05, 0.45),
                rng.uniform(0.05, 0.30),
            ]
            label = 0
        elif regime == "oversized_quantity":
            x = [
                0.0,
                0.0,
                rng.uniform(0.10, 1.0),
                0.0,
                0.0,
                0.0,
                rng.uniform(0.05, 0.40),
                rng.uniform(0.05, 0.30),
            ]
            label = 0
        elif regime == "prompt_injection_override":
            x = [
                rng.choice((0.0, 0.25)),
                rng.choice((0.0, 1.0)),
                0.0,
                rng.choice((0.0, 1.0)),
                1.0,
                0.0,
                rng.uniform(0.05, 0.50),
                rng.uniform(0.25, 0.75),
            ]
            label = 0
        elif regime == "missing_or_inverted_stop":
            x = [
                0.0,
                0.0,
                0.0,
                0.0,
                0.0,
                1.0,
                rng.uniform(0.05, 0.40),
                rng.uniform(0.05, 0.25),
            ]
            label = 0
        else:  # stale_quote_or_drift
            stale = rng.choice((1.0, rng.uniform(0.88, 1.0)))
            drift = rng.uniform(0.65, 1.0)
            unbacked = rng.choice((0.0, 1.0))
            x = [0.0, 0.0, 0.0, unbacked, 0.0, 0.0, stale, drift]
            label = 0
        rows.append({"regime": regime, "x": x, "y": label, "trend_confidence": trend_confidence})
    rng.shuffle(rows)
    return rows


def train_mlp(
    train_rows: list[dict],
    *,
    seed: int = 20261114,
    epochs: int = 120,
    batch_size: int = 64,
    lr: float = 0.015,
    l2: float = 1e-4,
) -> tuple[TKSMetaValveController, dict]:
    rng = random.Random(seed)  # nosec B311: deterministic reproducible ML training seed, not cryptographic
    w1 = [[rng.gauss(0.0, 0.35) for _ in range(8)] for _ in range(16)]
    b1 = [0.0 for _ in range(16)]
    w2 = [rng.gauss(0.0, 0.35) for _ in range(16)]
    b2 = 0.0

    # Adam state
    mw1 = [[0.0] * 8 for _ in range(16)]
    vw1 = [[0.0] * 8 for _ in range(16)]
    mb1 = [0.0] * 16
    vb1 = [0.0] * 16
    mw2 = [0.0] * 16
    vw2 = [0.0] * 16
    mb2 = 0.0
    vb2 = 0.0

    beta1, beta2, eps = 0.9, 0.999, 1e-8
    step_t = 0
    history: list[float] = []

    indices = list(range(len(train_rows)))
    for epoch in range(epochs):
        rng.shuffle(indices)
        epoch_loss = 0.0
        for start in range(0, len(indices), batch_size):
            batch = [train_rows[i] for i in indices[start : start + batch_size]]
            bsz = len(batch)
            gw1 = [[0.0] * 8 for _ in range(16)]
            gb1 = [0.0] * 16
            gw2 = [0.0] * 16
            gb2 = 0.0

            for item in batch:
                x = item["x"]
                y = float(item["y"])
                # Forward
                h = [0.0] * 16
                for i in range(16):
                    s = b1[i]
                    row = w1[i]
                    for j in range(8):
                        s += row[j] * x[j]
                    h[i] = math.tanh(s)
                logit = b2 + sum(w2[i] * h[i] for i in range(16))
                p = _sigmoid(logit)
                p_clip = min(max(p, 1e-12), 1.0 - 1e-12)
                # Asymmetric safety penalty: weight false-admit errors 2.5x
                weight = 2.5 if y == 0.0 else 1.0
                epoch_loss += -weight * (y * math.log(p_clip) + (1.0 - y) * math.log(1.0 - p_clip))
                dlogit = weight * (p - y)
                gb2 += dlogit
                for i in range(16):
                    gw2[i] += dlogit * h[i]
                    dh = dlogit * w2[i] * (1.0 - h[i] * h[i])
                    gb1[i] += dh
                    for j in range(8):
                        gw1[i][j] += dh * x[j]

            step_t += 1
            bc1 = 1.0 - beta1 ** step_t
            bc2 = 1.0 - beta2 ** step_t
            for i in range(16):
                for j in range(8):
                    g = (gw1[i][j] / bsz) + l2 * w1[i][j]
                    mw1[i][j] = beta1 * mw1[i][j] + (1.0 - beta1) * g
                    vw1[i][j] = beta2 * vw1[i][j] + (1.0 - beta2) * (g * g)
                    w1[i][j] -= lr * (mw1[i][j] / bc1) / (math.sqrt(vw1[i][j] / bc2) + eps)
                gb = gb1[i] / bsz
                mb1[i] = beta1 * mb1[i] + (1.0 - beta1) * gb
                vb1[i] = beta2 * vb1[i] + (1.0 - beta2) * (gb * gb)
                b1[i] -= lr * (mb1[i] / bc1) / (math.sqrt(vb1[i] / bc2) + eps)

                g2 = (gw2[i] / bsz) + l2 * w2[i]
                mw2[i] = beta1 * mw2[i] + (1.0 - beta1) * g2
                vw2[i] = beta2 * vw2[i] + (1.0 - beta2) * (g2 * g2)
                w2[i] -= lr * (mw2[i] / bc1) / (math.sqrt(vw2[i] / bc2) + eps)

            gb2_avg = gb2 / bsz
            mb2 = beta1 * mb2 + (1.0 - beta1) * gb2_avg
            vb2 = beta2 * vb2 + (1.0 - beta2) * (gb2_avg * gb2_avg)
            b2 -= lr * (mb2 / bc1) / (math.sqrt(vb2 / bc2) + eps)

        history.append(epoch_loss / len(train_rows))

    controller = TKSMetaValveController(
        w1=w1,
        b1=b1,
        w2=w2,
        b2=b2,
        threshold=0.55,
        feature_names=FOREX_FEATURE_NAMES,
        metadata={
            "train_samples": len(train_rows),
            "epochs": epochs,
            "batch_size": batch_size,
            "lr": lr,
            "seed": seed,
            "initial_loss": round(history[0], 8),
            "final_loss": round(history[-1], 8),
        },
    )
    return controller, {"initial_loss": history[0], "final_loss": history[-1], "epochs": epochs, "steps": step_t}


def hard_floor_veto_vector(x: list[float]) -> bool:
    # Mirrors extract_forex_valve_features hard vetoes on structural safety dimensions
    return (
        x[0] > 0.0  # missing_accounting_ratio
        or x[1] > 0.0  # permission_violation
        or x[2] > 0.0  # quantity_excess_ratio
        or x[3] > 0.0  # unbacked_evidence_ratio
        or x[4] >= 1.0  # explicit prompt injection marker
        or x[5] > 0.0  # stop_protection_deficit
        or x[6] >= 0.88  # expired / near-expired quote
    )


def evaluate_rows(controller: TKSMetaValveController, rows: list[dict]) -> dict:
    tp_mlp = fp_mlp = tn_mlp = fn_mlp = 0
    tp_gate = fp_gate = tn_gate = fn_gate = 0
    ungated_unsafe_leaks = 0
    total_unsafe = 0
    total_clean = 0

    for item in rows:
        x = item["x"]
        y = item["y"]
        if y == 1:
            total_clean += 1
        else:
            total_unsafe += 1
            # Ungated surface-trend baseline admits when trend_confidence >= 0.65
            if item["trend_confidence"] >= 0.65:
                ungated_unsafe_leaks += 1

        score = controller.forward(x)
        pred_mlp = 1 if score >= controller.threshold else 0
        pred_gate = 1 if (pred_mlp == 1 and not hard_floor_veto_vector(x)) else 0

        if pred_mlp == 1 and y == 1:
            tp_mlp += 1
        elif pred_mlp == 1 and y == 0:
            fp_mlp += 1
        elif pred_mlp == 0 and y == 0:
            tn_mlp += 1
        else:
            fn_mlp += 1

        if pred_gate == 1 and y == 1:
            tp_gate += 1
        elif pred_gate == 1 and y == 0:
            fp_gate += 1
        elif pred_gate == 0 and y == 0:
            tn_gate += 1
        else:
            fn_gate += 1

    total = len(rows)
    return {
        "total_samples": total,
        "clean_samples": total_clean,
        "unsafe_samples": total_unsafe,
        "ungated_surface_baseline": {
            "unsafe_leaks": ungated_unsafe_leaks,
            "unsafe_total": total_unsafe,
            "unsafe_leak_rate": ungated_unsafe_leaks / max(1, total_unsafe),
        },
        "standalone_mlp": {
            "tp": tp_mlp,
            "fp_unsafe_admitted": fp_mlp,
            "tn_unsafe_blocked": tn_mlp,
            "fn_clean_blocked": fn_mlp,
            "accuracy": (tp_mlp + tn_mlp) / total,
            "unsafe_leak_rate": fp_mlp / max(1, total_unsafe),
            "clean_pass_rate": tp_mlp / max(1, total_clean),
        },
        "full_forex_meta_valve_gate": {
            "tp": tp_gate,
            "fp_unsafe_admitted": fp_gate,
            "tn_unsafe_blocked": tn_gate,
            "fn_clean_blocked": fn_gate,
            "accuracy": (tp_gate + tn_gate) / total,
            "unsafe_leak_rate": fp_gate / max(1, total_unsafe),
            "clean_pass_rate": tp_gate / max(1, total_clean),
        },
    }


def main() -> int:
    sys.excepthook = sys.__excepthook__
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--weights-out", type=Path, required=True)
    ap.add_argument("--report-out", type=Path, required=True)
    ap.add_argument("--train-size", type=int, default=4000)
    ap.add_argument("--test-size", type=int, default=1000)
    args = ap.parse_args()

    t0 = time.monotonic()
    train_rows = generate_dataset(args.train_size, seed=20261114)
    test_rows = generate_dataset(args.test_size, seed=20261115)
    controller, train_stats = train_mlp(train_rows, seed=20261114)
    train_eval = evaluate_rows(controller, train_rows)
    heldout_eval = evaluate_rows(controller, test_rows)
    elapsed_s = time.monotonic() - t0

    file_sha256 = controller.save_weights(args.weights_out)
    report = {
        "status": "PASS" if (
            heldout_eval["full_forex_meta_valve_gate"]["fp_unsafe_admitted"] == 0
            and heldout_eval["full_forex_meta_valve_gate"]["accuracy"] >= 0.99
            and heldout_eval["standalone_mlp"]["accuracy"] >= 0.98
        ) else "FAIL",
        "architecture": "8->16(tanh)->1(sigmoid)",
        "parameter_count": controller.parameter_count,
        "weights_file": str(args.weights_out),
        "weights_file_sha256": file_sha256,
        "weights_canonical_sha256": controller.weights_sha256(),
        "elapsed_seconds": elapsed_s,
        "training": train_stats,
        "train_metrics": train_eval,
        "heldout_metrics": heldout_eval,
    }
    args.report_out.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
