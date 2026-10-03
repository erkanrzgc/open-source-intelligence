"""Evaluation metrics must count uncertainty and misses, not hide them."""

import json

import pytest

from core.evaluation import evaluate_dataset
from scripts.identity_benchmark import DEFAULT_DATASET, main


def test_labelled_regression_set_counts_false_negatives():
    report = evaluate_dataset(json.loads(DEFAULT_DATASET.read_text()))
    metrics = report["metrics"]
    assert metrics["pairs"] == 24
    assert metrics["positive_labels"] == metrics["negative_labels"] == 12
    assert metrics["false_positive"] == 0
    assert metrics["true_positive"] == 8
    assert metrics["false_negative"] == 4
    assert metrics["recall"] == 0.6667
    assert metrics["abstained"] == 16
    assert report["data_kind"] == "synthetic_development"
    assert report["discovery"]["results"][0]["rank"] == 1
    assert report["discovery"]["hit_at_24"] < 1.0


def test_no_predictions_have_undefined_precision_not_perfect_precision():
    report = evaluate_dataset({"identity_pairs": [
        {"id": "one", "same_person": True, "left": {}, "right": {}}
    ]})
    assert report["metrics"]["precision"] is None
    assert report["metrics"]["false_negative"] == 1
    assert report["metrics"]["false_positive_rate"] is None
    assert report["discovery"]["hit_at_12"] is None


@pytest.mark.parametrize("pairs", [[], [
    {"id": "bad", "same_person": "false", "left": {}, "right": {}}
]])
def test_invalid_labels_are_rejected(pairs):
    with pytest.raises(ValueError):
        evaluate_dataset({"identity_pairs": pairs})


def test_cli_fails_on_false_strong_match_and_writes_report(tmp_path, capsys):
    dataset = tmp_path / "dataset.json"
    dataset.write_text(json.dumps({"identity_pairs": [
        {"id": "false-proof", "same_person": False, "direct_link": True,
         "left": {}, "right": {}}
    ]}))
    output = tmp_path / "report.json"
    assert main(["--dataset", str(dataset), "--check", "--output", str(output)]) == 1
    report = json.loads(output.read_text())
    assert report["metrics"]["false_positive"] == 1
    assert report["metrics"]["false_confirmations"] == 1
    assert report["generated_at"]


def test_evidence_guardrails_on_regression_examples():
    report = evaluate_dataset(json.loads(DEFAULT_DATASET.read_text()))
    rows = {row["id"]: row for row in report["identity_pairs"]}
    assert rows["different_duplicate_external_evidence"]["verdict"] == "possible_same"
    assert "avatar" not in rows["different_avatar_url"]["evidence_kinds"]
    assert "avatar" in rows["same_name_phash"]["evidence_kinds"]
