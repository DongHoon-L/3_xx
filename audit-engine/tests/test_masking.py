from audit_engine.masking import mask_record, mask_text

SAMPLE = "synthetic contact: sample.user@example.com, 010-1234-5678, RRN 900101-1234567, card 4111-1111-1111-1111"


def test_mask_text_masks_all_four_pii_types_and_reports_findings():
    masked, findings = mask_text(SAMPLE)
    assert "sample.user@example.com" not in masked
    assert "010-1234-5678" not in masked
    assert "900101-1234567" not in masked
    assert "4111-1111-1111-1111" not in masked
    assert {f["type"] for f in findings} == {"email", "phone", "rrn", "card"}
    assert "[EMAIL_MASKED]" in masked and "[CARD_MASKED]" in masked


def test_rescan_after_masking_finds_nothing():
    masked, _ = mask_text(SAMPLE)
    assert mask_text(masked)[1] == []


def test_mask_record_recurses_and_does_not_mutate_input():
    record = {"purpose": SAMPLE, "details": {"note": "mail me at a@b.io"}, "actor": "alice", "n": 3}
    protected, findings = mask_record(record)
    assert record["purpose"] == SAMPLE
    assert "example.com" not in protected["purpose"]
    assert protected["details"]["note"] == "mail me at [EMAIL_MASKED]"
    assert protected["actor"] == "alice" and protected["n"] == 3
    assert len(findings) == 5


def test_direct_field_labels_mask_whole_value():
    protected, findings = mask_record({"email": "anything-here"})
    assert protected == {"email": "[EMAIL_MASKED]"}
    assert findings == [{"type": "email", "value": "anything-here"}]
