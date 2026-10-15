
import csv
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "data"

REQUIRED_FIELDS = {
    "authentication": {
        "timestamp", "event_type", "user", "user_id",
        "source_ip", "application", "result", "mfa_result",
    },
    "cloud_activity": {
        "timestamp", "event_type", "user", "user_id",
        "source_ip", "cloud_service", "action",
        "resource", "resource_type", "result",
    },
}

EXPECTED_COLUMNS = {
    "scenario_id",
    "detection_name",
    "event_time",
    "user",
    "source_ip",
    "expected_severity",
    "expected_outcome",
    "mitre_technique",
    "mitre_techniques",
}

MITRE_ID_PATTERN = re.compile(r"^T\d{4}(?:\.\d{3})?$")


def parse_timestamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Timestamp must include a timezone")
    return parsed.astimezone(timezone.utc)


def load_events(filename, expected_type):
    path = DATA_DIR / filename

    with path.open(encoding="utf-8") as file:
        events = json.load(file)

    if not isinstance(events, list):
        raise ValueError(f"{filename} must contain a JSON array")

    for index, event in enumerate(events, start=1):
        if not isinstance(event, dict):
            raise ValueError(
                f"{filename}, event {index}: expected an object"
            )

        missing = REQUIRED_FIELDS[expected_type] - event.keys()
        if missing:
            raise ValueError(
                f"{filename}, event {index}: missing {sorted(missing)}"
            )

        if event["event_type"] != expected_type:
            raise ValueError(
                f"{filename}, event {index}: unexpected event_type"
            )

        parse_timestamp(event["timestamp"])

        for field in ("user", "user_id", "source_ip", "result"):
            if not isinstance(event[field], str) or not event[field]:
                raise ValueError(
                    f"{filename}, event {index}: invalid {field}"
                )

    print(f"[PASS] {filename}: {len(events)} valid events")
    return events


def validate_expected_results(events):
    path = DATA_DIR / "expected-results.csv"

    with path.open(encoding="utf-8-sig", newline="") as file:
        reader = csv.DictReader(file)

        if not reader.fieldnames:
            raise ValueError("expected-results.csv is empty")

        if (
            len(reader.fieldnames) != len(set(reader.fieldnames))
            or set(reader.fieldnames) != EXPECTED_COLUMNS
        ):
            raise ValueError(
                "CSV headers do not match the required schema"
            )

        rows = list(reader)

    if not rows:
        raise ValueError("expected-results.csv has no scenarios")

    seen_ids = set()
    allowed_severities = {"Low", "Medium", "High", "Critical"}
    allowed_outcomes = {"Alert", "Investigate", "No Alert"}

    for line, row in enumerate(rows, start=2):
        if None in row or any(value is None for value in row.values()):
            raise ValueError(f"CSV line {line}: malformed row")

        required_values = [
            "scenario_id",
            "detection_name",
            "event_time",
            "user",
            "source_ip",
            "expected_severity",
            "expected_outcome",
        ]

        for key in required_values:
            if not row[key].strip():
                raise ValueError(
                    f"CSV line {line}: blank required value for {key}"
                )

        scenario_id = row["scenario_id"].strip()

        if scenario_id in seen_ids:
            raise ValueError(f"Duplicate scenario_id: {scenario_id}")
        seen_ids.add(scenario_id)

        if row["expected_severity"] not in allowed_severities:
            raise ValueError(
                f"CSV line {line}: invalid expected_severity"
            )

        if row["expected_outcome"] not in allowed_outcomes:
            raise ValueError(
                f"CSV line {line}: invalid expected_outcome"
            )

        primary = row["mitre_technique"].strip()
        techniques_raw = row["mitre_techniques"].strip()

        techniques = [
            technique.strip()
            for technique in techniques_raw.split(";")
            if technique.strip()
        ]

        if primary and not MITRE_ID_PATTERN.fullmatch(primary):
            raise ValueError(
                f"CSV line {line}: invalid mitre_technique ID"
            )

        if techniques_raw and not techniques:
            raise ValueError(
                f"CSV line {line}: invalid mitre_techniques"
            )

        for technique in techniques:
            if not MITRE_ID_PATTERN.fullmatch(technique):
                raise ValueError(
                    f"CSV line {line}: invalid MITRE technique ID "
                    f"{technique}"
                )

        if primary and primary not in techniques:
            raise ValueError(
                f"CSV line {line}: primary technique must appear "
                "in mitre_techniques"
            )

        if row["expected_outcome"] == "Alert" and not primary:
            raise ValueError(
                f"CSV line {line}: alert scenario requires a primary "
                "MITRE technique"
            )

        event_time = parse_timestamp(row["event_time"])

        matching_event = any(
            parse_timestamp(event["timestamp"]) == event_time
            and event["user"] == row["user"]
            and event["source_ip"] == row["source_ip"]
            for event in events
        )

        if not matching_event:
            raise ValueError(
                f"{scenario_id}: no event matches event_time, user "
                "and source_ip"
            )

    print(f"[PASS] expected-results.csv: {len(rows)} scenarios")
    print("[PASS] Every scenario references an event in the datasets")
    print("[PASS] MITRE technique IDs and primary mappings are valid")


def main():
    try:
        auth_events = load_events(
            "authentication-events.json", "authentication"
        )
        cloud_events = load_events(
            "cloud-activity-events.json", "cloud_activity"
        )

        all_events = auth_events + cloud_events
        validate_expected_results(all_events)

        print("\nValidation completed successfully.")
        print(f"Total events: {len(all_events)}")
        print("Note: this validates data integrity, not detection accuracy.")

    except (
        OSError,
        json.JSONDecodeError,
        csv.Error,
        ValueError,
    ) as error:
        print(f"\nValidation failed: {error}")
        sys.exit(1)


if __name__ == "__main__":
    main()