
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data" / "cloud-activity-events.json"
WINDOW = timedelta(minutes=15)


def parse_time(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def detect_sequences(events):
    """Return alerts for valid listing -> role enumeration -> object read sequences."""
    parsed = []

    for event in events:
        item = dict(event)
        item["_time"] = parse_time(item["timestamp"])
        parsed.append(item)

    alerts = []

    for read in parsed:
        if not (
            read.get("action") == "GetObject"
            and read.get("resource_type") == "object"
            and read.get("result") == "success"
        ):
            continue

        prior = [
            event for event in parsed
            if event.get("user") == read.get("user")
            and event.get("source_ip") == read.get("source_ip")
            and event.get("result") == "success"
            and event["_time"] < read["_time"]
        ]

        listings = [
            event for event in prior
            if event.get("action") == "ListObjects"
        ]
        role_enumerations = [
            event for event in prior
            if event.get("action") == "ListRoles"
        ]

        sequences = [
            (listing, role)
            for listing in listings
            for role in role_enumerations
            if listing["_time"] < role["_time"] < read["_time"]
            and role["_time"] - listing["_time"] <= WINDOW
            and read["_time"] - role["_time"] <= WINDOW
        ]

        if sequences:
            listing, role = max(
                sequences,
                key=lambda pair: (pair[1]["_time"], pair[0]["_time"])
            )
            alerts.append({
                "user": read["user"],
                "source_ip": read["source_ip"],
                "listing_time": listing["timestamp"],
                "role_time": role["timestamp"],
                "read_time": read["timestamp"],
                "object": read["resource"],
            })

    return alerts


def make_event(minute, action, *, user="tester",
               source_ip="203.0.113.10", result="success",
               resource_type=None, resource="test-resource"):
    """Create deterministic UTC events, allowing minute offsets across hours."""
    event_time = datetime(2026, 10, 12, 14, 0, tzinfo=timezone.utc) + timedelta(minutes=minute)
    event = {
        "timestamp": event_time.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "user": user,
        "source_ip": source_ip,
        "action": action,
        "result": result,
        "resource": resource,
        "resource_type": resource_type or (
            "object" if action == "GetObject" else "bucket"
        ),
    }
    return event


def run_edge_case_tests():
    valid = [
        make_event(0, "ListObjects"),
        make_event(5, "ListRoles"),
        make_event(10, "GetObject"),
    ]
    assert len(detect_sequences(valid)) == 1, "Valid sequence should alert"

    cases = {
        "missing role enumeration": [
            make_event(0, "ListObjects"),
            make_event(10, "GetObject"),
        ],
        "missing listing": [
            make_event(5, "ListRoles"),
            make_event(10, "GetObject"),
        ],
        "wrong order": [
            make_event(0, "ListRoles"),
            make_event(5, "ListObjects"),
            make_event(10, "GetObject"),
        ],
        "failed object read": [
            make_event(0, "ListObjects"),
            make_event(5, "ListRoles"),
            make_event(10, "GetObject", result="failure"),
        ],
        "user mismatch": [
            make_event(0, "ListObjects"),
            make_event(5, "ListRoles"),
            make_event(10, "GetObject", user="different-user"),
        ],
        "source IP mismatch": [
            make_event(0, "ListObjects"),
            make_event(5, "ListRoles"),
            make_event(10, "GetObject", source_ip="203.0.113.99"),
        ],
        "listing-to-role interval exceeds 15 minutes": [
            make_event(0, "ListObjects"),
            make_event(16, "ListRoles"),
            make_event(20, "GetObject"),
        ],
        "role-to-read interval exceeds 15 minutes": [
            make_event(0, "ListObjects"),
            make_event(5, "ListRoles"),
            make_event(21, "GetObject"),
        ],
        "wrong object resource type": [
            make_event(0, "ListObjects"),
            make_event(5, "ListRoles"),
            make_event(10, "GetObject", resource_type="bucket"),
        ],
    }

    for name, events in cases.items():
        assert not detect_sequences(events), f"Unexpected alert: {name}"
        print(f"[PASS] {name}")


    # Multiple qualifying listings: use the latest listing before the role event.
    repeated_listing = [
        make_event(0, "ListObjects", resource="older-bucket"),
        make_event(3, "ListObjects", resource="newer-bucket"),
        make_event(5, "ListRoles"),
        make_event(10, "GetObject"),
    ]
    repeated_alerts = detect_sequences(repeated_listing)
    assert len(repeated_alerts) == 1, (
        "One object read should produce one alert"
    )
    assert repeated_alerts[0]["listing_time"] == (
        "2026-10-12T14:03:00Z"
    ), "The latest qualifying listing should be selected"
    print("[PASS] Latest qualifying listing selected")

    # A later listing after role enumeration must not erase a valid sequence.
    listing_after_role = [
        make_event(0, "ListObjects", resource="valid-bucket"),
        make_event(5, "ListRoles"),
        make_event(7, "ListObjects", resource="later-bucket"),
        make_event(10, "GetObject"),
    ]
    later_listing_alerts = detect_sequences(listing_after_role)
    assert len(later_listing_alerts) == 1, (
        "A later listing must not hide an earlier valid listing-role sequence"
    )
    assert later_listing_alerts[0]["listing_time"] == (
        "2026-10-12T14:00:00Z"
    ), "The listing before the valid role event should be selected"
    print("[PASS] Later listing does not hide a valid sequence")

    # Multiple object reads should each produce one alert.
    multiple_reads = [
        make_event(0, "ListObjects"),
        make_event(5, "ListRoles"),
        make_event(10, "GetObject", resource="first-object"),
        make_event(12, "GetObject", resource="second-object"),
    ]
    read_alerts = detect_sequences(multiple_reads)
    assert len(read_alerts) == 2, (
        "Each qualifying object read should produce one alert"
    )
    assert [a["object"] for a in read_alerts] == [
        "first-object", "second-object"
    ], "Both object reads should be represented"
    print("[PASS] Multiple object reads produce separate alerts")


    # Repeated role enumeration: select the latest valid role and its listing.
    repeated_roles = [
        make_event(0, "ListObjects", resource="older-bucket"),
        make_event(3, "ListObjects", resource="newer-bucket"),
        make_event(5, "ListRoles"),
        make_event(7, "ListRoles"),
        make_event(10, "GetObject"),
    ]
    role_alerts = detect_sequences(repeated_roles)
    assert len(role_alerts) == 1, (
        "One object read should produce one alert"
    )
    assert role_alerts[0]["role_time"] == (
        "2026-10-12T14:07:00Z"
    ), "The latest valid role event should be selected"
    assert role_alerts[0]["listing_time"] == (
        "2026-10-12T14:03:00Z"
    ), "The latest qualifying listing should be associated"
    print("[PASS] Latest valid role and associated listing selected")

    # Exactly 15 minutes between consecutive stages is allowed.
    boundary = [
        make_event(0, "ListObjects"),
        make_event(15, "ListRoles"),
        make_event(30, "GetObject"),
    ]
    assert len(detect_sequences(boundary)) == 1, (
        "Exactly 15 minutes between stages should be allowed"
    )
    print("[PASS] Exact 15-minute stage boundaries")

    print("[PASS] All edge-case tests passed.")


if __name__ == "__main__":
    with DATA.open(encoding="utf-8") as file:
        events = json.load(file)

    alerts = detect_sequences(events)

    print(f"Events loaded: {len(events)}")
    print(f"Correlated alerts: {len(alerts)}")

    for alert in alerts:
        print(
            "[ALERT]",
            alert["user"],
            alert["source_ip"],
            alert["listing_time"],
            "->", alert["role_time"],
            "->", alert["read_time"],
            alert["object"],
        )

    expected = [
        (
            "charlie",
            "203.0.113.70",
            "2026-10-12T14:03:00Z",
            "2026-10-12T14:07:00Z",
            "2026-10-12T14:12:00Z",
        )
    ]

    actual = [
        (
            alert["user"],
            alert["source_ip"],
            alert["listing_time"],
            alert["role_time"],
            alert["read_time"],
        )
        for alert in alerts
    ]

    assert actual == expected, (
        f"Expected {expected!r}, got {actual!r}"
    )
    print("[PASS] Dataset produces only the expected correlated sequence.")

    run_edge_case_tests()
