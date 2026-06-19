#!/usr/bin/env python3
import sys
import json
import os

from config import BASE_DIR
from paths import ensure_instance_dir, logfile_path
from policy import get_policies
from yaml_log import ensure_yaml_header, map_to_yaml_event, insert_yaml_event_sorted
from privacy_mechanisms import (
    pseudonymize_endpoint,
    pseudonymize_label,
    transform_data_elements,
    apply_timeshift,
    apply_duration_shift,
    handle_loop_distribution_if_needed,
    assign_privacy_sequence,
)


def extract_event(notification: dict):
    instance = notification.get("instance")
    lifecycle = notification.get("name")
    timestamp = notification.get("timestamp")
    content = notification.get("content") or {}

    if instance is None or not lifecycle or not timestamp:
        return None

    event = dict(content)
    event["timestamp"] = timestamp
    event["lifecycle"] = lifecycle

    if "activity" not in event or event.get("activity") is None:
        event["activity"] = (
            content.get("activity")
            or content.get("id")
            or notification.get("activity")
            or notification.get("id")
        )

    if "label" not in event:
        event["label"] = content.get("label", "")

    if "endpoint" not in event:
        event["endpoint"] = content.get("endpoint", "")

    if "data" not in event and content.get("data") is not None:
        event["data"] = content.get("data")

    if "activity_uuid" not in event:
        event["activity_uuid"] = (
            content.get("activity_uuid")
            or content.get("activity-uuid")
        )

    if "cpee_instance" not in event:
        event["cpee_instance"] = (
            content.get("instance")
            or (content.get("attributes") or {}).get("uuid")
            or str(instance)
        )

    return event


def main():
    os.makedirs(BASE_DIR, exist_ok=True)

    raw = sys.stdin.read()
    if not raw.strip():
        sys.exit(0)

    try:
        notification = json.loads(raw)
    except Exception:
        sys.exit(0)

    event = extract_event(notification)
    if event is None:
        sys.exit(0)

    try:
        instance_id = int(notification["instance"])
    except Exception:
        sys.exit(0)

    ensure_instance_dir(instance_id)

    policies = get_policies(instance_id)
    activity = event.get("activity")

    if activity and activity in policies.get("no_log_ids", []):
        sys.exit(0)

    event = assign_privacy_sequence(event, instance_id)

    if (
        policies.get("transform_endpoint_global", False)
        or (activity and activity in policies.get("transform_endpoint_ids", []))
    ):
        if "endpoint" in event:
            event["endpoint"] = pseudonymize_endpoint(
                event.get("endpoint", ""),
                instance_id,
            )

    if (
        policies.get("transform_label_global", False)
        or (activity and activity in policies.get("transform_label_ids", []))
    ):
        if "label" in event:
            event["label"] = pseudonymize_label(
                event.get("label", ""),
                instance_id,
            )

    if policies.get("timeshift_global", False):
        event["timestamp"] = apply_timeshift(
            event.get("timestamp", ""),
            instance_id,
            policies.get("timeshift_config", {}),
        )


    if activity and policies.get("duration_shift_ids"):
        event["timestamp"] = apply_duration_shift(
            event.get("timestamp", ""),
            event,
            instance_id,
            set(policies.get("duration_shift_ids", [])),
            policies.get("duration_shift_configs", {}),
        )

    if handle_loop_distribution_if_needed(event, instance_id, policies):
        sys.exit(0)

    if policies.get("transform_data_global", False):
        event = transform_data_elements(
            event,
            instance_id,
            policies.get("transform_data_config", {}),
        )

    path = logfile_path(instance_id)
    ensure_yaml_header(path, instance_id)
    insert_yaml_event_sorted(path, map_to_yaml_event(event, instance_id))

    sys.exit(0)


if __name__ == "__main__":
    main()