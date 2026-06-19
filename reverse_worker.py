#!/usr/bin/env python3
import sys
import os
import re
from datetime import datetime
from paths import (
    logfile_path,
    reversed_logfile_path,
    endpoint_mapping_path,
    label_mapping_path,
    data_mapping_path,
    timeshift_mapping_path,
    duration_shift_mapping_path,
    loop_distribution_mapping_path,
    loop_distribution_log_path,
)
from policy import load_json_file
from privacy_mechanisms import shift_timestamp_by_seconds
from yaml_log import read_yaml_stream, write_yaml_stream, split_header_and_events


def invert_mapping(mapping: dict) -> dict:
    if not isinstance(mapping, dict):
        return {}
    return {pseudo: original for original, pseudo in mapping.items()}


def reverse_value(value, reverse_mapping: dict):
    if value is None or value == "":
        return value
    return reverse_mapping.get(str(value), value)


def parse_scalar_value(value: str):
    if value == "None":
        return None
    if value == "True":
        return True
    if value == "False":
        return False

    try:
        return int(value)
    except Exception:
        pass

    try:
        return float(value)
    except Exception:
        pass

    return value


def extract_original_data_value(mapped_key: str):
    if ":" not in mapped_key:
        return mapped_key

    _, original_value = mapped_key.split(":", 1)
    return parse_scalar_value(original_value)


def sort_events_by_sequence_then_timestamp(event_documents):
    def sort_key(doc):
        event = doc.get("event", {})

        sequence = event.get("_privacy_sequence")
        if sequence is not None:
            try:
                return (0, int(sequence))
            except Exception:
                pass

        timestamp = event.get("time:timestamp", "")
        try:
            return (1, datetime.fromisoformat(str(timestamp)))
        except Exception:
            return (1, datetime.min)

    return sorted(event_documents, key=sort_key)


def get_event_activity(event: dict) -> str:
    return (
        event.get("id:id")
        or event.get("cpee:activity")
        or event.get("activity")
        or ""
    )


def get_event_activity_uuid(event: dict) -> str:
    return (
        event.get("cpee:activity_uuid")
        or event.get("activity_uuid")
        or event.get("activity-uuid")
        or ""
    )


def get_event_timestamp(event: dict) -> str:
    return (
        event.get("time:timestamp")
        or event.get("timestamp")
        or ""
    )

def normalize_event_lifecycle(event: dict) -> str:
    lifecycle = str(
        event.get("cpee:lifecycle:transition")
        or event.get("lifecycle:transition")
        or event.get("lifecycle")
        or ""
    ).strip().lower()

    if lifecycle in {"start", "calling", "activity/calling"}:
        return "calling"

    if lifecycle in {"complete", "done", "activity/done"}:
        return "done"

    if lifecycle in {"decide", "gateway/decide"}:
        return "decide"

    if lifecycle in {"change", "dataelements/change"}:
        return "change"

    return lifecycle


def build_event_shift_key(event: dict) -> str:
    return (
        f"{get_event_activity(event)}:"
        f"{get_event_activity_uuid(event)}:"
        f"{get_event_timestamp(event)}:"
        f"{normalize_event_lifecycle(event)}"
    )

def build_data_context_key(event: dict, original_name: str) -> str:
    return (
        f"{get_event_activity(event)}:"
        f"{get_event_activity_uuid(event)}:"
        f"{get_event_timestamp(event)}:"
        f"{original_name}"
    )


def load_timeshift_seconds(instance_id: int):
    obj = load_json_file(timeshift_mapping_path(instance_id))
    if isinstance(obj, dict) and "shift_seconds" in obj:
        try:
            return int(obj["shift_seconds"])
        except Exception:
            return None
    return None


def load_duration_shift_state(instance_id: int) -> dict:
    obj = load_json_file(duration_shift_mapping_path(instance_id))
    if isinstance(obj, dict):
        return {
            "event_applied_shifts": dict(obj.get("event_applied_shifts", {})),
        }

    return {"event_applied_shifts": {}}


def load_event_documents_from_path(path: str):
    if not os.path.exists(path):
        return []

    documents = read_yaml_stream(path)
    _, event_documents = split_header_and_events(documents)
    return event_documents


def load_loop_distribution_events(instance_id: int):
    mapping = load_json_file(loop_distribution_mapping_path(instance_id)) or {}
    loops = mapping.get("loops", {})

    if not loops:
        return []

    all_events = []

    for loop_state in loops.values():
        if not isinstance(loop_state, dict):
            continue

        part_logs = loop_state.get("part_logs", {})

        if isinstance(part_logs, dict) and part_logs:
            ordered_parts = sorted(
                part_logs.items(),
                key=lambda item: int(item[0]) if str(item[0]).isdigit() else 999999,
            )

            for _, path in ordered_parts:
                all_events.extend(load_event_documents_from_path(path))

        else:
            segments = loop_state.get("segments", [])
            for index in range(len(segments)):
                path = loop_distribution_log_path(instance_id, index + 1)
                all_events.extend(load_event_documents_from_path(path))

    return all_events


def expand_loop_distribution(event_documents, instance_id: int):
    distribution_events = load_loop_distribution_events(instance_id)

    if not distribution_events:
        return event_documents

    mapping = load_json_file(loop_distribution_mapping_path(instance_id)) or {}
    loops = mapping.get("loops", {})

    distributed_activity_ids = set()
    distributed_loop_ids = set()

    for loop_state in loops.values():
        if isinstance(loop_state, dict):
            distributed_activity_ids.update(loop_state.get("activity_ids", []))
            if loop_state.get("loop_id"):
                distributed_loop_ids.add(loop_state.get("loop_id"))

    filtered_events = []

    for doc in event_documents:
        event = doc.get("event", {})
        activity = event.get("id:id") or event.get("cpee:activity")
        event_id = event.get("id:id") or event.get("eid")

        if activity in distributed_activity_ids:
            continue

        if event_id in distributed_loop_ids:
            continue

        filtered_events.append(doc)

    return filtered_events + distribution_events


def reverse_duration_shift_for_events(event_documents, instance_id: int):
    state = load_duration_shift_state(instance_id)
    event_applied_shifts = state.get("event_applied_shifts", {})

    if not event_applied_shifts:
        return event_documents

    for doc in event_documents:
        event = doc.get("event", {})
        timestamp = event.get("time:timestamp", "")

        if not timestamp:
            continue

        event_key = build_event_shift_key(event)

        try:
            applied_shift = int(event_applied_shifts.get(event_key, 0))
        except Exception:
            applied_shift = 0

        if applied_shift != 0:
            event["time:timestamp"] = shift_timestamp_by_seconds(
                timestamp,
                -applied_shift,
            )

    return event_documents


def reverse_timeshift_for_events(event_documents, instance_id: int):
    shift_seconds = load_timeshift_seconds(instance_id)
    if shift_seconds is None:
        return event_documents

    for doc in event_documents:
        event = doc.get("event", {})
        if "time:timestamp" in event:
            event["time:timestamp"] = shift_timestamp_by_seconds(
                event.get("time:timestamp", ""),
                -shift_seconds,
            )

    return event_documents


def reverse_pseudonyms_for_events(event_documents, instance_id: int):
    endpoint_mapping = load_json_file(endpoint_mapping_path(instance_id)) or {}
    label_mapping = load_json_file(label_mapping_path(instance_id)) or {}

    reverse_endpoint_mapping = invert_mapping(endpoint_mapping)
    reverse_label_mapping = invert_mapping(label_mapping)

    for doc in event_documents:
        event = doc.get("event", {})

        if "concept:endpoint" in event:
            event["concept:endpoint"] = reverse_value(
                event.get("concept:endpoint", ""),
                reverse_endpoint_mapping,
            )

        if "concept:name" in event:
            event["concept:name"] = reverse_value(
                event.get("concept:name", ""),
                reverse_label_mapping,
            )

    return event_documents


def reverse_condition_string(text: str, reverse_name_mapping: dict) -> str:
    if not isinstance(text, str):
        return text

    def replace_match(match):
        pseudo_name = match.group(1)
        original_name = reverse_name_mapping.get(pseudo_name)

        if not original_name:
            return match.group(0)

        return f"data.{original_name}"

    return re.sub(r"\bdata\.([A-Za-z_][A-Za-z0-9_]*)\b", replace_match, text)


def reverse_fixed_value_if_possible(event: dict, original_name: str, value, fixed_value_originals: dict):
    context_key = build_data_context_key(event, original_name)

    if context_key in fixed_value_originals:
        return fixed_value_originals[context_key]

    activity = get_event_activity(event)
    activity_uuid = get_event_activity_uuid(event)

    prefix = f"{activity}:{activity_uuid}:"
    suffix = f":{original_name}"

    for key, original_value in fixed_value_originals.items():
        if key.startswith(prefix) and key.endswith(suffix):
            return original_value

    return value

def reverse_nested_data_value(
    value,
    event: dict,
    reverse_name_mapping: dict,
    reverse_value_mapping: dict,
    fixed_value_originals: dict,
):
    if isinstance(value, dict):
        return reverse_data_dict(
            value,
            event,
            reverse_name_mapping,
            reverse_value_mapping,
            fixed_value_originals,
        )

    if isinstance(value, list):
        return reverse_data_list(
            value,
            event,
            reverse_name_mapping,
            reverse_value_mapping,
            fixed_value_originals,
        )

    mapped_key = reverse_value_mapping.get(str(value))
    if mapped_key is not None:
        return extract_original_data_value(mapped_key)

    return value

def reverse_data_list(
    data: list,
    event: dict,
    reverse_name_mapping: dict,
    reverse_value_mapping: dict,
    fixed_value_originals: dict,
):
    reversed_data = []

    for item in data:
        if not isinstance(item, dict):
            reversed_data.append(
                reverse_nested_data_value(
                    item,
                    event,
                    reverse_name_mapping,
                    reverse_value_mapping,
                    fixed_value_originals,
                )
            )
            continue

        new_item = dict(item)
        original_name = None

        if "name" in new_item:
            original_name = reverse_value(
                new_item.get("name"),
                reverse_name_mapping,
            )
            new_item["name"] = original_name

        if "value" in new_item:
            new_item["value"] = reverse_nested_data_value(
                new_item.get("value"),
                event,
                reverse_name_mapping,
                reverse_value_mapping,
                fixed_value_originals,
            )

            if original_name is not None:
                new_item["value"] = reverse_fixed_value_if_possible(
                    event,
                    original_name,
                    new_item.get("value"),
                    fixed_value_originals,
                )

        if "data" in new_item:
            new_item["data"] = reverse_nested_data_value(
                new_item.get("data"),
                event,
                reverse_name_mapping,
                reverse_value_mapping,
                fixed_value_originals,
            )

        reversed_data.append(new_item)

    return reversed_data


def reverse_data_dict(
    data: dict,
    event: dict,
    reverse_name_mapping: dict,
    reverse_value_mapping: dict,
    fixed_value_originals: dict,
):
    reversed_data = {}

    for key, value in data.items():
        original_key = reverse_name_mapping.get(str(key), key)

        value = reverse_nested_data_value(
            value,
            event,
            reverse_name_mapping,
            reverse_value_mapping,
            fixed_value_originals,
        )

        value = reverse_fixed_value_if_possible(
            event,
            original_key,
            value,
            fixed_value_originals,
        )

        if isinstance(value, str):
            value = reverse_condition_string(value, reverse_name_mapping)

            mapped_key = reverse_value_mapping.get(str(value))
            if mapped_key is not None:
                value = extract_original_data_value(mapped_key)

        reversed_data[original_key] = value

    return reversed_data

def reverse_data_elements_for_events(event_documents, instance_id: int):
    mapping = load_json_file(data_mapping_path(instance_id)) or {}

    name_mapping = mapping.get("names", {})
    value_mapping = mapping.get("values", {})
    fixed_value_originals = mapping.get("fixed_value_originals", {})

    reverse_name_mapping = invert_mapping(name_mapping)
    reverse_value_mapping = invert_mapping(value_mapping)

    if not reverse_name_mapping and not reverse_value_mapping and not fixed_value_originals:
        return event_documents

    for doc in event_documents:
        event = doc.get("event", {})

        data = event.get("data")

        if isinstance(data, list):
            event["data"] = reverse_data_list(
                data,
                event,
                reverse_name_mapping,
                reverse_value_mapping,
                fixed_value_originals,
            )

        elif isinstance(data, dict):
            event["data"] = reverse_data_dict(
                data,
                event,
                reverse_name_mapping,
                reverse_value_mapping,
                fixed_value_originals,
            )

        if isinstance(event.get("condition"), str):
            event["condition"] = reverse_condition_string(
                event["condition"],
                reverse_name_mapping,
            )

    return event_documents


def reverse_header(header_doc, instance_id: int):
    if not isinstance(header_doc, dict) or "log" not in header_doc:
        return header_doc

    trace = header_doc["log"].get("trace", {})
    if isinstance(trace, dict):
        trace["cpee:name"] = "reversed"
        trace["concept:name"] = str(instance_id)
        trace["cpee:instance"] = str(instance_id)

    return header_doc


def reverse_log(instance_id: int):
    input_log_path = logfile_path(instance_id)
    output_log_path = reversed_logfile_path(instance_id)

    if not os.path.exists(input_log_path):
        raise FileNotFoundError(f"Log file not found: {input_log_path}")

    documents = read_yaml_stream(input_log_path)
    header_doc, event_documents = split_header_and_events(documents)

    if header_doc is None:
        raise ValueError("YAML log is empty.")

    header_doc = reverse_header(header_doc, instance_id)
    event_documents = expand_loop_distribution(event_documents, instance_id)

    event_documents = sort_events_by_sequence_then_timestamp(event_documents)
    event_documents = reverse_duration_shift_for_events(event_documents, instance_id)
    event_documents = reverse_timeshift_for_events(event_documents, instance_id)
    event_documents = reverse_pseudonyms_for_events(event_documents, instance_id)
    event_documents = reverse_data_elements_for_events(event_documents, instance_id)

    event_documents = sort_events_by_sequence_then_timestamp(event_documents)

    event_documents = remove_privacy_sequence(event_documents)

    output_documents = [header_doc] + event_documents
    write_yaml_stream(output_log_path, output_documents)

    return output_log_path, len(event_documents)

def remove_privacy_sequence(event_documents):
    for doc in event_documents:
        event = doc.get("event", {})
        event.pop("_privacy_sequence", None)

    return event_documents

def main():
    if len(sys.argv) != 2:
        print("Usage: python3 reverse_worker.py <instance_id>")
        sys.exit(1)

    try:
        instance_id = int(sys.argv[1])
    except ValueError:
        print("Error: instance_id must be an integer.")
        sys.exit(1)

    try:
        output_path, count = reverse_log(instance_id)
        print(f"Reversed {count} events.")
        print(f"Output written to: {output_path}")
        sys.exit(0)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()