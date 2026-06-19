import os
import yaml
import fcntl
from datetime import datetime

def yaml_log_header(instance_id: int) -> dict:
    return {
        "log": {
            "namespaces": {
                "stream": "https://cpee.org/datastream/",
                "ssn": "http://www.w3.org/ns/ssn/",
                "sosa": "http://www.w3.org/ns/sosa/",
            },
            "trace": {
                "concept:name": str(instance_id),
                "cpee:name": "pseudonymized",
                "cpee:instance": str(instance_id),
            },
        }
    }


def ensure_yaml_header(path: str, instance_id: int):
    if os.path.exists(path) and os.path.getsize(path) > 0:
        return

    with open(path, "w", encoding="utf-8") as f:
        f.write("---\n")
        yaml.safe_dump(
            yaml_log_header(instance_id),
            f,
            sort_keys=False,
            allow_unicode=True,
        )


def ensure_named_yaml_header(path: str, instance_id: int, name: str):
    if os.path.exists(path) and os.path.getsize(path) > 0:
        return

    header = yaml_log_header(instance_id)
    header["log"]["trace"]["cpee:name"] = name

    with open(path, "w", encoding="utf-8") as f:
        f.write("---\n")
        yaml.safe_dump(
            header,
            f,
            sort_keys=False,
            allow_unicode=True,
        )


def normalize_lifecycle(lifecycle: str) -> str:
    return str(lifecycle).strip().lower()


def map_lifecycle_transition(lifecycle: str) -> str:
    lifecycle = normalize_lifecycle(lifecycle)

    if lifecycle == "calling":
        return "start"

    if lifecycle == "done":
        return "complete"

    if lifecycle in {"change", "decide", "receiving"}:
        return "unknown"

    return lifecycle if lifecycle else "unknown"


def map_cpee_lifecycle_transition(lifecycle: str) -> str:
    lifecycle = normalize_lifecycle(lifecycle)

    if lifecycle == "calling":
        return "activity/calling"

    if lifecycle == "done":
        return "activity/done"

    if lifecycle == "receiving":
        return "activity/receiving"

    if lifecycle == "change":
        return "dataelements/change"

    if lifecycle == "decide":
        return "gateway/decide"

    if "/" in lifecycle:
        return lifecycle

    return f"activity/{lifecycle}" if lifecycle else "unknown"


def extract_event_data(event: dict, lifecycle: str):
    if event.get("data") is not None:
        return event.get("data")

    if (
        isinstance(event.get("parameters"), dict)
        and event["parameters"].get("arguments")
    ):
        return event["parameters"]["arguments"]

    if event.get("changed") is not None and event.get("values") is not None:
        changed = event.get("changed") or []
        values = event.get("values") or {}

        return [
            {
                "name": name,
                "value": values.get(name),
            }
            for name in changed
        ]

    if (
        lifecycle == "decide"
        or event.get("code") is not None
        or event.get("condition") is not None
        or event.get("result") is not None
    ):
        data = {}

        if "code" in event:
            data["condition"] = event["code"]
        elif "condition" in event and isinstance(event.get("condition"), str):
            data["condition"] = event["condition"]

        if "result" in event:
            data["result"] = event["result"]
        elif "condition" in event and not isinstance(event.get("condition"), str):
            data["result"] = event["condition"]

        return data if data else None

    return None


def map_to_yaml_event(event: dict, instance_id: int) -> dict:
    lifecycle = normalize_lifecycle(event.get("lifecycle", ""))

    yaml_event = {
        "concept:instance": int(instance_id),
        "time:timestamp": event.get("timestamp", ""),
    }

    if event.get("_privacy_sequence") is not None:
        yaml_event["_privacy_sequence"] = event.get("_privacy_sequence")

    activity = event.get("activity")
    if activity is not None:
        yaml_event["id:id"] = activity
        yaml_event["cpee:activity"] = activity

    label = event.get("label")
    if label:
        yaml_event["concept:name"] = label

    endpoint = event.get("endpoint")
    if endpoint:
        yaml_event["concept:endpoint"] = endpoint

    activity_uuid = event.get("activity_uuid") or event.get("activity-uuid")
    if activity_uuid:
        yaml_event["cpee:activity_uuid"] = activity_uuid

    yaml_event["cpee:instance"] = (
        event.get("cpee_instance")
        or event.get("instance_uuid")
        or str(instance_id)
    )

    yaml_event["lifecycle:transition"] = map_lifecycle_transition(lifecycle)
    yaml_event["cpee:lifecycle:transition"] = map_cpee_lifecycle_transition(lifecycle)

    data = extract_event_data(event, lifecycle)
    if data is not None:
        yaml_event["data"] = data

    if lifecycle == "decide" and event.get("eid"):
        yaml_event["id:id"] = event["eid"]

    ignored_keys = {
        "timestamp",
        "activity",
        "label",
        "endpoint",
        "lifecycle",
        "activity_uuid",
        "activity-uuid",
        "cpee_instance",
        "instance_uuid",
        "data",
        "parameters",
        "attributes",
        "passthrough",
        "changed",
        "values",
        "condition",
        "result",
        "code",
        "eid",
    }

    for key, value in event.items():
        if key not in ignored_keys:
            yaml_event[key] = value

    return {
        "event": yaml_event,
    }


def append_yaml_event(path: str, event_obj: dict):
    with open(path, "a", encoding="utf-8") as f:
        f.write("---\n")
        yaml.safe_dump(
            event_obj,
            f,
            sort_keys=False,
            allow_unicode=True,
        )


def read_yaml_stream(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return list(yaml.safe_load_all(f))


def write_yaml_stream(path: str, documents):
    tmp_path = f"{path}.tmp"

    with open(tmp_path, "w", encoding="utf-8") as f:
        for doc in documents:
            if doc is None:
                continue

            f.write("---\n")
            yaml.safe_dump(
                doc,
                f,
                sort_keys=False,
                allow_unicode=True,
            )

        f.flush()
        os.fsync(f.fileno())

    os.replace(tmp_path, path)


def split_header_and_events(documents):
    documents = [doc for doc in documents if doc is not None]

    if not documents:
        return None, []

    header_doc = documents[0]

    event_documents = [
        doc
        for doc in documents[1:]
        if isinstance(doc, dict) and "event" in doc
    ]

    return header_doc, event_documents


def parse_event_timestamp(doc: dict):
    event = doc.get("event", {})

    seq = event.get("_privacy_sequence")
    if seq is not None:
        try:
            return (0, int(seq))
        except Exception:
            pass

    try:
        timestamp = event.get("time:timestamp", "")
        return (1, datetime.fromisoformat(timestamp))
    except Exception:
        return (2, datetime.min)

def instance_id_from_event(event_obj: dict) -> int:
    try:
        return int(event_obj.get("event", {}).get("concept:instance"))
    except Exception:
        return -1

def insert_yaml_event_sorted(path: str, event_obj: dict):
    lock_path = f"{path}.lock"

    with open(lock_path, "w", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)

        if os.path.exists(path) and os.path.getsize(path) > 0:
            documents = read_yaml_stream(path)
            header_doc, event_documents = split_header_and_events(documents)
        else:
            ensure_yaml_header(path, instance_id_from_event(event_obj))
            documents = read_yaml_stream(path)
            header_doc, event_documents = split_header_and_events(documents)

        event_documents.append(event_obj)
        event_documents.sort(key=parse_event_timestamp)

        output_documents = []
        if header_doc is not None:
            output_documents.append(header_doc)

        output_documents.extend(event_documents)
        write_yaml_stream(path, output_documents)

        fcntl.flock(lock_file, fcntl.LOCK_UN)