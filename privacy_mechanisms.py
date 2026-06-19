import random
import fcntl
import re
from datetime import datetime, timedelta

from config import (
    TIMESHIFT_MIN_SECONDS,
    TIMESHIFT_MAX_SECONDS,
    DURATION_SHIFT_MIN_SECONDS,
    DURATION_SHIFT_MAX_SECONDS,
)
from policy import load_json_file, save_json_file
from paths import (
    endpoint_mapping_path,
    label_mapping_path,
    data_mapping_path,
    timeshift_mapping_path,
    duration_shift_mapping_path,
    loop_distribution_mapping_path,
    loop_distribution_log_path,
    loop_distribution_lock_path,
    sequence_mapping_path,
)
from yaml_log import (
    ensure_named_yaml_header,
    map_to_yaml_event,
    append_yaml_event,
)

def load_mapping(path: str) -> dict:
    obj = load_json_file(path)
    return obj if isinstance(obj, dict) else {}


def save_mapping(path: str, mapping: dict):
    save_json_file(path, mapping)

def load_sequence_state(instance_id: int) -> dict:
    obj = load_json_file(sequence_mapping_path(instance_id))
    if isinstance(obj, dict):
        return {
            "next_sequence": int(obj.get("next_sequence", 1)),
        }

    return {
        "next_sequence": 1,
    }


def save_sequence_state(instance_id: int, state: dict):
    save_json_file(sequence_mapping_path(instance_id), state)


def assign_privacy_sequence(event: dict, instance_id: int) -> dict:
    event = dict(event)

    if "_privacy_sequence" in event:
        return event

    path = sequence_mapping_path(instance_id)
    lock_path = f"{path}.lock"

    with open(lock_path, "w", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)

        state = load_sequence_state(instance_id)
        sequence = int(state.get("next_sequence", 1))

        event["_privacy_sequence"] = sequence

        state["next_sequence"] = sequence + 1
        save_sequence_state(instance_id, state)

        fcntl.flock(lock_file, fcntl.LOCK_UN)

    return event

def get_event_activity_id(event: dict) -> str:
    return (
        event.get("activity")
        or event.get("id")
        or event.get("eid")
        or event.get("id:id")
        or event.get("cpee:activity")
        or ""
    )


def normalize_event_lifecycle(event: dict) -> str:
    lifecycle = str(event.get("lifecycle", "")).strip().lower()

    if lifecycle in {"start", "calling", "activity/calling"}:
        return "calling"

    if lifecycle in {"complete", "done", "activity/done"}:
        return "done"

    if lifecycle in {"decide", "gateway/decide"}:
        return "decide"
    
    if lifecycle in {"change", "dataelements/change"}:
        return "change"
    
    return lifecycle


def pseudonymize_value(original_value: str, path: str, prefix: str) -> str:
    if original_value is None or original_value == "":
        return original_value

    original_value = str(original_value)
    mapping = load_mapping(path)

    if original_value in mapping:
        return mapping[original_value]

    pseudonym = f"{prefix}_{len(mapping) + 1:04d}"
    mapping[original_value] = pseudonym
    save_mapping(path, mapping)
    return pseudonym


def pseudonymize_endpoint(endpoint: str, instance_id: int) -> str:
    return pseudonymize_value(endpoint, endpoint_mapping_path(instance_id), "endpoint")


def pseudonymize_label(label: str, instance_id: int) -> str:
    return pseudonymize_value(label, label_mapping_path(instance_id), "label")


def load_data_mapping(instance_id: int) -> dict:
    obj = load_json_file(data_mapping_path(instance_id))
    if isinstance(obj, dict):
        return {
            "names": dict(obj.get("names", {})),
            "values": dict(obj.get("values", {})),
            "fixed_values": dict(obj.get("fixed_values", {})),
            "fixed_value_originals": dict(obj.get("fixed_value_originals", {})),
        }

    return {
        "names": {},
        "values": {},
        "fixed_values": {},
        "fixed_value_originals": {},
    }


def save_data_mapping(instance_id: int, mapping: dict):
    save_json_file(data_mapping_path(instance_id), mapping)


def get_or_create_pseudonym(mapping: dict, key: str, prefix: str) -> str:
    key = str(key)

    if key in mapping:
        return mapping[key]

    pseudonym = f"{prefix}_{len(mapping) + 1:04d}"
    mapping[key] = pseudonym
    return pseudonym


def get_activity_uuid(event: dict) -> str:
    return (
        event.get("activity_uuid")
        or event.get("activity-uuid")
        or event.get("cpee:activity_uuid")
        or ""
    )


def build_data_context_key(event: dict, original_name: str) -> str:
    activity = get_event_activity_id(event)
    activity_uuid = get_activity_uuid(event)
    timestamp = event.get("timestamp") or event.get("time:timestamp") or ""

    return f"{activity}:{activity_uuid}:{timestamp}:{original_name}"

def build_event_shift_key(event: dict, timestamp: str) -> str:
    activity = get_event_activity_id(event)
    activity_uuid = get_activity_uuid(event)
    lifecycle = normalize_event_lifecycle(event)

    return f"{activity}:{activity_uuid}:{timestamp}:{lifecycle}"

def should_transform_data_name(name: str, config: dict) -> bool:
    if not isinstance(config, dict) or not config.get("enabled", False):
        return False

    if config.get("all", False):
        return True

    return name in set(config.get("names", []))


def transform_nested_data_value(value, event: dict, instance_id: int, config: dict):
    if isinstance(value, dict):
        return transform_data_dict(value, event, instance_id, config)

    if isinstance(value, list):
        return [
            transform_data_item(element, event, instance_id, config)
            if isinstance(element, dict) and "name" in element
            else transform_nested_data_value(element, event, instance_id, config)
            for element in value
        ]

    return value


def transform_data_item(item: dict, event: dict, instance_id: int, config: dict) -> dict:
    if not isinstance(item, dict):
        return item

    original_name = item.get("name")
    if original_name is None:
        return item

    original_name = str(original_name)
    transformed_item = dict(item)

    if "value" in transformed_item:
        transformed_item["value"] = transform_nested_data_value(
            transformed_item.get("value"),
            event,
            instance_id,
            config,
        )

    if not should_transform_data_name(original_name, config):
        return transformed_item

    mapping = load_data_mapping(instance_id)
    fixed_values = dict(config.get("fixed_values", {}))
    mapping["fixed_values"].update(fixed_values)

    if original_name not in fixed_values:
        transformed_item["name"] = get_or_create_pseudonym(
            mapping["names"],
            original_name,
            "data",
        )

    if original_name in fixed_values and "value" in transformed_item:
        context_key = build_data_context_key(event, original_name)
        mapping["fixed_value_originals"][context_key] = transformed_item.get("value")
        transformed_item["value"] = fixed_values[original_name]

    elif "value" in transformed_item and not isinstance(
        transformed_item.get("value"),
        (dict, list),
    ):
        original_value = transformed_item.get("value")
        transformed_item["value"] = get_or_create_pseudonym(
            mapping["values"],
            f"{original_name}:{original_value}",
            "value",
        )

    save_data_mapping(instance_id, mapping)
    return transformed_item


def transform_data_dict(data: dict, event: dict, instance_id: int, config: dict) -> dict:
    if not isinstance(data, dict):
        return data

    mapping = load_data_mapping(instance_id)
    fixed_values = dict(config.get("fixed_values", {}))
    mapping["fixed_values"].update(fixed_values)

    transformed = {}

    for original_name, original_value in data.items():
        original_name_str = str(original_name)

        nested_value = transform_nested_data_value(
            original_value,
            event,
            instance_id,
            config,
        )

        if should_transform_data_name(original_name_str, config):
            if original_name_str in fixed_values:
                context_key = build_data_context_key(event, original_name_str)
                mapping["fixed_value_originals"][context_key] = nested_value
                transformed[original_name_str] = fixed_values[original_name_str]
            else:
                transformed_name = get_or_create_pseudonym(
                    mapping["names"],
                    original_name_str,
                    "data",
                )
                transformed[transformed_name] = get_or_create_pseudonym(
                    mapping["values"],
                    f"{original_name_str}:{nested_value}",
                    "value",
                )
        else:
            transformed[original_name] = nested_value

    save_data_mapping(instance_id, mapping)
    return transformed


def transform_condition_string(text: str, instance_id: int, config: dict) -> str:
    if not isinstance(text, str):
        return text

    mapping = load_data_mapping(instance_id)
    name_mapping = mapping.get("names", {})

    def replace_match(match):
        original_name = match.group(1)

        if re.fullmatch(r"data_\d{4}", original_name):
            return f"data.{original_name}"

        pseudonym = name_mapping.get(original_name)
        if not pseudonym:
            return match.group(0)

        return f"data.{pseudonym}"

    return re.sub(r"\bdata\.([A-Za-z_][A-Za-z0-9_]*)\b", replace_match, text)


def transform_data_elements(event: dict, instance_id: int, config: dict) -> dict:
    if not isinstance(config, dict) or not config.get("enabled", False):
        return event

    event = dict(event)

    if (
        event.get("changed") is not None
        and event.get("values") is not None
        and isinstance(event.get("values"), dict)
    ):
        changed = event.get("changed") or []
        values = event.get("values") or {}

        event["data"] = [
            transform_data_item(
                {"name": name, "value": values.get(name)},
                event,
                instance_id,
                config,
            )
            for name in changed
        ]

        event.pop("changed", None)
        event.pop("values", None)

    elif isinstance(event.get("data"), list):
        event["data"] = [
            transform_data_item(item, event, instance_id, config)
            for item in event["data"]
        ]

    elif isinstance(event.get("data"), dict):
        event["data"] = transform_data_dict(
            event["data"],
            event,
            instance_id,
            config,
        )

    if isinstance(event.get("parameters"), dict):
        parameters = dict(event["parameters"])

        if isinstance(parameters.get("arguments"), list):
            parameters["arguments"] = [
                transform_data_item(item, event, instance_id, config)
                for item in parameters["arguments"]
            ]

        event["parameters"] = parameters

    if isinstance(event.get("code"), str):
        event["code"] = transform_condition_string(event["code"], instance_id, config)

    if isinstance(event.get("condition"), str):
        event["condition"] = transform_condition_string(
            event["condition"],
            instance_id,
            config,
        )

    return event


def shift_timestamp_by_seconds(timestamp_str: str, shift_seconds: int) -> str:
    if not timestamp_str:
        return timestamp_str

    try:
        dt = datetime.fromisoformat(timestamp_str)
    except Exception:
        return timestamp_str

    return (dt + timedelta(seconds=shift_seconds)).isoformat()


def normalize_range_config(config: dict, default_min: int, default_max: int) -> dict:
    if not isinstance(config, dict):
        config = {}

    min_seconds = int(config.get("min_seconds", default_min))
    max_seconds = int(config.get("max_seconds", default_max))

    if min_seconds > max_seconds:
        min_seconds, max_seconds = max_seconds, min_seconds

    return {
        "min_seconds": min_seconds,
        "max_seconds": max_seconds,
    }


def load_timeshift_seconds(instance_id: int):
    obj = load_json_file(timeshift_mapping_path(instance_id))
    if isinstance(obj, dict) and "shift_seconds" in obj:
        try:
            return int(obj["shift_seconds"])
        except Exception:
            return None

    return None


def save_timeshift_seconds(instance_id: int, shift_seconds: int, config: dict):
    save_json_file(
        timeshift_mapping_path(instance_id),
        {
            "shift_seconds": int(shift_seconds),
            "config": config,
        },
    )


def get_or_create_timeshift_seconds(instance_id: int, timeshift_config: dict = None) -> int:
    existing = load_timeshift_seconds(instance_id)
    if existing is not None:
        return existing

    config = normalize_range_config(
        timeshift_config,
        TIMESHIFT_MIN_SECONDS,
        TIMESHIFT_MAX_SECONDS,
    )

    shift_seconds = 0
    while shift_seconds == 0:
        shift_seconds = random.randint(config["min_seconds"], config["max_seconds"])

    save_timeshift_seconds(instance_id, shift_seconds, config)
    return shift_seconds


def apply_timeshift(timestamp_str: str, instance_id: int, timeshift_config: dict = None) -> str:
    shift_seconds = get_or_create_timeshift_seconds(instance_id, timeshift_config)
    return shift_timestamp_by_seconds(timestamp_str, shift_seconds)


def load_duration_shift_state(instance_id: int) -> dict:
    obj = load_json_file(duration_shift_mapping_path(instance_id))
    if isinstance(obj, dict):
        return {
            "cumulative_shift_seconds": int(obj.get("cumulative_shift_seconds", 0)),
            "activity_duration_shifts": dict(obj.get("activity_duration_shifts", {})),
            "activity_duration_shift_configs": dict(obj.get("activity_duration_shift_configs", {})),
            # shift_points: list of [calling_timestamp, shift_seconds] for each shifted
            # activity execution. shift_point_keys deduplicates re-delivered callings.
            "shift_points": list(obj.get("shift_points", [])),
            "shift_point_keys": list(obj.get("shift_point_keys", [])),
            "event_applied_shifts": dict(obj.get("event_applied_shifts", {})),
        }

    return {
        "cumulative_shift_seconds": 0,
        "activity_duration_shifts": {},
        "activity_duration_shift_configs": {},
        "shift_points": [],
        "shift_point_keys": [],
        "event_applied_shifts": {},
    }


def save_duration_shift_state(instance_id: int, state: dict):
    save_json_file(duration_shift_mapping_path(instance_id), state)


def get_or_create_activity_duration_shift(
    activity: str,
    state: dict,
    duration_config: dict = None,
) -> int:
    shifts = state["activity_duration_shifts"]

    if activity in shifts:
        return int(shifts[activity])

    config = normalize_range_config(
        duration_config,
        DURATION_SHIFT_MIN_SECONDS,
        DURATION_SHIFT_MAX_SECONDS,
    )

    shift_seconds = random.randint(config["min_seconds"], config["max_seconds"])

    shifts[activity] = int(shift_seconds)
    state["activity_duration_shift_configs"][activity] = config

    return shift_seconds


def sum_shift_points_before(shift_points: list, timestamp_str: str) -> int:
    """Sum the shift seconds of all shift points strictly earlier than timestamp_str.

    A shift point is [calling_timestamp, shift_seconds]. Using a strict "<" means a
    duration-shifted activity's own calling does not receive its own shift, while its
    done (and every later event) does. Comparison is on the post-timeshift timestamps,
    which is order-independent and therefore robust to event-arrival jitter.
    """
    try:
        reference = datetime.fromisoformat(timestamp_str)
    except (TypeError, ValueError):
        return 0

    total = 0
    for point_timestamp, shift_seconds in shift_points:
        try:
            if datetime.fromisoformat(point_timestamp) < reference:
                total += int(shift_seconds)
        except (TypeError, ValueError):
            continue
    return total


def apply_duration_shift(
    timestamp_str: str,
    event: dict,
    instance_id: int,
    duration_shift_ids: set,
    duration_shift_configs: dict = None,
) -> str:
    lock_path = f"{duration_shift_mapping_path(instance_id)}.lock"

    with open(lock_path, "w", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)

        state = load_duration_shift_state(instance_id)

        activity = get_event_activity_id(event)
        lifecycle = normalize_event_lifecycle(event)

        duration_shift_configs = duration_shift_configs or {}
        duration_config = duration_shift_configs.get(activity, {})

        # Register a "shift point" at the CALLING of a duration-shifted activity:
        # (calling timestamp, shift seconds). The shift then applies to every event
        # whose timestamp is strictly LATER than this calling — i.e. the activity's own
        # done and all subsequent events — and never to the calling itself or anything
        # before it.
        #
        # The applied shift per event is computed by TIMESTAMP COMPARISON against these
        # points, NOT by a running counter advanced in processing order. This makes the
        # result independent of event-arrival jitter: CPEE delivers near-simultaneous
        # boundary events (one activity's done vs the next activity's calling, ~1 ms
        # apart) in either order, and any order-dependent counter mis-assigns the shift
        # at those boundaries. A timestamp comparison is correct regardless of order,
        # because each shift point is keyed by its own (post-timeshift) timestamp.
        shift_points = state["shift_points"]
        if activity in duration_shift_ids and lifecycle == "calling":
            shift = get_or_create_activity_duration_shift(activity, state, duration_config)
            point_key = f"{activity}:{get_activity_uuid(event)}:{timestamp_str}"
            if point_key not in state["shift_point_keys"]:
                shift_points.append([timestamp_str, int(shift)])
                state["shift_point_keys"].append(point_key)

        applied_shift_for_event = sum_shift_points_before(shift_points, timestamp_str)
        shifted_timestamp = shift_timestamp_by_seconds(timestamp_str, applied_shift_for_event)

        # informational total (no longer used as a running counter)
        state["cumulative_shift_seconds"] = sum(int(s) for _, s in shift_points)

        event_key = build_event_shift_key(event, shifted_timestamp)
        state["event_applied_shifts"][event_key] = int(applied_shift_for_event)

        save_duration_shift_state(instance_id, state)

        fcntl.flock(lock_file, fcntl.LOCK_UN)

    return shifted_timestamp


def load_loop_distribution_mapping(instance_id: int) -> dict:
    obj = load_json_file(loop_distribution_mapping_path(instance_id))
    if isinstance(obj, dict):
        return {
            "loops": dict(obj.get("loops", {})),
            "activity_to_loop": dict(obj.get("activity_to_loop", {})),
        }

    return {
        "loops": {},
        "activity_to_loop": {},
    }


def save_loop_distribution_mapping(instance_id: int, mapping: dict):
    save_json_file(loop_distribution_mapping_path(instance_id), mapping)


def get_or_create_loop_distribution_state(
    instance_id: int,
    loop_id: str,
    loop_info: dict,
) -> dict:
    mapping = load_loop_distribution_mapping(instance_id)
    loops = mapping.get("loops", {})
    activity_to_loop = mapping.get("activity_to_loop", {})

    if loop_id not in loops:
        segments = list(loop_info.get("segments", []))

        loops[loop_id] = {
            "loop_id": loop_id,
            "activity_ids": list(loop_info.get("activity_ids", [])),
            "first_activity": loop_info.get("first_activity"),
            "first_activity_trigger_lifecycle": loop_info.get(
                "first_activity_trigger_lifecycle",
                "calling",
            ),
            "segments": segments,
            "current_iteration": 0,
            "current_part": 1,
            "active_iteration_events": [],
            "pending_iteration_events": [],
            "last_activity_uuid_to_part": {},
            "part_logs": {
                str(index + 1): loop_distribution_log_path(instance_id, index + 1)
                for index in range(len(segments))
            },
        }

        for act_id in loop_info.get("activity_ids", []):
            activity_to_loop[act_id] = loop_id

        mapping["loops"] = loops
        mapping["activity_to_loop"] = activity_to_loop
        save_loop_distribution_mapping(instance_id, mapping)

    state = loops[loop_id]
    state.setdefault("active_iteration_events", [])
    state.setdefault("pending_iteration_events", [])
    state.setdefault("last_activity_uuid_to_part", {})
    return state


def should_start_new_distribution_iteration(event: dict, distribution_state: dict) -> bool:
    activity = get_event_activity_id(event)
    lifecycle = normalize_event_lifecycle(event)

    trigger_lifecycle = str(
        distribution_state.get("first_activity_trigger_lifecycle", "calling")
    ).strip().lower()

    return (
        activity == distribution_state.get("first_activity")
        and lifecycle == trigger_lifecycle
    )


def should_end_distribution_iteration(event: dict, distribution_state: dict) -> bool:
    activity_ids = list(distribution_state.get("activity_ids", []))
    if not activity_ids:
        return False

    last_activity = activity_ids[-1]
    activity = get_event_activity_id(event)
    lifecycle = normalize_event_lifecycle(event)

    return activity == last_activity and lifecycle == "done"

def is_last_loop_activity(event: dict, distribution_state: dict) -> bool:
    activity_ids = list(distribution_state.get("activity_ids", []))
    if not activity_ids:
        return False

    return get_event_activity_id(event) == activity_ids[-1]


def get_loop_event_id(event: dict) -> str:
    return (
        event.get("eid")
        or event.get("id")
        or event.get("id:id")
        or event.get("cpee:activity")
        or ""
    )


def is_loop_decision_event(event: dict, loop_id: str) -> bool:
    lifecycle = normalize_event_lifecycle(event)
    cpee_lifecycle = str(event.get("cpee:lifecycle:transition", "")).strip().lower()

    return (
        get_loop_event_id(event) == loop_id
        and (
            lifecycle == "decide"
            or cpee_lifecycle == "gateway/decide"
            or "result" in event
        )
    )


def is_terminal_loop_decision(event: dict, loop_id: str) -> bool:
    if not is_loop_decision_event(event, loop_id):
        return False

    result = event.get("result")

    if result is None and "condition" in event and not isinstance(event.get("condition"), str):
        result = event.get("condition")

    if isinstance(result, str):
        return result.strip().lower() == "false"

    return result is False


def get_distribution_part_for_iteration(iteration: int, segments: list) -> int:
    if iteration <= 0:
        return 1

    upper_bound = 0

    for index, segment in enumerate(segments, start=1):
        if segment == "*":
            return index

        try:
            segment_size = int(segment)
        except Exception:
            continue

        upper_bound += segment_size

        if iteration <= upper_bound:
            return index

    return len(segments) if segments else 1


def build_distribution_transform_config(base_config: dict, part_index: int) -> dict:
    config = dict(base_config or {})

    fixed_value_lists = dict(config.get("fixed_value_lists", {}))
    fixed_values = dict(config.get("fixed_values", {}))

    for name, values in fixed_value_lists.items():
        if not isinstance(values, list) or not values:
            continue

        value_index = min(part_index - 1, len(values) - 1)
        fixed_values[name] = values[value_index]

    config["fixed_values"] = fixed_values
    return config

def write_distribution_events(
    events: list,
    instance_id: int,
    part_index: int,
    policies: dict,
):
    if not events:
        return

    transform_config = build_distribution_transform_config(
        policies.get("transform_data_config", {}),
        part_index,
    )

    public_path = loop_distribution_log_path(instance_id, part_index)

    ensure_named_yaml_header(
        public_path,
        instance_id,
        f"loop_distribution_part_{part_index:04d}",
    )

    for event in events:
        transformed_event = transform_data_elements(
            event,
            instance_id,
            transform_config,
        )

        yaml_event = map_to_yaml_event(transformed_event, instance_id)
        append_yaml_event(public_path, yaml_event)

def find_loop_id_for_event(event: dict, policies: dict):
    activity_to_loop = policies.get("loop_distribution_activity_to_loop", {})
    loop_infos = policies.get("loop_distribution_loop_info", {})

    activity = get_event_activity_id(event)
    loop_id = activity_to_loop.get(activity)

    if loop_id is not None:
        return loop_id

    event_id = get_loop_event_id(event)

    for candidate_loop_id in loop_infos:
        if event_id == candidate_loop_id:
            return candidate_loop_id

    return None


def handle_loop_distribution_if_needed(event: dict, instance_id: int, policies: dict) -> bool:
    loop_id = find_loop_id_for_event(event, policies)

    if loop_id is None:
        return False

    loop_infos = policies.get("loop_distribution_loop_info", {})
    loop_info = loop_infos.get(loop_id, {})
    lock_path = loop_distribution_lock_path(instance_id)

    with open(lock_path, "w", encoding="utf-8") as lock_file:
        fcntl.flock(lock_file, fcntl.LOCK_EX)

        distribution_state = get_or_create_loop_distribution_state(
            instance_id,
            loop_id,
            loop_info,
        )

        distribution_state.setdefault("active_iteration_events", [])
        distribution_state.setdefault("pending_iteration_events", [])
        distribution_state.setdefault("last_activity_uuid_to_part", {})

        lifecycle = normalize_event_lifecycle(event)
        activity_uuid = get_activity_uuid(event)

        starts_new_iteration = should_start_new_distribution_iteration(
            event,
            distribution_state,
        )

        if starts_new_iteration:
            if distribution_state.get("active_iteration_events"):
                previous_part = int(distribution_state.get("current_part", 1))

                write_distribution_events(
                    distribution_state.get("active_iteration_events", []),
                    instance_id,
                    previous_part,
                    policies,
                )

                distribution_state["active_iteration_events"] = []

            distribution_state["current_iteration"] = (
                int(distribution_state.get("current_iteration", 0)) + 1
            )

            distribution_state["current_part"] = get_distribution_part_for_iteration(
                int(distribution_state["current_iteration"]),
                distribution_state.get("segments", []),
            )

            distribution_state["active_iteration_events"] = (
                distribution_state.get("pending_iteration_events", []) + [event]
            )
            distribution_state["pending_iteration_events"] = []

        elif distribution_state.get("active_iteration_events"):
            distribution_state["active_iteration_events"].append(event)

        elif (
            is_last_loop_activity(event, distribution_state)
            and lifecycle == "done"
            and activity_uuid
            and activity_uuid in distribution_state.get("last_activity_uuid_to_part", {})
        ):
            target_part = int(
                distribution_state["last_activity_uuid_to_part"].pop(activity_uuid)
            )

            write_distribution_events(
                [event],
                instance_id,
                target_part,
                policies,
            )

        else:
            distribution_state["pending_iteration_events"].append(event)

        current_part = int(distribution_state.get("current_part", 1))

        if (
            is_last_loop_activity(event, distribution_state)
            and lifecycle != "done"
            and activity_uuid
        ):
            distribution_state["last_activity_uuid_to_part"][activity_uuid] = current_part

        if is_terminal_loop_decision(event, loop_id):
            if distribution_state.get("active_iteration_events"):
                write_distribution_events(
                    distribution_state.get("active_iteration_events", []),
                    instance_id,
                    current_part,
                    policies,
                )
                distribution_state["active_iteration_events"] = []

            if distribution_state.get("pending_iteration_events"):
                write_distribution_events(
                    distribution_state.get("pending_iteration_events", []),
                    instance_id,
                    current_part,
                    policies,
                )
                distribution_state["pending_iteration_events"] = []

        mapping = load_loop_distribution_mapping(instance_id)
        mapping["loops"][loop_id] = distribution_state
        save_loop_distribution_mapping(instance_id, mapping)

        fcntl.flock(lock_file, fcntl.LOCK_UN)

    return True