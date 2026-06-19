import json
import time
import xml.etree.ElementTree as ET
from urllib.request import urlopen, Request

from config import (
    CACHE_TTL_SECONDS,
    PROPERTIES_URL_TEMPLATE,
    TIMESHIFT_MIN_SECONDS,
    TIMESHIFT_MAX_SECONDS,
    DURATION_SHIFT_MIN_SECONDS,
    DURATION_SHIFT_MAX_SECONDS,
)
from paths import cache_path


def truthy(text) -> bool:
    if text is None:
        return False
    return str(text).strip().lower() in {"true", "1", "yes", "y"}


def enabled_annotation(el) -> bool:
    if el is None:
        return False
    if el.text is None or str(el.text).strip() == "":
        return True
    return truthy(el.text)


def annotation_value(el):
    if el is None:
        return None

    if el.text is None or str(el.text).strip() == "":
        return True

    text = str(el.text).strip()
    lowered = text.lower()

    if lowered in {"true", "1", "yes", "y"}:
        return True

    if lowered in {"false", "0", "no", "n"}:
        return False

    return text


def parse_int_list(value, expected_len: int):
    if value is None or value is True or value is False:
        return None

    parts = [p.strip() for p in str(value).split(",")]
    if len(parts) != expected_len:
        return None

    try:
        return [int(p) for p in parts]
    except Exception:
        return None


def parse_range_config(value, default_min: int, default_max: int) -> dict:
    config = {
        "enabled": value not in {None, False},
        "min_seconds": default_min,
        "max_seconds": default_max,
    }

    if value is None or value is False:
        return config

    if value is True:
        return config

    try:
        seconds = int(str(value).strip())
        config["enabled"] = True
        config["min_seconds"] = seconds
        config["max_seconds"] = seconds
        return config
    except Exception:
        pass

    parsed = parse_int_list(value, 2)
    if parsed is not None:
        config["enabled"] = True
        config["min_seconds"] = parsed[0]
        config["max_seconds"] = parsed[1]

    return config


def parse_loop_distribution_config(value) -> dict:
    config = {
        "enabled": False,
        "segments": [],
    }

    if value in {None, False, True}:
        return config

    parts = [p.strip() for p in str(value).split(",") if p.strip()]
    if not parts:
        return config

    # "*" assigns all remaining iterations.
    if parts[-1] != "*":
        return config

    segments = []

    for part in parts:
        if part == "*":
            segments.append("*")
            continue

        try:
            number = int(part)
        except Exception:
            return config

        if number <= 0:
            return config

        segments.append(number)

    config["enabled"] = True
    config["segments"] = segments

    return config


def parse_transform_data_config(value) -> dict:
    config = {
        "enabled": value not in {None, False},
        "all": False,
        "names": set(),
        "fixed_values": {},
        "fixed_value_lists": {},
    }

    if value is True:
        config["enabled"] = True
        config["all"] = True
        return config

    if value in {None, False}:
        return config

    tokens = [p.strip() for p in str(value).split(",") if p.strip()]
    current_fixed_name = None

    for token in tokens:
        if "=" in token:
            name, fixed_value = token.split("=", 1)
            name = name.strip()
            fixed_value = fixed_value.strip()

            if not name:
                current_fixed_name = None
                continue

            config["names"].add(name)
            config["fixed_values"][name] = fixed_value
            config["fixed_value_lists"][name] = [fixed_value]
            current_fixed_name = name

        else:
            # Enables syntax like transform_data=amount=444,666,999.
            if current_fixed_name is not None:
                config["fixed_value_lists"][current_fixed_name].append(token)
            else:
                config["names"].add(token)

    if tokens:
        config["enabled"] = True

    return config


def local_name(el) -> str:
    tag = str(el.tag)
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def load_json_file(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None


def save_json_file(path: str, obj):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"Could not save JSON file {path}: {e}")


def normalize_transform_data_config(config: dict) -> dict:
    config = dict(config or {})
    config["names"] = set(config.get("names", []))
    config["fixed_values"] = dict(config.get("fixed_values", {}))
    config["fixed_value_lists"] = dict(config.get("fixed_value_lists", {}))
    return config


def serializable_transform_data_config(config: dict) -> dict:
    config = dict(config or {})
    config["names"] = sorted(config.get("names", []))
    config["fixed_values"] = dict(config.get("fixed_values", {}))
    config["fixed_value_lists"] = dict(config.get("fixed_value_lists", {}))
    return config

def merge_transform_data_configs(base: dict, addition: dict) -> dict:
    base = dict(base or {})
    addition = dict(addition or {})

    base["enabled"] = bool(base.get("enabled", False) or addition.get("enabled", False))
    base["all"] = bool(base.get("all", False) or addition.get("all", False))

    base["names"] = set(base.get("names", set()))
    base["names"].update(addition.get("names", set()))

    base["fixed_values"] = dict(base.get("fixed_values", {}))
    base["fixed_values"].update(addition.get("fixed_values", {}))

    base["fixed_value_lists"] = dict(base.get("fixed_value_lists", {}))
    base["fixed_value_lists"].update(addition.get("fixed_value_lists", {}))

    return base

def load_cached_policies(instance_id: int):
    obj = load_json_file(cache_path(instance_id))
    if not isinstance(obj, dict):
        return None

    try:
        ts = float(obj.get("ts", 0))
        if (time.time() - ts) > CACHE_TTL_SECONDS:
            return None

        transform_data_config = normalize_transform_data_config(
            obj.get("transform_data_config", {})
        )

        return {
            "no_log_ids": set(obj.get("no_log_ids", [])),
            "transform_endpoint_ids": set(obj.get("transform_endpoint_ids", [])),
            "transform_endpoint_global": bool(obj.get("transform_endpoint_global", False)),
            "transform_label_ids": set(obj.get("transform_label_ids", [])),
            "transform_label_global": bool(obj.get("transform_label_global", False)),
            "transform_data_global": bool(obj.get("transform_data_global", False)),
            "transform_data_config": transform_data_config,
            "timeshift_global": bool(obj.get("timeshift_global", False)),
            "timeshift_config": dict(obj.get("timeshift_config", {})),
            "duration_shift_ids": set(obj.get("duration_shift_ids", [])),
            "duration_shift_configs": dict(obj.get("duration_shift_configs", {})),
            "loop_distribution_activity_to_loop": dict(obj.get("loop_distribution_activity_to_loop", {})),
            "loop_distribution_loop_info": dict(obj.get("loop_distribution_loop_info", {})),
        }

    except Exception as e:
        print(f"Could not load cached policies for instance {instance_id}: {e}")
        return None


def save_cached_policies(instance_id: int, policies: dict):
    obj = dict(policies)
    obj["ts"] = time.time()

    for key in [
        "no_log_ids",
        "transform_endpoint_ids",
        "transform_label_ids",
        "duration_shift_ids",
    ]:
        obj[key] = sorted(obj.get(key, []))

    obj["transform_data_config"] = serializable_transform_data_config(
        obj.get("transform_data_config", {})
    )

    save_json_file(cache_path(instance_id), obj)


def fetch_properties_xml(instance_id: int) -> str:
    url = PROPERTIES_URL_TEMPLATE.format(id=instance_id)
    req = Request(url, headers={"Accept": "application/xml"})
    with urlopen(req, timeout=10) as r:
        return r.read().decode("utf-8", errors="replace")


def default_policies() -> dict:
    return {
        "no_log_ids": set(),
        "transform_endpoint_ids": set(),
        "transform_endpoint_global": False,
        "transform_label_ids": set(),
        "transform_label_global": False,
        "transform_data_global": False,
        "transform_data_config": {
            "enabled": False,
            "all": False,
            "names": set(),
            "fixed_values": {},
            "fixed_value_lists": {},
        },
        "timeshift_global": False,
        "timeshift_config": {
            "enabled": False,
            "min_seconds": TIMESHIFT_MIN_SECONDS,
            "max_seconds": TIMESHIFT_MAX_SECONDS,
        },
        "duration_shift_ids": set(),
        "duration_shift_configs": {},
        "loop_distribution_activity_to_loop": {},
        "loop_distribution_loop_info": {},
    }


def parse_policies(properties_xml: str) -> dict:
    policies = default_policies()
    root = ET.fromstring(properties_xml)

    generic_root = root.find(".//{*}dslx/{*}description/{*}_generic")

    if generic_root is not None:
        transform_endpoint_el = generic_root.find("./{*}transform_endpoint")
        if enabled_annotation(transform_endpoint_el):
            policies["transform_endpoint_global"] = True

        transform_label_el = generic_root.find("./{*}transform_label")
        if enabled_annotation(transform_label_el):
            policies["transform_label_global"] = True

        transform_data_config = policies["transform_data_config"]

        for transform_data_el in generic_root.findall("./{*}transform_data"):
            transform_data_value = annotation_value(transform_data_el)
            parsed_config = parse_transform_data_config(transform_data_value)
            transform_data_config = merge_transform_data_configs(
                transform_data_config,
                parsed_config,
            )

        if transform_data_config["enabled"]:
            policies["transform_data_global"] = True
            policies["transform_data_config"] = transform_data_config

        timeshift_el = generic_root.find("./{*}timeshift")
        timeshift_value = annotation_value(timeshift_el)
        timeshift_config = parse_range_config(
            timeshift_value,
            TIMESHIFT_MIN_SECONDS,
            TIMESHIFT_MAX_SECONDS,
        )

        if timeshift_config["enabled"]:
            policies["timeshift_global"] = True
            policies["timeshift_config"] = timeshift_config

    for loop in root.findall(".//{*}dslx//{*}loop"):
        loop_id = loop.get("eid") or loop.get("id")
        if not loop_id:
            continue

        loop_elements = []
        for element in loop.iter():
            if local_name(element) not in {"call", "manipulate"}:
                continue
            if element.get("id"):
                loop_elements.append(element)

        loop_activities = [el.get("id") for el in loop_elements]

        first_activity = None
        first_activity_trigger_lifecycle = "calling"

        if loop_elements:
            first_el = loop_elements[0]
            first_activity = first_el.get("id")
            first_activity_trigger_lifecycle = (
                "calling" if local_name(first_el) == "call" else "done"
            )

        loop_distribution_el = loop.find(
            ".//{*}_annotations/{*}_generic/{*}loop_distribution"
        )
        loop_distribution_value = annotation_value(loop_distribution_el)
        loop_distribution_config = parse_loop_distribution_config(
            loop_distribution_value
        )

        if loop_distribution_config["enabled"]:
            for act_id in loop_activities:
                policies["loop_distribution_activity_to_loop"][act_id] = loop_id

            policies["loop_distribution_loop_info"][loop_id] = {
                "loop_id": loop_id,
                "activity_ids": loop_activities,
                "first_activity": first_activity,
                "first_activity_trigger_lifecycle": first_activity_trigger_lifecycle,
                "segments": loop_distribution_config["segments"],
            }

    for call in root.findall(".//{*}dslx//{*}call"):
        act_id = call.get("id")
        if not act_id:
            continue

        generic = call.find(".//{*}annotations/{*}_generic")
        if generic is None:
            continue

        no_log_el = generic.find("./{*}no_log")
        if enabled_annotation(no_log_el):
            policies["no_log_ids"].add(act_id)

        transform_endpoint_el = generic.find("./{*}transform_endpoint")
        if enabled_annotation(transform_endpoint_el):
            policies["transform_endpoint_ids"].add(act_id)

        transform_label_el = generic.find("./{*}transform_label")
        if enabled_annotation(transform_label_el):
            policies["transform_label_ids"].add(act_id)

        duration_shift_el = generic.find("./{*}duration_shift")
        duration_shift_value = annotation_value(duration_shift_el)
        duration_shift_config = parse_range_config(
            duration_shift_value,
            DURATION_SHIFT_MIN_SECONDS,
            DURATION_SHIFT_MAX_SECONDS,
        )

        if duration_shift_config["enabled"]:
            policies["duration_shift_ids"].add(act_id)
            policies["duration_shift_configs"][act_id] = duration_shift_config

    return policies


def get_policies(instance_id: int) -> dict:
    cached = load_cached_policies(instance_id)
    if cached is not None:
        return cached

    try:
        xml_str = fetch_properties_xml(instance_id)
        policies = parse_policies(xml_str)
        save_cached_policies(instance_id, policies)
        return policies
    except Exception as e:
        print(f"Could not load policies for instance {instance_id}: {e}")
        return default_policies()