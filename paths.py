import os
from config import BASE_DIR


def instance_dir_path(instance_id: int) -> str:
    return os.path.join(BASE_DIR, str(instance_id))


def ensure_instance_dir(instance_id: int):
    path = instance_dir_path(instance_id)
    os.makedirs(path, exist_ok=True)

    # ensure shared write access on server
    try:
        os.chmod(path, 0o777)
    except Exception:
        pass

def cache_path(instance_id: int) -> str:
    return os.path.join(instance_dir_path(instance_id), f"cpee_model_properties_{instance_id}_cache.json")


def logfile_path(instance_id: int) -> str:
    return os.path.join(instance_dir_path(instance_id), f"cpee_filtered_events_{instance_id}.xes.yaml")


def reversed_logfile_path(instance_id: int) -> str:
    return os.path.join(instance_dir_path(instance_id), f"cpee_reversed_events_{instance_id}.xes.yaml")


def endpoint_mapping_path(instance_id: int) -> str:
    return os.path.join(instance_dir_path(instance_id), f"cpee_endpoint_mapping_{instance_id}.json")


def label_mapping_path(instance_id: int) -> str:
    return os.path.join(instance_dir_path(instance_id), f"cpee_label_mapping_{instance_id}.json")


def data_mapping_path(instance_id: int) -> str:
    return os.path.join(instance_dir_path(instance_id), f"cpee_data_mapping_{instance_id}.json")


def timeshift_mapping_path(instance_id: int) -> str:
    return os.path.join(instance_dir_path(instance_id), f"cpee_timeshift_mapping_{instance_id}.json")


def duration_shift_mapping_path(instance_id: int) -> str:
    return os.path.join(instance_dir_path(instance_id), f"cpee_duration_shift_mapping_{instance_id}.json")


def loop_distribution_mapping_path(instance_id: int) -> str:
    return os.path.join(instance_dir_path(instance_id), f"cpee_loop_distribution_mapping_{instance_id}.json")

def loop_distribution_log_path(instance_id: int, part_index: int) -> str:
    return os.path.join(instance_dir_path(instance_id), f"cpee_loop_distribution_events_{instance_id}_part_{part_index:04d}.xes.yaml")

def sequence_mapping_path(instance_id: int) -> str:
    return os.path.join(instance_dir_path(instance_id), f"cpee_sequence_mapping_{instance_id}.json")

def loop_distribution_lock_path(instance_id: int) -> str:
    return os.path.join(instance_dir_path(instance_id), f"cpee_loop_distribution_lock_{instance_id}.lock")