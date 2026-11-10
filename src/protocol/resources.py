"""Conservative capacity gates, separate from actual process measurements."""
from __future__ import annotations

import platform
import re
import shutil
import subprocess
from src.config import ROOT

GiB = 1024**3


class ResourceBlocked(RuntimeError):
    pass


def available_memory():
    if platform.system() == 'Linux':
        with open('/proc/meminfo') as stream:
            values = dict(line.split(':', 1) for line in stream)
        return int(values['MemAvailable'].split()[0]) * 1024
    if platform.system() == 'Darwin':
        text = subprocess.check_output(['vm_stat'], text=True)
        page = int(re.search(r'page size of (\d+) bytes', text).group(1))
        counts = {name: int(value) for name, value in
                  re.findall(r'^([^:\n]+):\s+(\d+)\.', text, re.M)}
        return sum(counts.get(key, 0) for key in
                   ['Pages free', 'Pages inactive', 'Pages speculative']) * page
    return None


def capacity(cfg, phase, stage='a'):
    large = cfg['id'] == 's3' and stage == 'a'
    medium_setup = cfg['id'] == 's2' and stage == 'a' and phase == 'setup'
    small_setup = cfg['id'] == 's1' and stage == 'a' and phase == 'setup'
    minimum = (8 if phase == 'compile' else 16) if large else (8 if medium_setup else 4 if small_setup else 1)
    if phase == 'artifact_verify' and stage == 'a' and not large:
        minimum = 2.5 if cfg['id'] == 's1' else 10
    memory = available_memory()
    disk = shutil.disk_usage(ROOT).free
    disk_minimum = 35 if large and phase == 'setup' else 4
    return dict(status='PASS' if memory is not None and memory >= minimum * GiB
                and disk >= disk_minimum * GiB else 'RESOURCE BLOCKED',
                phase=phase, configuration=cfg['id'], stage=stage.upper(),
                memory_available_bytes=memory, disk_free_bytes=disk,
                minimum_memory_policy_bytes=int(minimum * GiB),
                minimum_disk_policy_bytes=disk_minimum * GiB,
                policy_is_estimate=True)


def require_capacity(cfg, phase, stage='a'):
    result = capacity(cfg, phase, stage)
    if result['status'] != 'PASS':
        raise ResourceBlocked(str(result))
    return result
