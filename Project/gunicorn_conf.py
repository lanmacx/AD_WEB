from __future__ import print_function

from pathlib import Path
import json
import math
import multiprocessing
import os


def get_cpu_quota_within_docker():
    """ Ref. https://gitlab.com/amchambrasil/amcham.restapi/-/issues/181 """
    cpu_cores = None

    cfs_period = Path("/sys/fs/cgroup/cpu/cpu.cfs_period_us")
    cfs_quota = Path("/sys/fs/cgroup/cpu/cpu.cfs_quota_us")

    if cfs_period.exists() and cfs_quota.exists():
        # We are in a linux container with cpu quotas!
        with cfs_period.open("rb") as p, cfs_quota.open("rb") as q:
            p, q = int(p.read()), int(q.read())

            # get the cores allocated by dividing the quote
            # in microseconds by the period in microseconds
            cpu_cores = math.ceil(q / p) if q > 0 and p > 0 else None
    return cpu_cores


bind_host = os.getenv("HOST", "0.0.0.0")
bind_port = os.getenv("PORT", "3000")

docker_cpus = get_cpu_quota_within_docker()
cores = os.getenv("AVAILABLE_CORES", multiprocessing.cpu_count())

workers = docker_cpus if docker_cpus else cores
worker_class = 'gevent'
worker_tmp_dir = '/dev/shm'
log_level = os.getenv("LOG_LEVEL", "info")
keep_alive = os.getenv("SESSION_LIFETIME", 120)
timeout = 120
forwarded_allow_ips = '*'
secure_scheme_headers = {'X-FORWARDED-PROTO': 'https'}
bind = '0.0.0.0:5000'

# For debugging and testing
log_data = {
    "loglevel": log_level,
    "workers": workers,
    "bind": "{}:{}".format(bind_host, bind_port),
}
print(json.dumps(log_data))