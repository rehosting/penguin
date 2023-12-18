import os
import sys
import glob
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed, ProcessPoolExecutor
from typing import List, Tuple
import threading
import time

NWORKERS = 2


def run_command_with_output(cmd: List[str], stdout_file: str, stderr_file: str) -> Tuple[str, str]:
    with open(stdout_file, "w") as stdout, open(stderr_file, "w") as stderr:
        try:
            subprocess.run(cmd, check=True, stdout=stdout, stderr=stderr)
        except subprocess.CalledProcessError as e:
            with open(stdout_file, "r") as stdout_file, open(stderr_file, "r") as stderr_file:
                return stdout_file.read(), stderr_file.read()
    return None, None


def run_config(base_dir: str, n: int):
    start = time.time()
    print(f"Running config in {base_dir} for the {n}th time")

    conf_yaml = os.path.join(base_dir, "config.yaml")
    new_conf = os.path.join(base_dir, "config.yaml")

    out_dir = os.path.join(base_dir, f"output{n}")
    os.makedirs(out_dir, exist_ok=True)

    cmd = ["/igloo/penguin_run.py", new_conf, base_dir, out_dir]
    stdout_file = os.path.join(out_dir, "qemu_stdout.txt")
    stderr_file = os.path.join(out_dir, "qemu_stderr.txt")

    stdout, stderr = run_command_with_output(cmd, stdout_file, stderr_file)

    ran_file = os.path.join(out_dir, ".ran")
    if not os.path.isfile(ran_file):
        print(f"\nERROR with {conf_yaml}: no .ran file")
        print(f"STDOUT: {stdout}")
        print(f"STDERR: {stderr}")
        return f"ERROR, running {conf_yaml} in {base_dir} did not produce {out_dir}/.ran file"

    end = time.time()
    rv = (f"\tFinished config in {base_dir} for the {n} time in {end - start:.02f} seconds")
    print(rv)
    return rv

# XXX unused
'''
from threading import Semaphore
semaphore = Semaphore(5)
def run_limited_config(current_dir: str, idx: int):

    print(f"Get semaphore for {current_dir} {idx}")
    semaphore.acquire()  # Ensure no more than 5 are running at a time
    print(f"\tGot semaphore for {current_dir} {idx}")

    try:
        run_config(current_dir, idx)
    except Exception as e:
        print(f"Error running config {current_dir}: {e}")
    finally:
        print("Release semaphore for", current_dir, idx)
        semaphore.release()
'''

def run_unique_configs(N: int, base_directory: str):
    configs = glob.glob(f"{base_directory}/**/config.yaml", recursive=True)

    to_run = []
    for config_path in configs:
        current_dir = os.path.dirname(config_path)

        if not os.path.isfile(config_path):
            print(f"Skip {config_path} for all runs: missing config.yaml")
            continue

        for run_idx in range(N):
            out_dir = os.path.join(current_dir, f"output{run_idx}")
            ran_file = os.path.join(out_dir, ".ran")

            if os.path.isdir(out_dir) and os.path.isfile(ran_file):
                print(f"Skip {config_path} run #{run_idx}: Already ran")
                continue

            print(f"Queue up run {run_idx} for {current_dir}")
            to_run.append((current_dir, run_idx))

    # Single threaded
    '''
    for (current_dir, run_idx) in to_run:
        print("Start run")
        start = time.time()
        run_config(current_dir, run_idx)
        end = time.time()
        print(f"Finished {current_dir} {run_idx} in {end - start:.02f} seconds")
    '''

    # Multi threaded
    futures = []
    with ProcessPoolExecutor(max_workers=NWORKERS) as executor:
        for (current_dir, run_idx) in to_run:
            futures.append(executor.submit(run_config, current_dir, run_idx))

        for future in as_completed(futures):
            try:
                print("Result", future.result())
            except Exception as e:
                print("Exception", e)

if __name__ == '__main__':
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <N_reruns> <outdir>")
        sys.exit(1)

    run_unique_configs(int(sys.argv[1]), sys.argv[2])
