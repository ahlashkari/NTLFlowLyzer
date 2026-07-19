#!/usr/bin/env python3

import glob
import json
import os
import subprocess
import sys
import tempfile
import time

from .config_loader import ConfigLoader


def find_pcap_files(directory: str, recursive: bool = False) -> list:
    """Find pcap files under `directory`.

    When `recursive` is False this preserves the tool's original flat-glob
    behavior (single directory, any file). When True, it walks all
    subdirectories and only picks up files with a `.pcap` extension, which
    is required to safely tell pcap files apart from unrelated files (e.g.
    logs, configs) that might live alongside them in nested folders.
    """
    if not recursive:
        return glob.glob(directory + '/*')

    pcap_files = []
    for root, _dirs, files in os.walk(directory):
        for fname in files:
            if fname.lower().endswith('.pcap'):
                pcap_files.append(os.path.join(root, fname))
    return pcap_files


def _output_path_for(pcap_file: str, batch_address: str, batch_address_output: str,
                      recursive: bool) -> str:
    if recursive:
        rel = os.path.relpath(pcap_file, batch_address)
        out = os.path.join(batch_address_output, os.path.splitext(rel)[0] + '.csv')
        os.makedirs(os.path.dirname(out), exist_ok=True)
        return out
    output_file_name = os.path.basename(pcap_file)
    return f"{batch_address_output}/{output_file_name}.csv"


def run_sequential_batch(config: ConfigLoader, pcap_files: list, online_capturing: bool,
                          continues_batch_mode: bool):
    """Original batch behavior: convert every file one after another in this
    same process. Kept as the default (batch_parallel_files=1) so existing
    configs and scripts see no behavior change.
    """
    from .network_flow_analyzer import NTLFlowLyzer

    for pcap_file in pcap_files:
        print(100 * "#")
        config.pcap_file_address = pcap_file
        config.output_file_address = _output_path_for(
            pcap_file, config.batch_address, config.batch_address_output, config.batch_recursive)
        NTLFlowLyzer(config, online_capturing, continues_batch_mode).run()


def run_parallel_batch(config: ConfigLoader, pcap_files: list, online_capturing: bool,
                        continues_batch_mode: bool):
    """Convert several pcap files at the same time.

    A single NTLFlowLyzer run already manages its own internal
    multiprocessing pool (capture + feature-extraction + writer), so
    cross-file parallelism is implemented with one independent OS process
    per pcap file (`python -m NTLFlowLyzer -c <per-file config>`) rather
    than nesting another pool inside a pool worker -- the latter fails on
    platforms (e.g. Windows) where pool workers are daemonic and cannot
    spawn children.

    `batch_ram_limit_percent` throttles how many files get started: once
    system memory usage crosses that threshold, no new file is launched
    until one finishes and frees up memory. This requires `psutil`; if it
    isn't installed, the RAM check is skipped with a warning and only the
    concurrency limit applies.
    """
    try:
        import psutil
    except ImportError:
        psutil = None
        print(">> psutil is not installed, so 'batch_ram_limit_percent' will be ignored. "
              "Install it (`pip install psutil`) to enable RAM-aware throttling.")

    total = len(pcap_files)
    max_concurrent = max(1, int(config.batch_parallel_files))
    print(f">> Running up to {max_concurrent} files concurrently "
          f"(batch_ram_limit_percent={config.batch_ram_limit_percent}).")

    with tempfile.TemporaryDirectory(prefix="ntlflowlyzer_batch_") as tmp_dir:
        pending = list(pcap_files)
        running = []  # list of (Popen, pcap_file)
        done_ok = 0
        done_fail = 0

        def launch(pcap_file, index):
            output_file = _output_path_for(
                pcap_file, config.batch_address, config.batch_address_output, config.batch_recursive)
            per_file_config = {
                "pcap_file_address": pcap_file,
                "output_file_address": output_file,
                "label": config.label,
                "number_of_threads": config.number_of_threads,
                "max_flow_duration": config.max_flow_duration,
                "activity_timeout": config.activity_timeout,
                "floating_point_unit": config.floating_point_unit,
                "features_ignore_list": config.features_ignore_list,
                "feature_extractor_min_flows": config.feature_extractor_min_flows,
                "writer_min_rows": config.writer_min_rows,
                "read_packets_count_value_log_info": config.read_packets_count_value_log_info,
                "check_flows_ending_min_flows": config.check_flows_ending_min_flows,
                "capturer_updating_flows_min_value": config.capturer_updating_flows_min_value,
                "max_rows_number": config.max_rows_number,
            }
            config_path = os.path.join(tmp_dir, f"cfg_{index:06d}.json")
            with open(config_path, "w") as f:
                json.dump(per_file_config, f)
            proc = subprocess.Popen(
                [sys.executable, "-m", "NTLFlowLyzer", "-c", config_path],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            return proc

        index = 0
        while pending or running:
            still_running = []
            for proc, pcap_file in running:
                if proc.poll() is None:
                    still_running.append((proc, pcap_file))
                else:
                    if proc.returncode == 0:
                        done_ok += 1
                    else:
                        done_fail += 1
                        output = proc.stdout.read().decode(errors="replace") if proc.stdout else ""
                        print(f">> [FAILED] {pcap_file} (exit {proc.returncode})")
                        if output.strip():
                            print(output.strip().splitlines()[-1])
            running = still_running

            mem_percent = psutil.virtual_memory().percent if psutil else 0.0
            while pending and len(running) < max_concurrent and mem_percent < config.batch_ram_limit_percent:
                pcap_file = pending.pop(0)
                index += 1
                print(f">> [{index}/{total}] Starting {pcap_file} "
                      f"(running={len(running) + 1}, mem={mem_percent:.0f}%)")
                running.append((launch(pcap_file, index), pcap_file))
                mem_percent = psutil.virtual_memory().percent if psutil else 0.0

            if pending or running:
                time.sleep(2)

        print(f">> Batch finished: {done_ok} succeeded, {done_fail} failed.")


def run_batch(config: ConfigLoader, online_capturing: bool, continues_batch_mode: bool):
    pcap_files = find_pcap_files(config.batch_address, config.batch_recursive)
    print(f">> {len(pcap_files)} number of files detected. Lets go for analyze them!")
    if int(config.batch_parallel_files) <= 1:
        run_sequential_batch(config, pcap_files, online_capturing, continues_batch_mode)
    else:
        run_parallel_batch(config, pcap_files, online_capturing, continues_batch_mode)
