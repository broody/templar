"""Measure an isolated M31 benchmark process or browser under process-group limits.

The recorded command must contain no wallet secrets. This runner makes no
privacy qualification; the caller must identify exactly what was measured.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import threading
import time

HERE = Path(__file__).resolve().parent


def save(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--name', required=True)
    parser.add_argument('--cap-gib', type=int, default=2)
    parser.add_argument('--cpu-cores', dest='threads', type=int, choices=[1, 4], default=4)
    parser.add_argument('--scope', required=True)
    parser.add_argument('--prover-workers', type=int, default=1)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    assert args.name.replace('-', '').replace('_', '').isalnum()
    assert args.cap_gib > 0
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    assert command
    binary = Path(command[0]).resolve()
    assert binary.is_file()
    command[0] = str(binary)
    out = HERE / 'results' / args.name
    out.mkdir(exist_ok=False)
    harness_files = ['measure.py']
    harness_hashes = {}
    for relative in harness_files:
        source = HERE / relative
        target = out / 'harness-source' / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        harness_hashes[relative] = hashlib.sha256(source.read_bytes()).hexdigest()
    save(out / 'harness-source.json', harness_hashes)
    unit = 'templar-m31-' + args.name + '-' + str(time.time_ns())
    cores = '0' if args.threads == 1 else '0 1 2 3'
    invocation = [
        'systemd-run', '--user', '--wait', '--pipe', '--unit=' + unit,
        '-p', 'WorkingDirectory=' + str(HERE.parent.parent),
        '-p', f'MemoryMax={args.cap_gib}G', '-p', 'MemorySwapMax=0',
        '-p', f'CPUQuota={args.threads * 100}%', '-p', 'CPUAffinity=' + cores,
        '-p', 'RuntimeMaxSec=1200', '--setenv=RAYON_NUM_THREADS=' + str(args.threads),
        '--setenv=PATH=' + os.environ['PATH'], '/usr/bin/time', '-v', *command,
    ]
    samples = []
    stopped = threading.Event()
    start = time.perf_counter()
    summary = {
        'scope': args.scope, 'command': command,
        'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
        'cap_gib': args.cap_gib, 'cpu_budget_cores': args.threads, 'prover_workers': args.prover_workers, 'cpu_affinity': cores,
        'privacy_qualified_by_measurement': False,
    }
    save(out / 'command.json', {'command': invocation})
    with (out / 'stdout.log').open('w') as log:
        process = subprocess.Popen(invocation, stdout=log, stderr=subprocess.STDOUT)
        cgroup = None
        for _ in range(100):
            result = subprocess.run(
                ['systemctl', '--user', 'show', unit, '-p', 'ControlGroup', '--value'],
                text=True, capture_output=True,
            )
            if result.stdout.strip():
                cgroup = Path('/sys/fs/cgroup') / result.stdout.strip().lstrip('/')
                effective = {}
                for name in ['memory.max', 'memory.swap.max', 'cpu.max']:
                    try:
                        effective[name] = (cgroup / name).read_text().strip()
                    except OSError:
                        pass
                save(out / 'cgroup-start.json', effective)
                break
            if process.poll() is not None:
                break
            time.sleep(.02)

        def sample():
            while not stopped.is_set():
                row = {'unix_ms': time.time_ns() // 1_000_000}
                if cgroup is not None:
                    for name in ['memory.peak', 'memory.current', 'memory.swap.current', 'memory.events']:
                        try:
                            row[name] = (cgroup / name).read_text().strip()
                        except OSError:
                            pass
                    try:
                        for pid in (cgroup / 'cgroup.procs').read_text().split():
                            proc = Path('/proc') / pid
                            if (proc / 'exe').resolve() != binary:
                                continue
                            for line in (proc / 'status').read_text().splitlines():
                                if line.startswith(('VmRSS:', 'VmHWM:')):
                                    row[line.split(':')[0] + '_KiB'] = int(line.split()[1])
                    except OSError:
                        pass
                samples.append(row)
                stopped.wait(.025)

        thread = threading.Thread(target=sample)
        thread.start()
        try:
            summary['exit_code'] = process.wait(timeout=1220)
        except subprocess.TimeoutExpired:
            summary['exit_code'] = 124
            summary['harness_timeout'] = True
        finally:
            stopped.set()
            thread.join()
            props = subprocess.run(
                ['systemctl', '--user', 'show', unit, '-p',
                 'MemoryPeak,MemorySwapPeak,MemoryMax,MemorySwapMax,CPUAffinity,CPUUsageNSec,Result'],
                text=True, capture_output=True,
            )
            (out / 'cgroup.txt').write_text(props.stdout)
            final_properties = dict(line.split('=', 1) for line in props.stdout.splitlines() if '=' in line)
            summary['systemd_result'] = final_properties.get('Result')
            peak = final_properties.get('MemoryPeak', '')
            summary['final_cgroup_peak_bytes'] = int(peak) if peak.isdigit() else None
            swap_peak = final_properties.get('MemorySwapPeak', '')
            summary['final_cgroup_swap_peak_bytes'] = int(swap_peak) if swap_peak.isdigit() else None
            subprocess.run(['systemctl', '--user', 'stop', unit], capture_output=True)
            if process.poll() is None:
                try:
                    process.wait(timeout=20)
                except subprocess.TimeoutExpired:
                    summary['cleanup_timeout'] = True
                    process.kill()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        summary['cleanup_exit_unconfirmed'] = True
    def observed_peak(key):
        values = [int(s[key]) for s in samples if key in s]
        return max(values) if values else None

    def gib(value):
        return value / 2**30 if value is not None else None

    hwm = observed_peak('VmHWM_KiB')
    peak_candidates = [x for x in [observed_peak('memory.peak'), summary.get('final_cgroup_peak_bytes')] if x is not None]
    event_values = [int(dict(line.split() for line in s['memory.events'].splitlines()).get('oom_kill', 0)) for s in samples if 'memory.events' in s]
    summary.update(
        elapsed_seconds=time.perf_counter() - start,
        sampled_command_peak_rss_gib=hwm / 2**20 if hwm is not None else None,
        sampled_peak_cgroup_gib=gib(observed_peak('memory.peak')),
        effective_peak_cgroup_gib=gib(max(peak_candidates)) if peak_candidates else None,
        sampled_swap_peak_bytes=observed_peak('memory.swap.current'),
        sampled_oom_kill=max(event_values) if event_values else None,
        sample_count=len(samples),
        cgroup_sample_count=sum('memory.current' in s for s in samples),
    )
    time_rss = re.search(r'Maximum resident set size \(kbytes\): (\d+)', (out / 'stdout.log').read_text())
    summary['time_largest_process_peak_rss_gib'] = int(time_rss[1]) / 2**20 if time_rss else None
    save(out / 'resources.json', samples)
    save(out / 'summary.json', summary)
    print(json.dumps(summary, indent=2))
    raise SystemExit(summary['exit_code'])


if __name__ == '__main__':
    main()
