"""Source-only future B guest launcher; never authorized by Stage A approval.

Explicit Linux root invocation only after the separate controller has fixed the
run identity, no-overlap decision, resource/account/expiry proof and frozen config.
No cloud API, installation, download or retained-state replacement is implemented.
"""
import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import math
import os
from pathlib import Path
import subprocess
import sys
from model_guest_boundary import config_contract, load, need, regular, verify_controller_evidence, verify_sources, verify_python


def launch_argv(cfg, config_path, config_sha, remaining):
    need(type(remaining) is int and remaining > 0, 'no absolute runtime remaining')
    unit = 'cas-forex-' + cfg['run_id']
    base = str(Path(cfg['source_directory']).parent)
    properties = {
        'Type': 'exec', 'Restart': 'no', 'RuntimeMaxSec': str(remaining),
        'TimeoutStopSec': '1', 'KillMode': 'control-group', 'SendSIGKILL': 'yes',
        'DynamicUser': 'yes', 'NoNewPrivileges': 'yes', 'UMask': '0077',
        'CapabilityBoundingSet': '', 'AmbientCapabilities': '',
        'PrivateNetwork': 'yes', 'PrivateDevices': 'yes', 'PrivateTmp': 'yes',
        'ProtectSystem': 'strict', 'ProtectHome': 'yes', 'ProtectProc': 'default', 'ProcSubset': 'all',
        'ProtectKernelTunables': 'yes', 'ProtectKernelModules': 'yes', 'ProtectKernelLogs': 'yes',
        'ProtectControlGroups': 'yes', 'RestrictSUIDSGID': 'yes', 'RestrictNamespaces': 'yes',
        'LockPersonality': 'yes', 'RestrictAddressFamilies': 'AF_UNIX AF_INET AF_INET6',
        'IPAddressDeny': 'any', 'IPAddressAllow': 'localhost',
        'InaccessiblePaths': '-/root -/home -/media -/mnt',
        'ReadOnlyPaths': base, 'StateDirectory': unit, 'StateDirectoryMode': '0700',
        'MemoryMax': '12G', 'CPUQuota': '400%',
    }
    argv = ['systemd-run', '--unit='+unit, '--wait', '--pipe']
    argv.extend('--property='+key+'='+value for key, value in properties.items())
    argv.extend(['/usr/bin/python3', '-B', cfg['source_directory']+'/approved_model_driver.py',
                 '--guest-config', str(config_path), '--config-sha256', config_sha])
    return argv


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', type=Path, required=True)
    parser.add_argument('--config-sha256', required=True)
    args = parser.parse_args()
    need(sys.platform == 'linux' and sys.version_info[:2] == (3, 12) and os.geteuid() == 0, 'approved Linux guest root required')
    path = regular(args.config, Path('/opt/cas-forex'), root_owned=True)
    raw = path.read_bytes()
    need(len(raw) <= 4194304 and sha256(raw).hexdigest() == args.config_sha256, 'exact B config hash required')
    cfg = load(raw)
    base, deadline, _ = config_contract(cfg, now=datetime.now(timezone.utc))
    need(Path(__file__).resolve() == Path(cfg['source_directory'])/'approved_model_launcher.py', 'launcher path differs')
    need(path.is_relative_to(base), 'configuration outside selected B root')
    verify_python(cfg, readonly=False)
    # The root launcher hashes inputs before sandbox creation; inside the worker
    # the same check additionally demands real read-only mounts.
    verify_sources(cfg, base, readonly=False)
    verify_controller_evidence(cfg, base, readonly=False)
    clean = {'PATH': '/usr/sbin:/usr/bin:/sbin:/bin', 'LANG': 'C.UTF-8'}
    active = subprocess.run(['systemctl', 'list-units', '--all', '--type=service', '--state=active,activating,deactivating',
        '--output=json', '--no-pager', 'cas-forex-*'], env=clean, capture_output=True, text=True, check=True, timeout=10)
    need(json.loads(active.stdout) == [], 'another CAS Forex service is still active')
    unit = 'cas-forex-' + cfg['run_id']
    previous = subprocess.run(['systemctl', 'show', unit, '--property=LoadState', '--value'],
        env=clean, capture_output=True, text=True, check=True, timeout=10).stdout.strip()
    need(previous == 'not-found', 'B unit already exists; no automatic restart')
    output = base/'receipts'; output.mkdir(mode=0o700, exist_ok=True)
    remaining = math.floor((deadline-datetime.now(timezone.utc)).total_seconds())-5
    argv = launch_argv(cfg, path, args.config_sha256, remaining)
    # This retained intent survives transient-unit garbage collection. Failed or
    # unknown launch is not permission to replace it or create another identity.
    with (output/'b-guest-launch.intent.json').open('x', encoding='utf-8') as handle:
        json.dump({'run_id': cfg['run_id'], 'config_sha256': args.config_sha256,
                   'work_deadline_utc': cfg['work_deadline_utc'], 'mode': cfg['execution_mode']}, handle)
        handle.flush(); os.fsync(handle.fileno())
    return subprocess.run(argv, env=clean, check=False).returncode


if __name__ == '__main__':
    raise SystemExit(main())
