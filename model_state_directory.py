"""Read-only checks for the one systemd DynamicUser StateDirectory alias.

No link creation, permission changes, mounting, directory scan, or configuration
supplied observations. This exception applies only to retained state, never to
source/runtime/model/controller inputs.
"""
import os
from pathlib import Path
import re
import stat


def _need(ok, reason):
    if not ok:
        raise RuntimeError(reason)


def _record(info):
    return dict(mode=info.st_mode, uid=info.st_uid, gid=info.st_gid,
                device=info.st_dev, inode=info.st_ino)


def validate_state_layout(observation, *, run_id, uid, gid):
    """Pure validation helper; the production caller supplies only live reads."""
    _need(type(run_id) is str and re.fullmatch(r'fx-b-[a-f0-9]{16}', run_id), 'invalid B state identity')
    _need(type(uid) is int and uid > 0 and type(gid) is int and gid > 0, 'nonroot workload UID/GID required')
    name = 'cas-forex-' + run_id
    alias, target = '/var/lib/' + name, '/var/lib/private/' + name
    _need(observation['alias_path'] == alias and observation['environment_path'] == alias
          and observation['target_path'] == target and observation['resolved_path'] == target,
          'state path differs from exact systemd geometry')
    _need(set(observation['parents']) == {'/', '/var', '/var/lib', '/var/lib/private'},
          'state parent coverage incomplete')
    for info in observation['parents'].values():
        _need(stat.S_ISDIR(info['mode']) and info['uid'] == 0 and info['mode'] & 0o022 == 0,
              'state ancestor is linked or writable by a nonroot user')
    link, directory = observation['alias'], observation['target']
    _need(stat.S_ISLNK(link['mode']) and link['uid'] == 0 and link['gid'] == 0
          and observation['link_text'] in ('private/' + name, target),
          'state alias is not the exact root-owned systemd link')
    _need(stat.S_ISDIR(directory['mode']) and stat.S_IMODE(directory['mode']) == 0o700
          and directory['uid'] == uid and directory['gid'] == gid,
          'private state target mode or workload ownership differs')
    _need(observation['opened_target'] == directory and observation['alias_followed'] == directory,
          'state directory identity changed or alias differs')
    mounts = observation['target_mounts']
    _need(len(mounts) == 1 and mounts[0]['mountpoint'] == target
          and mounts[0]['device'] == str(os.major(directory['device'])) + ':' + str(os.minor(directory['device']))
          and 'rw' in mounts[0]['options'] and 'ro' not in mounts[0]['options']
          and observation['filesystem_readonly'] is False,
          'private state lacks its exact writable namespace mount')
    return dict(alias_path=alias, private_target=target, alias_root_owned=True,
                uid=uid, gid=gid, mode='0700', device=directory['device'], inode=directory['inode'],
                mount_id=mounts[0]['mount_id'], mountpoint=target, writable_mount_observed=True)


def observe_state_directory(cfg):
    """Observe only the known state paths, metadata and matching mount record."""
    run_id = cfg['run_id']
    _need(type(run_id) is str and re.fullmatch(r'fx-b-[a-f0-9]{16}', run_id), 'invalid B state identity')
    name = 'cas-forex-' + run_id
    alias = Path('/var/lib') / name
    target = Path('/var/lib/private') / name
    _need(cfg['state_directory'] == str(alias), 'unconfined configured state')
    parents = {path: _record(Path(path).lstat()) for path in ('/', '/var', '/var/lib', '/var/lib/private')}
    # Parent ownership and exact link identity are checked before resolving or
    # opening a target. A root controller/service manager remains the trust root.
    for info in parents.values():
        _need(stat.S_ISDIR(info['mode']) and info['uid'] == 0 and info['mode'] & 0o022 == 0,
              'unsafe state ancestor')
    alias_info = _record(alias.lstat())
    _need(stat.S_ISLNK(alias_info['mode']) and alias_info['uid'] == 0 and alias_info['gid'] == 0,
          'unexpected state alias')
    link_text = os.readlink(alias)
    _need(link_text in ('private/' + name, str(target)), 'state link escapes selected private target')
    target_info = _record(target.lstat())
    _need(stat.S_ISDIR(target_info['mode']), 'private state target is linked or not a directory')
    descriptor = os.open(target, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        opened = _record(os.fstat(descriptor))
        readonly = bool(os.fstatvfs(descriptor).f_flag & os.ST_RDONLY)
        raw = Path('/proc/self/mountinfo').read_bytes()
        _need(len(raw) <= 4194304, 'mount observation exceeds bound')
        mounts = []
        for line in raw.decode('utf-8', 'strict').splitlines():
            fields = line.split()
            _need(len(fields) >= 10 and '-' in fields, 'malformed mount observation')
            # Selected paths contain only fixed ASCII slashes/hyphens/hex; no
            # unescaping or arbitrary mount path is necessary or returned.
            if fields[4] == str(target):
                mounts.append(dict(mount_id=int(fields[0]), device=fields[2],
                                   mountpoint=fields[4], options=fields[5].split(',')))
        observation = dict(alias_path=str(alias), environment_path=os.environ.get('STATE_DIRECTORY'),
            target_path=str(target), resolved_path=str(alias.resolve(strict=True)), parents=parents,
            alias=alias_info, target=target_info, link_text=link_text,
            opened_target=opened, alias_followed=_record(alias.stat()),
            target_mounts=mounts, filesystem_readonly=readonly)
        return validate_state_layout(observation, run_id=run_id, uid=os.geteuid(), gid=os.getegid())
    finally:
        os.close(descriptor)

