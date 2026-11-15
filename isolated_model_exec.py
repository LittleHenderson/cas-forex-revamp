"""Explicit model child wrapper. No action on import; source-only on MSI."""
import argparse
import json
import os
from pathlib import Path
from role_boundary import confine, need, open_probe


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--bootstrap-fd',type=int,required=True)
    parser.add_argument('--ready-fd',type=int,required=True);args=parser.parse_args()
    with os.fdopen(args.bootstrap_fd,'rb') as handle:
        raw=handle.read(1048577)
    need(0<len(raw)<=1048576,'bounded model bootstrap required')
    cfg=json.loads(raw)
    need(set(cfg)=={'policy','binary','environment','cwd','probe_paths','boot_id'},'unknown model bootstrap field')
    need(os.getcwd()==cfg['cwd'],'model working directory differs')
    observed=confine(cfg['policy'],allowed_fds={args.ready_fd},boot_id=cfg['boot_id'])
    observed['access_probes']=[open_probe(p) for p in cfg['probe_paths']]
    os.write(args.ready_fd,json.dumps(observed,separators=(',',':')).encode()+b'\n')
    os.close(args.ready_fd)
    # Same PID becomes the pinned Ollama executable; no custody channel survives.
    os.execve(cfg['binary'],[cfg['binary'],'serve'],cfg['environment'])


if __name__=='__main__':
    try: main()
    except Exception:
        # No exception details on public stdout/stderr.
        raise SystemExit(1)
