#!/usr/bin/env python3
"""Local verification of existing fixes. No fuzz campaigns, network scanning,
deployment, publication, merges or Git writes. Run from repository root.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

parser = argparse.ArgumentParser()
parser.add_argument('phase', choices=['core', 'race', 'storage', 'coverage'])
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
os.chdir(root)
logs = root / 'audit' / 'logs'
logs.mkdir(exist_ok=True)
env = dict(os.environ)
env.update(GOTOOLCHAIN='go1.27.3', GOMODCACHE='/home/pasich/go/pkg/mod',
           GOCACHE='/home/pasich/.cache/go-build', GOPROXY='off')
commands = {
 'core': [('version', ['go', 'version']), ('format', ['go', 'fmt', './...']),
          ('build', ['go', 'build', '-p', '2', './...']),
          ('vet', ['go', 'vet', '-p', '2', './...']),
          ('modverify', ['go', 'mod', 'verify']),
          ('regression', ['go', 'test', '-p', '2', './...', '-count=1'])],
 'race': [('race', ['go', 'test', '-race', '-p', '2', './...', '-count=1'])],
 'storage': [('storage', ['go', 'test', '-p', '2', './v2/chain',
              '-run', '^TestSecurity', '-count=1', '-v'])],
 'coverage': [('coverage', ['go', 'test', '-p', '2', '-coverprofile=audit/coverage.out',
                           './...', '-count=1']),
              ('coverage-summary', ['go', 'tool', 'cover', '-func=audit/coverage.out'])]
}
results = []
for name, cmd in commands[args.phase]:
    target = logs / ('verification-' + name + '.log')
    start = time.monotonic()
    utc = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with target.open('w') as out:
        code = subprocess.run(cmd, env=env, stdout=out, stderr=subprocess.STDOUT).returncode
    row = dict(name=name, command=cmd, environment={k:env[k] for k in
                 ['GOTOOLCHAIN','GOMODCACHE','GOCACHE','GOPROXY']},
               started_utc=utc, elapsed_seconds=round(time.monotonic()-start,3),
               exit_code=code, log=str(target.relative_to(root)),
               log_sha256=hashlib.sha256(target.read_bytes()).hexdigest())
    results.append(row)
    (logs / ('verification-'+args.phase+'-results.json')).write_text(
        json.dumps(results,indent=2)+'\n')
    print(json.dumps({k:row[k] for k in ['name','exit_code','elapsed_seconds','log']}),flush=True)
raise SystemExit(any(row['exit_code'] for row in results))
