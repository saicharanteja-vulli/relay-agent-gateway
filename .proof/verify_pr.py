import hashlib
import json
import re
from pathlib import PurePosixPath
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, model_validator, field_validator

class Strict(BaseModel):
    model_config = ConfigDict(extra='forbid')

class Source(Strict):
    path: str = Field(min_length=1, max_length=180)
    content: str = Field(max_length=150_000)

    @field_validator('path')
    @classmethod
    def safe_path(cls, value):
        path = PurePosixPath(value)
        if not re.fullmatch(r'[a-zA-Z0-9_./-]+', value) or path.is_absolute() or any(p in {'..', '.', ''} for p in value.split('/')):
            raise ValueError('Use a relative project file path without traversal.')
        if any(p.startswith('.') or p in {'data','node_modules','__pycache__','venv'} for p in path.parts):
            raise ValueError('Hidden files, private data and runtimes are excluded.')
        if path.suffix not in {'.py','.html','.css','.js','.json','.txt','.md','.toml','.svg'}:
            raise ValueError('Unsupported source file type.')
        return value

class Check(Strict):
    name: str = Field(min_length=1,max_length=100)
    method: Literal['GET','POST','PUT','PATCH','DELETE'] = 'GET'
    path: str = Field(min_length=1,max_length=500)
    headers: dict[str,str] = Field(default_factory=dict,max_length=12)
    body: dict | list | None = None
    expected_status: int = Field(ge=100,le=599)
    expected_json: dict | None = None

    @field_validator('path')
    @classmethod
    def local_path(cls,value):
        if not value.startswith('/') or value.startswith('//') or any(ord(c)<32 for c in value) or '#' in value:
            raise ValueError('Use a local API path, such as /api/status.')
        return value

    @model_validator(mode='after')
    def bounded(self):
        if len(json.dumps(self.model_dump()).encode()) > 12_000:
            raise ValueError('Check payload is too large.')
        for k,v in self.headers.items():
            if not re.fullmatch(r'[A-Za-z0-9-]{1,60}',k) or any(ord(c)<32 or ord(c)>126 for c in v) or len(v)>1000:
                raise ValueError('Invalid HTTP header.')
            if k.lower() in {'host','content-length','transfer-encoding','connection'}:
                raise ValueError('Transport headers are controlled by Proof.')
        return self

class SourceInput(Strict):
    github_import_id: str | None = Field(default=None,pattern=r'^[a-f0-9]{32}$')
    title: str = Field(min_length=1,max_length=100)
    requirement: str = Field(min_length=10,max_length=2000)
    entrypoint: str = Field(default='app:app',pattern=r'^[A-Za-z_]\w*(\.[A-Za-z_]\w*)*:[A-Za-z_]\w*$')
    baseline: list[Source] = Field(min_length=1,max_length=80)
    candidate: list[Source] = Field(min_length=1,max_length=80)

    @model_validator(mode='after')
    def consistent(self):
        for files in (self.baseline,self.candidate):
            paths=[f.path for f in files]
            if len(set(paths))!=len(paths): raise ValueError('Duplicate source paths.')
            if sum(len(f.content.encode()) for f in files)>2_000_000: raise ValueError('Each version is limited to 2 MB.')
            module=self.entrypoint.split(':')[0].replace('.','/')
            if module+'.py' not in paths and module+'/__init__.py' not in paths:
                raise ValueError('Entrypoint module is missing from a source version.')
        return self

class Review(SourceInput):
    checks: list[Check] = Field(min_length=1,max_length=12)
    execution_consent: Literal[True]
    proposal_id: str | None = Field(default=None, pattern=r'^[a-f0-9]{32}$')
    tests_reviewed: bool = False

    @model_validator(mode='after')
    def checks_valid(self):
        if len({c.name for c in self.checks})!=len(self.checks): raise ValueError('Check names must be unique.')
        if (self.proposal_id or self.github_import_id) and not self.tests_reviewed: raise ValueError('Review the proposed tests before running.')
        return self

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':')).encode()).hexdigest()

"""Run reviewed source in Docker only. Never import submitted code on the host."""
import difflib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid


IMAGE='proof-fastapi-runner:1'

def command(args, timeout=8, input=None):
    return subprocess.run(['docker',*args],input=input,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=timeout,check=False)

def runtime():
    try:
        info=command(['info','--format','{{.ServerVersion}}'],4)
        if info.returncode: return {'ready':False,'message':'Start Docker Desktop to enable isolated verification.'}
        image=command(['image','inspect',IMAGE,'--format','{{.Id}}'],4)
        if image.returncode: return {'ready':False,'message':'Build the runner once with sh setup-runner.sh.'}
        return {'ready':True,'message':'Docker runner ready','image':image.stdout.strip(),'version':info.stdout.strip()}
    except (OSError,subprocess.TimeoutExpired):
        return {'ready':False,'message':'Docker is unavailable. Proof will not run code directly on your computer.'}

def redact(text):
    text=re.sub(r'(?i)(bearer\s+)[A-Za-z0-9._~-]+',r'\1[redacted]',text)
    return re.sub(r'(?i)((?:password|secret|token|api_key)[\"\s]*[:=]\s*[\"\x27]?)[^\s\"\x27,}]+',r'\1[redacted]',text)[:16000]

def subset(expected, actual):
    if isinstance(expected,dict):
        return isinstance(actual,dict) and all(k in actual and subset(v,actual[k]) for k,v in expected.items())
    return type(expected) is type(actual) and expected==actual

def assess(check, observed):
    if observed.get('error'): return {'passed':False,'reason':observed['error'],'status':observed.get('status'),'body':redact(observed.get('body',''))}
    status=observed.get('status')
    ok=status==check['expected_status']
    reason='Expected status and JSON assertions matched.' if ok else f"Expected HTTP {check['expected_status']}, received {status}."
    if ok and check.get('expected_json') is not None:
        try: ok=subset(check['expected_json'],json.loads(observed.get('body','')))
        except (ValueError,TypeError): ok=False
        if not ok: reason='Response JSON did not contain the expected values.'
    return {'passed':ok,'reason':reason,'status':status,'body':redact(observed.get('body',''))}

def diff_files(before, after):
    left={f['path']:f['content'] for f in before};right={f['path']:f['content'] for f in after};result=[]
    for name in sorted(left.keys()|right.keys()):
        if left.get(name)==right.get(name): continue
        patch=''.join(difflib.unified_diff(left.get(name,'').splitlines(True),right.get(name,'').splitlines(True),fromfile='baseline/'+name,tofile='candidate/'+name))
        result.append({'path':name,'kind':'added' if name not in left else 'removed' if name not in right else 'modified','patch':redact(patch),'truncated':len(patch)>16000})
    return result

def container_args(name,folder,image_id,entrypoint):
    return ['run','--detach','--pull=never','--name',name,'--label','proof.managed=true','--network=none','--read-only',
        '--cap-drop=ALL','--security-opt=no-new-privileges','--pids-limit=64','--memory=256m','--memory-swap=256m','--cpus=1',
        '--log-driver=local','--log-opt=max-size=1m','--log-opt=max-file=1','--log-opt=compress=false',
        '--tmpfs','/tmp:rw,noexec,nosuid,size=33554432,mode=1777','--user','65534:65534',
        '--mount',f'type=bind,source={folder},target=/workspace,readonly','--workdir','/workspace',
        '--env','RELAY_DATA=/tmp/relay','--env','CONTROL_DB=/tmp/orbit/control.db','--env','AEGIS_DATA=/tmp/aegis',
        '--env','HOME=/tmp','--entrypoint','python',image_id,'-m','uvicorn',entrypoint,'--host','127.0.0.1','--port','8000','--no-access-log']

def probe(name,check):
    reply=command(['exec','--user','1001:1001','-i',name,'python','-I','/opt/proof/probe.py'],6,input=json.dumps(check))
    if reply.returncode: return {'error':'Probe could not run; application container may have stopped.'}
    try: return json.loads(reply.stdout)
    except ValueError: return {'error':'Probe returned invalid evidence.'}

def run_version(files,entrypoint,checks,image_id,progress):
    name='proof-'+uuid.uuid4().hex
    started=time.monotonic();results=[];cleanup=True
    with tempfile.TemporaryDirectory(prefix='proof-source-') as folder:
        # Temporary snapshots contain only explicitly submitted source, never live app data.
        os.chmod(folder,0o755)
        for f in files:
            p=Path(folder)/f['path'];p.parent.mkdir(parents=True,exist_ok=True);p.write_text(f['content']);p.chmod(0o444)
        try:
            launch=command(container_args(name,str(Path(folder).resolve()),image_id,entrypoint),15)
            if launch.returncode: return {'error':'Container startup failed. Check Docker and available resources.','diagnostic':redact(launch.stderr),'checks':[],'duration':round(time.monotonic()-started,2)}
            ready=False
            for _ in range(20):
                response=probe(name,{'method':'GET','path':'/','headers':{}})
                if 'status' in response: ready=True;break
                if time.monotonic()-started>20: break
                time.sleep(.35)
            if not ready:
                logs=command(['logs','--tail','20',name],4)
                return {'error':'Application did not become ready within 20 seconds. Confirm entrypoint and supported dependencies.','diagnostic':redact(logs.stderr+logs.stdout),'checks':[],'duration':round(time.monotonic()-started,2)}
            for i,check in enumerate(checks):
                if time.monotonic()-started>65: raise TimeoutError('Version exceeded the 65-second time budget.')
                observed=probe(name,check)
                results.append({'name':check['name'],'expected_status':check['expected_status'],**assess(check,observed)})
                progress(i+1,len(checks))
            return {'checks':results,'duration':round(time.monotonic()-started,2)}
        except (OSError,subprocess.TimeoutExpired,TimeoutError) as exc:
            return {'error':'Verification interrupted: '+type(exc).__name__,'checks':results,'duration':round(time.monotonic()-started,2)}
        finally:
            try:
                removed=command(['rm','--force',name],10)
                cleanup=removed.returncode==0 or 'No such container' in removed.stderr
            except Exception: cleanup=False
            if not cleanup: raise RuntimeError('Container cleanup failed. Stop Docker and inspect proof-managed containers before retrying.')

def compare(baseline,candidate,checks):
    if baseline.get('error') or candidate.get('error') or len(baseline['checks'])!=len(checks) or len(candidate['checks'])!=len(checks):
        return {'verdict':'inconclusive','summary':'Execution was incomplete. No approval recommendation is available.','rows':[]}
    rows=[]
    for b,c,check in zip(baseline['checks'],candidate['checks'],checks):
        state='unchanged_pass' if b['passed'] and c['passed'] else 'improved' if c['passed'] else 'regression' if b['passed'] else 'persistent_failure'
        rows.append({'name':check['name'],'method':check['method'],'path':check['path'],'transition':state,'baseline':b,'candidate':c})
    failures=sum(not r['candidate']['passed'] for r in rows);regressions=sum(r['transition']=='regression' for r in rows)
    return {'verdict':'blocked' if failures else 'checks_passed','summary':f'{regressions} regression(s); {failures} candidate check(s) failed.' if failures else 'All supplied checks passed on the candidate. Human review is still required.','rows':rows}

DOCKERFILE = 'FROM python:3.14-slim\nRUN pip install --no-cache-dir fastapi==0.143.1 uvicorn==0.54.0 pydantic==2.14.1 httpx==0.28.1 certifi==2026.7.22\nCOPY probe.py /opt/proof/probe.py\nENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1\nWORKDIR /workspace\nUSER 65534:65534\n'
PROBE = '"""Trusted HTTP probe; executed with a different UID from the app under test."""\nimport http.client\nimport json\nimport sys\n\ncheck = json.load(sys.stdin)\ntry:\n    body = json.dumps(check[\'body\']).encode() if check.get(\'body\') is not None else None\n    headers = {\'Host\': \'localhost\', **check.get(\'headers\', {})}\n    if body is not None:\n        headers.setdefault(\'Content-Type\', \'application/json\')\n    conn = http.client.HTTPConnection(\'127.0.0.1\', 8000, timeout=3)\n    conn.request(check[\'method\'], check[\'path\'], body=body, headers=headers)\n    response = conn.getresponse()\n    raw = response.read(65537)\n    if len(raw) > 65536:\n        print(json.dumps({\'error\': \'Response exceeds 64 KB evidence limit.\'}))\n    else:\n        print(json.dumps({\'status\': response.status, \'body\': raw.decode(\'utf-8\', \'replace\')}))\nexcept Exception as exc:\n    print(json.dumps({\'error\': type(exc).__name__ + \': \' + str(exc)[:300]}))\n'
"""Run the base branch's committed policy against the exact PR head in Docker."""
import json,os,re,subprocess,sys
from pathlib import Path
from pydantic import ValidationError

def git(*args): return subprocess.check_output(['git',*args])
def files(sha):
    result=[]
    for line in git('ls-tree','-r',sha).decode().splitlines():
        meta,path=line.split('\t',1);mode,kind,_=meta.split()
        if mode=='120000': raise ValueError('Symlinks are unsupported')
        if kind!='blob': continue
        try: Source(path=path,content='')
        except ValidationError: continue
        blob=git('show',sha+':'+path)
        if len(blob)>150000: raise ValueError('Source file exceeds size limit')
        result.append({'path':path,'content':blob.decode()})
        if len(result)>80 or sum(len(f['content'].encode()) for f in result)>2000000: raise ValueError('Source snapshot exceeds limits')
    return result

def main():
    base,head=os.environ['BASE_SHA'],os.environ['HEAD_SHA']
    if not all(re.fullmatch('[a-f0-9]{40}',s) for s in (base,head)): raise ValueError('Invalid commit')
    # Never load policy or host-side scripts from PR source.
    policy=json.loads(git('show',base+':.proof/policy.json'))
    payload=Review.model_validate({**policy,'baseline':files(base),'candidate':files(head),'execution_consent':True}).model_dump()
    import tempfile
    with tempfile.TemporaryDirectory(prefix='proof-image-') as folder:
        Path(folder,'Dockerfile').write_text(DOCKERFILE)
        Path(folder,'probe.py').write_text(PROBE)
        subprocess.run(['docker','build','-t','proof-fastapi-runner:1',folder],check=True)
    rt=runtime()
    if not rt['ready']: raise RuntimeError(rt['message'])
    results={side:run_version(payload[side],payload['entrypoint'],payload['checks'],rt['image'],lambda *_:None) for side in ('baseline','candidate')}
    report={**compare(results['baseline'],results['candidate'],payload['checks']),'base_sha':base,'head_sha':head,'image':rt['image'],'checks':payload['checks']}
    Path('proof-report.json').write_text(json.dumps(report,indent=2))
    lines=['## Proof verification',f"Base: `{base}`",f"Head: `{head}`",'','| Check | Baseline | Candidate | Result |','|---|---|---|---|']
    for row in report['rows']:
        lines.append(f"| {row['name'].replace('|','/')} | {row['baseline']['status']} | {row['candidate']['status']} | {row['transition']} |")
    lines+=['',report['summary'],'','Policy and runner came from the base commit. Local AI drafts do not change this required policy.']
    if os.environ.get('GITHUB_STEP_SUMMARY'): Path(os.environ['GITHUB_STEP_SUMMARY']).write_text('\n'.join(lines))
    print(json.dumps(report,indent=2))
    return 0 if report['verdict']=='checks_passed' else 1
if __name__=='__main__': sys.exit(main())
