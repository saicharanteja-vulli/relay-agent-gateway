import hmac
import json
import os
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Literal
from uuid import uuid4
from urllib.parse import urlsplit
from fastapi import FastAPI, Request, Response, HTTPException, Depends
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from .core import initialize, connect, record, expire, fingerprint, artifact
from .orbit_security import password_hash, SaveArgs, digest, public_target

COOKIE=os.environ.get('RELAY_COOKIE_NAME', 'relay_session')
BASE=Path(__file__).resolve().parent.parent

@asynccontextmanager
async def lifespan(app):
    initialize()
    yield

app=FastAPI(title='Relay — Agent Approval Gateway',version='1.0.0',lifespan=lifespan,docs_url=None,redoc_url=None)

@app.middleware('http')
async def boundary(request,call_next):
    if request.headers.get('sec-fetch-site') == 'same-site':
        return JSONResponse({'detail':'Cross-site browser request blocked.'},status_code=403)
    host=request.url.hostname
    if host not in ('localhost','127.0.0.1','testserver'):
        return JSONResponse({'detail':'Relay is local-only. Public deployment requires separate hardening.'},status_code=403)
    if request.method in ('POST','PUT','PATCH','DELETE'):
        origin=request.headers.get('origin')
        if origin and origin!=str(request.base_url).rstrip('/'):
            return JSONResponse({'detail':'Cross-origin request blocked.'},status_code=403)
        length=request.headers.get('content-length','0')
        try: oversized=int(length)>100000
        except ValueError: oversized=True
        if oversized: return JSONResponse({'detail':'Request too large.'},status_code=413)
        # Enforce the cap while receiving, including chunked requests without Content-Length.
        chunks=[]
        received=0
        async for chunk in request.stream():
            received+=len(chunk)
            if received>100000:
                return JSONResponse({'detail':'Request too large.'},status_code=413)
            chunks.append(chunk)
        request._body=b''.join(chunks)
        if not request.headers.get('authorization') and request.headers.get('x-relay-client')!='dashboard':
            return JSONResponse({'detail':'Dashboard request header required.'},status_code=403)
    response=await call_next(request)
    response.headers['X-Content-Type-Options']='nosniff'
    response.headers['Referrer-Policy']='no-referrer'
    response.headers['X-Frame-Options']='DENY'
    response.headers['Cache-Control']='no-store'
    response.headers['Content-Security-Policy']="default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    return response

class Input(BaseModel):
    model_config=ConfigDict(extra='forbid')

class Credentials(Input):
    username:str=Field(min_length=3,max_length=50,pattern=r'^[a-zA-Z0-9_.-]+$')
    password:str=Field(min_length=12,max_length=128)


def human(request:Request):
    with connect() as db:
        row=db.execute('SELECT s.*,u.username FROM sessions s JOIN users u ON u.id=s.owner WHERE s.token=? AND s.expires>?',(fingerprint(request.cookies.get(COOKIE,'')),time.time())).fetchone()
    if not row: raise HTTPException(401,'Sign in to continue.')
    if request.method not in ('GET','HEAD') and not hmac.compare_digest(request.headers.get('x-relay-csrf',''),row['csrf']):
        raise HTTPException(403,'Session verification failed. Refresh and try again.')
    return dict(row)


def machine(request:Request):
    raw=request.headers.get('authorization','')
    if not raw.startswith('Bearer '): raise HTTPException(401,'Agent API key required.')
    with connect() as db:
        row=db.execute('SELECT * FROM agents WHERE token=? AND active=1',(fingerprint(raw[7:]),)).fetchone()
    if not row: raise HTTPException(401,'Invalid or revoked agent key.')
    return dict(row)


def issue(uid,username,response):
    token,csrf=secrets.token_urlsafe(32),secrets.token_urlsafe(32)
    with connect() as db:
        db.execute('DELETE FROM sessions WHERE expires<=?',(time.time(),))
        db.execute('INSERT INTO sessions VALUES(?,?,?,?)',(fingerprint(token),uid,csrf,time.time()+28800))
    response.set_cookie(COOKIE,token,max_age=28800,httponly=True,samesite='strict',secure=os.environ.get('RELAY_SECURE_COOKIE')=='1')
    return {'username':username,'csrf':csrf}

@app.get('/api/status')
def status():
    with connect() as db:
        return {'setup_required':not bool(db.execute('SELECT 1 FROM users').fetchone())}

@app.post('/api/setup')
def setup(body:Credentials,response:Response):
    hashed=password_hash(body.password)
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        if db.execute('SELECT 1 FROM users').fetchone(): raise HTTPException(409,'Setup is already complete.')
        uid=str(uuid4())
        db.execute('INSERT INTO users VALUES(?,?,?)',(uid,body.username.lower(),hashed))
        record(db,uid,None,'account','Workspace owner created.')
    return issue(uid,body.username.lower(),response)

@app.post('/api/login')
def login(body:Credentials,request:Request,response:Response):
    ip=request.client.host
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        db.execute('DELETE FROM attempts WHERE at<?',(time.time()-300,))
        if db.execute('SELECT COUNT(*) FROM attempts WHERE ip=?',(ip,)).fetchone()[0]>=10: raise HTTPException(429,'Too many login attempts. Try in five minutes.')
        db.execute('INSERT INTO attempts VALUES(?,?)',(ip,time.time()))
        u=db.execute('SELECT * FROM users WHERE username=?',(body.username.lower(),)).fetchone()
    test=password_hash(body.password,u['password'].split(':')[0] if u else '00'*16)
    if not u or not hmac.compare_digest(test,u['password']): raise HTTPException(401,'Invalid username or password.')
    return issue(u['id'],u['username'],response)

@app.get('/api/me')
def me(u=Depends(human)): return {'username':u['username'],'csrf':u['csrf']}

@app.post('/api/logout')
def logout(response:Response,u=Depends(human)):
    with connect() as db: db.execute('DELETE FROM sessions WHERE token=?',(u['token'],))
    response.delete_cookie(COOKIE)
    return {'ok':True}

class AgentInput(Input):
    name:str=Field(min_length=2,max_length=60)
    tools:list[Literal['save_file','send_webhook','log_event']]=Field(min_length=1,max_length=3)

@app.get('/api/agents')
def agents(u=Depends(human)):
    with connect() as db:
        return [dict(r) for r in db.execute('SELECT id,name,prefix,tools,active,created FROM agents WHERE owner=? ORDER BY created DESC',(u['owner'],))]

@app.post('/api/agents',status_code=201)
def new_agent(body:AgentInput,u=Depends(human)):
    token='rly_'+secrets.token_urlsafe(32)
    uid=str(uuid4())
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        if db.execute('SELECT COUNT(*) FROM agents WHERE owner=? AND active=1',(u['owner'],)).fetchone()[0]>=50: raise HTTPException(409,'Limit of 50 active agents reached.')
        db.execute('INSERT INTO agents VALUES(?,?,?,?,?,?,1,?)',(uid,u['owner'],body.name,fingerprint(token),token[:12],json.dumps(body.tools),time.time()))
        record(db,u['owner'],None,'agent_created',body.name+' connected; key shown once.')
    return {'id':uid,'key':token}

@app.post('/api/agents/{aid}/revoke')
def revoke(aid:str,u=Depends(human)):
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        if not db.execute('SELECT 1 FROM agents WHERE id=? AND owner=?',(aid,u['owner'])).fetchone(): raise HTTPException(404,'Agent not found.')
        db.execute('UPDATE agents SET active=0 WHERE id=?',(aid,))
        for a in db.execute("SELECT id FROM actions WHERE agent=? AND status IN ('pending','approved')",(aid,)).fetchall():
            db.execute("UPDATE actions SET status='blocked',error='Agent key revoked' WHERE id=?",(a['id'],))
            record(db,u['owner'],a['id'],'blocked','Agent key revoked before dispatch.')
        record(db,u['owner'],None,'agent_revoked','Key revoked. In-flight actions cannot be recalled.')
    return {'ok':True}

class Proposal(Input):
    title:str=Field(min_length=3,max_length=120)
    reason:str=Field(min_length=3,max_length=2000)
    tool:Literal['save_file','send_webhook','log_event']
    arguments:dict
    idempotency_key:str=Field(min_length=8,max_length=100)
    expires_in:int=Field(default=3600,ge=60,le=86400)


def submit(body,g):
    try: size=len(json.dumps(body.arguments,allow_nan=False).encode())
    except ValueError: raise HTTPException(422,'Arguments must contain valid finite JSON values.')
    if size>60000: raise HTTPException(422,'Arguments exceed 60 KB.')
    if body.tool not in json.loads(g['tools']): raise HTTPException(403,'This tool is outside the agent permission scope.')
    try:
        if body.tool=='save_file': args=SaveArgs.model_validate(body.arguments).model_dump()
        elif body.tool=='send_webhook':
            if set(body.arguments)!={'payload'} or not isinstance(body.arguments['payload'],dict): raise ValueError('Provide only a JSON payload; the owner configures the destination.')
            args=dict(body.arguments)
        else:
            if set(body.arguments)!={'message'} or not isinstance(body.arguments['message'],str) or not 1<=len(body.arguments['message'])<=2000: raise ValueError('Log message must be 1–2000 characters.')
            args=body.arguments
    except ValueError as e: raise HTTPException(422,str(e))
    request_digest=digest('request',body.model_dump())
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        if not db.execute('SELECT 1 FROM agents WHERE id=? AND active=1',(g['id'],)).fetchone(): raise HTTPException(401,'Agent key revoked.')
        old=db.execute('SELECT * FROM actions WHERE agent=? AND idem=?',(g['id'],body.idempotency_key)).fetchone()
        if old:
            if old['request_digest']!=request_digest: raise HTTPException(409,'Idempotency key already used for another proposal.')
            return display(old)
        if db.execute("SELECT COUNT(*) FROM actions WHERE owner=? AND status IN ('pending','approved')",(g['owner'],)).fetchone()[0]>=200: raise HTTPException(429,'Approval queue is full.')
        if body.tool=='send_webhook':
            cfg=db.execute('SELECT webhook FROM settings WHERE owner=?',(g['owner'],)).fetchone()
            if not cfg or not cfg['webhook']: raise HTTPException(409,'The owner must configure a webhook first.')
            args['destination']=cfg['webhook']
        aid=str(uuid4()); state='succeeded' if body.tool=='log_event' else 'pending'
        result=json.dumps({'recorded':True}) if state=='succeeded' else None
        db.execute('INSERT INTO actions VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',(aid,g['owner'],g['id'],body.title,body.reason,body.tool,json.dumps(args),digest(body.tool,args),state,time.time(),time.time()+body.expires_in,None,result,None,body.idempotency_key,request_digest))
        record(db,g['owner'],aid,'submitted',body.title)
        record(db,g['owner'],aid,'auto_allowed' if state=='succeeded' else 'review_required','Internal log recorded; no external side effect.' if state=='succeeded' else 'Write action paused for owner review.')
        return display(db.execute('SELECT * FROM actions WHERE id=?',(aid,)).fetchone())


def display(r):
    d=dict(r)
    for k in ('arguments','result'): d[k]=json.loads(d[k]) if d[k] else None
    d.pop('request_digest',None)
    return d

@app.post('/v1/actions',status_code=201)
def propose(body:Proposal,g=Depends(machine)): return submit(body,g)

@app.get('/v1/actions/{aid}')
def machine_status(aid:str,g=Depends(machine)):
    with connect() as db:
        expire(db)
        r=db.execute('SELECT * FROM actions WHERE id=? AND agent=?',(aid,g['id'])).fetchone()
        if not r: raise HTTPException(404,'Action not found.')
        return display(r)

@app.get('/api/actions')
def actions(u=Depends(human)):
    with connect() as db:
        expire(db)
        return [display(r) for r in db.execute('SELECT a.*,g.name agent_name FROM actions a JOIN agents g ON g.id=a.agent WHERE a.owner=? ORDER BY a.created DESC LIMIT 200',(u['owner'],))]

@app.get('/api/actions/{aid}')
def action(aid:str,u=Depends(human)):
    with connect() as db:
        expire(db)
        r=db.execute('SELECT a.*,g.name agent_name FROM actions a JOIN agents g ON g.id=a.agent WHERE a.id=? AND a.owner=?',(aid,u['owner'])).fetchone()
        if not r: raise HTTPException(404,'Action not found.')
        d=display(r)
        d['events']=[dict(e) for e in db.execute('SELECT * FROM audit WHERE action=? ORDER BY id',(aid,))]
        return d

class Decision(Input):
    approved:bool
    digest:str=Field(pattern=r'^[a-f0-9]{64}$')
    note:str=Field(default='',max_length=1000)

@app.post('/api/actions/{aid}/decision')
def decide(aid:str,body:Decision,u=Depends(human)):
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        a=db.execute('SELECT * FROM actions WHERE id=? AND owner=?',(aid,u['owner'])).fetchone()
        if not a: raise HTTPException(404,'Action not found.')
        if a['status']!='pending' or a['expires']<=time.time(): raise HTTPException(409,'This action is no longer awaiting a decision.')
        if not hmac.compare_digest(body.digest,a['digest']): raise HTTPException(409,'Proposal changed. Refresh before deciding.')
        state='approved' if body.approved else 'rejected'
        db.execute('UPDATE actions SET status=?,decided=? WHERE id=?',(state,time.time(),aid))
        record(db,u['owner'],aid,state,('Owner approved the exact payload.' if body.approved else 'Owner rejected execution.')+(' Note: '+body.note if body.note else ''))
    return {'status':state}

@app.get('/api/actions/{aid}/artifact')
def download(aid:str,u=Depends(human)):
    with connect() as db:
        a=db.execute("SELECT * FROM actions WHERE id=? AND owner=? AND status='succeeded' AND tool='save_file'",(aid,u['owner'])).fetchone()
        if not a: raise HTTPException(404,'Approved artifact not available.')
        p=artifact(a)
        if not p.exists(): raise HTTPException(404,'Artifact missing.')
    return FileResponse(p,filename=p.name,media_type='application/octet-stream')

@app.get('/api/audit')
def audit(u=Depends(human)):
    with connect() as db: return [dict(r) for r in db.execute('SELECT * FROM audit WHERE owner=? ORDER BY id DESC LIMIT 300',(u['owner'],))]

@app.get('/api/health')
def health(u=Depends(human)):
    with connect() as db: r=db.execute('SELECT at FROM heartbeat WHERE id=1').fetchone()
    return {'worker_online':bool(r and time.time()-r['at']<15),'storage':'SQLite','version':'1.0.0'}

@app.get('/api/connection')
def connection(u=Depends(human)):
    with connect() as db: r=db.execute('SELECT webhook FROM settings WHERE owner=?',(u['owner'],)).fetchone()
    return {'configured':bool(r and r['webhook']),'hostname':urlsplit(r['webhook']).hostname if r and r['webhook'] else None}

class Connection(Input):
    url:str=Field(max_length=2048)

@app.put('/api/connection')
def save_connection(body:Connection,u=Depends(human)):
    if body.url:
        try: public_target(body.url)
        except (ValueError,OSError): raise HTTPException(422,'Use a reachable public HTTPS webhook on port 443.')
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        db.execute('INSERT OR REPLACE INTO settings VALUES(?,?)',(u['owner'],body.url))
        for r in db.execute("SELECT id FROM actions WHERE owner=? AND tool='send_webhook' AND status IN ('pending','approved')",(u['owner'],)).fetchall():
            db.execute("UPDATE actions SET status='blocked',error='Webhook configuration changed' WHERE id=?",(r['id'],))
            record(db,u['owner'],r['id'],'blocked','Destination changed before dispatch.')
        record(db,u['owner'],None,'connection_updated','Webhook configured.' if body.url else 'Webhook disconnected.')
    return {'ok':True}

@app.post('/api/demo',status_code=201)
def demo(u=Depends(human)):
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        g=db.execute("SELECT * FROM agents WHERE owner=? AND name='Sample research agent' AND active=1",(u['owner'],)).fetchone()
        if not g:
            gid=str(uuid4())
            db.execute('INSERT INTO agents VALUES(?,?,?,?,?,?,1,?)',(gid,u['owner'],'Sample research agent',fingerprint(secrets.token_urlsafe(32)),'internal',json.dumps(['save_file','log_event']),time.time()))
            g=db.execute('SELECT * FROM agents WHERE id=?',(gid,)).fetchone()
    return submit(Proposal(title='Save a research handoff',reason='The sample agent has prepared a short report. Review its exact contents before it becomes a file.',tool='save_file',arguments={'filename':'relay-handoff.md','content':'# Relay handoff\n\nThis is a sample report, not live research.\n\nThe agent can propose an action. Only its owner can approve the exact payload.\n\nNo file exists until you approve this request.\n'},idempotency_key=str(uuid4())),dict(g))

app.mount('/static',StaticFiles(directory=BASE/'static'),name='static')
@app.get('/')
def home(): return FileResponse(BASE/'static/index.html')

@app.get('/docs')
def docs(): return FileResponse(BASE/'static/api.html')


@app.get('/v1/actions/{aid}/artifact')
def agent_download(aid:str,g=Depends(machine)):
    with connect() as db:
        a=db.execute("SELECT * FROM actions WHERE id=? AND agent=? AND status='succeeded' AND tool='save_file'",(aid,g['id'])).fetchone()
        if not a: raise HTTPException(404,'Approved artifact not available.')
        p=artifact(a)
        if not p.is_file() or p.is_symlink(): raise HTTPException(404,'Artifact missing.')
    return FileResponse(p,filename=p.name,media_type='application/octet-stream')
