import json
import secrets
import sqlite3
import time
from uuid import uuid4
import pytest
from fastapi.testclient import TestClient
from relay.app import app
from relay import core
from relay.orbit_security import password_hash, public_target

@pytest.fixture
def env(tmp_path,monkeypatch):
    monkeypatch.setenv('RELAY_DATA',str(tmp_path))
    with TestClient(app) as c:
        c.headers['x-relay-client']='dashboard'
        r=c.post('/api/setup',json={'username':'owner','password':'owner-test-password-123'})
        assert r.status_code==200
        c.headers['x-relay-csrf']=r.json()['csrf']
        key=c.post('/api/agents',json={'name':'Research agent','tools':['save_file','send_webhook','log_event']}).json()
        yield c, {'Authorization':'Bearer '+key['key']}, key['id']


def body(**kw):
    value={'title':'Research report','reason':'Review before delivery','tool':'save_file','arguments':{'filename':'report.md','content':'# Research\n\nExact approved content.\n'},'idempotency_key':str(uuid4())}
    value.update(kw)
    return value


def propose(env,**kw):
    c,h,_=env
    r=c.post('/v1/actions',headers=h,json=body(**kw))
    assert r.status_code==201,r.text
    return r.json()


def decide(c,a,approved=True):
    return c.post('/api/actions/'+a['id']+'/decision',json={'approved':approved,'digest':a['digest']})


def test_complete_file_flow(env):
    c,h,_=env;a=propose(env)
    assert not core.tick()
    assert not (core.root()/'artifacts').exists()
    assert c.get('/api/actions/'+a['id']+'/artifact').status_code==404
    assert decide(c,a).status_code==200
    assert core.tick()
    r=c.get('/v1/actions/'+a['id'],headers=h).json()
    assert r['status']=='succeeded'
    assert c.get(r['result']['download_url']).text==a['arguments']['content']
    assert not core.tick()
    assert decide(c,a).status_code==409
    assert [e['kind'] for e in c.get('/api/actions/'+a['id']).json()['events']]==['submitted','review_required','approved','running','succeeded']


def test_rejected_never_dispatches(env):
    c,_,_=env;a=propose(env)
    assert decide(c,a,False).status_code==200
    assert not core.tick()
    assert not (core.root()/'artifacts').exists()


def test_wrong_digest(env):
    c,_,_=env;a=propose(env)
    assert c.post('/api/actions/'+a['id']+'/decision',json={'approved':True,'digest':'0'*64}).status_code==409
    assert not core.tick()


def test_key_cannot_approve(env):
    c,h,_=env;a=propose(env)
    with TestClient(app) as agent:
        assert agent.post('/api/actions/'+a['id']+'/decision',headers=h,json={'approved':True,'digest':a['digest']}).status_code==401


def test_csrf_and_origin(env):
    c,_,_=env;a=propose(env)
    assert c.post('/api/actions/'+a['id']+'/decision',headers={'x-relay-csrf':'wrong'},json={'approved':True,'digest':a['digest']}).status_code==403
    assert c.post('/api/demo',headers={'Origin':'https://evil.example'}).status_code==403
    assert c.get('/api/actions',headers={'Host':'evil.example'}).status_code==403


def test_idempotency(env):
    c,h,_=env;b=body()
    a=c.post('/v1/actions',headers=h,json=b).json()
    assert c.post('/v1/actions',headers=h,json=b).json()['id']==a['id']
    b['arguments']['content']='Changed'
    assert c.post('/v1/actions',headers=h,json=b).status_code==409


def test_cross_user_and_agent_isolation(env):
    c,h,_=env;a=propose(env)
    with core.connect() as db: db.execute('INSERT INTO users VALUES(?,?,?)',(str(uuid4()),'second',password_hash('second-owner-pass123')))
    with TestClient(app) as other:
        other.headers['x-relay-client']='dashboard'
        s=other.post('/api/login',json={'username':'second','password':'second-owner-pass123'}).json()
        other.headers['x-relay-csrf']=s['csrf']
        assert other.get('/api/actions').json()==[]
        assert other.get('/api/actions/'+a['id']).status_code==404
        assert decide(other,a).status_code==404
        assert other.get('/api/actions/'+a['id']+'/artifact').status_code==404
        assert other.post('/api/agents/'+env[2]+'/revoke').status_code==404
    key=c.post('/api/agents',json={'name':'Different agent','tools':['save_file']}).json()['key']
    assert c.get('/v1/actions/'+a['id'],headers={'Authorization':'Bearer '+key}).status_code==404


@pytest.mark.parametrize('filename',['../secret.txt','report.html','/tmp/out.txt','a/b.md','file.py'])
def test_bad_filenames(env,filename):
    c,h,_=env
    assert c.post('/v1/actions',headers=h,json=body(arguments={'filename':filename,'content':'No'})).status_code==422


def test_scope_and_arbitrary_tools(env):
    c,_,_=env
    k=c.post('/api/agents',json={'name':'Logger only','tools':['log_event']}).json()['key']
    h={'Authorization':'Bearer '+k}
    assert c.post('/v1/actions',headers=h,json=body()).status_code==403
    assert c.post('/v1/actions',headers=h,json=body(tool='execute_shell')).status_code==422


def test_log_policy(env):
    a=propose(env,tool='log_event',arguments={'message':'Research ready'})
    assert a['status']=='succeeded'
    assert a['result']=={'recorded':True}
    assert not (core.root()/'artifacts').exists()


def test_expiry(env,monkeypatch):
    c,_,_=env;a=propose(env,expires_in=60)
    now=time.time();monkeypatch.setattr(time,'time',lambda:now+61)
    assert decide(c,a).status_code==409
    assert not core.tick()
    assert c.get('/api/actions/'+a['id']).json()['status']=='expired'


def test_revoke_queued_action(env):
    c,h,gid=env;a=propose(env);decide(c,a)
    assert c.post('/api/agents/'+gid+'/revoke').status_code==200
    assert not core.tick()
    assert c.get('/api/actions/'+a['id']).json()['status']=='blocked'
    assert c.post('/v1/actions',headers=h,json=body()).status_code==401


def test_immutable_arguments_and_audit(env):
    a=propose(env)
    with pytest.raises(sqlite3.IntegrityError),core.connect() as db:
        db.execute('UPDATE actions SET arguments=? WHERE id=?',('{}',a['id']))
    with pytest.raises(sqlite3.IntegrityError),core.connect() as db: db.execute("UPDATE audit SET message='tamper'")
    with pytest.raises(sqlite3.IntegrityError),core.connect() as db: db.execute('DELETE FROM audit')


def test_webhook_approval_and_destination_change(env,monkeypatch):
    c,_,_=env
    monkeypatch.setattr('relay.app.public_target',lambda url:None)
    sent=[]
    monkeypatch.setattr(core,'post_webhook',lambda *args:sent.append(args) or {'accepted':True})
    assert c.put('/api/connection',json={'url':'https://example.com/hook'}).status_code==200
    a=propose(env,tool='send_webhook',arguments={'payload':{'hello':'world'}})
    assert not core.tick();assert sent==[]
    decide(c,a);core.tick()
    assert sent==[('https://example.com/hook',{'hello':'world'},a['id'])]
    b=propose(env,tool='send_webhook',arguments={'payload':{'next':True}});decide(c,b)
    c.put('/api/connection',json={'url':'https://example.com/new'})
    assert not core.tick();assert len(sent)==1
    assert c.get('/api/actions/'+b['id']).json()['status']=='blocked'


def test_uncertain_no_retry(env,monkeypatch):
    c,_,_=env
    monkeypatch.setattr('relay.app.public_target',lambda url:None)
    c.put('/api/connection',json={'url':'https://example.com/hook'})
    attempts=[]
    def fail(*args): attempts.append(1);raise TimeoutError()
    monkeypatch.setattr(core,'post_webhook',fail)
    a=propose(env,tool='send_webhook',arguments={'payload':{}});decide(c,a);core.tick()
    assert c.get('/api/actions/'+a['id']).json()['status']=='unknown'
    assert not core.tick();assert len(attempts)==1


def test_restart_does_not_replay(env):
    c,_,_=env;a=propose(env)
    with core.connect() as db: db.execute("UPDATE actions SET status='running' WHERE id=?",(a['id'],))
    core.recover()
    assert c.get('/api/actions/'+a['id']).json()['status']=='unknown'
    assert not core.tick()


@pytest.mark.parametrize('url',['http://example.com','https://127.0.0.1/hook','https://localhost/hook','https://user:pass@example.com','https://example.com:8080/hook'])
def test_private_destinations(url):
    with pytest.raises((ValueError,OSError)): public_target(url)


def test_sessions_hashed_logout_setup(env):
    c,h,_=env
    with core.connect() as db:
        assert db.execute('SELECT token FROM sessions').fetchone()[0]!=c.cookies.get('relay_session')
        assert db.execute('SELECT token FROM agents').fetchone()[0]!=h['Authorization'][7:]
    assert c.post('/api/setup',json={'username':'hijack','password':'another-secret-123'}).status_code==409
    assert c.post('/api/logout').status_code==200
    assert c.get('/api/actions').status_code==401


def test_agent_artifact_is_scoped_and_approval_gated(env):
    c,h,gid=env
    a=propose(env)
    url='/v1/actions/'+a['id']+'/artifact'
    assert c.get(url,headers=h).status_code==404
    assert decide(c,a).status_code==200
    core.tick()
    assert c.get(url,headers=h).text==a['arguments']['content']
    other=c.post('/api/agents',json={'name':'Other agent','tools':['save_file']}).json()
    assert c.get(url,headers={'Authorization':'Bearer '+other['key']}).status_code==404
    assert c.get(url).status_code==401
    c.post('/api/agents/'+gid+'/revoke')
    assert c.get(url,headers=h).status_code==401
