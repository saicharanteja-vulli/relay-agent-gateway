import hashlib
import json
import os
import sqlite3
import time
from contextlib import contextmanager
from pathlib import Path
from uuid import uuid4
from .orbit_security import digest, post_webhook


def root():
    return Path(os.environ.get('RELAY_DATA', Path(__file__).resolve().parent.parent / 'data')).resolve()


@contextmanager
def connect():
    root().mkdir(parents=True, exist_ok=True, mode=0o700)
    db = sqlite3.connect(root() / 'relay.db', timeout=15)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    try:
        yield db
        db.commit()
    except BaseException:
        db.rollback()
        raise
    finally:
        db.close()


def initialize():
    with connect() as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript('''
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, owner TEXT REFERENCES users(id), csrf TEXT, expires REAL);
CREATE TABLE IF NOT EXISTS attempts(ip TEXT, at REAL);
CREATE TABLE IF NOT EXISTS agents(id TEXT PRIMARY KEY, owner TEXT REFERENCES users(id), name TEXT NOT NULL, token TEXT UNIQUE NOT NULL, prefix TEXT, tools TEXT, active INTEGER DEFAULT 1, created REAL);
CREATE TABLE IF NOT EXISTS actions(id TEXT PRIMARY KEY, owner TEXT REFERENCES users(id), agent TEXT REFERENCES agents(id), title TEXT, reason TEXT, tool TEXT, arguments TEXT, digest TEXT, status TEXT, created REAL, expires REAL, decided REAL, result TEXT, error TEXT, idem TEXT, request_digest TEXT, UNIQUE(agent,idem));
CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY AUTOINCREMENT, owner TEXT, action TEXT, kind TEXT, message TEXT, at REAL);
CREATE TABLE IF NOT EXISTS settings(owner TEXT PRIMARY KEY REFERENCES users(id), webhook TEXT DEFAULT '');
CREATE TABLE IF NOT EXISTS heartbeat(id INTEGER PRIMARY KEY CHECK(id=1), at REAL);
CREATE TRIGGER IF NOT EXISTS immutable_proposal BEFORE UPDATE OF owner,agent,title,reason,tool,arguments,digest,expires,idem,request_digest ON actions BEGIN SELECT RAISE(ABORT,'Proposals are immutable'); END;
CREATE TRIGGER IF NOT EXISTS immutable_audit BEFORE UPDATE ON audit BEGIN SELECT RAISE(ABORT,'Audit events are immutable'); END;
CREATE TRIGGER IF NOT EXISTS no_audit_delete BEFORE DELETE ON audit BEGIN SELECT RAISE(ABORT,'Audit events cannot be deleted'); END;
''')
    os.chmod(root() / 'relay.db', 0o600)


def record(db, owner, action, kind, message):
    db.execute('INSERT INTO audit(owner,action,kind,message,at) VALUES(?,?,?,?,?)', (owner,action,kind,message,time.time()))


def expire(db):
    for a in db.execute("SELECT * FROM actions WHERE status IN ('pending','approved') AND expires<=?", (time.time(),)).fetchall():
        db.execute("UPDATE actions SET status='expired' WHERE id=?", (a['id'],))
        record(db,a['owner'],a['id'],'expired','Approval window expired; execution blocked.')


def artifact(action):
    return root() / 'artifacts' / action['id'] / json.loads(action['arguments'])['filename']


def recover():
    with connect() as db:
        for a in db.execute("SELECT * FROM actions WHERE status='running'").fetchall():
            db.execute("UPDATE actions SET status='unknown',error='Worker interrupted; inspect the destination before submitting a new action.' WHERE id=?", (a['id'],))
            record(db,a['owner'],a['id'],'unknown','Worker recovery: action will not be replayed.')


def tick():
    with connect() as db:
        db.execute('BEGIN IMMEDIATE')
        db.execute('INSERT OR REPLACE INTO heartbeat VALUES(1,?)',(time.time(),))
        expire(db)
        a=db.execute("SELECT a.* FROM actions a JOIN agents g ON g.id=a.agent WHERE a.status='approved' AND g.active=1 ORDER BY a.created LIMIT 1").fetchone()
        if not a: return False
        a=dict(a)
        args=json.loads(a['arguments'])
        if digest(a['tool'],args)!=a['digest']:
            db.execute("UPDATE actions SET status='blocked',error='Proposal integrity check failed' WHERE id=?",(a['id'],))
            record(db,a['owner'],a['id'],'blocked','Proposal integrity check failed.')
            return True
        db.execute("UPDATE actions SET status='running' WHERE id=?",(a['id'],))
        record(db,a['owner'],a['id'],'running','Worker claimed the exact approved action. No automatic retries.')
    try:
        if a['tool']=='save_file':
            p=artifact(a)
            p.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
            with p.open('x',encoding='utf-8') as f: f.write(args['content'])
            result={'filename':args['filename'],'bytes':len(args['content'].encode()),'download_url':f"/api/actions/{a['id']}/artifact"}
        elif a['tool']=='send_webhook':
            result=post_webhook(args['destination'],args['payload'],a['id'])
        else:
            raise ValueError('Unsupported executor')
        status,error='succeeded',None
    except Exception:
        status,result,error='unknown',None,'Execution could not be confirmed. Check the destination before submitting another action.'
    with connect() as db:
        db.execute('UPDATE actions SET status=?,result=?,error=? WHERE id=?',(status,json.dumps(result) if result else None,error,a['id']))
        record(db,a['owner'],a['id'],status,'Execution completed.' if result else error)
    return True


def fingerprint(value):
    return hashlib.sha256(value.encode()).hexdigest()
