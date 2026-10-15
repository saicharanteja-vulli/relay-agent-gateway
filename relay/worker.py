"""Run separately: python -m relay.worker. Never replay uncertain writes."""
import fcntl
import time
from .core import initialize, root, recover, tick


def main():
    initialize()
    with (root() / 'worker.lock').open('w') as lock:
        try: fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise SystemExit('A Relay worker is already running.')
        recover()
        print('Relay worker ready',flush=True)
        while True:
            tick()
            time.sleep(.6)

if __name__=='__main__': main()
