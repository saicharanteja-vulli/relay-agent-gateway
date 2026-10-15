"""Run with RELAY_API_KEY set. Submits only; never approves automatically."""
import json
import os
import urllib.request
from uuid import uuid4
base=os.environ.get('RELAY_URL','http://127.0.0.1:8080')
body={'title':'Save a research handoff','reason':'Review this report before creating a file.','tool':'save_file','arguments':{'filename':'report.md','content':'# Agent report\n\nReplace this sample with your actual research.\n'},'idempotency_key':str(uuid4())}
request=urllib.request.Request(base+'/v1/actions',data=json.dumps(body).encode(),headers={'Authorization':'Bearer '+os.environ['RELAY_API_KEY'],'Content-Type':'application/json'})
with urllib.request.urlopen(request,timeout=15) as response: print(response.read().decode())
