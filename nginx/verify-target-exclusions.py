#!/usr/bin/env python3
"""Check target exclusions and audit scores without networking or host services."""
import argparse
import http.client
import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import uuid

spec=importlib.util.spec_from_file_location('compat',Path(__file__).with_name('verify-waf-compat.py'))
compat=importlib.util.module_from_spec(spec);spec.loader.exec_module(compat)


def check(image,work):
    work.mkdir();work.chmod(0o755);logs=work/'logs';logs.mkdir()
    backend=compat.UnixHTTP(str(work/'backend.sock'),compat.Backend)
    os.chmod(work/'backend.sock',0o666);threading.Thread(target=backend.serve_forever,daemon=True).start()
    cases=[
        ('static-exact', ['fixture-static'],'fixture-static','ARGS:foo','foo',200),
        ('static-other-field',['fixture-static'],'fixture-static','ARGS:foo','bar',403),
        ('static-collection',['fixture-static'],'fixture-static','ARGS','foo',200),
        ('static-wrong-tag',['fixture-static'],'other','ARGS:foo','foo',403),
        ('case-sensitive-field',['fixture-static'],'fixture-static','ARGS:Foo','foo',403),
        ('case-sensitive-tag',['fixture-static'],'FIXTURE-STATIC','ARGS:foo','foo',403),
        ('multiple-tags',['first','fixture-static'],'fixture-static','ARGS:foo','foo',200),
        ('duplicate-exclusion',['fixture-static'],'fixture-static','ARGS:foo','foo',200),
        ('dynamic-exact',['%{tx.fixture_tag}'],'fixture-dynamic','ARGS:foo','foo',200),
        ('dynamic-other-field',['%{tx.fixture_tag}'],'fixture-dynamic','ARGS:foo','bar',403),
        ('dynamic-collection',['%{tx.fixture_tag}'],'fixture-dynamic','ARGS','foo',200),
        ('dynamic-wrong-tag',['%{tx.fixture_tag}'],'other','ARGS:foo','foo',403),
        ('mixed-dynamic-tags',['fixture-static','%{tx.fixture_tag}','%{DURATION}','%{TIME_EPOCH}'],'fixture-static','ARGS:foo','bar',403),
        ('mixed-dynamic-wrong-tag',['fixture-static','%{tx.fixture_tag}','%{DURATION}','%{TIME_EPOCH}'],'not-present','ARGS:missing','foo',403),
        ('no-tags',[],'fixture-static','ARGS:foo','foo',403),
    ]
    servers=[]
    for i,(label,tags,remove,target,field,status)in enumerate(cases):
        control='ctl:ruleRemoveTargetByTag='+remove+';'+target
        if label=='duplicate-exclusion':control+=','+control
        rules=['SecRuleEngine On','SecRequestBodyAccess On','SecAuditEngine On','SecAuditLogType Serial',
               'SecAuditLogFormat JSON','SecAuditLogParts AHZ','SecAuditLog /var/log/nginx/audit.json',
               'SecAction "id:500001,phase:1,pass,nolog,setvar:tx.fixture_tag=fixture-dynamic,setvar:tx.fixture_score=0"',
               'SecAction "id:500002,phase:1,pass,nolog,'+control+'"',
               'SecRule ARGS "@streq fixture-block" "id:600001,phase:2,deny,status:403,log,t:none,msg:fixture-rule,logdata:\'score=%{tx.fixture_score}\',setvar:tx.fixture_score=+5'+''.join(",tag:'"+tag+"'"for tag in tags)+'"']
        (work/('rules-'+str(i)+'.conf')).write_text('\n'.join(rules)+'\n')
        if i==0:
            (work/'empty-tag.conf').write_text('\n'.join(rules).replace("tag:'fixture-static'","tag:''")+'\n')
        servers.append('server { listen unix:/test/front.sock; server_name t'+str(i)+'.example; modsecurity on; modsecurity_rules_file /test/rules-'+str(i)+'.conf; location / { proxy_pass http://fixture; } }')
    (work/'nginx.conf').write_text('load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;\npid /run/nginx.pid;\nerror_log /var/log/nginx/error.log error;\nworker_processes 1;\nevents { worker_connections 128; }\nhttp { upstream fixture { server unix:/test/backend.sock; }\n'+'\n'.join(servers)+'\n}\n')
    (work/'invalid-empty-tag.conf').write_text((work/'nginx.conf').read_text().replace('/test/rules-0.conf','/test/empty-tag.conf'))
    name='waf-target-exclusions-'+uuid.uuid4().hex[:8];results=[]
    try:
        compat.run('docker','run','-d','--pull=never','--name',name,'--network=none','--read-only','--cpus=1','--memory=512m','--pids-limit=64',
                   '--tmpfs','/run:rw,size=8m','--tmpfs','/tmp:rw,size=8m','--tmpfs','/var/cache/nginx:rw,size=8m',
                   '--mount','type=bind,src='+str(work)+',dst=/test','--mount','type=bind,src='+str(logs)+',dst=/var/log/nginx',
                   '--mount','type=bind,src='+str(work/'nginx.conf')+',dst=/etc/nginx/nginx.conf,readonly','--entrypoint','nginx',image,'-g','daemon off;')
        for _ in range(100):
            if(work/'front.sock').exists():break
            time.sleep(.05)
        compat.run('docker','exec',name,'nginx','-t')
        for i,(label,tags,remove,target,field,expected)in enumerate(cases):
            c=http.client.HTTPConnection('localhost',timeout=10)
            def connect():
                c.sock=socket.socket(socket.AF_UNIX);c.sock.settimeout(10);c.sock.connect(str(work/'front.sock'))
            c.connect=connect;c.request('GET','/'+label+'?'+field+'=fixture-block',headers={'Host':'t'+str(i)+'.example','Connection':'close'})
            r=c.getresponse();r.read();status=r.status;c.close()
            assert status==expected,(label,status,expected)
            results.append({'test':label,'status':status,'rules':[],'scores':[]})
        invalid=subprocess.run(['docker','exec',name,'nginx','-t','-c','/test/invalid-empty-tag.conf'],capture_output=True)
        assert invalid.returncode!=0 and b'empty-tag.conf' in invalid.stderr and b'syntax error' in invalid.stderr
        results.append({'test':'empty-literal-tag-invalid','status':'configuration-rejected','rules':[],'scores':[]})
    finally:
        output=subprocess.run(['docker','logs',name],capture_output=True)
        (work/'container.log').write_bytes(output.stdout+output.stderr)
        subprocess.run(['docker','rm','-f',name],capture_output=True)
        backend.shutdown();backend.server_close()
    records={}
    for line in(logs/'audit.json').read_text().splitlines():
        d=json.loads(line)['transaction'];label=d['request']['uri'].split('?',1)[0].removeprefix('/')
        records[label]=[m['details']for m in d.get('messages',[])if str(m.get('details',{}).get('ruleId'))=='600001']
    for r in results:
        records_for_case=records.get(r['test'],[])
        r['rules']=[str(x['ruleId'])for x in records_for_case];r['scores']=[x.get('data','')for x in records_for_case]
        assert r['rules']==(['600001']if r['status']==403 else []),r
        assert all('score=5'in x for x in r['scores']),r
    (work/'results.json').write_text(json.dumps(results,indent=2))
    return results


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('--image',required=True);p.add_argument('--baseline');p.add_argument('--evidence-dir',type=Path);a=p.parse_args()
    root=a.evidence_dir or Path(tempfile.mkdtemp(prefix='target-exclusions-'));root.mkdir(exist_ok=True)
    try:
        current=check(a.image,root/'current')
        if a.baseline:assert current==check(a.baseline,root/'baseline')
        print(json.dumps({'passed':len(current),'baseline_identical':bool(a.baseline),'evidence':str(root)if a.evidence_dir else None}))
    finally:
        if a.evidence_dir is None:shutil.rmtree(root)
