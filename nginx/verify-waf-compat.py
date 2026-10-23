#!/usr/bin/env python3
"""Verify compatible image defaults without public ports or external requests."""
import argparse
import base64
import hashlib
import http.client
import http.server
import json
import os
from pathlib import Path
import shutil
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import urllib.parse
import uuid


class Backend(http.server.BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*_):pass
    def respond(self):
        length=int(self.headers.get('Content-Length','0'))
        if length>16*1024*1024:self.send_error(413);return
        body=self.rfile.read(length)
        if self.path=='/sse':
            self.send_response(200);self.send_header('Content-Type','text/event-stream');self.send_header('Connection','close');self.end_headers()
            self.wfile.write(b'data: fixture\n\n');self.close_connection=True;return
        if self.path=='/ws' and self.headers.get('Upgrade','').lower()=='websocket':
            value=self.headers['Sec-WebSocket-Key']+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11'
            self.send_response(101);self.send_header('Upgrade','websocket');self.send_header('Connection','Upgrade')
            self.send_header('Sec-WebSocket-Accept',base64.b64encode(hashlib.sha1(value.encode()).digest()).decode());self.end_headers();self.close_connection=True;return
        data=json.dumps({'client':self.headers.get('X-Real-IP'),'method':self.command,'bytes':len(body)}).encode()
        self.send_response(200);self.send_header('Content-Type','application/json');self.send_header('Content-Length',str(len(data)));self.send_header('Connection','close');self.end_headers()
        if self.command!='HEAD':self.wfile.write(data)
        self.close_connection=True
    do_GET=do_HEAD=do_POST=do_OPTIONS=do_PUT=do_PATCH=do_DELETE=respond


class UnixHTTP(socketserver.ThreadingMixIn,socketserver.UnixStreamServer):
    daemon_threads=True


def run(*args):return subprocess.run(args,check=True,capture_output=True,timeout=60)


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--image',required=True);parser.add_argument('--evidence-dir',type=Path);args=parser.parse_args()
    temporary=args.evidence_dir is None
    work=Path(tempfile.mkdtemp(prefix='waf-image-')) if temporary else args.evidence_dir.absolute()
    if not temporary:work.mkdir()
    work.chmod(0o755)
    if len(str(work/'backend.sock'))>103:raise ValueError('Use a shorter evidence directory')
    logs=work/'logs';logs.mkdir()
    backend=UnixHTTP(str(work/'backend.sock'),Backend);os.chmod(work/'backend.sock',0o666)
    threading.Thread(target=backend.serve_forever,daemon=True).start()
    proxy='''location / { proxy_http_version 1.1; proxy_buffering off; proxy_set_header Host $host; proxy_set_header X-Real-IP $remote_addr; proxy_set_header X-Forwarded-For $remote_addr; proxy_set_header Upgrade $http_upgrade; proxy_set_header Connection $fixture_upgrade; proxy_pass http://fixture; }'''
    text='''load_module /etc/nginx/modules/ngx_http_modsecurity_module.so;
pid /run/nginx.pid;
worker_processes 1;
error_log /var/log/nginx/error.log error;
events { worker_connections 256; }
http {
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/modsecurity.conf;
    client_max_body_size 64m;
    map $http_upgrade $fixture_upgrade { default upgrade; '' close; }
    upstream fixture { server unix:/test/backend.sock; }
'''
    for host,settings in [('direct.example',''),('cf.example','set_real_ip_from unix:; real_ip_header CF-Connecting-IP; real_ip_recursive off;'),('off.example','modsecurity off;')]:
        text+='server { listen unix:/test/front.sock; server_name '+host+'; '+settings+proxy+' }\n'
    text+='server { listen 127.0.0.1:18080; server_name direct.example; '+proxy+' }\n}\n'
    (work/'nginx.conf').write_text(text,encoding='utf-8')
    name='waf-image-compat-'+uuid.uuid4().hex[:10];results=[]
    def request(host='direct.example',path='/',method='GET',body=None,headers=None,expected=200,label=None):
        connection=http.client.HTTPConnection('localhost',timeout=15)
        def connect():
            connection.sock=socket.socket(socket.AF_UNIX);connection.sock.settimeout(15);connection.sock.connect(str(work/'front.sock'))
        connection.connect=connect
        connection.request(method,path,body,{'Host':host,'Connection':'close',**(headers or {})})
        response=connection.getresponse();status=response.status;data=response.read();connection.close()
        results.append({'test':label or method+' '+host+path,'status':status,'passed':status==expected})
        if status!=expected:raise AssertionError(f'{label or path}: expected {expected}, got {status}')
        return data
    try:
        run('docker','run','-d','--pull=never','--name',name,'--network=none','--read-only','--memory=768m','--cpus=1','--pids-limit=64',
            '--tmpfs','/tmp:rw,nosuid,size=64m','--tmpfs','/run:rw,nosuid,size=8m','--tmpfs','/var/cache/nginx:rw,nosuid,size=128m',
            '--mount',f'type=bind,src={work},dst=/test','--mount',f'type=bind,src={logs},dst=/var/log/nginx',
            '--mount',f'type=bind,src={work}/nginx.conf,dst=/etc/nginx/nginx.conf,readonly','--entrypoint','nginx',args.image,'-g','daemon off;')
        for _ in range(100):
            if (work/'front.sock').exists():break
            time.sleep(0.05)
        run('docker','exec',name,'nginx','-t')
        for host in ['direct.example','cf.example']:
            for method in ['GET','HEAD','POST','OPTIONS','PUT','PATCH','DELETE']:request(host=host,method=method,label=host+' REST '+method)
        request(method='POST',body=json.dumps({'text':'a'*(1024*1024)}),headers={'Content-Type':'application/json'},label='1MiB JSON headroom')
        request(method='POST',body=urllib.parse.urlencode({'p'+str(i):'x' for i in range(1500)}),headers={'Content-Type':'application/x-www-form-urlencoded'},label='1500 valid arguments')
        request(method='POST',body=urllib.parse.urlencode({'p'+str(i):'x' for i in range(2050)}),headers={'Content-Type':'application/x-www-form-urlencoded'},expected=400,label='argument budget rejects')
        request(method='POST',body='{broken',headers={'Content-Type':'application/json'},expected=400,label='malformed JSON rejects')
        boundary='imageFixtureBoundary'
        body=('--'+boundary+'\r\nContent-Disposition: form-data; name="file"; filename="sample.txt"\r\nContent-Type: text/plain\r\n\r\n').encode()+b'x'*(9*1024*1024)+('\r\n--'+boundary+'--\r\n').encode()
        request(method='POST',body=body,headers={'Content-Type':'multipart/form-data; boundary='+boundary},label='9MiB multipart file')
        for path in ['/feed','/readme.html','/xmlrpc.php','/.well-known/security.txt','/.well-known/acme-challenge/token']:request(path=path,label='legitimate '+path)
        attack='?'+urllib.parse.urlencode({'q':"1' UNION SELECT password FROM users--",'html':'<script>alert(1)</script>','path':'../../etc/passwd'})
        for path in ['/','/feed','/.well-known/acme-challenge/token']:request(path=path+attack,expected=403,label='attack rules active at '+path)
        request(host='off.example',path='/'+attack,label='existing Off preserved')
        for path in ['/.git/config','/nested/.env','/wp-config.php.bak']:request(path=path,expected=403,label='secret guard '+path)
        data=request(host='cf.example',headers={'CF-Connecting-IP':'8.8.8.8'},label='trusted proxy identity')
        assert json.loads(data)['client']=='8.8.8.8'
        data=request(host='cf.example',headers={'CF-Connecting-IP':'2001:4860:4860::8888'},label='trusted proxy IPv6')
        assert json.loads(data)['client']=='2001:4860:4860::8888'
        direct=run('docker','exec',name,'wget','-q','-T','5','-O','-','--header=Host: direct.example','--header=CF-Connecting-IP: 6.6.6.6','--header=X-Forwarded-For: 7.7.7.7','http://127.0.0.1:18080/').stdout
        assert json.loads(direct)['client']=='127.0.0.1';results.append({'test':'direct forwarding-header forgery rejected','passed':True})
        assert b'data: fixture' in request(path='/sse',label='SSE')
        request(path='/ws',headers={'Upgrade':'websocket','Connection':'Upgrade','Sec-WebSocket-Key':'dGhlIHNhbXBsZSBub25jZQ==','Sec-WebSocket-Version':'13'},expected=101,label='WebSocket')
        print(json.dumps({'image':args.image,'passed':len(results),'evidence':str(work)}))
    finally:
        (work/'results.json').write_text(json.dumps(results,indent=2),encoding='utf-8')
        r=subprocess.run(['docker','logs',name],capture_output=True);(work/'container.log').write_bytes(r.stdout+r.stderr)
        subprocess.run(['docker','rm','-f',name],capture_output=True)
        backend.shutdown();backend.server_close()
        if temporary:shutil.rmtree(work)


if __name__=='__main__':main()
