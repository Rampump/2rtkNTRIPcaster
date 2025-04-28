#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
2RTK NTRIP Caster 1.0.8
Copyright (C) 2025 2RTK 
This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.
You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.   
"""
import socketserver
import base64
import time
import configparser
import logging
from threading import Lock, Timer
from collections import deque
import os
import datetime
import signal
import sys

# ------------------------
# Global debug mode
# ------------------------
DEBUG = True

def dbg(*args, **kwargs):
    if DEBUG:
        print(*args, **kwargs)

# ------------------------
# Read configuration
# ------------------------
config = configparser.ConfigParser()
if not config.read('config.ini'):
    print("Configuration file 'config.ini' not found. Please check if the configuration file exists.")
    sys.exit(1)
try:
    ALLOWED_MOUNTS = [m.strip() for m in config.get('General','ALLOWED_MOUNTPOINT').split(',')]
    UPLOAD_PASS    = config.get('General','UPLOAD_PASSWORD')
    MOUNT_FILE     = config.get('General','MOUNTPOINT_FILE')
    DOWNLOAD_USERS = dict(config.items('DownloadUsers'))
except (configparser.NoSectionError, configparser.NoOptionError) as e:
    print(f"Configuration error: {e}")
    sys.exit(1)

# ------------------------
# Log and cache initialization
# ------------------------
logging.basicConfig(
    level=logging.WARNING,
    format='[%(asctime)s] %(levelname)s %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger('2RTK')

BUFFER_MAXLEN = 2000
rtcm_lock     = Lock()
rtcm_buffer   = deque(maxlen=BUFFER_MAXLEN)

clients_lock          = Lock()
authenticated_clients = []  # Store dictionaries: socket, user, mount, agent, addr, auth_time, last_refresh

# logo
BANNER = r"""
    ██████╗ ██████╗ ████████╗██╗  ██╗
    ╚════██╗██╔══██╗╚══██╔══╝██║ ██╔╝
     █████╔╝██████╔╝   ██║   █████╔╝
    ██╔═══╝ ██╔══██╗   ██║   ██  ██
    ███████╗██║  ██║   ██║   ██╗  ██╗
    ╚══════╝╚═╝  ╔═╝   ╚═╝   ╚═╝  ╚═╝
         2RTK Ntrip Caster/1.0.8
"""

def get_client_model(agent):
    if agent and 'NTRIP' in agent:
        return agent.split('NTRIP', 1)[1].strip()
    return 'N/A'

def get_protocol_version(req):
    parts = req.split()
    if len(parts) >= 3:
        protocol = parts[-1]
        if protocol == 'HTTP/1.1':
            return 'NRTIP v2.0'
        elif protocol == 'HTTP/1.0':
            return 'NRTIP v1.0'
    return 'N/A'

# Clear the screen
def clear_banner():
    os.system('cls' if os.name=='nt' else 'clear')
    print(BANNER)
    with clients_lock:
        c = len(authenticated_clients)
    print(f"Authenticated clients: {c}")
    print(f"Allowed mount points: {', '.join(ALLOWED_MOUNTS)}")
    # Schedule the next screen clearing after 100 seconds
    t = Timer(100, clear_banner)
    t.daemon = True
    t.start()

# Clean up old RTCM data
def clear_old():
    now = time.time()
    with rtcm_lock:
        while rtcm_buffer and now - rtcm_buffer[0][0] > 3600:
            rtcm_buffer.popleft()
    logger.info("Cleaned RTCM data older than one hour.")
    # Schedule the next cleaning after 1 hour
    Timer(3600, clear_old, daemon=True).start()

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        dbg(f"Connection: {self.client_address}")
        try:
            raw = self.request.recv(1024).decode(errors='ignore')
        except Exception as e:
            logger.error(f"Receive failed: {e}")
            return
        if not raw:
            return
        req, hdrs = self._parse(raw)
        protocol_version = get_protocol_version(req)
        if req.startswith('SOURCE'):
            self._source(req, hdrs, protocol_version)
        elif req.startswith('GET'):
            self._get(req, hdrs, protocol_version)
        else:
            logger.warning(f"Unknown request: {req}")

    def _parse(self, raw: str):
        lines = raw.splitlines()
        req = lines[0] if lines else ''
        h = {}
        for l in lines[1:]:
            if ': ' in l:
                k,v = l.split(': ',1); h[k.strip()]=v.strip()
        return req, h

    def _source(self, req: str, hdrs: dict, protocol_version):
        dbg("SOURCE Uploader")
        p = req.split()
        if len(p)<3 or p[1]!=UPLOAD_PASS or p[2] not in ALLOWED_MOUNTS:
            self.request.sendall(b'ERROR - Bad Password\r\n'); return
        self.request.sendall(b'ICY 200 OK\r\n')
        mount = p[2]
        agent = get_client_model(hdrs.get('Source-Agent', ''))
        logger.info(f"Upload authentication: mount={mount}, addr={self.client_address}")
        print(f"⟳ {mount} Receiving... Client identifier: {agent}, Protocol standard: {protocol_version}")
        while True:
            try:
                chunk = self.request.recv(4096)
            except Exception as e:
                logger.error(f"SOURCE receive exception: {e}"); break
            if not chunk: break
            ts = time.time()
            with rtcm_lock:
                rtcm_buffer.append((ts,mount,chunk))
            self._broadcast(mount)
        logger.info(f"SOURCE disconnected: {self.client_address}")

    def _get(self, req: str, hdrs: dict, protocol_version):
        dbg("GET User")
        parts = req.split()
        if len(parts)<3: return
        path = parts[1]; mount = path.lstrip('/')
        if path=='/':
            logger.info(f"Request for mount point list: {self.client_address}")
            agent = get_client_model(hdrs.get('User-Agent', ''))
            print(f"Request for mount point list, Client identifier: {agent}, Protocol standard: {protocol_version}")
            return self._send_list()
        logger.info(f"Request verification: mount={mount}, addr={self.client_address}")
        agent = get_client_model(hdrs.get('User-Agent', ''))
        print(f"Request for verification of mount point {mount}, Client identifier: {agent}, Protocol standard: {protocol_version}")
        if mount not in ALLOWED_MOUNTS:
            self.request.sendall(b'HTTP/1.1 404 Not Found\r\n\r\n'); return
        auth = hdrs.get('Authorization')
        if not auth: return self._challenge()
        try:
            m,cred = auth.split(' ',1)
            if m.upper()!='BASIC': raise
            u,pw = base64.b64decode(cred).decode().split(':',1)
            if DOWNLOAD_USERS.get(u)!=pw: raise
        except:
            self.request.sendall(b'HTTP/1.1 401 Unauthorized\r\n\r\n'); return
        now = time.time()
        with clients_lock:
            for c in authenticated_clients:
                if c['user']==u and c['mount']==mount and c['agent']==agent:
                    c['last_refresh']=now; return
            sess=[c for c in authenticated_clients if c['user']==u and c['mount']==mount]
            if len(sess)>=3:
                old=min(sess,key=lambda x:x['auth_time']); authenticated_clients.remove(old)
            client={'socket':self.request,'user':u,'mount':mount,'agent':agent,'addr':self.client_address,'auth_time':now-5,'last_refresh':now}
            authenticated_clients.append(client)
        logger.info(f"Authentication passed: user={u},agent={agent},mount={mount}")
        print(f"Username: {u} Download authentication passed for mount point {mount}, Client identifier: {agent}, Protocol standard: {protocol_version}")
        ver, date = parts[2], datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        if ver=='HTTP/1.1' and hdrs.get('Ntrip-Version')=='Ntrip/2.0':
            hdr = '\r\n'.join([
                'HTTP/1.1 200 OK','Ntrip-Version: Ntrip/2.0','Server: 2RTK Caster/1.0.8',
                f'Date: {date}','Cache-Control: no-store,max-age=0','Pragma: no-cache',
                'Connection: close','Content-Type: gnss/data','Transfer-Encoding: chunked',''
            ])
        else:
            hdr='ICY 200 OK\r\n'
        self.request.sendall(hdr.encode())
        # Keep hanging
        try:
            while True: time.sleep(0.1)
        except: pass
        finally:
            with clients_lock:
                if client in authenticated_clients: authenticated_clients.remove(client)
            logger.info(f"Download closed: {self.client_address}")

    def _send_list(self):
        try: tbl=open(MOUNT_FILE).read()
        except: tbl=''
        date=datetime.datetime.utcnow().strftime('%a, %d %b %Y %H:%M:%S GMT')
        resp='\r\n'.join([
            'SOURCETABLE 200 OK','Server: 2RTK Caster/1.0.8',f'Date: {date}',
            'Content-Type: text/plain',f'Content-Length: {len(tbl)}','Connection: close','','',tbl
        ])
        self.request.sendall(resp.encode())

    def _challenge(self):
        self.request.sendall(b'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="NTRIP"\r\nContent-Length: 0\r\n\r\n')

    def _broadcast(self, mount):
        with rtcm_lock:
            data = [(ts,chunk) for ts,mp,chunk in rtcm_buffer if mp==mount]
        to_remove=[]
        with clients_lock:
            clients=list(authenticated_clients)
        for c in clients:
            if c['mount']!=mount: continue
            for ts,chunk in data:
                if ts<=c['auth_time']: continue
                try:
                    c['socket'].sendall(chunk)
                except Exception as e:
                    logger.warning(f"Communication closed, removing connection data: addr={c['addr']}, err={e}")
                    to_remove.append(c)
                    break
        if to_remove:
            with clients_lock:
                for c in to_remove:
                    if c in authenticated_clients:
                        authenticated_clients.remove(c)

def shutdown(sig, frame):
    print("\nShutting down the server...")
    sys.exit(0)

if __name__=='__main__':
    socketserver.ThreadingTCPServer.allow_reuse_address = True
    # Initial screen clearing
    clear_banner()
    # Schedule the first buffer cleaning after 1 hour
    t_clean = Timer(3600, clear_old)
    t_clean.daemon = True
    t_clean.start()
    host = config.get('Server','HOST')
    port = config.getint('Server','PORT')
    try:
        server = socketserver.ThreadingTCPServer((host, port), Handler)
    except OSError as e:
        logger.error(f"Port binding failed: {e}")
        sys.exit(1)
    print(f"Starting 2RTK NTRIP Caster {host}:{port}")
    logger.info(f"Starting Caster {host}:{port}")
    server.serve_forever()
