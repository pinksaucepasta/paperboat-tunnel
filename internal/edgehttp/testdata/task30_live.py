"""Opt-in Hetzner Task30 runner; copy beside three workspace-built test binaries.

Only task-owned Docker resources, exact DNS names and two temporary /128s are
modified. Deployed server environment is read in memory for its DNS reference.
No credential values or provider response bodies are printed.
"""
import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parent
AUX = 'paperboat-task30-live-aux'
DB = 'paperboat-task30-live-db'
CACHE = 'paperboat-task30-live-cache'
BROWSER = 'paperboat-task30-browser'
IPS = ['2a01:4f9:c013:cb4a::30:1', '2a01:4f9:c013:cb4a::30:2']

def command(args, **kwargs):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, **kwargs)
    if result.returncode:
        raise RuntimeError('task30 command failed: ' + args[0])
    return result.stdout.strip()

def docker(*args):
    return command(['docker', *args])

def write(path, value):
    path = Path(path)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, 'w') as output:
        json.dump(value, output)

def deployed_dns():
    inspected = json.loads(docker('inspect', 'paperboat-server-1'))[0]
    environment = dict(item.split('=', 1) for item in inspected['Config']['Env'] if '=' in item)
    reference = environment['PAPERBOAT_CERTIFICATES_DNS_TOKEN_REFERENCE']
    normalized = ''.join(c if c.isascii() and c.isalnum() else '_' for c in reference.upper())
    key = 'PAPERBOAT_CERT_SECRET_' + normalized + '_' + hashlib.sha256(reference.encode()).hexdigest()[:12]
    return environment['PAPERBOAT_CERTIFICATES_DNS_ZONE_ID'], reference, key, environment[key]

def namespace_record(zone, token, name=None, record_id=None):
    base = 'https://api.cloudflare.com/client/v4/zones/' + zone + '/dns_records'
    headers = {'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json'}
    if record_id:
        record = json.load(urllib.request.urlopen(urllib.request.Request(base + '/' + record_id, headers=headers), timeout=5))['result']
        if record['name'] != name or record['type'] != 'TXT' or record.get('comment') != 'paperboat-task30-namespace' or record['content'].strip('"') != 'paperboat-task30-isolated-namespace':
            raise RuntimeError('namespace ownership changed; refusing deletion')
        urllib.request.urlopen(urllib.request.Request(base + '/' + record_id, headers=headers, method='DELETE'), timeout=5).close()
        return
    payload = dict(type='TXT', name=name, content='paperboat-task30-isolated-namespace', ttl=60, comment='paperboat-task30-namespace')
    result = json.load(urllib.request.urlopen(urllib.request.Request(base, data=json.dumps(payload).encode(), headers=headers), timeout=5))
    return result['result']['id']

def publish(request_path):
    request = json.loads(Path(request_path).read_text())
    zone, reference, token_key, token = deployed_dns()
    database = json.loads(docker('inspect', DB))[0]
    database_env = dict(item.split('=', 1) for item in database['Config']['Env'] if '=' in item)
    database_ip = database['NetworkSettings']['Networks'][AUX]['IPAddress']
    dsn = 'postgres://task30:' + database_env['POSTGRES_PASSWORD'] + '@' + database_ip + ':5432/task30_dns_test?sslmode=disable'
    env = os.environ.copy()
    env.pop('PAPERBOAT_DATABASE_DSN', None)
    env[token_key] = token
    config_path, desired_path, result_path = [ROOT / name for name in ['dns-config', 'dns-desired', 'dns-result']]
    env['PAPERBOAT_TASK30_LIVE_DNS_CONFIG'] = str(config_path)
    for host in request['Hosts']:
        if not host.startswith('task30-') or not host.endswith('.pprbt.dev'):
            raise RuntimeError('refusing non-task hostname')
        deadline = time.monotonic() + 180
        while time.monotonic() < deadline:
            now = datetime.datetime.now(datetime.timezone.utc)
            desired = dict(Owner='task30_' + hashlib.sha256(host.encode()).hexdigest()[:24], Hostname=host,
                           ResourceGeneration=1, ReadinessVersion=','.join(request['Addresses']),
                           ObservedAt=now.isoformat(), ValidUntil=(now + datetime.timedelta(seconds=15)).isoformat(),
                           Addresses=request['Addresses'], IPv6ReachabilityVerified=True)
            write(desired_path, desired)
            write(config_path, dict(dsn=dsn, zone_id=zone, token_reference=reference,
                                    desired_path=str(desired_path), result_path=str(result_path),
                                    migrate=not (ROOT / 'migrated').exists()))
            run = subprocess.run(['docker', 'run', '--rm', '--network', 'host', '--dns', '1.1.1.1', '--label', 'paperboat.task=30', '--mount', 'type=bind,src=' + str(ROOT) + ',dst=' + str(ROOT), '--env', token_key, '--env', 'PAPERBOAT_TASK30_LIVE_DNS_CONFIG', '--entrypoint', str(ROOT / 'dns.test'), 'postgres:17-alpine', '-test.run=^TestTask30LiveDNSReconcile$',
                                  '-test.count=1', '-test.timeout=1m'], env=env,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            if run.returncode:
                raise RuntimeError('live DNS helper failed (credentials/output withheld)')
            (ROOT / 'migrated').touch(mode=0o600)
            if not (ROOT / 'regression-checked').exists():
                checks_env = env.copy()
                checks_env['PAPERBOAT_TEST_DATABASE_DSN'] = dsn
                check = subprocess.run([str(ROOT / 'dns.test'), '-test.run=^(TestAddressReconcilerReservedWithdrawalOnPostgres|TestAddressReconcilerPersistsUncertainWriteAndRetainsHealthyRecordOnPostgres|TestDatabaseCloudflareAddressAdmissionSharedOnPostgres)$', '-test.count=1', '-test.timeout=1m'], env=checks_env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                if check.returncode:
                    print('\n'.join(line for line in check.stdout.splitlines() if 'FAIL' in line or '.go:' in line), flush=True)
                    raise RuntimeError('isolated DNS regression checks failed')
                (ROOT / 'regression-checked').touch(mode=0o600)
                print('isolated PostgreSQL DNS reservation/reconciliation checks passed', flush=True)

            result = json.loads(result_path.read_text())
            if result['state'] == 'verified' and not result.get('error_kind'):
                print(host, 'verified', 'addresses=' + str(len(request['Addresses'])),
                      'generation=' + str(result.get('publication_generation')), flush=True)
                break
            if result.get('error_kind') in ['conflict', 'unsupported', 'invalid']:
                raise RuntimeError('publication rejected: ' + result['error_kind'])
            time.sleep(6)
        else:
            raise RuntimeError('live publication did not converge within 180 seconds')

def run():
    for name in [DB, CACHE, BROWSER]:
        probe = subprocess.run(['docker', 'inspect', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if probe.returncode == 0:
            raise RuntimeError('task resource already exists; inspect before reusing')
    zone, _, _, token = deployed_dns()
    request = urllib.request.Request('https://api.cloudflare.com/client/v4/zones/' + zone,
                                     headers={'Authorization': 'Bearer ' + token})
    zone_name = json.load(urllib.request.urlopen(request, timeout=5))['result']['name']
    if zone_name != 'pprbt.dev':
        raise RuntimeError('unexpected test zone')
    suffix = secrets.token_hex(4)
    parent = 'task30-live-' + suffix + '.' + zone_name
    hosts = ['task30-http.' + parent, 'task30-tcp.' + parent]
    anchor_id = namespace_record(zone, token, name=parent)
    write(ROOT / 'namespace-record', dict(name=parent, id=anchor_id))
    write(ROOT / 'owned-hosts', hosts)
    cleanup_errors = []
    network_created = False
    try:
        docker('network', 'create', '--label', 'paperboat.task=30', AUX)
        network_created = True
        docker('run', '-d', '--name', DB, '--network', AUX, '--label', 'paperboat.task=30',
               '--memory=384m', '--pids-limit=128', '--tmpfs', '/var/lib/postgresql/data:rw,size=256m',
               '-e', 'POSTGRES_USER=task30', '-e', 'POSTGRES_DB=task30_dns_test',
               '-e', 'POSTGRES_PASSWORD=' + secrets.token_hex(24), 'postgres:17-alpine')
        for _ in range(30):
            ready = subprocess.run(['docker', 'exec', DB, 'pg_isready', '-U', 'task30', '-d', 'task30_dns_test'],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if ready.returncode == 0:
                break
            time.sleep(.2)
        else:
            raise RuntimeError('isolated database not ready')
        docker('run', '-d', '--name', CACHE, '--network', AUX, '--label', 'paperboat.task=30',
               '--memory=64m', '--pids-limit=32', 'alpine:3.22', 'sh', '-c',
               'apk add --no-cache dnsmasq >/dev/null && exec dnsmasq --keep-in-foreground --user=root --no-resolv --no-hosts --server=1.1.1.1 --server=8.8.8.8 --cache-size=150')
        for _ in range(60):
            ready = subprocess.run(['docker', 'exec', CACHE, 'pidof', 'dnsmasq'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if ready.returncode == 0:
                break
            time.sleep(.5)
        else:
            raise RuntimeError('isolated caching resolver not ready')
        cache_ip = json.loads(docker('inspect', CACHE))[0]['NetworkSettings']['Networks'][AUX]['IPAddress']
        browser_only = os.environ.get('PAPERBOAT_TASK30_BROWSER_ONLY') == '1'
        if browser_only:
            docker('run', '-d', '--name', BROWSER, '--network', 'host', '--dns', cache_ip,
                   '--label', 'paperboat.task=30', '--memory=768m', '--pids-limit=256',
                   'alpine:3.22', 'sleep', '900')
            docker('exec', BROWSER, 'apk', 'add', '--no-cache', 'chromium', 'nss-tools', 'py3-websocket-client')
            docker('cp', str(ROOT / 'task30_browser.py'), BROWSER + ':/task30_browser.py')
            print(docker('exec', BROWSER, 'chromium', '--version'), flush=True)
        write(ROOT / 'live-fixture', dict(BrowserOnly=browser_only, HTTPHostname=hosts[0], TCPHostname=hosts[1],
              PublicIPs=IPS, DNSAddress=cache_ip + ':53', Publisher=str(Path(__file__).resolve())))
        env = os.environ.copy()
        env['PAPERBOAT_TASK30_DOCKER_DIRECTORY'] = str(ROOT)
        env['PAPERBOAT_TASK30_LIVE_FIXTURE'] = str(ROOT / 'live-fixture')
        result = subprocess.run([str(ROOT / 'edge.test'), '-test.run=^TestTask30DockerEdgeRecovery$',
                                 '-test.count=1', '-test.v', '-test.timeout=15m'], env=env)
        if result.returncode:
            raise RuntimeError('live edge test failed')
    finally:
        # Keep the test database/addresses only if DNS cleanup fails, so a later
        # cleanup can retain owner/generation fencing instead of deleting blindly.
        if (ROOT / 'migrated').exists():
            write(ROOT / 'withdraw-request', dict(Hosts=hosts, Addresses=[]))
            try:
                publish(ROOT / 'withdraw-request')
            except Exception:
                cleanup_errors.append('DNS withdrawal needs retry; retained isolated state at ' + str(ROOT))
        if not cleanup_errors:
            for name in [BROWSER, CACHE, DB]:
                subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if network_created:
                docker('network', 'rm', AUX)
            namespace_record(zone, token, name=parent, record_id=anchor_id)
        if cleanup_errors:
            raise RuntimeError('; '.join(cleanup_errors))

if __name__ == '__main__':
    try:
        if len(sys.argv) == 2:
            publish(sys.argv[1])
        else:
            run()
    except Exception as error:
        print(type(error).__name__ + ': ' + str(error), file=sys.stderr)
        sys.exit(1)
