#!/usr/bin/env python3
"""Production ingress acceptance. Requires Docker, openssl, and Python 3.

All containers/networks/files belong to a unique fixture; cleanup runs on failure.
The caller supplies an already built Andy Auth image. No deployment credentials.
"""
import argparse
import csv
import io
import ipaddress
import json
from pathlib import Path
import secrets
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


def run(*args):
    return subprocess.check_output(args, text=True, stderr=subprocess.STDOUT).strip()


def eventually(check, label, timeout=120):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        try:
            if check():
                print('PASS:', label, flush=True)
                return
        except (OSError, ValueError, AssertionError) as error:
            last = error
        time.sleep(1)
    raise AssertionError(f'{label}: timed out; last error: {last}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True)
    args = parser.parse_args()
    prefix = 'andy-accept-' + secrets.token_hex(5)
    containers, networks = [], []
    with tempfile.TemporaryDirectory(prefix=prefix) as temporary:
        root = Path(temporary)
        # These are throwaway test keys, with no authority outside this fixture.
        root.chmod(0o755)
        data = root / 'data'
        data.mkdir(mode=0o777)
        data.chmod(0o777)
        (data / 'ring').mkdir(mode=0o777)
        (data / 'ring').chmod(0o777)
        password = secrets.token_urlsafe(24)

        def network(suffix):
            name = prefix + '-' + suffix
            run('docker', 'network', 'create', name)
            networks.append(name)
            # Recreate Docker's allocated subnet explicitly so --ip is supported.
            subnet = json.loads(run('docker', 'network', 'inspect', name))[0]['IPAM']['Config'][0]['Subnet']
            run('docker', 'network', 'rm', name)
            run('docker', 'network', 'create', '--subnet', subnet, name)
            return name

        def container(suffix, *options, image, command=()):
            name = prefix + '-' + suffix
            run('docker', 'create', '--name', name, *options, image, *command)
            containers.append(name)
            return name

        try:
            for purpose in ('signing', 'encryption', 'protection', 'edge'):
                key, cert = root / (purpose + '.key'), root / (purpose + '.crt')
                run('openssl', 'req', '-x509', '-nodes', '-days', '2', '-newkey', 'rsa:2048',
                    '-keyout', str(key), '-out', str(cert), '-subj', '/CN=localhost',
                    '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1')
                if purpose != 'edge':
                    bundle = root / (purpose + '.pfx')
                    run('openssl', 'pkcs12', '-export', '-out', str(bundle), '-inkey', str(key),
                        '-in', str(cert), '-passout', 'pass:' + password)
                    bundle.chmod(0o644)
            (root / 'edge.pem').write_text((root / 'edge.crt').read_text() + (root / 'edge.key').read_text())
            (root / 'edge.pem').chmod(0o644)
            backend, cache, outside = network('backend'), network('cache'), network('outside')
            redis = container('redis', '--network', cache, '--network-alias', 'redis', image='redis:7.4-alpine')
            run('docker', 'start', redis)
            # Reserve the proxy's exact address before configuring app trust.
            config = root / 'haproxy.cfg'
            subnet = json.loads(run('docker', 'network', 'inspect', backend))[0]['IPAM']['Config'][0]['Subnet']
            proxy_ip = str(ipaddress.ip_network(subnet).network_address + 10)
            edge = container('edge', '--network', backend, '--ip', proxy_ip, '-p', '127.0.0.1::8443',
                             '-p', '127.0.0.1::8404', '-v', f'{root}:/fixture:ro',
                             image='haproxy:3.0-alpine', command=('haproxy', '-W', '-db', '-f', '/fixture/haproxy.cfg'))
            run('docker', 'network', 'connect', outside, edge)
            # Docker allocates IP addresses when starting, so start with a valid
            # frontend-only configuration before adding the application backend.
            config.write_text('global\n  maxconn 128\ndefaults\n  mode http\n  timeout connect 2s\n  timeout client 10s\n  timeout server 10s\nfrontend probe\n  bind :8404\n  http-request return status 503\n')
            run('docker', 'start', edge)
            run('docker', 'stop', edge)
            env = {
                'ASPNETCORE_ENVIRONMENT': 'Production', 'ASPNETCORE_URLS': 'http://+:5000',
                'ASPNETCORE_HTTPS_PORT': '443', 'Database__Provider': 'Sqlite',
                'ConnectionStrings__DefaultConnection': 'Data Source=/data/auth.sqlite',
                'OpenIddict__Issuer': 'https://localhost/', 'ADMIN_PASSWORD_DEFAULT': password + 'Aa1!',
                'ADMIN_PASSWORD_SAM': password + 'Aa1!', 'ADMIN_PASSWORD_TY': password + 'Aa1!',
                'DataProtection__KeyRingPath': '/data/ring', 'DataProtection__ApplicationName': prefix,
                'RateLimiting__RequireDistributed': 'true',
                'RateLimiting__RedisConnectionString': 'redis:6379,connectTimeout=1000,syncTimeout=1000,asyncTimeout=1000',
                'ForwardedHeaders__KnownProxies__0': proxy_ip,
                'Diagnostics__EnableClientInfoEndpoint': 'true',
                'IpRateLimiting__GeneralRules__0__Endpoint': 'post:/connect/token',
                'IpRateLimiting__GeneralRules__0__Period': '1h',
                'IpRateLimiting__GeneralRules__0__Limit': '6',
            }
            for group, purpose in [('OpenIddict__Certificates__Signing', 'signing'),
                                   ('OpenIddict__Certificates__Encryption', 'encryption'),
                                   ('DataProtection__Certificates', 'protection')]:
                env[group + '__0__Path'] = '/fixture/' + purpose + '.pfx'
                env[group + '__0__Password'] = password
            options = [item for k, v in env.items() for item in ('-e', k + '=' + v)]
            replicas = []
            for name in ('a', 'b'):
                replica = container(name, '--network', backend, '--network-alias', name,
                                    '-v', f'{root}:/fixture:ro', '-v', f'{data}:/data',
                                    *options, image=args.image)
                run('docker', 'network', 'connect', cache, replica)
                replicas.append(replica)
            config.write_text('''global
  maxconn 128
resolvers docker
  nameserver docker 127.0.0.11:53
  hold valid 1s
defaults
  mode http
  timeout connect 2s
  timeout client 10s
  timeout server 10s
frontend stats
  bind :8404
  stats enable
  stats uri /stats
frontend public
  bind :8443 ssl crt /fixture/edge.pem
  http-request set-header X-Forwarded-For %[src]
  http-request set-header X-Forwarded-Proto https
  default_backend auth
backend auth
  balance roundrobin
  option httpchk
  http-check send meth GET uri /ready ver HTTP/1.1 hdr Host localhost hdr X-Forwarded-Proto https
  http-check expect status 200
  http-response set-header X-Auth-Replica %[srv_name]
  server a a:5000 check inter 1s fall 2 rise 2 resolvers docker resolve-prefer ipv4 init-addr libc,none
  server b b:5000 check inter 1s fall 2 rise 2 resolvers docker resolve-prefer ipv4 init-addr libc,none
''')
            # Start A and the proxy first, then B after migrations/seeding finish.
            run('docker', 'start', replicas[0], edge)
            ports = json.loads(run('docker', 'inspect', edge))[0]['NetworkSettings']['Ports']
            port = ports['8443/tcp'][0]['HostPort']
            stats_port = ports['8404/tcp'][0]['HostPort']
            context = ssl.create_default_context(cafile=str(root / 'edge.crt'))

            def request(path, headers=None, data=None):
                req = urllib.request.Request('https://localhost:' + port + path, headers=headers or {}, data=data)
                try:
                    response = urllib.request.urlopen(req, context=context, timeout=12)
                except urllib.error.HTTPError as error:
                    response = error
                with response:
                    return response.status, response.headers, response.read().decode()

            def status(name):
                with urllib.request.urlopen('http://127.0.0.1:' + stats_port + '/stats;csv', timeout=3) as response:
                    rows = csv.DictReader(io.StringIO(response.read().decode().lstrip('# ')))
                    return next(row['status'] for row in rows if row['pxname'] == 'auth' and row['svname'] == name)

            eventually(lambda: request('/ready')[0] == 200, 'first Production replica is ready')
            run('docker', 'start', replicas[1])
            eventually(lambda: status('a') == status('b') == 'UP', 'both replicas admitted')
            seen = set()
            for _ in range(4):
                code, headers, body = request('/internal/client-info',
                    {'X-Forwarded-For': '198.51.100.99', 'X-Forwarded-Proto': 'http', 'X-Real-IP': '198.51.100.98'})
                assert code == 200, (code, body)
                identity = json.loads(body)
                assert identity['scheme'] == 'https' and identity['ip'] not in ('198.51.100.99', '198.51.100.98'), identity
                seen.add(headers['X-Auth-Replica'])
            assert seen == {'a', 'b'}, seen
            print('PASS: TLS edge overwrites spoofed forwarding headers on both replicas', flush=True)
            seen.clear()
            for i in range(7):
                code, headers, body = request('/connect/token', {'X-Forwarded-For': f'198.51.100.{i + 1}'}, b'grant_type=invalid')
                assert code == (400 if i < 6 else 429), (i, code, body)
                seen.add(headers['X-Auth-Replica'])
            assert seen == {'a', 'b'}, seen
            run('docker', 'restart', replicas[0])
            eventually(lambda: status('a') == 'UP', 'restarted replica readmitted')
            for _ in range(4):
                assert request('/connect/token', data=b'grant_type=invalid')[0] == 429
            print('PASS: shared allowance survives replica switching and restart', flush=True)
            for replica in replicas:
                bindings = json.loads(run('docker', 'inspect', replica))[0]['HostConfig']['PortBindings']
                assert not bindings, bindings
            peer = container('peer', '--network', backend, image='curlimages/curl:8.12.1',
                             command=('-sS', '--max-time', '5', '-o', '/dev/null', '-w', '%{http_code}',
                                      '-H', 'X-Forwarded-Proto: https', '-H', 'X-Forwarded-For: 198.51.100.99',
                                      'http://a:5000/internal/client-info'))
            assert run('docker', 'start', '-a', peer) == '307'
            print('PASS: untrusted private peer cannot spoof HTTPS; apps have no published ports', flush=True)
            app_ip = json.loads(run('docker', 'inspect', replicas[0]))[0]['NetworkSettings']['Networks'][backend]['IPAddress']
            outsider = container('outsider', '--network', outside, image='curlimages/curl:8.12.1',
                                 command=('-sS', '--max-time', '3', 'http://' + app_ip + ':5000/health'))
            subprocess.run(['docker', 'start', '-a', outsider], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            exit_code = json.loads(run('docker', 'inspect', outsider))[0]['State']['ExitCode']
            assert exit_code in (7, 28), exit_code
            print('PASS: external network cannot bypass ingress to reach a backend', flush=True)
            run('docker', 'network', 'disconnect', cache, replicas[0])
            eventually(lambda: status('a').startswith('DOWN') and status('b') == 'UP', 'isolated replica removed by readiness')
            for _ in range(6):
                code, headers, _ = request('/ready')
                assert code == 200 and headers['X-Auth-Replica'] == 'b'
            run('docker', 'network', 'connect', cache, replicas[0])
            eventually(lambda: status('a') == 'UP', 'recovered replica readmitted')
            run('docker', 'stop', redis)
            eventually(lambda: status('a').startswith('DOWN') and status('b').startswith('DOWN'), 'shared Redis outage removes both replicas')
            assert request('/.well-known/openid-configuration')[0] == 503
            print('PASS: no traffic admitted when all replicas are unready', flush=True)
        except Exception:
            for name in containers:
                if name.endswith(('-a', '-b', '-edge')):
                    print(run('docker', 'logs', '--tail', '35', name), flush=True)
            raise
        finally:
            for name in reversed(containers):
                subprocess.run(['docker', 'rm', '-f', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for name in reversed(networks):
                subprocess.run(['docker', 'network', 'rm', name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == '__main__':
    main()
