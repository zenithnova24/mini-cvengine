import socket, json, concurrent.futures
from datetime import datetime, timezone

COMMON_PORTS = [22, 80, 443, 3000, 8000, 8080]
TIMEOUT = 0.8

def resolve(host):
    try:
        return socket.gethostbyname(host)
    except OSError as exc:
        return {'error': f'DNS resolution failed: {exc}'}

def probe(ip, port):
    evidence = {'port': port, 'state': 'closed', 'banner': ''}
    try:
        with socket.create_connection((ip, port), timeout=TIMEOUT) as sock:
            evidence['state'] = 'open'
            sock.settimeout(TIMEOUT)
            try:
                banner = sock.recv(128).decode('utf-8', errors='replace').strip()
                evidence['banner'] = banner
            except socket.timeout:
                evidence['banner'] = '<no banner>'
    except OSError:
        pass
    return evidence

def assess(host):
    ip = resolve(host)
    if isinstance(ip, dict):
        return {'target': host, 'error': ip['error']}
    findings = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(COMMON_PORTS)) as pool:
        futures = [pool.submit(probe, ip, port) for port in COMMON_PORTS]
        for future in concurrent.futures.as_completed(futures):
            findings.append(future.result())
    open_ports = [f for f in findings if f['state'] == 'open']
    return {
        'target': host,
        'ip': ip,
        'assessed_at': datetime.now(timezone.utc).isoformat(),
        'open_ports': sorted(open_ports, key=lambda item: item['port']),
        'evidence': sorted(findings, key=lambda item: item['port']),
    }

if __name__ == '__main__':
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else '127.0.0.1'
    print(json.dumps(assess(target), indent=2, ensure_ascii=False))
