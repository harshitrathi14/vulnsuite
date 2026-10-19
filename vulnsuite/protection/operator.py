"""Inspect operational records or request a temporary block using a protected token file."""
import argparse
import json
from pathlib import Path
from urllib.parse import urlparse

import httpx


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--url', required=True)
    parser.add_argument('--token-file', required=True)
    commands = parser.add_subparsers(dest='command', required=True)
    for name in ('alerts', 'hosts', 'responses', 'audit', 'overview', 'incidents',
                 'playbooks', 'suppressions'):
        commands.add_parser(name)
    block = commands.add_parser('block')
    block.add_argument('--alert-id', type=int, required=True)
    block.add_argument('--duration', type=int, default=300)
    block.add_argument('--reason', required=True)
    args = parser.parse_args()
    parsed = urlparse(args.url)
    if parsed.scheme != 'https' and not (parsed.scheme == 'http' and parsed.hostname in ('127.0.0.1', '::1')):
        parser.error('HTTPS required except on loopback')
    token = Path(args.token_file).read_text().strip()
    with httpx.Client(base_url=args.url.rstrip('/'), timeout=15, trust_env=False,
                      headers={'Authorization': f'Bearer {token}'}) as client:
        if args.command == 'block':
            response = client.post('/v1/blocks', json={'alert_id': args.alert_id,
                                   'duration_seconds': args.duration, 'reason': args.reason})
        else:
            response = client.get(f'/v1/{args.command}')
        if response.is_error:
            parser.exit(1, f'Protection API returned {response.status_code}: {response.text}\n')
        print(json.dumps(response.json(), indent=2))


if __name__ == '__main__':
    main()
