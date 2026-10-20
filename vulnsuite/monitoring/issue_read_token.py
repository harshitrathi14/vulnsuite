"""Refresh the local assessment bridge's scoped, eight-hour read-only JWT."""
from pathlib import Path
import time
from jose import jwt
ROOT=Path('/mnt/harshitrathi/vulnsuite/runtime')
now=int(time.time())
token=jwt.encode({'sub':'protection-assessment-reader','iss':'https://vulnsuite.local/offline','aud':'vulnsuite-api','iat':now,'exp':now+28800,'tenant_id':'00000000-0000-0000-0000-000000000001','roles':['viewer']},(ROOT/'local-signing.pem').read_text(),algorithm='RS256',headers={'kid':'local-server-1'})
p=ROOT/'assessment-token.tmp'
p.touch(mode=0o600,exist_ok=True);p.chmod(0o600);p.write_text(token);p.replace(ROOT/'assessment-token')
