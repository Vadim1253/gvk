"""Copy only encrypted cloud envelopes. Never decrypt or publish source credentials."""
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import sys
import urllib.request

LIMIT = 8 * 1024 * 1024

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def fetch(url, body=None, headers=None):
    if not url.startswith('https://'): raise ValueError('HTTPS required')
    request = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                     headers={'Content-Type':'application/json', **(headers or {})})
    with urllib.request.build_opener(NoRedirect).open(request, timeout=30) as response:
        raw = response.read(LIMIT + 1)
    if len(raw) > LIMIT: raise ValueError('Oversized response')
    value = json.loads(raw)
    if not isinstance(value, dict): raise ValueError('Invalid response')
    return value

def encrypted(entry, cipher):
    nonce = entry['nonce']
    payload = entry[cipher]
    if len(base64.b64decode(nonce, validate=True)) != 12: raise ValueError('Invalid nonce')
    if not 16 <= len(base64.b64decode(payload, validate=True)) <= LIMIT: raise ValueError('Invalid ciphertext')
    return {'nonce': nonce, cipher: payload}

def public_mirror(catalog, state):
    if catalog['format'] != 'goodini-vpn-standalone-v1': raise ValueError('Invalid catalog')
    keys = {}
    for digest, entry in catalog['keys'].items():
        if not re.fullmatch('[a-f0-9]{64}', digest): raise ValueError('Invalid key hash')
        keys[digest] = encrypted(entry, 'payload')
    if not keys or len(keys) > 20000: raise ValueError('Invalid key count')
    if state['payload']['format'] != 'goodini-vpn-live-v1': raise ValueError('Invalid state')
    if type(state['revision']) is not int or state['revision'] < 1: raise ValueError('Invalid revision')
    if type(state['count']) is not int or not 1 <= state['count'] <= 20000: raise ValueError('Invalid count')
    batch = catalog['batch']
    if not isinstance(batch,str) or not re.fullmatch('[a-zA-Z0-9_.-]{1,128}',batch): raise ValueError('Invalid batch')
    return {
        'format':'goodini-github-mirror-v1',
        'catalog':{'format':catalog['format'],'batch':batch,'keys':keys},
        'state':{'payload':{'format':'goodini-vpn-live-v1', **encrypted(state['payload'],'ciphertext')},
                 'revision':state['revision'],'count':state['count']},
    }

def update(config, target):
    catalog = fetch(config['catalog_url'])
    state = fetch(config['api_url'] + 'gvpn_desktop_read', {'p_key':config['read_token']},
                  {'apikey':config['public_key'],'Authorization':'Bearer '+config['public_key']})
    result = public_mirror(catalog, state)
    if target.exists():
        old = json.loads(target.read_text(encoding='utf-8'))
        old.pop('synced_at', None)
        if old == result: return False
    result['synced_at'] = datetime.now(timezone.utc).isoformat()
    raw = json.dumps(result, ensure_ascii=True, separators=(',',':'))
    # Only explicitly selected encrypted fields may be made public.
    for field in ('read_token','public_key','catalog_url','api_url'):
        if config[field] in raw: raise ValueError('Source credential in output')
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_suffix('.tmp')
    temporary.write_text(raw,encoding='utf-8')
    temporary.replace(target)
    return True

if __name__ == '__main__':
    try:
        config = json.loads(os.environ['SOURCE_CONFIG'])
        changed = update(config,Path(__file__).parent/'data/mirror.json')
        print('Encrypted mirror updated.' if changed else 'Encrypted mirror is current.')
    except Exception as error:
        # URL/HTTP exceptions may contain signed URLs; never print exception bodies.
        print('Mirror sync failed: '+type(error).__name__,file=sys.stderr)
        sys.exit(1)
