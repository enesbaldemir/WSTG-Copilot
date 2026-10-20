"""
Yetkilendirme matrisi belgesinin doğrulanması (Flask'tan bağımsız).

Belge:
  {
    "roles":     [{"id": "r1", "name": "Anonim"}, ...],
    "endpoints": [{"id": "e1", "method": "GET", "path": "/api/users", "note": ""}, ...],
    "cells":     {"e1:r1": {"expected": "deny", "observed": "allowed",
                            "note": "200 döndü", "finding_id": 12}, ...}
  }

expected: "allow" | "deny" | null      (bu rol bu endpoint'e erişmeli mi?)
observed: "allowed" | "denied" | null  (test sonucu; null = denenmedi)

Matris yalnızca pentester'ın girdiği bilgiyi tutar; uygulama hedefe istek
atmaz. Bilinmeyen alanlar atılır, var olmayan rol/endpoint'e ait hücreler
düşürülür.
"""

import re

MAX_ROLES = 12
MAX_ENDPOINTS = 500
MAX_NAME = 60
MAX_PATH = 500
MAX_NOTE = 500
METHODS = ('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS', 'ANY')
EXPECTED = ('allow', 'deny')
OBSERVED = ('allowed', 'denied')

_ID_RE = re.compile(r'^[A-Za-z0-9_-]{1,24}$')
_CONTROL_RE = re.compile(r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]')


class MatrixValidationError(ValueError):
    pass


def empty():
    return {'roles': [], 'endpoints': [], 'cells': {}}


def _text(value, limit, field, required=False, single_line=True):
    if value is None:
        value = ''
    if not isinstance(value, str):
        raise MatrixValidationError(f'{field} metin olmalı')
    value = _CONTROL_RE.sub('', value)
    if single_line:
        value = value.replace('\r', ' ').replace('\n', ' ')
    value = value.strip()
    if required and not value:
        raise MatrixValidationError(f'{field} boş olamaz')
    if len(value) > limit:
        raise MatrixValidationError(f'{field} en fazla {limit} karakter olabilir')
    return value


def _id(value, field):
    if not isinstance(value, str) or not _ID_RE.match(value):
        raise MatrixValidationError(f'Geçersiz {field} kimliği')
    return value


def validate(doc):
    """Gelen belgeyi doğrular ve normalize edilmiş kopyasını döndürür."""
    if not isinstance(doc, dict):
        raise MatrixValidationError('JSON nesnesi bekleniyordu')
    roles_in = doc.get('roles') or []
    endpoints_in = doc.get('endpoints') or []
    cells_in = doc.get('cells') or {}
    if not isinstance(roles_in, list) or not isinstance(endpoints_in, list) or not isinstance(cells_in, dict):
        raise MatrixValidationError('roles ve endpoints liste, cells nesne olmalı')
    if len(roles_in) > MAX_ROLES:
        raise MatrixValidationError(f'En fazla {MAX_ROLES} rol tanımlanabilir')
    if len(endpoints_in) > MAX_ENDPOINTS:
        raise MatrixValidationError(f'En fazla {MAX_ENDPOINTS} endpoint tanımlanabilir')

    roles, role_ids, role_names = [], set(), set()
    for r in roles_in:
        if not isinstance(r, dict):
            raise MatrixValidationError('Geçersiz rol kaydı')
        rid = _id(r.get('id'), 'rol')
        name = _text(r.get('name'), MAX_NAME, 'Rol adı', required=True)
        if rid in role_ids:
            raise MatrixValidationError('Rol kimlikleri tekrar ediyor')
        if name.casefold() in role_names:
            raise MatrixValidationError(f'"{name}" rolü iki kez tanımlanmış')
        role_ids.add(rid)
        role_names.add(name.casefold())
        roles.append({'id': rid, 'name': name})

    endpoints, ep_ids, ep_keys = [], set(), set()
    for e in endpoints_in:
        if not isinstance(e, dict):
            raise MatrixValidationError('Geçersiz endpoint kaydı')
        eid = _id(e.get('id'), 'endpoint')
        method = str(e.get('method') or 'GET').strip().upper()
        if method not in METHODS:
            raise MatrixValidationError(f'Geçersiz HTTP metodu: {method}')
        path = _text(e.get('path'), MAX_PATH, 'Endpoint yolu', required=True)
        note = _text(e.get('note'), MAX_NOTE, 'Endpoint notu')
        if eid in ep_ids:
            raise MatrixValidationError('Endpoint kimlikleri tekrar ediyor')
        key = (method, path)
        if key in ep_keys:
            raise MatrixValidationError(f'{method} {path} iki kez eklenmiş')
        ep_ids.add(eid)
        ep_keys.add(key)
        endpoints.append({'id': eid, 'method': method, 'path': path, 'note': note})

    cells = {}
    for key, c in cells_in.items():
        if not isinstance(key, str) or key.count(':') != 1 or not isinstance(c, dict):
            raise MatrixValidationError('Geçersiz hücre kaydı')
        eid, rid = key.split(':')
        if eid not in ep_ids or rid not in role_ids:
            continue   # silinmiş satır/sütuna ait hücre
        expected = c.get('expected')
        observed = c.get('observed')
        if expected not in (None,) + EXPECTED:
            raise MatrixValidationError('expected "allow", "deny" ya da null olmalı')
        if observed not in (None,) + OBSERVED:
            raise MatrixValidationError('observed "allowed", "denied" ya da null olmalı')
        note = _text(c.get('note'), MAX_NOTE, 'Hücre notu', single_line=False)
        finding_id = c.get('finding_id')
        if finding_id is not None and (not isinstance(finding_id, int) or isinstance(finding_id, bool) or finding_id <= 0):
            raise MatrixValidationError('finding_id pozitif tam sayı olmalı')
        if expected is None and observed is None and not note and finding_id is None:
            continue   # boş hücre saklanmaz
        cells[key] = {'expected': expected, 'observed': observed, 'note': note, 'finding_id': finding_id}

    return {'roles': roles, 'endpoints': endpoints, 'cells': cells}


def summarize(doc):
    """{'cells', 'tested', 'violations', 'over_restricted', 'untested'}"""
    total = len(doc['roles']) * len(doc['endpoints'])
    tested = violations = over = 0
    for c in doc['cells'].values():
        if c['observed']:
            tested += 1
            if c['expected'] == 'deny' and c['observed'] == 'allowed':
                violations += 1
            elif c['expected'] == 'allow' and c['observed'] == 'denied':
                over += 1
    return {'cells': total, 'tested': tested, 'violations': violations,
            'over_restricted': over, 'untested': total - tested}
