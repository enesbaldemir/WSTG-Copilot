"""
Proje yedekleme: bir projeyi tek bir JSON dosyasına dışa aktarır ve böyle bir
dosyadan YENİ bir proje olarak geri yükler (var olan hiçbir proje
değiştirilmez).

Güvenlik notları:
  - Geri yükleme dosyası kullanıcı tarafından değiştirilebilir; bu yüzden
    her alan sütun türüne ve uzunluğuna göre doğrulanır, durum/önem gibi
    sabit değerli alanlar izin listesinden kontrol edilir, bilinmeyen alanlar
    yok sayılır.
  - Kimlikler (UUID / sayısal) dosyadan alınmaz; yeniden üretilir ve
    ilişkiler (bulgu <-> oturum <-> kanıt) yeni kimliklere eşlenir.
  - Kanıt görselleri base64'ten çözülür, türü içerikten (magic bytes)
    belirlenir, diske yeni ve rastgele bir adla yazılır. Not görselleri
    notes.sanitize_images ile, yetki matrisi authz_matrix.validate ile
    doğrulanır.
  - AI etkileşim günlükleri yedeğe alınmaz.
"""

import base64
import binascii
import json
import os
import uuid
from datetime import date, datetime

from sqlalchemy import Boolean, Date, DateTime, Float, Integer, String, Text

import authz_matrix
import image_types
import notes as notes_lib
from models import (AuthzMatrix, CustomTest, Evidence, Finding, Note, Project, ReconRun, ScopeItem,
                    Session, TestResult, TimelineEvent, ToolRun)

FORMAT = 'wstg-copilot-project'
VERSION = 1
MAX_EVIDENCE_BYTES = 10 * 1024 * 1024
MAX_ITEMS = 20000          # tek bir listede en fazla kayıt (bozuk/kötü niyetli dosyaya karşı)

# Dosyadan alınmayan sütunlar: kimlikler ve ilişkiler (yeniden eşlenir) ile
# diskteki dosya adı (yeniden üretilir).
_ALWAYS_SKIP = {'id', 'project_id'}


class BackupError(ValueError):
    pass


# ---------------------------------------------------------------- dışa aktarma

def _row(obj, skip=()):
    out = {}
    for col in obj.__table__.columns:
        if col.name in _ALWAYS_SKIP or col.name in skip:
            continue
        value = getattr(obj, col.name)
        if isinstance(value, (datetime, date)):
            value = value.isoformat()
        out[col.name] = value
    return out


def export_project(project, evidence_dir):
    """Projeyi JSON'a çevrilebilir bir sözlük olarak döndürür."""
    sessions = Session.query.filter_by(project_id=project.id).order_by(Session.created_at.asc()).all()
    findings = Finding.query.filter_by(project_id=project.id).order_by(Finding.id.asc()).all()
    evidence_items = Evidence.query.filter_by(project_id=project.id).order_by(Evidence.id.asc()).all()
    matrix = AuthzMatrix.query.filter_by(project_id=project.id).first()

    evidence_out = []
    for ev in evidence_items:
        row = _row(ev, skip={'stored_filename'})
        row['_ref'] = ev.id
        row['file_base64'] = None
        if ev.evidence_type == 'image' and ev.stored_filename:
            path = os.path.join(evidence_dir, os.path.basename(ev.stored_filename))
            if os.path.isfile(path):
                with open(path, 'rb') as fh:
                    row['file_base64'] = base64.b64encode(fh.read()).decode('ascii')
        evidence_out.append(row)

    return {
        'format': FORMAT,
        'version': VERSION,
        'exported_at': datetime.utcnow().isoformat() + 'Z',
        'project': _row(project),
        'scope_items': [_row(x) for x in ScopeItem.query.filter_by(project_id=project.id).order_by(ScopeItem.id).all()],
        'custom_tests': [_row(x) for x in CustomTest.query.filter_by(project_id=project.id).order_by(CustomTest.id).all()],
        'sessions': [dict(_row(s), _ref=s.id,
                          results=[_row(r, skip={'session_id'}) for r in TestResult.query.filter_by(session_id=s.id).order_by(TestResult.id).all()],
                          notes=[_row(n, skip={'session_id'}) for n in Note.query.filter_by(session_id=s.id).order_by(Note.id).all()])
                     for s in sessions],
        'findings': [dict(_row(f), _ref=f.id) for f in findings],
        'evidence': evidence_out,
        'authz_matrix': json.loads(matrix.data) if matrix and matrix.data else None,
        'recon_runs': [_row(x) for x in ReconRun.query.filter_by(project_id=project.id).order_by(ReconRun.id).all()],
        'tool_runs': [_row(x) for x in ToolRun.query.filter_by(project_id=project.id).order_by(ToolRun.id).all()],
        'timeline': [_row(x) for x in TimelineEvent.query.filter_by(project_id=project.id).order_by(TimelineEvent.id).all()],
    }


# ---------------------------------------------------------------- geri yükleme

def _parse_value(col, value, where):
    if value is None:
        return None
    t = col.type
    try:
        if isinstance(t, DateTime):
            if not isinstance(value, str):
                raise ValueError
            return datetime.fromisoformat(value.rstrip('Z'))
        if isinstance(t, Date):
            if not isinstance(value, str):
                raise ValueError
            return date.fromisoformat(value[:10])
        if isinstance(t, Boolean):
            if not isinstance(value, bool):
                raise ValueError
            return value
        if isinstance(t, Integer):
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError
            return value
        if isinstance(t, Float):
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise ValueError
            return float(value)
        if isinstance(t, (String, Text)):
            if not isinstance(value, str):
                raise ValueError
            if getattr(t, 'length', None) and len(value) > t.length:
                raise BackupError(f'{where}.{col.name} çok uzun (en fazla {t.length} karakter)')
            return value
    except BackupError:
        raise
    except (ValueError, TypeError):
        raise BackupError(f'{where}.{col.name} geçersiz')
    return value


def _kwargs(model, data, where, skip=()):
    if not isinstance(data, dict):
        raise BackupError(f'{where} bir nesne olmalı')
    out = {}
    for col in model.__table__.columns:
        if col.name in _ALWAYS_SKIP or col.name in skip or col.name not in data:
            continue
        out[col.name] = _parse_value(col, data[col.name], where)
    return out


def _check_enum(kwargs, field, allowed, where, required=False):
    value = kwargs.get(field)
    if value is None and not required:
        return
    if value not in allowed:
        raise BackupError(f'{where}.{field} geçersiz değer: {value!r}')


def _list(data, key):
    value = data.get(key) or []
    if not isinstance(value, list):
        raise BackupError(f'{key} bir liste olmalı')
    if len(value) > MAX_ITEMS:
        raise BackupError(f'{key} çok fazla kayıt içeriyor')
    return value


def import_project(data, db, evidence_dir_for, enums, name_exists):
    """Yedekten YENİ bir proje oluşturur ve döndürür. Commit etmez; hata
    olursa çağıran rollback yapar.

    enums: {'project_status', 'scope_type', 'finding_severity', 'finding_status',
            'result_status', 'test_finding_status'} -> izin verilen değerler
    evidence_dir_for(project_id) -> kanıt klasörü yolu
    name_exists(name) -> bool
    """
    if not isinstance(data, dict) or data.get('format') != FORMAT:
        raise BackupError('Bu dosya bir WSTG-Copilot proje yedeği değil')
    if data.get('version') != VERSION:
        raise BackupError(f'Desteklenmeyen yedek sürümü: {data.get("version")!r}')

    # --- proje
    pkw = _kwargs(Project, data.get('project'), 'project', skip={'created_at', 'updated_at'})
    name = (pkw.get('name') or '').strip()
    if not name:
        raise BackupError('project.name zorunludur')
    _check_enum(pkw, 'status', enums['project_status'], 'project')
    base = name[:180]
    candidate, n = base, 1
    while name_exists(candidate):
        n += 1
        candidate = f'{base} (yedek {n})' if n > 2 else f'{base} (yedek)'
    pkw['name'] = candidate
    project = Project(id=str(uuid.uuid4()), **pkw)
    db.session.add(project)
    db.session.flush()
    pid = project.id

    for i, item in enumerate(_list(data, 'scope_items')):
        kw = _kwargs(ScopeItem, item, f'scope_items[{i}]')
        if not (kw.get('value') or '').strip():
            raise BackupError(f'scope_items[{i}].value zorunludur')
        _check_enum(kw, 'type', enums['scope_type'], f'scope_items[{i}]', required=True)
        db.session.add(ScopeItem(project_id=pid, **kw))

    for i, item in enumerate(_list(data, 'custom_tests')):
        kw = _kwargs(CustomTest, item, f'custom_tests[{i}]')
        if not kw.get('test_id') or not kw.get('title'):
            raise BackupError(f'custom_tests[{i}] test_id ve title zorunludur')
        db.session.add(CustomTest(project_id=pid, **kw))

    # --- oturumlar, sonuçlar, notlar
    session_map = {}
    for i, item in enumerate(_list(data, 'sessions')):
        where = f'sessions[{i}]'
        kw = _kwargs(Session, item, where)
        if not kw.get('name'):
            raise BackupError(f'{where}.name zorunludur')
        _check_enum(kw, 'status', {'active', 'completed'}, where)
        _check_enum(kw, 'study_group', {'ai_assisted', 'control'}, where)
        new_id = str(uuid.uuid4())
        if isinstance(item.get('_ref'), str):
            session_map[item['_ref']] = new_id
        db.session.add(Session(id=new_id, project_id=pid, **kw))
        db.session.flush()
        seen_tests = set()
        for j, r in enumerate(_list(item, 'results')):
            rw = f'{where}.results[{j}]'
            rkw = _kwargs(TestResult, r, rw, skip={'session_id'})
            if not rkw.get('test_id') or rkw['test_id'] in seen_tests:
                raise BackupError(f'{rw}.test_id eksik ya da tekrarlanmış')
            seen_tests.add(rkw['test_id'])
            _check_enum(rkw, 'status', enums['result_status'], rw)
            _check_enum(rkw, 'severity', enums['finding_severity'], rw)
            _check_enum(rkw, 'finding_status', enums['test_finding_status'], rw)
            _check_enum(rkw, 'kanban_status', {'todo', 'testing', 'review', 'confirmed', 'done'}, rw)
            db.session.add(TestResult(session_id=new_id, **rkw))
        for j, note in enumerate(_list(item, 'notes')):
            nw = f'{where}.notes[{j}]'
            nkw = _kwargs(Note, note, nw, skip={'session_id'})
            _check_enum(nkw, 'severity', enums['finding_severity'], nw)
            try:
                # Skor ve derece dosyadan alınmaz; vektörden yeniden hesaplanır.
                nkw['cvss_vector'], nkw['cvss_score'], nkw['cvss_rating'] = notes_lib.cvss_fields(nkw.get('cvss_vector'))
            except notes_lib.NoteValidationError as e:
                raise BackupError(f'{nw}.cvss_vector: {e}')
            try:
                images = json.loads(nkw['images']) if nkw.get('images') else []
                nkw['images'] = notes_lib.sanitize_images(images)
            except (ValueError, notes_lib.NoteValidationError) as e:
                raise BackupError(f'{nw}.images: {e}')
            db.session.add(Note(session_id=new_id, **nkw))

    # --- bulgular
    finding_map = {}
    for i, item in enumerate(_list(data, 'findings')):
        where = f'findings[{i}]'
        kw = _kwargs(Finding, item, where, skip={'session_id', 'merged_finding_ids'})
        if not (kw.get('title') or '').strip():
            raise BackupError(f'{where}.title zorunludur')
        _check_enum(kw, 'severity', enums['finding_severity'], where)
        _check_enum(kw, 'status', enums['finding_status'], where)
        _check_enum(kw, 'retest_result', {'not_tested', 'fixed', 'not_fixed'}, where)
        f = Finding(project_id=pid, session_id=session_map.get(item.get('session_id')), **kw)
        db.session.add(f)
        db.session.flush()
        if isinstance(item.get('_ref'), int) and not isinstance(item.get('_ref'), bool):
            finding_map[item['_ref']] = f.id

    # --- kanıtlar
    ev_dir = None
    written = []
    try:
        for i, item in enumerate(_list(data, 'evidence')):
            where = f'evidence[{i}]'
            kw = _kwargs(Evidence, item, where,
                         skip={'stored_filename', 'mime_type', 'size_bytes', 'linked_finding_id', 'linked_session_id'})
            _check_enum(kw, 'evidence_type', {'image', 'http_transaction'}, where)
            _check_enum(kw, 'review_status', {'pending', 'accepted', 'rejected', 'manual'}, where)
            ev = Evidence(project_id=pid,
                          linked_finding_id=finding_map.get(item.get('linked_finding_id')),
                          linked_session_id=session_map.get(item.get('linked_session_id')), **kw)
            if (kw.get('evidence_type') or 'image') == 'image':
                raw_b64 = item.get('file_base64')
                if not isinstance(raw_b64, str) or not raw_b64:
                    continue      # dosyası olmayan görsel kaydı geri yüklenmez
                if len(raw_b64) > (MAX_EVIDENCE_BYTES * 4) // 3 + 4:
                    raise BackupError(f'{where}: görsel çok büyük')
                try:
                    raw = base64.b64decode(raw_b64, validate=True)
                except (binascii.Error, ValueError):
                    raise BackupError(f'{where}: görsel verisi bozuk')
                kind = image_types.detect_image_type(raw)
                if not kind:
                    raise BackupError(f'{where}: dosya PNG, JPEG, GIF ya da WebP değil')
                if ev_dir is None:
                    ev_dir = evidence_dir_for(pid)
                stored = f'{uuid.uuid4().hex}{image_types.EXT_BY_TYPE[kind]}'
                dest = os.path.join(ev_dir, stored)
                with open(dest, 'wb') as fh:
                    fh.write(raw)
                written.append(dest)
                ev.stored_filename = stored
                ev.mime_type = image_types.MIME_BY_TYPE[kind]
                ev.size_bytes = len(raw)
            db.session.add(ev)

        # --- yetki matrisi
        if data.get('authz_matrix') is not None:
            try:
                doc = authz_matrix.validate(data['authz_matrix'])
            except authz_matrix.MatrixValidationError as e:
                raise BackupError(f'authz_matrix: {e}')
            db.session.add(AuthzMatrix(project_id=pid, data=json.dumps(doc, ensure_ascii=False)))

        for i, item in enumerate(_list(data, 'recon_runs')):
            db.session.add(ReconRun(project_id=pid, **_kwargs(ReconRun, item, f'recon_runs[{i}]')))
        for i, item in enumerate(_list(data, 'tool_runs')):
            kw = _kwargs(ToolRun, item, f'tool_runs[{i}]')
            if not kw.get('tool') or not kw.get('target'):
                raise BackupError(f'tool_runs[{i}] tool ve target zorunludur')
            _check_enum(kw, 'status', {'completed', 'failed', 'timeout'}, f'tool_runs[{i}]')
            db.session.add(ToolRun(project_id=pid, **kw))
        for i, item in enumerate(_list(data, 'timeline')):
            kw = _kwargs(TimelineEvent, item, f'timeline[{i}]')
            if not kw.get('event_type') or not kw.get('message'):
                raise BackupError(f'timeline[{i}] event_type ve message zorunludur')
            db.session.add(TimelineEvent(project_id=pid, **kw))

        db.session.flush()
    except Exception:
        # Veritabanı geri alınacak; diske yazılmış görseller de silinsin.
        for path in written:
            try:
                os.remove(path)
            except OSError:
                pass
        raise
    return project
