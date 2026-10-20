import sys, os
sys.path.insert(0, '.')
os.environ['FLASK_ENV'] = 'development'

import app as app_module


def _client():
    app_module.app.config['TESTING'] = True
    return app_module.app.test_client()


def test_create_session_with_study_group():
    client = _client()
    resp = client.post('/api/sessions', json={'name': 'AI Grubu Testi', 'study_group': 'ai_assisted'})
    assert resp.status_code == 201
    assert resp.get_json()['study_group'] == 'ai_assisted'
    print("OK: oturum oluştururken study_group ayarlanabiliyor")


def test_invalid_study_group_rejected_on_create():
    client = _client()
    resp = client.post('/api/sessions', json={'name': 'x', 'study_group': 'bogus'})
    assert resp.status_code == 400
    print("OK: geçersiz study_group değeri oturum oluştururken reddediliyor")


def test_update_session_study_group():
    client = _client()
    sid = client.post('/api/sessions', json={'name': 'x'}).get_json()['id']
    resp = client.put(f'/api/sessions/{sid}', json={'study_group': 'control'})
    assert resp.status_code == 200
    assert resp.get_json()['study_group'] == 'control'
    # null'a geri döndürme de çalışmalı
    resp2 = client.put(f'/api/sessions/{sid}', json={'study_group': None})
    assert resp2.get_json()['study_group'] is None
    print("OK: mevcut bir oturumun study_group'u PUT ile güncellenebiliyor (null dahil)")


def test_note_false_positive_flag():
    client = _client()
    sid = client.post('/api/sessions', json={'name': 'x'}).get_json()['id']
    note = client.post(f'/api/sessions/{sid}/notes', json={'content': 'bulgu'}).get_json()
    assert note['is_false_positive'] is None

    resp = client.put(f'/api/sessions/{sid}/notes/{note["id"]}', json={'is_false_positive': True})
    assert resp.get_json()['is_false_positive'] is True

    resp2 = client.put(f'/api/sessions/{sid}/notes/{note["id"]}', json={'is_false_positive': False})
    assert resp2.get_json()['is_false_positive'] is False
    print("OK: bulgunun false-positive durumu PUT ile true/false olarak işaretlenebiliyor")


def test_note_false_positive_flag_at_creation_time():
    # Bu, gerçek bir regresyon senaryosu: create_note endpoint'i başlangıçta
    # is_false_positive alanını hiç işlemiyordu (sadece update_note işliyordu).
    client = _client()
    sid = client.post('/api/sessions', json={'name': 'x'}).get_json()['id']

    note_true = client.post(f'/api/sessions/{sid}/notes', json={'content': 'bulgu', 'is_false_positive': True}).get_json()
    assert note_true['is_false_positive'] is True

    note_false = client.post(f'/api/sessions/{sid}/notes', json={'content': 'bulgu2', 'is_false_positive': False}).get_json()
    assert note_false['is_false_positive'] is False

    note_none = client.post(f'/api/sessions/{sid}/notes', json={'content': 'bulgu3'}).get_json()
    assert note_none['is_false_positive'] is None
    print("OK: is_false_positive, not OLUŞTURULURKEN de (sadece güncellemede değil) doğru kaydediliyor")


def test_study_metrics_endpoint_full_flow():
    client = _client()

    # AI grubu oturumu: hizli tamamlanmis, cok bulgu
    ai_sid = client.post('/api/sessions', json={'name': 'AI S1', 'study_group': 'ai_assisted'}).get_json()['id']
    for i in range(3):
        client.post(f'/api/sessions/{ai_sid}/notes', json={'content': f'bulgu {i}', 'severity': 'high'})
    client.put(f'/api/sessions/{ai_sid}', json={'status': 'completed'})

    # Kontrol oturumu: daha az bulgu
    ctrl_sid = client.post('/api/sessions', json={'name': 'Ctrl S1', 'study_group': 'control'}).get_json()['id']
    client.post(f'/api/sessions/{ctrl_sid}/notes', json={'content': 'tek bulgu', 'severity': 'medium'})
    client.put(f'/api/sessions/{ctrl_sid}', json={'status': 'completed'})

    # Etiketlenmemis bir oturum da olustur, hesaplamaya dahil OLMAMALI
    client.post('/api/sessions', json={'name': 'Etiketsiz'})

    resp = client.get('/api/study/metrics')
    assert resp.status_code == 200
    body = resp.get_json()

    # Not: test dosyasındaki diğer testler de aynı sqlite dosyasını paylaştığı için
    # (izole bir test veritabanı kurulmadı) burada SADECE bu testte oluşturulan iki
    # oturumun doğru şekilde göründüğünü/hesaplandığını doğruluyoruz; toplam sayıya
    # (diğer testlerden kalan oturumlar da dahil olabileceği için) bakmıyoruz.
    session_ids_in_response = {s['session_id'] for s in body['sessions']}
    assert ai_sid in session_ids_in_response and ctrl_sid in session_ids_in_response

    ai_session_metrics = next(s for s in body['sessions'] if s['session_id'] == ai_sid)
    ctrl_session_metrics = next(s for s in body['sessions'] if s['session_id'] == ctrl_sid)
    assert ai_session_metrics['total_findings'] == 3
    assert ctrl_session_metrics['total_findings'] == 1
    assert ai_session_metrics['study_group'] == 'ai_assisted'
    assert ctrl_session_metrics['study_group'] == 'control'

    comparison = body['comparison']
    assert comparison['ai_assisted']['n'] >= 1
    assert comparison['control']['n'] >= 1
    print("OK: /api/study/metrics uçtan uca doğru veri topluyor, gruplandırıyor ve karşılaştırıyor")


if __name__ == '__main__':
    test_create_session_with_study_group()
    test_invalid_study_group_rejected_on_create()
    test_update_session_study_group()
    test_note_false_positive_flag()
    test_note_false_positive_flag_at_creation_time()
    test_study_metrics_endpoint_full_flow()
    print("\nTüm Faz 5 study endpoint testleri geçti.")
