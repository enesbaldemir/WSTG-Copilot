"""
Attack Chain / Finding Correlation Engine
==========================================

Bir projede zaten toplanmış bulguları (TestResult.finding dolu olan
kayıtlar) alır ve bilinen saldırı zinciri kalıplarıyla eşleştirir.

ÖNEMLİ — dürüstlük notu: Bu bir LLM/AI çağrısı YAPMAZ. WSTG-Copilot'taki
Test Planı (planner) modülüyle aynı felsefe: sabit, izlenebilir kurallar.
"Attack Chain Detected" çıktısı, önceden tanımlanmış zincir şablonlarının
(ör. Kullanıcı Numaralandırma → Zayıf Kimlik Doğrulama → Hesap Ele
Geçirme) projedeki gerçek bulgularla kaç adımının eşleştiğine bakar.
Hiçbir ağ isteği atmaz, hiçbir komut çalıştırmaz — sadece veritabanındaki
mevcut bulgu kayıtları üzerinde çalışır.
"""

SEVERITY_WEIGHT = {'critical': 100, 'high': 70, 'medium': 40, 'low': 15, 'info': 5}

CHAIN_TEMPLATES = [
    {
        'id': 'user-enum-to-takeover',
        'name': 'Kullanıcı Numaralandırma → Zayıf Kimlik Doğrulama → Hesap Ele Geçirme',
        'steps': [
            {'label': 'Kullanıcı Numaralandırma', 'test_ids': ['WSTG-IDNT-04', 'WSTG-IDNT-05']},
            {'label': 'Zayıf Kimlik Doğrulama', 'test_ids': ['WSTG-ATHN-02', 'WSTG-ATHN-03', 'WSTG-ATHN-07']},
            {'label': 'Hesap Ele Geçirme / Yetki Yükseltme', 'test_ids': ['WSTG-ATHZ-03', 'WSTG-SESS-01']},
        ],
    },
    {
        'id': 'authz-bypass-to-idor',
        'name': 'Yetkilendirme Şeması Atlatma → IDOR → Yetkisiz Veri Erişimi',
        'steps': [
            {'label': 'Yetkilendirme Şeması Atlatma', 'test_ids': ['WSTG-ATHZ-02']},
            {'label': 'IDOR (Insecure Direct Object Reference)', 'test_ids': ['WSTG-ATHZ-04']},
            {'label': 'Yetki Yükseltme / Veri Erişimi', 'test_ids': ['WSTG-ATHZ-03']},
        ],
    },
    {
        'id': 'xss-to-session-hijack',
        'name': 'Cross-Site Scripting → Oturum Değişkenlerine Erişim → Oturum Ele Geçirme',
        'steps': [
            {'label': 'XSS (Reflected/Stored/DOM)', 'test_ids': ['WSTG-INPV-01', 'WSTG-INPV-02', 'WSTG-CLNT-01']},
            {'label': 'Güvensiz Cookie / Oturum Değişkeni İfşası', 'test_ids': ['WSTG-SESS-02', 'WSTG-SESS-04']},
            {'label': 'Oturum Ele Geçirme', 'test_ids': ['WSTG-SESS-09', 'WSTG-SESS-03']},
        ],
    },
    {
        'id': 'sqli-to-data-exfil',
        'name': 'SQL Injection → Hata Bilgisi Sızıntısı → Veri Sızdırma',
        'steps': [
            {'label': 'SQL Injection', 'test_ids': ['WSTG-INPV-05']},
            {'label': 'Ayrıntılı Hata Mesajı / Stack Trace', 'test_ids': ['WSTG-ERRH-01', 'WSTG-ERRH-02']},
            {'label': 'Veri Sızdırma Riski', 'test_ids': ['WSTG-CRYP-03', 'WSTG-CONF-11']},
        ],
    },
    {
        'id': 'backup-exposure-to-compromise',
        'name': 'Hassas/Yedek Dosya İfşası → Kimlik Bilgisi Sızıntısı → Yetkisiz Erişim',
        'steps': [
            {'label': 'Yedek/Referanssız Dosya İfşası', 'test_ids': ['WSTG-CONF-04', 'WSTG-CONF-03']},
            {'label': 'Kimlik Bilgisi / Gizli Anahtar Sızıntısı', 'test_ids': ['WSTG-ATHN-02', 'WSTG-CRYP-04']},
            {'label': 'Yetkisiz Erişim', 'test_ids': ['WSTG-ATHZ-03', 'WSTG-CONF-05']},
        ],
    },
    {
        'id': 'cors-to-data-theft',
        'name': 'CORS Yanlış Yapılandırması → Cross-Origin Veri Hırsızlığı',
        'steps': [
            {'label': 'CORS Yanlış Yapılandırması', 'test_ids': ['WSTG-CLNT-07']},
            {'label': 'Oturum/Depolama Verisine Erişim', 'test_ids': ['WSTG-SESS-04', 'WSTG-CLNT-12']},
        ],
    },
    {
        'id': 'csrf-to-forced-action',
        'name': 'CSRF → Zorla İşlem Yaptırma (Request Forgery)',
        'steps': [
            {'label': 'CSRF Koruması Eksik', 'test_ids': ['WSTG-SESS-05']},
            {'label': 'İstek Sahteciliği ile İş Mantığını Kötüye Kullanma', 'test_ids': ['WSTG-BUSL-02', 'WSTG-BUSL-06']},
        ],
    },
    {
        'id': 'malicious-upload-to-rce',
        'name': 'Zararlı Dosya Yükleme → Uzaktan Kod Çalıştırma',
        'steps': [
            {'label': 'Beklenmeyen Dosya Türü Yükleme', 'test_ids': ['WSTG-BUSL-08']},
            {'label': 'Zararlı Dosya Yükleme', 'test_ids': ['WSTG-BUSL-09']},
            {'label': 'Uzaktan Kod Çalıştırma', 'test_ids': ['WSTG-INPV-13', 'WSTG-INPV-19']},
        ],
    },
    {
        'id': 'api-authz-to-mass-exposure',
        'name': 'API Yetkilendirme Eksikliği → Kitlesel Veri İfşası',
        'steps': [
            {'label': 'API Endpoint (GraphQL vb.)', 'test_ids': ['WSTG-APIT-01']},
            {'label': 'IDOR / Yetkilendirme Eksikliği', 'test_ids': ['WSTG-ATHZ-04', 'WSTG-ATHZ-02']},
        ],
    },
    {
        'id': 'ssrf-to-internal-access',
        'name': 'SSRF → İç Ağ / Bulut Metadata Servisine Erişim',
        'steps': [
            {'label': 'SSRF (Server-Side Request Forgery)', 'test_ids': ['WSTG-INPV-20']},
            {'label': 'İç Altyapı / Bulut Depolama İfşası', 'test_ids': ['WSTG-CONF-01', 'WSTG-CONF-11']},
        ],
    },
]


def _severity_score(sev):
    return SEVERITY_WEIGHT.get((sev or 'info').lower(), 5)


def detect_chains(findings):
    """findings: list of {'test_id': str, 'severity': str} — projedeki tüm
    dolu 'finding' alanına sahip TestResult kayıtları.
    Dönüş: eşleşen zincirlerin listesi, risk skoruna göre azalan sırada."""
    by_test_id = {}
    for f in findings:
        by_test_id.setdefault(f['test_id'], f)

    chains = []
    for template in CHAIN_TEMPLATES:
        matched_steps = []
        for step in template['steps']:
            hit = None
            for tid in step['test_ids']:
                if tid in by_test_id:
                    hit = by_test_id[tid]
                    break
            matched_steps.append({
                'label': step['label'],
                'possible_test_ids': step['test_ids'],
                'matched_test_id': hit['test_id'] if hit else None,
                'severity': hit.get('severity') if hit else None,
                'matched': hit is not None,
            })

        matched_count = sum(1 for s in matched_steps if s['matched'])
        # En az 2 adım eşleşmeden bir "zincir" iddia etmiyoruz — tek bulgu
        # bir zincir değildir, sadece bir bulgudur.
        if matched_count < 2:
            continue

        completeness = round((matched_count / len(template['steps'])) * 100)
        severity_total = sum(_severity_score(s['severity']) for s in matched_steps if s['matched'])
        risk_score = round(severity_total * (matched_count / len(template['steps'])))

        chains.append({
            'id': template['id'],
            'name': template['name'],
            'steps': matched_steps,
            'matched_count': matched_count,
            'total_steps': len(template['steps']),
            'completeness_pct': completeness,
            'risk_score': risk_score,
        })

    chains.sort(key=lambda c: c['risk_score'], reverse=True)
    return chains
