"""
Tool Integration -- gercek kesif araclarini (nmap, httpx, whatweb, subfinder,
dnsx) kullanicinin kendi makinesinde, guvenli sekilde calistirir.

Guvenlik ilkeleri (bilerek konuldu, gevsetilmemeli):
  - Komutlar HER ZAMAN subprocess'e bir ARGUMAN LISTESI olarak verilir,
    ASLA shell=True ile string birlestirme kullanilmaz. Bu, hedef string'i
    ne icerirse icersin shell injection'i yapisal olarak imkansiz kilar.
  - Her aracin komut satiri sablonu SABITTIR (TOOL_DEFINITIONS). Kullanici
    keyfi flag/parametre enjekte edemez -- sadece hedefi secer.
  - Hedef, recon.py'deki SSRF korumali normalize_target() ile dogrulanir
    (private/loopback/link-local/reserved IP'ler reddedilir).
  - nuclei ve ffuf BILINCLI OLARAK burada YOK: nuclei sablon kutuphanesi
    gercek CVE'ler icin calisan exploit-dogrulama payload'lari icerir
    (kesiften ote aktif zafiyet dogrulama), ffuf ise buyuk wordlist'lerle
    agresif dizin fuzzing yapar. Ikisi de ayri, daha siki kapsamli bir
    iterasyon gerektirir.
  - Kurulu olmayan bir arac icin ASLA otomatik kurulum denenmez -- sadece
    "kurulu degil" bilgisi donulur.
"""

import shutil
import subprocess

import recon

STDOUT_LIMIT = 20000
STDERR_LIMIT = 4000


class ToolError(Exception):
    pass


def _nmap_args(hostname):
    return ['-Pn', '-sV', '--top-ports', '100', '-T4', hostname]


def _httpx_args(hostname):
    return ['-u', hostname, '-title', '-tech-detect', '-status-code', '-silent']


def _whatweb_args(hostname):
    return ['--no-errors', hostname]


def _subfinder_args(hostname):
    return ['-d', hostname, '-silent']


def _dnsx_args(hostname):
    return ['-d', hostname, '-silent', '-a', '-resp']


TOOL_DEFINITIONS = {
    'nmap': {
        'binary': 'nmap',
        'label': 'Nmap',
        'description': 'Port/servis tarama (en yaygin 100 port, -Pn -sV -T4).',
        'build_args': _nmap_args,
        'timeout': 90,
    },
    'httpx': {
        'binary': 'httpx',
        'label': 'httpx',
        'description': 'HTTP(S) probe: durum kodu, sayfa basligi, teknoloji tespiti (ProjectDiscovery httpx).',
        'build_args': _httpx_args,
        'timeout': 30,
    },
    'whatweb': {
        'binary': 'whatweb',
        'label': 'WhatWeb',
        'description': 'Web teknolojisi parmak izi cikarma.',
        'build_args': _whatweb_args,
        'timeout': 30,
    },
    'subfinder': {
        'binary': 'subfinder',
        'label': 'Subfinder',
        'description': 'Pasif subdomain kesfi (crt.sh ve benzeri kaynaklar; brute-force yapmaz).',
        'build_args': _subfinder_args,
        'timeout': 45,
    },
    'dnsx': {
        'binary': 'dnsx',
        'label': 'dnsx',
        'description': 'DNS cozumleme (A kayitlari).',
        'build_args': _dnsx_args,
        'timeout': 20,
    },
}


def is_tool_available(tool_name):
    defn = TOOL_DEFINITIONS.get(tool_name)
    if not defn:
        return False
    return shutil.which(defn['binary']) is not None


def list_tools():
    return [
        {
            'id': name,
            'label': defn['label'],
            'description': defn['description'],
            'timeout': defn['timeout'],
            'available': is_tool_available(name),
        }
        for name, defn in TOOL_DEFINITIONS.items()
    ]


def preview_command(tool_name, raw_target):
    """Onay ekraninda gosterilecek TAM komutu doner -- hicbir sey calistirmaz."""
    defn = TOOL_DEFINITIONS.get(tool_name)
    if not defn:
        raise ToolError('Bilinmeyen arac: ' + str(tool_name))
    hostname, _base_url, _ips = recon.normalize_target(raw_target)
    args = defn['build_args'](hostname)
    return {
        'tool': tool_name,
        'binary': defn['binary'],
        'command': ' '.join([defn['binary']] + args),
        'target': hostname,
        'available': is_tool_available(tool_name),
    }


def run_tool(tool_name, raw_target):
    """Araci gercekten calistirir. Hedef onceden normalize_target() ile
    dogrulanir (SSRF korumasi burada da uygulanir -- onizleme ile calistirma
    arasinda TOCTOU riskini azaltmak icin ayni dogrulama tekrar yapilir)."""
    defn = TOOL_DEFINITIONS.get(tool_name)
    if not defn:
        raise ToolError('Bilinmeyen arac: ' + str(tool_name))

    if not shutil.which(defn['binary']):
        raise ToolError(
            defn['binary'] + " sisteminizde kurulu degil ya da PATH'te bulunamiyor. "
            "Kurulum sonrasi tekrar deneyin."
        )

    hostname, _base_url, _ips = recon.normalize_target(raw_target)
    args = defn['build_args'](hostname)
    full_cmd = [defn['binary']] + args
    command_str = ' '.join(full_cmd)

    try:
        proc = subprocess.run(
            full_cmd,
            capture_output=True,
            text=True,
            timeout=defn['timeout'],
            shell=False,  # KASITLI: shell=True ASLA kullanilmaz
        )
        return {
            'status': 'completed',
            'command': command_str,
            'target': hostname,
            'exit_code': proc.returncode,
            'stdout': (proc.stdout or '')[:STDOUT_LIMIT],
            'stderr': (proc.stderr or '')[:STDERR_LIMIT],
        }
    except subprocess.TimeoutExpired as e:
        return {
            'status': 'timeout',
            'command': command_str,
            'target': hostname,
            'exit_code': None,
            'stdout': (e.stdout or '')[:STDOUT_LIMIT] if e.stdout else '',
            'stderr': ('Zaman asimi (' + str(defn['timeout']) + 's) asildi.'),
        }
    except Exception as e:
        return {
            'status': 'failed',
            'command': command_str,
            'target': hostname,
            'exit_code': None,
            'stdout': '',
            'stderr': str(e)[:STDERR_LIMIT],
        }
