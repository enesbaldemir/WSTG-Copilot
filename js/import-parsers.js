/*
 * WSTGImport — dış araç çıktılarını (Nmap / Nikto / WPScan / Burp Suite /
 * OWASP ZAP) parse edip WSTG checklist maddeleriyle eşleştiren yardımcı modül.
 *
 * Bu dosya saf JS'tir, DOM state'ine veya app.js içindeki değişkenlere
 * dokunmaz — sadece metin/dosya girdisini normalize edilmiş bir bulgu
 * listesine çevirir: { tool, testIds, title, detail, severity, source }
 * Burp/ZAP bulgularında ek olarak:
 *   pro:  { title, severity, endpoint, parameter, cwe, description,
 *           remediation, references }  -> profesyonel Finding taslağı
 *   http: { request, response, label }  -> HTTP kanıtı (varsa)
 *
 * XML, tarayıcının DOMParser'ı ile okunur (dış varlık / XXE çözümlemez,
 * script çalıştırmaz). Eşleme ve normalleştirme DOM'suzdur; Node'da
 * js/tests/import-parsers.test.js ile test edilir.
 *
 * Eşleştirmeler sezgiseldir (anahtar kelime tabanlı); amaç, tarayıcı
 * çıktısını otomatik olarak ilgili checklist maddelerine bağlayıp
 * test uzmanına bir başlangıç noktası + hazır not sunmaktır. Bulgular
 * her zaman kullanıcı onayından (önizleme adımı) geçer, kör bir şekilde
 * uygulanmaz.
 */
(function (global) {
  "use strict";

  const SEVERITIES = ["info", "low", "medium", "high", "critical"];

  // Genel anahtar-kelime -> WSTG test id eşleşme tablosu.
  // Hem Nmap NSE script çıktılarında hem Nikto/WPScan bulgu metinlerinde
  // aranır. En spesifik kural en üstte olacak şekilde sıralamak faydalı
  // olsa da, tüm eşleşen kurallar toplanır (bir metin birden çok testi
  // tetikleyebilir).
  const KEYWORD_RULES = [
    { re: /anonymous ftp/i, ids: ["WSTG-CONF-01"], sev: "medium" },
    { re: /\btelnet\b/i, ids: ["WSTG-CRYP-03", "WSTG-CONF-01"], sev: "medium" },
    { re: /x-frame-options/i, ids: ["WSTG-CLNT-09"], sev: "low" },
    { re: /strict-transport-security|\bhsts\b/i, ids: ["WSTG-CONF-07"], sev: "low" },
    { re: /x-content-type-options/i, ids: ["WSTG-CONF-02"], sev: "low" },
    { re: /x-xss-protection/i, ids: ["WSTG-CLNT-01"], sev: "info" },
    { re: /directory indexing|index of \/|directory listing/i, ids: ["WSTG-CONF-01", "WSTG-INFO-03"], sev: "medium" },
    { re: /\btrace\b.*method|http trace/i, ids: ["WSTG-CONF-06"], sev: "medium" },
    { re: /\bput\b method|\bdelete\b method|methods allowed/i, ids: ["WSTG-CONF-06"], sev: "medium" },
    { re: /backup|\.bak\b|\.old\b|\.swp\b|~\//i, ids: ["WSTG-CONF-04"], sev: "medium" },
    { re: /phpinfo\(\)|phpinfo\.php/i, ids: ["WSTG-CONF-03", "WSTG-INFO-02"], sev: "medium" },
    { re: /(admin|administrator|wp-admin|management console).*(interface|panel|login)/i, ids: ["WSTG-CONF-05"], sev: "low" },
    { re: /sql injection|sqli\b/i, ids: ["WSTG-INPV-05"], sev: "high" },
    { re: /cross site scripting|\bxss\b/i, ids: ["WSTG-INPV-01", "WSTG-INPV-02"], sev: "high" },
    { re: /clickjack/i, ids: ["WSTG-CLNT-09"], sev: "medium" },
    { re: /cookie.*(missing|without).*(httponly|secure)|httponly flag|secure flag/i, ids: ["WSTG-SESS-02"], sev: "low" },
    { re: /outdated|end.of.life|obsolete|appears to be outdated/i, ids: ["WSTG-INFO-02"], sev: "low" },
    { re: /self.signed certificate|expired certificate|weak cipher|sslv2|sslv3|deprecated.*(tls|ssl)/i, ids: ["WSTG-CRYP-01"], sev: "medium" },
    { re: /subdomain takeover/i, ids: ["WSTG-CONF-10"], sev: "high" },
    { re: /cors|cross.origin resource sharing/i, ids: ["WSTG-CLNT-07"], sev: "medium" },
    { re: /open redirect/i, ids: ["WSTG-CLNT-04"], sev: "medium" },
    { re: /user enumeration|username enumeration|users found/i, ids: ["WSTG-IDNT-04"], sev: "medium" },
    { re: /default credential|default password/i, ids: ["WSTG-ATHN-02"], sev: "high" },
    { re: /xmlrpc/i, ids: ["WSTG-CONF-06", "WSTG-ATHN-03"], sev: "low" },
    { re: /readme\.(html|txt)|changelog\.txt|license\.txt/i, ids: ["WSTG-CONF-03"], sev: "info" },
    { re: /robots\.txt|sitemap\.xml/i, ids: ["WSTG-INFO-03"], sev: "info" }
  ];

  function severityRank(s) {
    const i = SEVERITIES.indexOf(s);
    return i === -1 ? 0 : i;
  }
  function maxSeverity(a, b) {
    return severityRank(b) > severityRank(a) ? b : a;
  }

  function matchKeywordRules(text) {
    if (!text) return [];
    const hits = [];
    KEYWORD_RULES.forEach(rule => {
      if (rule.re.test(text)) hits.push(rule);
    });
    return hits;
  }

  function pushFinding(list, finding) {
    // Aynı tool+title+testId kombinasyonu tekrar geliyorsa detail'i birleştir.
    list.push(finding);
  }

  // ---------- Araç Tipi Algılama ----------

  function detectTool(text, filename) {
    const name = (filename || "").toLowerCase();
    const head = (text || "").slice(0, 4000);

    if (/\.xml$/.test(name) && /<nmaprun/i.test(head)) return "nmap";
    if (/<nmaprun/i.test(head)) return "nmap";

    if (/\.xml$/.test(name) && /<niktoscan/i.test(head)) return "nikto-xml";
    if (/<niktoscan/i.test(head)) return "nikto-xml";

    // Burp dışa aktarımı kökten önce uzun bir DTD taşıyabilir.
    const longHead = (text || "").slice(0, 30000);
    if (/<issues[\s>]/i.test(longHead) && /burpVersion|<issue>/i.test(longHead)) return "burp-xml";
    if (/<OWASPZAPReport/i.test(longHead)) return "zap-xml";

    try {
      const trimmed = (text || "").trim();
      if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
        const json = JSON.parse(trimmed);
        if (json && json.site && (/zap/i.test(String(json["@programName"] || "")) || [].concat(json.site)[0]?.alerts)) return "zap-json";
        if (json && (json.vulnerabilities || json.host) && (json.banner || json.vulnerabilities)) return "nikto-json";
        if (json && (json.plugins || json.themes || json.version || json.interesting_findings)) return "wpscan-json";
        if (Array.isArray(json) && json.length && json[0].vulnerabilities) return "nikto-json";
      }
    } catch (e) { /* not JSON, ignore */ }

    if (/wpscan/i.test(name)) return "wpscan-json";
    if (/nikto/i.test(name)) return "nikto-json";
    if (/nmap/i.test(name)) return "nmap";

    return null;
  }

  // ---------- Nmap XML ----------

  function parseNmap(xmlText) {
    const findings = [];
    const parser = new DOMParser();
    const doc = parser.parseFromString(xmlText, "application/xml");
    if (doc.querySelector("parsererror")) {
      throw new Error("Nmap XML ayrıştırılamadı (geçersiz XML).");
    }

    const hosts = Array.from(doc.querySelectorAll("host"));
    hosts.forEach(host => {
      const addrEl = host.querySelector("address[addrtype='ipv4'], address[addrtype='ipv6'], address");
      const addr = addrEl ? addrEl.getAttribute("addr") : "target";
      const hostnameEl = host.querySelector("hostnames > hostname");
      const hostLabel = hostnameEl ? hostnameEl.getAttribute("name") : addr;

      const ports = Array.from(host.querySelectorAll("ports > port"));
      const openPorts = ports.filter(p => {
        const state = p.querySelector("state");
        return state && state.getAttribute("state") === "open";
      });

      if (openPorts.length) {
        const portSummary = openPorts.map(p => {
          const portId = p.getAttribute("portid");
          const proto = p.getAttribute("protocol");
          const svc = p.querySelector("service");
          const svcName = svc ? svc.getAttribute("name") : "";
          const product = svc ? (svc.getAttribute("product") || "") : "";
          const version = svc ? (svc.getAttribute("version") || "") : "";
          return `${portId}/${proto} ${svcName} ${product} ${version}`.replace(/\s+/g, " ").trim();
        }).join("\n");

        pushFinding(findings, {
          tool: "nmap",
          testIds: ["WSTG-INFO-02"],
          title: `${hostLabel}: ${openPorts.length} açık port bulundu`,
          detail: portSummary,
          severity: "info",
          source: `Nmap · ${hostLabel}`
        });
      }

      openPorts.forEach(p => {
        const portId = p.getAttribute("portid");
        const svc = p.querySelector("service");
        const svcName = svc ? (svc.getAttribute("name") || "") : "";
        const scripts = Array.from(p.querySelectorAll("script"));
        const scriptText = scripts.map(s => `[${s.getAttribute("id")}] ${s.getAttribute("output") || ""}`).join("\n");
        const combined = `${svcName} ${scriptText}`;

        const hits = matchKeywordRules(combined);
        hits.forEach(rule => {
          pushFinding(findings, {
            tool: "nmap",
            testIds: rule.ids,
            title: `${hostLabel}:${portId} — ${svcName || "servis"} üzerinde eşleşen bulgu`,
            detail: scriptText || combined,
            severity: rule.sev,
            source: `Nmap · ${hostLabel}:${portId}`
          });
        });
      });

      // Host-level (SMB/OS discovery vb.) scriptler
      const hostScripts = Array.from(host.querySelectorAll(":scope > hostscript > script"));
      hostScripts.forEach(s => {
        const output = s.getAttribute("output") || "";
        const hits = matchKeywordRules(`${s.getAttribute("id")} ${output}`);
        hits.forEach(rule => {
          pushFinding(findings, {
            tool: "nmap",
            testIds: rule.ids,
            title: `${hostLabel} — host script: ${s.getAttribute("id")}`,
            detail: output,
            severity: rule.sev,
            source: `Nmap · ${hostLabel}`
          });
        });
      });
    });

    return findings;
  }

  // ---------- Nikto (XML / JSON) ----------

  function parseNiktoXml(xmlText) {
    const findings = [];
    const parser = new DOMParser();
    const doc = parser.parseFromString(xmlText, "application/xml");
    if (doc.querySelector("parsererror")) {
      throw new Error("Nikto XML ayrıştırılamadı (geçersiz XML).");
    }
    const items = Array.from(doc.querySelectorAll("scandetails item"));
    items.forEach(item => niktoItemToFindings(findings, {
      desc: (item.querySelector("description")?.textContent || "").trim(),
      uri: (item.querySelector("uri")?.textContent || "").trim(),
      osvdb: item.getAttribute("osvdbid") || ""
    }));
    return findings;
  }

  function parseNiktoJson(jsonText) {
    const findings = [];
    const data = JSON.parse(jsonText);
    const vulns = Array.isArray(data) ? data : (data.vulnerabilities || []);
    vulns.forEach(v => niktoItemToFindings(findings, {
      desc: v.msg || v.message || v.description || "",
      uri: v.url || v.uri || "",
      osvdb: v.id || v.OSVDB || ""
    }));
    return findings;
  }

  function niktoItemToFindings(findings, item) {
    const text = `${item.desc} ${item.uri}`;
    const hits = matchKeywordRules(text);
    if (hits.length) {
      hits.forEach(rule => {
        pushFinding(findings, {
          tool: "nikto",
          testIds: rule.ids,
          title: item.desc.slice(0, 140) || "Nikto bulgusu",
          detail: `${item.uri ? "URI: " + item.uri + "\n" : ""}${item.desc}${item.osvdb ? "\nOSVDB: " + item.osvdb : ""}`,
          severity: rule.sev,
          source: "Nikto"
        });
      });
    } else if (item.desc) {
      // Eşleşmeyen bulgular da listelenir (kategorize edilemedi), test
      // uzmanı önizlemede manuel olarak ilgili maddeyi seçebilir.
      pushFinding(findings, {
        tool: "nikto",
        testIds: ["WSTG-INFO-04"],
        title: item.desc.slice(0, 140),
        detail: `${item.uri ? "URI: " + item.uri + "\n" : ""}${item.desc}${item.osvdb ? "\nOSVDB: " + item.osvdb : ""}\n(Otomatik eşleşme bulunamadı — kategoriyi elle güncelleyin.)`,
        severity: "info",
        source: "Nikto",
        unmatched: true
      });
    }
  }

  // ---------- WPScan (JSON) ----------

  function parseWpscan(jsonText) {
    const findings = [];
    const data = JSON.parse(jsonText);

    if (data.version && data.version.number) {
      const status = (data.version.status || "").toLowerCase();
      pushFinding(findings, {
        tool: "wpscan",
        testIds: ["WSTG-INFO-02"],
        title: `WordPress sürümü: ${data.version.number}${status ? " (" + status + ")" : ""}`,
        detail: JSON.stringify(data.version, null, 2).slice(0, 800),
        severity: status === "insecure" ? "medium" : "low",
        source: "WPScan"
      });
    }

    const interesting = data.interesting_findings || [];
    interesting.forEach(f => {
      const text = `${f.type || ""} ${f.to_s || f.message || ""}`;
      const hits = matchKeywordRules(text);
      const ids = hits.length ? Array.from(new Set(hits.flatMap(h => h.ids))) : ["WSTG-INFO-04"];
      const sev = hits.reduce((acc, h) => maxSeverity(acc, h.sev), "info");
      pushFinding(findings, {
        tool: "wpscan",
        testIds: ids,
        title: (f.to_s || f.type || "WPScan bulgusu").slice(0, 140),
        detail: `${f.url ? "URL: " + f.url + "\n" : ""}${f.to_s || f.message || ""}`,
        severity: sev,
        source: "WPScan",
        unmatched: !hits.length
      });
    });

    ["plugins", "themes"].forEach(kind => {
      const entries = data[kind];
      if (!entries || typeof entries !== "object") return;
      Object.keys(entries).forEach(slug => {
        const entry = entries[slug];
        const vulns = entry.vulnerabilities || [];
        const outdated = entry.outdated === true;
        if (vulns.length) {
          pushFinding(findings, {
            tool: "wpscan",
            testIds: ["WSTG-CONF-01", "WSTG-INFO-04"],
            title: `${kind === "plugins" ? "Eklenti" : "Tema"} güvenlik açığı: ${slug} (${vulns.length} kayıt)`,
            detail: vulns.map(v => `- ${v.title || v.name || "İsimsiz zafiyet"}`).join("\n").slice(0, 1000),
            severity: "high",
            source: "WPScan"
          });
        } else if (outdated) {
          pushFinding(findings, {
            tool: "wpscan",
            testIds: ["WSTG-INFO-02"],
            title: `${kind === "plugins" ? "Eklenti" : "Tema"} güncel değil: ${slug}`,
            detail: `Yüklü sürüm: ${entry.version && entry.version.number ? entry.version.number : "bilinmiyor"}`,
            severity: "low",
            source: "WPScan"
          });
        }
      });
    });

    if (data.users && typeof data.users === "object") {
      const names = Object.values(data.users).map(u => u.username || u.name).filter(Boolean);
      if (names.length) {
        pushFinding(findings, {
          tool: "wpscan",
          testIds: ["WSTG-IDNT-04"],
          title: `Kullanıcı adı numaralandırma: ${names.length} kullanıcı bulundu`,
          detail: names.join(", "),
          severity: "medium",
          source: "WPScan"
        });
      }
    }

    return findings;
  }

  // ---------- Burp Suite / OWASP ZAP ----------
  //
  // WSTG eşlemesi üç adımda yapılır (ilk sonuç veren kazanır):
  //   1. SCANNER_RULES: tarayıcı sorun adına göre, en spesifikten genele,
  //      İLK eşleşen kural (ör. "Cross-site scripting (stored)" -> INPV-02).
  //   2. CWE_TO_WSTG: sorunun CWE numarası.
  //   3. KEYWORD_RULES: Nikto/Nmap için kullanılan genel tablo (tümü).
  // Hiçbiri eşleşmezse bulgu "kategori önerisi yok" olarak listelenir.
  // Önem derecesi kurallardan değil, aracın kendi değerlendirmesinden gelir.
  // ID'ler bu uygulamanın checklist'ine göredir (data/wstg-checklist.*.json).

  const SCANNER_RULES = [
    { re: /cross.site scripting filter|x-xss-protection/i, ids: ["WSTG-CONF-02"] },
    { re: /cross.site scripting \(dom|dom.based (xss|cross)|dom xss/i, ids: ["WSTG-CLNT-01"] },
    { re: /cross.site scripting \((stored|persistent)|(stored|persistent) (xss|cross)/i, ids: ["WSTG-INPV-02"] },
    { re: /cross.site scripting|\bxss\b/i, ids: ["WSTG-INPV-01"] },
    { re: /sql injection|\bsqli\b/i, ids: ["WSTG-INPV-05"] },
    { re: /ldap injection/i, ids: ["WSTG-INPV-06"] },
    { re: /xml external entit|\bxxe\b|xml injection|xslt injection/i, ids: ["WSTG-INPV-07"] },
    { re: /\bssi\b|server.side include/i, ids: ["WSTG-INPV-08"] },
    { re: /xpath injection/i, ids: ["WSTG-INPV-09"] },
    { re: /smtp (header )?injection|imap injection|e-?mail header injection/i, ids: ["WSTG-INPV-10"] },
    { re: /remote file inclusion/i, ids: ["WSTG-INPV-12"] },
    { re: /(path|directory) traversal|file path (traversal|manipulation)|local file inclusion/i, ids: ["WSTG-ATHZ-01", "WSTG-INPV-11"] },
    { re: /command injection|os command|remote os/i, ids: ["WSTG-INPV-13"] },
    { re: /format string/i, ids: ["WSTG-INPV-14"] },
    { re: /request smuggling|response splitting|crlf|http header injection/i, ids: ["WSTG-INPV-16"] },
    { re: /host header/i, ids: ["WSTG-INPV-18"] },
    { re: /template injection|\bssti\b/i, ids: ["WSTG-INPV-19"] },
    { re: /server.side request forgery|\bssrf\b|external service interaction/i, ids: ["WSTG-INPV-20"] },
    { re: /parameter pollution/i, ids: ["WSTG-INPV-04"] },
    { re: /cross.site request forgery|\bcsrf\b|anti-csrf/i, ids: ["WSTG-SESS-05"] },
    { re: /session fixation/i, ids: ["WSTG-SESS-03"] },
    { re: /session (token|id|identifier) in url|session id in url rewrite/i, ids: ["WSTG-SESS-04"] },
    { re: /cookie|samesite/i, ids: ["WSTG-SESS-02"] },
    { re: /open redirect|url redirect(ion)?|redirect.*(user.controlled|parameter)/i, ids: ["WSTG-CLNT-04"] },
    { re: /clickjack|x-frame-options|frame.ancestors|frameable response/i, ids: ["WSTG-CLNT-09"] },
    { re: /cross.origin resource sharing|\bcors\b|access-control-allow-origin|cross.domain misconfiguration/i, ids: ["WSTG-CLNT-07"] },
    { re: /web ?socket/i, ids: ["WSTG-CLNT-10"] },
    { re: /local ?storage|session ?storage|browser storage/i, ids: ["WSTG-CLNT-12"] },
    { re: /graphql/i, ids: ["WSTG-APIT-01"] },
    { re: /strict.transport.security|\bhsts\b/i, ids: ["WSTG-CONF-07"] },
    { re: /cleartext submission of password|password (submitted|transmitted).*(http|unencrypted|clear)/i, ids: ["WSTG-ATHN-01"] },
    { re: /password field with autocomplete|autocomplete/i, ids: ["WSTG-ATHN-05"] },
    { re: /cacheable https|cache.control|browser cache|retrieved from cache|cacheable content/i, ids: ["WSTG-ATHN-06"] },
    { re: /\btls\b|\bssl\b|certificate|cipher/i, ids: ["WSTG-CRYP-01"] },
    { re: /mixed content|unencrypted|cleartext|http:\/\/ /i, ids: ["WSTG-CRYP-03"] },
    { re: /stack trace|application error|error message|debug (error|message)|verbose error/i, ids: ["WSTG-ERRH-01", "WSTG-ERRH-02"] },
    { re: /backup file|\.bak\b|old file|source code disclosure/i, ids: ["WSTG-CONF-04"] },
    { re: /http methods?|trace method|options method|put method|webdav/i, ids: ["WSTG-CONF-06"] },
    { re: /insecure direct object|\bidor\b/i, ids: ["WSTG-ATHZ-04"] },
    { re: /privilege escalation/i, ids: ["WSTG-ATHZ-03"] },
    { re: /authorization bypass|access control|broken access/i, ids: ["WSTG-ATHZ-02"] },
    { re: /file upload/i, ids: ["WSTG-BUSL-08", "WSTG-BUSL-09"] },
    { re: /(vulnerable|outdated) (javascript|js|component|librar)/i, ids: ["WSTG-INFO-08"] },
    { re: /x-powered-by|server leaks|server header|version (disclosure|information)|banner/i, ids: ["WSTG-INFO-02"] },
    { re: /comment|e-?mail address(es)? disclosed|private ip|internal ip|timestamp disclosure|hash disclosure|information disclosure/i, ids: ["WSTG-INFO-05"] },
    { re: /content.security.policy|\bcsp\b|x-content-type-options|permissions.policy|referrer.policy|security header|spectre|cross-origin-(embedder|opener|resource)/i, ids: ["WSTG-CONF-02"] },
    { re: /directory (listing|browsing)/i, ids: ["WSTG-CONF-02", "WSTG-INFO-03"] },
    { re: /robots\.txt|sitemap\.xml/i, ids: ["WSTG-INFO-03"] },
  ];

  const CWE_TO_WSTG = {
    79: ["WSTG-INPV-01"], 80: ["WSTG-INPV-01"], 83: ["WSTG-INPV-01"], 87: ["WSTG-INPV-01"],
    89: ["WSTG-INPV-05"], 564: ["WSTG-INPV-05"], 90: ["WSTG-INPV-06"],
    91: ["WSTG-INPV-07"], 611: ["WSTG-INPV-07"], 776: ["WSTG-INPV-07"],
    97: ["WSTG-INPV-08"], 643: ["WSTG-INPV-09"], 98: ["WSTG-INPV-11", "WSTG-INPV-12"],
    22: ["WSTG-ATHZ-01"], 23: ["WSTG-ATHZ-01"], 35: ["WSTG-ATHZ-01"], 73: ["WSTG-ATHZ-01"],
    77: ["WSTG-INPV-13"], 78: ["WSTG-INPV-13"], 134: ["WSTG-INPV-14"],
    93: ["WSTG-INPV-16"], 113: ["WSTG-INPV-16"], 444: ["WSTG-INPV-16"],
    1336: ["WSTG-INPV-19"], 918: ["WSTG-INPV-20"],
    352: ["WSTG-SESS-05"], 384: ["WSTG-SESS-03"], 613: ["WSTG-SESS-07"],
    614: ["WSTG-SESS-02"], 1004: ["WSTG-SESS-02"], 1275: ["WSTG-SESS-02"],
    601: ["WSTG-CLNT-04"], 1021: ["WSTG-CLNT-09"], 942: ["WSTG-CLNT-07"], 1385: ["WSTG-CLNT-10"],
    922: ["WSTG-CLNT-12"],
    209: ["WSTG-ERRH-01"], 550: ["WSTG-ERRH-02"], 497: ["WSTG-INFO-05"], 615: ["WSTG-INFO-05"],
    311: ["WSTG-CRYP-03"], 319: ["WSTG-CRYP-03"], 523: ["WSTG-ATHN-01"],
    326: ["WSTG-CRYP-04"], 327: ["WSTG-CRYP-04"], 328: ["WSTG-CRYP-04"],
    525: ["WSTG-ATHN-06"], 524: ["WSTG-ATHN-06"],
    287: ["WSTG-ATHN-04"], 288: ["WSTG-ATHN-04"], 306: ["WSTG-ATHN-04"], 307: ["WSTG-ATHN-03"],
    521: ["WSTG-ATHN-07"], 640: ["WSTG-ATHN-09"], 798: ["WSTG-ATHN-02"], 1392: ["WSTG-ATHN-02"],
    284: ["WSTG-ATHZ-02"], 285: ["WSTG-ATHZ-02"], 862: ["WSTG-ATHZ-02"], 863: ["WSTG-ATHZ-02"],
    639: ["WSTG-ATHZ-04"], 269: ["WSTG-ATHZ-03"],
    434: ["WSTG-BUSL-09"], 530: ["WSTG-CONF-04"], 538: ["WSTG-CONF-04"],
    693: ["WSTG-CONF-02"], 16: ["WSTG-CONF-02"], 548: ["WSTG-CONF-02"],
  };

  const MAX_TEXT = 8000;          // açıklama / çözüm önerisi
  const MAX_HTTP = 100000;        // tek istek veya yanıt (karakter)
  const MAX_INSTANCES_LISTED = 20;

  const ENTITY = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " " };

  // HTML parçasını düz metne çevirir (DOM'suz). Çıktı her zaman metin
  // olarak kullanılır ve gösterilirken ayrıca escape edilir.
  function htmlToText(html) {
    if (html === null || html === undefined) return "";
    let s = String(html);
    s = s.replace(/<(script|style)\b[\s\S]*?<\/\1\s*>/gi, "");
    s = s.replace(/<br\s*\/?>/gi, "\n").replace(/<\/(p|div|li|h[1-6]|tr|pre)\s*>/gi, "\n").replace(/<li\b[^>]*>/gi, "• ");
    s = s.replace(/<[^>]*>/g, "");
    s = s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => {
      if (e[0] === "#") {
        const code = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
        return Number.isFinite(code) && code > 0 && code < 0x110000 ? String.fromCodePoint(code) : "";
      }
      return Object.prototype.hasOwnProperty.call(ENTITY, e.toLowerCase()) ? ENTITY[e.toLowerCase()] : m;
    });
    return s.replace(/[ \t\f\v\r]+/g, " ").replace(/ *\n */g, "\n").replace(/\n{3,}/g, "\n\n").trim();
  }

  function clip(s, n) {
    s = String(s || "");
    return s.length > n ? s.slice(0, n) + "\n… (kısaltıldı)" : s;
  }

  function extractUrls(html) {
    const out = [];
    String(html || "").replace(/https?:\/\/[^\s"'<>)]+/gi, u => { if (out.indexOf(u) === -1) out.push(u); return u; });
    return out;
  }

  function normalizeCwe(value) {
    const m = String(value === undefined || value === null ? "" : value).match(/(\d{1,5})/);
    if (!m) return null;
    const n = parseInt(m[1], 10);
    return n > 0 ? n : null;
  }

  // { name, cwe } -> { testIds, unmatched }
  function mapScannerIssue(name, cwe) {
    const text = String(name || "");
    for (const rule of SCANNER_RULES) {
      if (rule.re.test(text)) return { testIds: rule.ids.slice(), unmatched: false };
    }
    const n = normalizeCwe(cwe);
    if (n && CWE_TO_WSTG[n]) return { testIds: CWE_TO_WSTG[n].slice(), unmatched: false };
    const hits = matchKeywordRules(text);
    if (hits.length) return { testIds: Array.from(new Set(hits.flatMap(h => h.ids))), unmatched: false };
    return { testIds: ["WSTG-INFO-04"], unmatched: true };
  }

  function buildScannerFinding(tool, src) {
    const map = mapScannerIssue(src.name, src.cwe);
    const cweNum = normalizeCwe(src.cwe);
    const cwe = cweNum ? "CWE-" + cweNum : null;
    const where = [src.endpoint, src.parameter ? `parametre: ${src.parameter}` : ""].filter(Boolean).join(" · ");
    const noteDetail = [
      where,
      src.confidence ? `${tool === "burp" ? "Burp" : "ZAP"} güveni: ${src.confidence}` : "",
      cwe || "",
      clip(src.summary || src.description, 400),
    ].filter(Boolean).join("\n");
    const description = [
      src.description,
      src.instancesText ? "Etkilenen adresler:\n" + src.instancesText : "",
      src.confidence ? `Kaynak: ${src.sourceLabel} (güven: ${src.confidence})` : `Kaynak: ${src.sourceLabel}`,
    ].filter(Boolean).join("\n\n");
    const finding = {
      tool,
      testIds: map.testIds,
      unmatched: map.unmatched,
      title: clip(src.name, 200) || "İsimsiz bulgu",
      detail: noteDetail,
      severity: src.severity,
      source: src.sourceLabel,
      pro: {
        title: clip(src.name, 300),
        severity: src.severity,
        endpoint: src.endpoint ? String(src.endpoint).slice(0, 300) : null,
        parameter: src.parameter ? String(src.parameter).slice(0, 200) : null,
        cwe,
        description: clip(description, MAX_TEXT),
        remediation: src.remediation ? clip(src.remediation, MAX_TEXT) : null,
        references: src.references && src.references.length ? src.references.join("\n") : null,
      },
    };
    if (src.request || src.response) {
      finding.http = {
        request: clip(src.request, MAX_HTTP),
        response: clip(src.response, MAX_HTTP),
        label: `${src.sourceLabel}: ${clip(src.name, 120)}`,
      };
    }
    return finding;
  }

  // --- Burp Suite ---

  const BURP_SEVERITY = { high: "high", medium: "medium", low: "low", information: "info", info: "info" };

  function decodeBase64Text(b64) {
    if (!b64) return "";
    let bin;
    try { bin = atob(String(b64).replace(/\s+/g, "")); } catch (e) { return ""; }
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    const text = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    return stripBinaryBody(text, bytes.length);
  }

  // İkili gövde (görsel, PDF…) metin olarak saklanmaz; başlıklar kalır.
  function stripBinaryBody(text, size) {
    if (text.indexOf("\u0000") === -1) return text;
    const sep = text.indexOf("\r\n\r\n") !== -1 ? "\r\n\r\n" : "\n\n";
    const head = text.indexOf(sep) !== -1 ? text.slice(0, text.indexOf(sep)) : "";
    return `${head}${sep}[ikili içerik atlandı, ${size} bayt]`;
  }

  // issue: Burp XML <issue> öğesinden okunmuş düz nesne (bkz. parseBurpXml).
  function normalizeBurpIssue(issue) {
    const sevKey = String(issue.severity || "").trim().toLowerCase();
    if (sevKey === "false positive") return null;
    const severity = BURP_SEVERITY[sevKey] || "info";
    const host = String(issue.host || "").trim().replace(/\/+$/, "");
    const path = String(issue.path || "").trim();
    const location = String(issue.location || "").trim();
    const paramMatch = location.match(/\[([^\]]+?) (?:parameter|cookie|header|JSON parameter|XML parameter)\]/i);
    const cweMatch = String(issue.vulnerabilityClassifications || "").match(/CWE-(\d+)/i);
    const description = [htmlToText(issue.issueBackground), htmlToText(issue.issueDetail)].filter(Boolean).join("\n\n");
    const remediation = [htmlToText(issue.remediationDetail), htmlToText(issue.remediationBackground)].filter(Boolean).join("\n\n");
    const rr = (issue.requestResponses || [])[0] || {};
    return buildScannerFinding("burp", {
      name: String(issue.name || "").trim(),
      severity,
      confidence: String(issue.confidence || "").trim(),
      endpoint: host + (path || ""),
      parameter: paramMatch ? paramMatch[1] : null,
      cwe: cweMatch ? cweMatch[1] : null,
      summary: htmlToText(issue.issueDetail) || htmlToText(issue.issueBackground),
      description,
      remediation,
      references: extractUrls(issue.references),
      request: rr.request ? (rr.requestBase64 ? decodeBase64Text(rr.request) : rr.request) : "",
      response: rr.response ? (rr.responseBase64 ? decodeBase64Text(rr.response) : rr.response) : "",
      sourceLabel: "Burp Suite",
    });
  }

  function childText(el, tag) {
    const c = Array.from(el.children || []).find(x => x.tagName === tag);
    return c ? c.textContent : "";
  }

  function parseBurpXml(xmlText) {
    const doc = new DOMParser().parseFromString(xmlText, "application/xml");
    if (doc.querySelector("parsererror")) throw new Error("Burp XML ayrıştırılamadı (geçersiz XML).");
    const findings = [];
    Array.from(doc.querySelectorAll("issues > issue")).forEach(el => {
      const rrs = Array.from(el.querySelectorAll(":scope > requestresponse")).map(rr => {
        const req = rr.querySelector(":scope > request");
        const res = rr.querySelector(":scope > response");
        return {
          request: req ? req.textContent : "", requestBase64: !!req && req.getAttribute("base64") === "true",
          response: res ? res.textContent : "", responseBase64: !!res && res.getAttribute("base64") === "true",
        };
      });
      const f = normalizeBurpIssue({
        name: childText(el, "name"), host: childText(el, "host"), path: childText(el, "path"),
        location: childText(el, "location"), severity: childText(el, "severity"), confidence: childText(el, "confidence"),
        issueBackground: childText(el, "issueBackground"), remediationBackground: childText(el, "remediationBackground"),
        issueDetail: childText(el, "issueDetail"), remediationDetail: childText(el, "remediationDetail"),
        vulnerabilityClassifications: childText(el, "vulnerabilityClassifications"), references: childText(el, "references"),
        requestResponses: rrs,
      });
      if (f) findings.push(f);
    });
    return findings;
  }

  // --- OWASP ZAP ---

  const ZAP_RISK = { 0: "info", 1: "low", 2: "medium", 3: "high" };
  const ZAP_CONFIDENCE = { 0: "False Positive", 1: "Low", 2: "Medium", 3: "High", 4: "Confirmed" };

  // alert: ZAP JSON/XML raporundaki tek alert (alanlar aynı adlarla).
  function normalizeZapAlert(alert, siteName) {
    const confidence = String(alert.confidence === undefined ? "" : alert.confidence).trim();
    if (confidence === "0") return null;   // ZAP'ta yanlış pozitif olarak işaretlenmiş
    const risk = parseInt(alert.riskcode, 10);
    const instances = Array.isArray(alert.instances) ? alert.instances : [];
    const first = instances[0] || {};
    const instancesText = instances.slice(0, MAX_INSTANCES_LISTED).map(i =>
      `- ${i.method ? i.method + " " : ""}${i.uri || ""}${i.param ? " [" + i.param + "]" : ""}${i.evidence ? " — kanıt: " + clip(i.evidence, 120) : ""}`
    ).join("\n") + (instances.length > MAX_INSTANCES_LISTED ? `\n… ve ${instances.length - MAX_INSTANCES_LISTED} adres daha` : "");
    const reqHead = first.requestHeader || first["request-header"] || "";
    const reqBody = first.requestBody || first["request-body"] || "";
    const resHead = first.responseHeader || first["response-header"] || "";
    const resBody = first.responseBody || first["response-body"] || "";
    const join = (h, b) => (h || b) ? `${String(h).replace(/\s+$/, "")}${b ? "\r\n\r\n" + b : ""}` : "";
    return buildScannerFinding("zap", {
      name: String(alert.name || alert.alert || "").trim(),
      severity: ZAP_RISK[risk] || "info",
      confidence: ZAP_CONFIDENCE[confidence] || "",
      endpoint: first.uri || siteName || "",
      parameter: first.param || null,
      cwe: alert.cweid,
      summary: htmlToText(alert.desc),
      description: [htmlToText(alert.desc), htmlToText(alert.otherinfo)].filter(Boolean).join("\n\n"),
      remediation: htmlToText(alert.solution),
      references: extractUrls(alert.reference),
      instancesText: instances.length > 1 ? instancesText : "",
      request: join(reqHead, reqBody),
      response: join(resHead, resBody),
      sourceLabel: "OWASP ZAP",
    });
  }

  function parseZapJson(jsonText) {
    const data = typeof jsonText === "string" ? JSON.parse(jsonText) : jsonText;
    const sites = Array.isArray(data.site) ? data.site : (data.site ? [data.site] : []);
    const findings = [];
    sites.forEach(site => (site.alerts || []).forEach(a => {
      const f = normalizeZapAlert(a, site["@name"] || site.name);
      if (f) findings.push(f);
    }));
    return findings;
  }

  function parseZapXml(xmlText) {
    const doc = new DOMParser().parseFromString(xmlText, "application/xml");
    if (doc.querySelector("parsererror")) throw new Error("ZAP XML ayrıştırılamadı (geçersiz XML).");
    const findings = [];
    Array.from(doc.querySelectorAll("OWASPZAPReport > site")).forEach(site => {
      Array.from(site.querySelectorAll(":scope > alerts > alertitem")).forEach(el => {
        const alert = {};
        ["pluginid", "alert", "name", "riskcode", "confidence", "desc", "solution", "otherinfo", "reference", "cweid"]
          .forEach(k => { alert[k] = childText(el, k); });
        alert.instances = Array.from(el.querySelectorAll(":scope > instances > instance")).map(i => ({
          uri: childText(i, "uri"), method: childText(i, "method"), param: childText(i, "param"),
          attack: childText(i, "attack"), evidence: childText(i, "evidence"),
          requestHeader: childText(i, "requestheader"), requestBody: childText(i, "requestbody"),
          responseHeader: childText(i, "responseheader"), responseBody: childText(i, "responsebody"),
        }));
        const f = normalizeZapAlert(alert, site.getAttribute("name"));
        if (f) findings.push(f);
      });
    });
    return findings;
  }

  // ---------- Ortak Giriş Noktası ----------

  function parse(text, toolHint, filename) {
    const tool = toolHint && toolHint !== "auto" ? toolHint : detectTool(text, filename);
    if (!tool) {
      throw new Error("Dosya türü otomatik olarak algılanamadı. Lütfen aracı elle seçin.");
    }
    let findings;
    switch (tool) {
      case "nmap": findings = parseNmap(text); break;
      case "nikto-xml": findings = parseNiktoXml(text); break;
      case "nikto-json": findings = parseNiktoJson(text); break;
      case "wpscan-json": findings = parseWpscan(text); break;
      case "burp-xml": findings = parseBurpXml(text); break;
      case "zap-xml": findings = parseZapXml(text); break;
      case "zap-json": findings = parseZapJson(text); break;
      default: throw new Error("Desteklenmeyen araç türü: " + tool);
    }
    return { tool, findings };
  }

  const api = {
    parse, detectTool, SEVERITIES,
    // Burp/ZAP yardımcıları (testler için dışa açık)
    htmlToText, mapScannerIssue, normalizeBurpIssue, normalizeZapAlert, parseZapJson,
    SCANNER_RULES, CWE_TO_WSTG, KEYWORD_RULES,
  };
  if (typeof module === "object" && module.exports) module.exports = api;
  else global.WSTGImport = api;
})(typeof window !== "undefined" ? window : globalThis);
