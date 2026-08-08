/*
 * WSTGImport — dış araç çıktılarını (Nmap / Nikto / WPScan) parse edip
 * WSTG checklist maddeleriyle eşleştiren yardımcı modül.
 *
 * Bu dosya saf JS'tir, DOM state'ine veya app.js içindeki değişkenlere
 * dokunmaz — sadece metin/dosya girdisini normalize edilmiş bir bulgu
 * listesine çevirir: { tool, testIds, title, detail, severity, source }
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

    try {
      const trimmed = (text || "").trim();
      if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
        const json = JSON.parse(trimmed);
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
      default: throw new Error("Desteklenmeyen araç türü: " + tool);
    }
    return { tool, findings };
  }

  global.WSTGImport = { parse, detectTool, SEVERITIES };
})(window);
