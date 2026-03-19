"""
DİZ-Analist: LLM Destekli Raporlama
Hayabusa, Chainsaw, Volatility (ve Zeek) bulgularını birleştirip 'Saldırı Senaryosu' üretir.

Ayrıca **Müdahale Önerileri (Playbook)**: Microsoft Sentinel Automation / CrowdStrike response
mantığına paralel, kural tabanlı somut adımlar (firewall blok, IAM sıfırlama, karantina vb.).

OpenAI API veya yerel Ollama (Llama3 vb.) kullanır.
Atıf: Cellebrite Smart Collector akıllı özetleme — çapraz kaynak senaryo üretimi.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Literal

ROOT = Path(__file__).resolve().parent.parent
RESULTS = ROOT / "data" / "results"

Provider = Literal["openai", "ollama"]

_IP_V4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
_WIN_PATH = re.compile(
    r"(?:[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]+|\\\\[^\\/]+\\[^|]+)",
    re.I,
)


def _load_json(path: Path) -> Any:
    """JSON dosyası — liste (Chainsaw/Hayabusa dizileri) veya nesne (cloud / network_analysis) olarak döner."""
    if not path.exists():
        return []
    try:
        with open(path, encoding="utf-8", errors="ignore") as f:
            data = json.load(f)
        if isinstance(data, (list, dict)):
            return data
        return [data] if data else []
    except (json.JSONDecodeError, Exception):
        return []


def _is_private_or_special_ip(ip: str) -> bool:
    ip = ip.strip()
    parts = ip.split(".")
    if len(parts) != 4:
        return True
    try:
        o = [int(x) for x in parts]
    except ValueError:
        return True
    if o[0] == 10:
        return True
    if o[0] == 172 and 16 <= o[1] <= 31:
        return True
    if o[0] == 192 and o[1] == 168:
        return True
    if o[0] == 127:
        return True
    if o[0] == 169 and o[1] == 254:
        return True
    if o[0] == 100 and 64 <= o[1] <= 127:  # CGNAT
        return True
    return False


def _extract_public_ips_from_text(text: str, limit: int = 24) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in _IP_V4.finditer(text or ""):
        ip = m.group(0)
        if _is_private_or_special_ip(ip) or ip in seen:
            continue
        seen.add(ip)
        out.append(ip)
        if len(out) >= limit:
            break
    return out


def _collect_ips_from_network_json(net: Any, limit: int = 20) -> list[str]:
    if not isinstance(net, dict):
        return []
    seen: set[str] = set()
    out: list[str] = []
    for key in ("beaconing_suspicious", "dns_tunneling_suspicious", "connections", "http_traffic"):
        for row in net.get(key) or []:
            if not isinstance(row, dict):
                continue
            blob = json.dumps(row, ensure_ascii=False)
            for m in _IP_V4.finditer(blob):
                ip = m.group(0)
                if _is_private_or_special_ip(ip) or ip in seen:
                    continue
                seen.add(ip)
                out.append(ip)
                if len(out) >= limit:
                    return out
    return out


def _extract_file_paths_from_text(text: str, limit: int = 12) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for m in _WIN_PATH.finditer(text or ""):
        p = m.group(0).strip()
        if len(p) < 6 or p in seen:
            continue
        low = p.lower()
        if any(low.endswith(ext) for ext in (".exe", ".dll", ".ps1", ".bat", ".vbs", ".js", ".msi")):
            seen.add(p)
            out.append(p[:400])
        if len(out) >= limit:
            break
    return out


def _load_cloud_identity_arns(limit: int = 8) -> list[str]:
    p = RESULTS / "cloud_findings.json"
    raw = _load_json(p)
    if not isinstance(raw, dict):
        return []
    ids: list[str] = []
    seen: set[str] = set()
    for bucket in ("critical_events", "hybrid_attacks", "bulut_sizintisi"):
        for ev in raw.get(bucket) or []:
            if not isinstance(ev, dict):
                continue
            u = ev.get("User_Identity") or ev.get("user_arn") or ev.get("privilege_summary")
            if isinstance(u, str) and len(u.strip()) > 6:
                s = u.strip()[:240]
                if s not in seen:
                    seen.add(s)
                    ids.append(s)
            if len(ids) >= limit:
                return ids
    return ids


def generate_intervention_playbook(
    findings: list[dict],
    alignment: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    Kural tabanlı müdahale önerileri (Sentinel Logic App / CrowdStrike playbook tarzı somut adımlar).
    LLM gerektirmez — operasyon ekiplerine doğrudan kontrol listesi.
    """
    steps: list[dict[str, Any]] = []
    all_text = "\n".join(
        f"{f.get('summary', '')} {f.get('details', '')}" for f in findings if isinstance(f, dict)
    )
    net = _load_json(RESULTS / "network_analysis.json")
    if not isinstance(net, dict):
        net = {}

    public_ips = _extract_public_ips_from_text(all_text, limit=32)
    for ip in _collect_ips_from_network_json(net):
        if ip not in public_ips:
            public_ips.append(ip)
    public_ips = public_ips[:16]

    if public_ips:
        ip_list = ", ".join(f"`{x}`" for x in public_ips[:12])
        steps.append(
            {
                "priority": "P1",
                "category": "firewall",
                "title_tr": "Ağ — şüpheli dış IP’ler (firewall / WAF)",
                "actions_tr": [
                    f"Firewall / NGFW / Cloud WAF: aşağıdaki adresleri **blok listesine** alın veya geçici **deny rule** tanımlayın "
                    f"(Sentinel *Block IP* / CrowdStrike *Network containment* playbook mantığı): {ip_list}",
                    "SIEM’te bu IP’ler için son 7 günlük oturumları korelasyonlayın; O365 / VPN / proxy loglarını ek korelasyon listesine alın.",
                ],
            }
        )

    zeek_beacon = any(
        isinstance(f, dict) and f.get("tool") == "Zeek/Tshark" and "Beaconing" in str(f.get("summary", ""))
        for f in findings
    )
    if zeek_beacon or (isinstance(net, dict) and (net.get("beaconing_suspicious") or [])):
        steps.append(
            {
                "priority": "P1",
                "category": "network_exfil",
                "title_tr": "Ağ — olası C2 / beaconing veya exfil",
                "actions_tr": [
                    "Egress filtreleri: bilinmeyen hedef **TCP/UDP yüksek port** ve uzun süreli oturumları inceleyin; SOC runbook ile **geçici blok** uygulayın.",
                    "Paket yakalama (PCAP) veya Zeek conn log **arıkleri muhafaza** edin; gerekirse IDS imzası güncelleyin.",
                ],
            }
        )

    dns_tun = any(
        isinstance(f, dict) and "DNS" in str(f.get("summary", "")) for f in findings
    ) or bool(net.get("dns_tunneling_suspicious") if isinstance(net, dict) else False)
    if dns_tun:
        steps.append(
            {
                "priority": "P1",
                "category": "dns",
                "title_tr": "DNS — tünelleme / anormal sorgu hacmi",
                "actions_tr": [
                    "İç DNS sunucularında veya güvenlik DNS çözümleyicide **şüpheli FQDN** için policy deny / sinkhole uygulayın.",
                    "Uç noktalarda DNS trafiğini 53/UDP dışına zorlayan uygulamaları (DoH bypass) kontrol edin.",
                ],
            }
        )

    has_vol_malfind = any(
        isinstance(f, dict) and "malfind" in str(f.get("tool", "")).lower() for f in findings
    )
    if has_vol_malfind:
        steps.append(
            {
                "priority": "P1",
                "category": "memory",
                "title_tr": "RAM — kod enjeksiyonu / malfind bulgusu",
                "actions_tr": [
                    "İlgili **endpoint'i izole** edin (ağ segmentasyonu veya EDR containment — Sentinel 'isolate device' benzeri).",
                    "Şüpheli **PID'leri sonlandırmadan önce** bellek dökümü ve disk imajı alın (adli zincir).",
                    "Aynı kullanıcı oturumu ile diğer istasyonlarda IOC taraması başlatın.",
                ],
            }
        )

    has_disk_high = any(
        isinstance(f, dict)
        and f.get("source") in ("Hayabusa", "Chainsaw")
        and _severity_score(str(f.get("severity", "info"))) >= 80
        for f in findings
    )
    paths = _extract_file_paths_from_text(all_text, limit=16)
    if paths:
        for pth in paths[:6]:
            steps.append(
                {
                    "priority": "P2",
                    "category": "quarantine",
                    "title_tr": f"Disk — şüpheli dosya yolu",
                    "actions_tr": [
                        f"EDR veya dosya sunucusunda `{pth}` yolunu **karantinaya alın** veya erişimi salt-okunur karantin paylaşımına taşıyın.",
                        "Dosya **hash'ini** (SHA-256) tehdit istihbaratı ile karşılaştırın; grupta aynı adı taşıyan diğer kopyaları arayın.",
                    ],
                }
            )
    elif has_disk_high:
        steps.append(
            {
                "priority": "P2",
                "category": "edr",
                "title_tr": "Disk — kritik EVTX / Sigma bulgusu",
                "actions_tr": [
                    "PowerShell / WMI / servis kurulumu ile ilişkili **süreç ağacını** EDR'de sonlandırın ve kalıcılık anahtarlarını tarayın.",
                    "Admin hesaplarında **zorunlu şifre sıfırlama** ve MFA yeniden kaydı düşünün.",
                ],
            }
        )

    for identity in _load_cloud_identity_arns(limit=6):
        steps.append(
            {
                "priority": "P1",
                "category": "cloud_iam",
                "title_tr": "Bulut — şüpheli kimlik / oturum",
                "actions_tr": [
                    f"**AWS / Azure / GCP:** `{identity}` ile ilişkili **geçici erişim anahtarlarını iptal** edin, **console oturumlarını** sonlandırın (Sentinel 'revoke session' playbook).",
                    "IAM: son 24 saatte eklenen policy / role attachment kayıtlarını **geri alın** ve CloudTrail / Activity Log üzerinde denetim başlatın.",
                    "Kritik kaynaklar için **break-glass** prosedürü ve onaylı geri dönüş planı uygulayın.",
                ],
            }
        )

    if alignment and str(alignment.get("summary_tr", "")).strip():
        steps.append(
            {
                "priority": "P2",
                "category": "coordination",
                "title_tr": "Korelasyon — çok kaynaklı zaman penceresi",
                "actions_tr": [
                    "Correlator özetindeki **yüksek örtüşmeli** zaman diliminde NOC + SOC + bulut ekibini ortak savaş odasına alın.",
                    "Mobil, disk, aynı aralıkta üretilen **ek delil** (yedek, PCAP parçası) toplayın.",
                ],
            }
        )

    if not steps:
        steps.append(
            {
                "priority": "P3",
                "category": "baseline",
                "title_tr": "Genel — yüksek öncelikli bulgu yok",
                "actions_tr": [
                    "Standart **hardening kontrol listesi** ve zayıf parola / MFA denetimini yineleyin.",
                    "Önleyici olarak egress ve DNS loglarını SIEM'e aktardığınızdan emin olun.",
                ],
            }
        )

    return {
        "playbook_version": "1.0",
        "steps": steps,
        "references_tr": (
            "Bu liste Microsoft Sentinel **Automation rules / Logic Apps** ve CrowdStrike **Response actions** "
            "mantığıyla uyumlu **somut müdahale taslaklarıdır**; üretim ortamında değişiklik yönetimi ve onay zorunludur."
        ),
    }


def format_intervention_playbook_markdown(playbook: dict[str, Any]) -> str:
    """Rapor dosyasına eklenecek Markdown blok."""
    lines = [
        "## Müdahale Önerileri (DİZ Playbook)",
        "",
        "> **Atıf:** Sentinel **Automation playbooks** ve CrowdStrike **automated remediation** akışlarına paralel; "
        "her madde operasyon ekibinin **anında çalıştırabileceği** net eylem cümleleri içerir.",
        "",
        f"*{playbook.get('references_tr', '')}*",
        "",
    ]
    for i, st in enumerate(playbook.get("steps") or [], 1):
        if not isinstance(st, dict):
            continue
        pr = st.get("priority", "P2")
        tit = st.get("title_tr", "Adım")
        cat = st.get("category", "")
        lines.append(f"### {i}. [{pr}] {tit} `{cat}`")
        lines.append("")
        for a in st.get("actions_tr") or []:
            lines.append(f"- {a}")
        lines.append("")
    lines.append("---")
    lines.append("")
    return "\n".join(lines)


def _load_hayabusa_events(path: Path) -> list[dict]:
    """Tek JSON dizisi veya NDJSON (satır satır) Hayabusa çıktısı."""
    if not path.exists():
        return []
    raw = path.read_text(encoding="utf-8", errors="ignore")
    try:
        data = json.loads(raw)
        ev = data if isinstance(data, list) else [data]
        return [e for e in ev if isinstance(e, dict)]
    except json.JSONDecodeError:
        out: list[dict] = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                o = json.loads(line)
                if isinstance(o, dict):
                    out.append(o)
            except json.JSONDecodeError:
                continue
        return out


def _severity_score(level: str) -> int:
    l = (level or "").lower().strip()
    if l in ("critical", "crit"):
        return 100
    if l in ("high", "yüksek"):
        return 80
    if l in ("medium", "orta"):
        return 50
    if l in ("low", "düşük"):
        return 30
    return 10


def collect_critical_findings(max_items: int = 10) -> list[dict]:
    """
    Hayabusa, Chainsaw, Volatility ve ağ (Zeek) kaynaklarından en kritik bulguları toplar.
    Her kayıt: source, tool, summary, severity, raw_hint
    """
    scored: list[tuple[int, dict]] = []

    # Hayabusa
    for p in [RESULTS / "hayabusa_output.json", RESULTS / "hayabusa.json"]:
        data = _load_hayabusa_events(p)
        if not data:
            continue
        for e in data:
            lv = e.get("Level") or e.get("level") or "info"
            rt = str(e.get("RuleTitle") or e.get("Rule Title") or "")[:200]
            dt = str(e.get("Details") or e.get("details") or "")[:300]
            ts = str(e.get("Timestamp") or "")[:19]
            sc = _severity_score(str(lv))
            if sc >= 50:
                scored.append((sc, {
                    "source": "Hayabusa",
                    "tool": "Hayabusa",
                    "timestamp": ts,
                    "severity": lv,
                    "summary": rt,
                    "details": dt,
                }))
        break

    # Chainsaw
    _cs_raw = _load_json(RESULTS / "chainsaw_output.json")
    _cs_list = _cs_raw if isinstance(_cs_raw, list) else []
    for e in _cs_list:
        if not isinstance(e, dict):
            continue
        lv = str(e.get("level") or e.get("Level") or "info")
        rt = str(e.get("Rule Title") or e.get("RuleTitle") or "")[:200]
        dt = str(e.get("Details") or e.get("EventData") or "")[:300]
        ts = str(e.get("Timestamp") or "")[:19]
        sc = _severity_score(lv)
        if sc >= 30:
            scored.append((sc, {
                "source": "Chainsaw",
                "tool": "Chainsaw (Sigma)",
                "timestamp": ts,
                "severity": lv,
                "summary": rt,
                "details": dt,
            }))

    # Volatility: malfind / netscan özetleri
    malfind = _load_json(RESULTS / "volatility" / "windows_malfind.json")
    rows = _flatten_vol_tree(malfind)
    for r in rows[:15]:
        if not isinstance(r, dict):
            continue
        pid = r.get("PID") or r.get("pid")
        proc = r.get("Process") or r.get("process") or ""
        scored.append((85, {
            "source": "Volatility",
            "tool": "Volatility (malfind)",
            "timestamp": "",
            "severity": "high",
            "summary": f"Şüpheli bellek bölgesi / enjeksiyon: PID {pid} {proc}",
            "details": str(r)[:400],
        }))

    netscan = _load_json(RESULTS / "volatility" / "windows_netscan.json")
    for r in _flatten_vol_tree(netscan)[:10]:
        if not isinstance(r, dict):
            continue
        loc = r.get("LocalAddress") or r.get("LocalAddr")
        rem = r.get("RemoteAddress") or r.get("RemoteAddr")
        pid = r.get("PID")
        scored.append((60, {
            "source": "Volatility",
            "tool": "Volatility (netscan)",
            "timestamp": "",
            "severity": "info",
            "summary": f"Ağ bağlantısı: {loc} -> {rem} (PID {pid})",
            "details": str(r)[:400],
        }))

    # Zeek / ağ
    net = _load_json(RESULTS / "network_analysis.json")
    if isinstance(net, dict):
        for c in net.get("beaconing_suspicious", [])[:5]:
            if isinstance(c, dict):
                scored.append((75, {
                    "source": "Zeek",
                    "tool": "Zeek/Tshark",
                    "timestamp": "",
                    "severity": "high",
                    "summary": "Alışılmadık port / Beaconing şüphesi",
                    "details": str(c)[:400],
                }))
        for c in net.get("dns_tunneling_suspicious", [])[:3]:
            if isinstance(c, dict):
                scored.append((70, {
                    "source": "Zeek",
                    "tool": "Zeek/Tshark",
                    "timestamp": "",
                    "severity": "high",
                    "summary": "DNS tünelleme şüphesi",
                    "details": str(c)[:400],
                }))

    scored.sort(key=lambda x: -x[0])
    out = [x[1] for x in scored[:max_items]]
    return out


def _flatten_vol_tree(data: Any) -> list[dict]:
    if isinstance(data, list):
        out = []
        for item in data:
            out.extend(_flatten_vol_tree(item))
        return out
    if isinstance(data, dict):
        if "__children" in data:
            row = {k: v for k, v in data.items() if k != "__children"}
            out = [row] if row else []
            for c in data.get("__children", []):
                out.extend(_flatten_vol_tree(c))
            return out
        return [data]
    return []


def _findings_block_text(findings: list[dict]) -> str:
    lines = []
    for i, f in enumerate(findings, 1):
        lines.append(
            f"{i}. [{f.get('tool')}] ({f.get('severity')}) {f.get('summary', '')}\n"
            f"   Detay: {f.get('details', '')[:250]}"
        )
    return "\n".join(lines)


def build_attack_scenario_prompt(findings: list[dict]) -> str:
    """LLM için saldırı senaryosu promptu (Türkçe)."""
    block = _findings_block_text(findings)

    return f"""Sen deneyimli bir DFIR uzmanısın. Aşağıda farklı adli araçlardan gelen EN KRİTİK bulgular var (Hayabusa, Chainsaw/Sigma, Volatility bellek analizi, Zeek ağ analizi).

Görevin: Bu bulguları TEK bir akıcı paragrafta birleştirerek olası SALDIRI SENARYOSUNU yaz (Türkçe).

Kurallar:
- Her bulguyu hangi araçtan geldiğini parantez içinde kısaca belirt (örn. Hayabusa, Volatility, Zeek).
- Kronoloji ve nedensellik kur: önce sızma/erişim, sonra kalıcılık veya gizleme, sonra veri sızıntısı veya C2.
- Spekülatif ifadeleri "olasılık" olarak işaretle; kesin olmayan şeyleri abartma.
- Örnek üslup: "Saldırgan RDP üzerinden brute-force ile sızmış olabilir (Hayabusa), ardından RAM'de gizli bir shell tespit edilmiş (Volatility) ve dışarıdaki X IP'sine yoğun trafik görülmüş (Zeek)."

Kritik bulgular:
{block}

Yanıtını şu başlıkla başlat:
## Saldırı Senaryosu (DİZ-Analist)

Ardından 1-3 paragraf senaryo metni yaz. Son olarak kısa bir "## Özet Maddeler" listesi ekle (3-5 madde).
"""


def build_detective_investigation_prompt(
    findings: list[dict],
    alignment: dict[str, Any] | None = None,
) -> str:
    """
    Dedektif uslubu: başlangıç → ilerleyiş → sonuç.
    ``alignment``: ``correlator.build_cross_source_timestamp_alignment`` çıktısı.
    """
    block = _findings_block_text(findings)
    align_section = ""
    if alignment:
        st = str(alignment.get("summary_tr") or "").strip()
        if st:
            align_section = f"\n## Çok kaynaklı zaman hizalaması (DİZ correlator)\n{st}\n"
        ranked = alignment.get("ranked_by_coverage") or []
        if ranked:
            align_section += (
                "\nEn yüksek örtüşmeli zaman pencereleri (özet):\n"
                + json.dumps(ranked[:6], ensure_ascii=False, indent=2)[:6000]
                + "\n"
            )
    return f"""Sen deneyimli bir siber suç dedektifisin (adli analiz + olay müdahalesi disiplini).

Bu veriler ışığında şunları bir dedektif gibi, net ve kanıta dayalı şekilde raporla (Türkçe):

1. **Başlangıç noktası** — Saldırı zincirinin muhtemel ilk görünür adımı veya ilk tutarlı kanıt (hangi kanal, hangi zaman).
2. **İlerleyiş** — Olayların nasıl ilerlediği: disk günlükleri, bellek, ağ çıkışları, bulut API'leri ve mobil kanıtlar arasında bağ kur.
3. **Sonuç** — Operasyonun ulaştığı muhtemel sonuç (ör. veri sızdırma, yetki kötüye kullanımı); kanıt yoksa bunu açıkça belirt.

Kurallar:
- Kanıtta olmayanı kesin diye söyleme; tahminleri "olası" olarak işaretle.
- Zaman sırasına özellikle dikkat et; aşağıdaki correlator özeti farklı kanalların aynı zaman penceresinde örtüştüğü anları listeler.

{align_section}

### Kritik bulgular (özet liste)
{block}

Yanıtını şu yapıda ver:
## Soruşturma Raporu (Dedektif)
### Başlangıç
### İlerleyiş
### Sonuç
### Açık sorular ve önerilen sonraki adımlar (madde işaretli, kısa)
"""


def _call_openai(prompt: str, model: str = "gpt-4o-mini") -> str:
    try:
        from openai import OpenAI
    except ImportError:
        raise ImportError("pip install openai")

    api_key = os.environ.get("OPENAI_API_KEY")
    if not api_key:
        raise ValueError("OPENAI_API_KEY ortam değişkeni gerekli")

    client = OpenAI(api_key=api_key)
    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": "Sen Türkçe konuşan bir siber güvenlik ve DFIR uzmanısın."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.35,
        max_tokens=3500,
    )
    return response.choices[0].message.content or ""


def _call_ollama(prompt: str, model: str = "llama3.2") -> str:
    try:
        from ollama import Client
    except ImportError:
        raise ImportError("pip install ollama")

    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
    client = Client(host=host)
    response = client.chat(
        model=model,
        messages=[
            {"role": "system", "content": "Sen Türkçe konuşan bir siber güvenlik ve DFIR uzmanısın."},
            {"role": "user", "content": prompt},
        ],
    )
    return response.message.content or ""


def build_intervention_playbook_prompt_addon(findings: list[dict]) -> str:
    """İsteğe bağlı: LLM’ye müdahale üslubu hatırlatması (deterministic playbook ayrıca eklenir)."""
    return (
        "\n\nEk görev (kısa): Sonunda '## Müdahale Önerileri (özet)' başlığı altında 3-5 madde ile "
        "**somut** eylemler öner (ör. hangi IP’yi bloklamak, hangi kullanıcı oturumunu kesmek). "
        "Bulgularda geçen teknik ayrıntıları aynen kullan. Deterministik playbook raporda ayrıca listelenecek.\n"
    )


def run_diz_analyst(
    provider: Provider | None = None,
    model: str | None = None,
    max_findings: int = 10,
    output_path: Path | None = None,
    detective_mode: bool = False,
    alignment: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """
    DİZ-Analist: Kritik bulguları toplar, LLM ile saldırı senaryosu üretir.

    Args:
        detective_mode: True ise dedektif uslubu (başlangıç / ilerleyiş / sonuç) promptu kullanılır.
        alignment: ``build_cross_source_timestamp_alignment`` çıktısı (dedektif modunda ek bağlam).

    Returns:
        success, report_text, report_path, findings_used, provider, model, error
    """
    findings = collect_critical_findings(max_items=max_findings)
    if not findings:
        return {
            "success": False,
            "error": "Kritik bulgu bulunamadi. Once main.py ile analiz calistirin.",
            "findings_used": [],
        }

    if detective_mode:
        prompt = build_detective_investigation_prompt(findings, alignment)
    else:
        prompt = build_attack_scenario_prompt(findings)
    prompt = prompt + build_intervention_playbook_prompt_addon(findings)

    if provider is None:
        provider = "openai" if os.environ.get("OPENAI_API_KEY") else "ollama"
    model = model or ("gpt-4o-mini" if provider == "openai" else "llama3.2")

    try:
        if provider == "openai":
            report = _call_openai(prompt, model=model)
        else:
            report = _call_ollama(prompt, model=model)
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "findings_used": findings,
            "provider": provider,
            "model": model,
        }

    playbook = generate_intervention_playbook(findings, alignment)
    playbook_md = format_intervention_playbook_markdown(playbook)

    out_dir = RESULTS / "diz_analyst"
    out_dir.mkdir(parents=True, exist_ok=True)
    default_name = "detective_report.md" if detective_mode else "attack_scenario.md"
    rp = Path(output_path) if output_path else out_dir / default_name
    rp.write_text(
        report
        + "\n\n"
        + playbook_md
        + "\n\n---\n\n## Kaynak bulgular (DİZ)\n\n"
        + json.dumps(findings, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )

    pb_path = out_dir / "intervention_playbook.json"
    try:
        pb_path.write_text(json.dumps(playbook, ensure_ascii=False, indent=2), encoding="utf-8")
    except OSError:
        pass

    meta = out_dir / "diz_analyst_metadata.json"
    meta.write_text(
        json.dumps(
            {
                "findings_count": len(findings),
                "provider": provider,
                "model": model,
                "report_path": str(rp),
                "intervention_playbook_path": str(pb_path),
                "intervention_steps": len(playbook.get("steps") or []),
            },
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    return {
        "success": True,
        "report_text": report,
        "report_path": str(rp),
        "findings_used": findings,
        "provider": provider,
        "model": model,
        "intervention_playbook": playbook,
        "intervention_markdown": playbook_md,
    }


def analyze_from_events(
    events: list[dict],
    provider: Provider | None = None,
    model: str | None = None,
) -> dict[str, Any]:
    """
    Harici olay listesi (normalize timeline) ile analiz — test ve entegrasyon için.
    En kritik 10 olayı seçer.
    """
    scored = []
    for e in events:
        if not isinstance(e, dict):
            continue
        lv = e.get("Level") or e.get("level") or "info"
        sc = _severity_score(str(lv))
        scored.append((sc, {
            "source": e.get("Source") or e.get("source_tool") or "unknown",
            "tool": e.get("Source") or "timeline",
            "timestamp": str(e.get("Timestamp", ""))[:19],
            "severity": lv,
            "summary": str(e.get("RuleTitle", ""))[:200],
            "details": str(e.get("Details", ""))[:300],
        }))
    scored.sort(key=lambda x: -x[0])
    findings = [x[1] for x in scored[:10]]
    if not findings:
        return {"success": False, "error": "Olay yok"}

    prompt = build_attack_scenario_prompt(findings) + build_intervention_playbook_prompt_addon(findings)
    provider = provider or ("openai" if os.environ.get("OPENAI_API_KEY") else "ollama")
    model = model or ("gpt-4o-mini" if provider == "openai" else "llama3.2")

    if provider == "openai":
        report = _call_openai(prompt, model=model)
    else:
        report = _call_ollama(prompt, model=model)

    playbook = generate_intervention_playbook(findings, None)
    return {
        "success": True,
        "report_text": report,
        "findings_used": findings,
        "provider": provider,
        "model": model,
        "intervention_playbook": playbook,
        "intervention_markdown": format_intervention_playbook_markdown(playbook),
    }
