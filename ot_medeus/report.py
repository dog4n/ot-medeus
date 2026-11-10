"""Rapor üretimi: JSON (ham), Markdown (özet + diff), HTML (basit tablo)."""

from __future__ import annotations

import html
import json
from pathlib import Path

from .models import ScanResult
from .storage import ScanDiff


def write_json(result: ScanResult, path: str | Path) -> str:
    path = Path(path)
    path.write_text(json.dumps(result.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    return str(path)


def _diff_md(diff: ScanDiff) -> list[str]:
    lines = ["## Değişiklikler (önceki taramaya göre)"]
    if diff.previous_scan_id is None:
        lines.append("- İlk tarama; karşılaştırılacak önceki kayıt yok.\n")
        return lines
    if not diff.has_changes:
        lines.append("- Değişiklik yok (ortam sabit).\n")
        return lines
    if diff.new_hosts:
        lines.append(f"- 🆕 **Yeni cihaz(lar):** `{', '.join(diff.new_hosts)}`")
    if diff.removed_hosts:
        lines.append(f"- ❌ **Kaybolan cihaz(lar):** `{', '.join(diff.removed_hosts)}`")
    for ip, svcs in diff.new_services.items():
        lines.append(f"- ⚠️ `{ip}` üzerinde **yeni servis/port:** `{', '.join(svcs)}`")
    for ip, svcs in diff.removed_services.items():
        lines.append(f"- `{ip}` üzerinde kapanan servis/port: `{', '.join(svcs)}`")
    lines.append("")
    return lines


def write_markdown(result: ScanResult, diff: ScanDiff | None, path: str | Path) -> str:
    L: list[str] = [
        f"# OT-Medeus Raporu — `{result.workspace}`",
        f"- İş akışı: `{result.workflow}` | Profil: `{result.profile}`",
        f"- Başlangıç: {result.started_at} | Bitiş: {result.finished_at}",
        f"- Taranan hedef: {result.total_scanned} | OT/BMS adayı: {len(result.ot_hosts())}",
        "",
    ]
    if diff is not None:
        L += _diff_md(diff)
    L.append("## Bulgular")
    if not result.ot_hosts():
        L.append("- OT/BMS adayı cihaz bulunamadı.")
    for h in result.ot_hosts():
        header = f"### `{h.ip}`"
        meta = []
        if h.vendor and h.vendor not in ("Bilinmiyor", "Standart / Tanımsız OUI"):
            meta.append(h.vendor)
        if h.mac:
            meta.append(f"MAC `{h.mac}`")
        if meta:
            header += " — " + " | ".join(meta)
        L.append(header)
        if h.device_type:
            L.append(f"- **Tip:** {h.device_type} | Purdue: {h.purdue_level} "
                     f"(güven: {h.classification_confidence})")
        if h.shodan.get("ports"):
            L.append(f"- Shodan portları: `{h.shodan['ports']}`")
        if h.vulns:
            L.append(f"- **CVE ({len(h.vulns)}):** `{', '.join(h.vulns[:15])}`"
                     + (" …" if len(h.vulns) > 15 else ""))
        for c in h.cve_details[:5]:
            cvss = f" [CVSS {c['cvss']}]" if c.get("cvss") else ""
            L.append(f"    - `{c['id']}`{cvss}: {c.get('summary', '')}")
        for url in h.advisory_urls:
            L.append(f"- ICS-CERT/CISA advisory arama: {url}")
        for s in h.services:
            tail = f" — {s.detail}" if s.detail else ""
            L.append(f"- `{s.protocol}/{s.port}` {s.service}{tail}")
        for w in h.web_panels:
            L.append(f"- [WEB PANEL] `{w.scheme.upper()}:{w.port}` | "
                     f"başlık: `{w.title}` | imza: `{w.matched_signatures}` | SSL: `{w.ssl_matches}`")
        L.append("")
    path = Path(path)
    path.write_text("\n".join(L), encoding="utf-8")
    return str(path)


def write_html(result: ScanResult, diff: ScanDiff | None, path: str | Path) -> str:
    def esc(x) -> str:
        return html.escape(str(x))

    rows = []
    for h in result.ot_hosts():
        svc = "<br>".join(
            esc(f"{s.protocol}/{s.port} {s.service}" + (f" — {s.detail}" if s.detail else ""))
            for s in h.services
        )
        panels = "<br>".join(
            esc(f"{w.scheme.upper()}:{w.port} {w.title} {w.matched_signatures}")
            for w in h.web_panels
        )
        shodan = esc(h.shodan.get("ports", ""))
        tip = esc(f"{h.device_type}" + (f" · {h.purdue_level}" if h.purdue_level else ""))
        cve = esc(", ".join(h.vulns[:10])) + (" …" if len(h.vulns) > 10 else "")
        rows.append(
            f"<tr><td>{esc(h.ip)}</td><td>{esc(h.vendor or '')}</td>"
            f"<td>{tip}</td><td>{esc(h.mac or '')}</td><td>{svc}</td>"
            f"<td>{panels}</td><td>{shodan}</td>"
            f"<td class='cve'>{cve}</td></tr>"
        )

    diff_html = ""
    if diff and diff.has_changes:
        items = []
        for ip in diff.new_hosts:
            items.append(f"<li class='new'>Yeni cihaz: {esc(ip)}</li>")
        for ip in diff.removed_hosts:
            items.append(f"<li class='gone'>Kaybolan cihaz: {esc(ip)}</li>")
        for ip, s in diff.new_services.items():
            items.append(f"<li class='warn'>{esc(ip)} yeni port: {esc(', '.join(s))}</li>")
        diff_html = f"<h2>Değişiklikler</h2><ul>{''.join(items)}</ul>"

    doc = f"""<!DOCTYPE html>
<html lang="tr"><head><meta charset="utf-8">
<title>OT-Medeus — {esc(result.workspace)}</title>
<style>
 body{{font-family:system-ui,Segoe UI,sans-serif;margin:2rem;color:#1a2332;background:#f6f8fa}}
 h1{{font-size:1.4rem}} .meta{{color:#555}}
 table{{border-collapse:collapse;width:100%;background:#fff;margin-top:1rem}}
 th,td{{border:1px solid #d0d7de;padding:.5rem;text-align:left;vertical-align:top;font-size:.9rem}}
 th{{background:#24324a;color:#fff}}
 ul li.new{{color:#0a7d33}} ul li.gone{{color:#b01919}} ul li.warn{{color:#b06a00}}
 td.cve{{color:#b01919;font-weight:600}}
</style></head><body>
<h1>OT-Medeus Keşif Raporu — {esc(result.workspace)}</h1>
<p class="meta">İş akışı: {esc(result.workflow)} · Profil: {esc(result.profile)} ·
 Taranan: {esc(result.total_scanned)} · OT adayı: {len(result.ot_hosts())}</p>
{diff_html}
<h2>Bulgular</h2>
<table><thead><tr><th>IP</th><th>Üretici</th><th>Tip / Purdue</th><th>MAC</th>
<th>Servisler</th><th>Web Panel</th><th>Shodan</th><th>CVE</th></tr></thead>
<tbody>{''.join(rows) or '<tr><td colspan=8>Bulgu yok</td></tr>'}</tbody></table>
</body></html>"""
    path = Path(path)
    path.write_text(doc, encoding="utf-8")
    return str(path)
