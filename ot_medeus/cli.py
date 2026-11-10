"""OT-Medeus komut satırı arayüzü.

Örnekler:
  # Dış ağ (perimeter) — SADECE YETKİLİ hedeflerde
  python -m ot_medeus -w kurum_dis -f external -d kurum.com.tr -t 203.0.113.0/24

  # İç ağ güvenli aktif tarama
  sudo python -m ot_medeus -w kurum_ic -f internal-active -t 10.10.20.0/24 --profile safe

  # Pasif dinleme (hiç paket göndermez)
  sudo python -m ot_medeus -w kurum_pasif -f internal-passive -i eth0 --duration 120
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .config import PROFILES
from .report import write_html, write_json, write_markdown
from .storage import Store
from .workflow import run_workflow

BANNER = r"""
  ___ _____   __  __         _
 / _ \_   _| |  \/  |___ ___| |___ _  _ ___
| (_) || |   | |\/| / -_) _ \ / -_) || (_-<
 \___/ |_|   |_|  |_\___\___/_\___|\_,_/__/
   Kurumsal OT / ICS / BMS Keşif Orkestratörü  v%s
""" % __version__

LEGAL = ("[!] Yalnızca YETKİLİ varlık envanteri / sızma testi için. "
         "Hedefleri taramaya yazılı izniniz olduğundan emin olun.")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ot_medeus", description="OT/ICS/BMS keşif motoru")
    p.add_argument("-w", "--workspace", required=True, help="Çalışma alanı adı")
    p.add_argument("-f", "--workflow", required=True,
                   choices=["external", "internal-active", "internal-passive", "full"])
    p.add_argument("-t", "--target", help="Hedef IP/CIDR (virgülle ayrılabilir)")
    p.add_argument("-d", "--domain", help="Dış ağ CT Log (crt.sh) taraması için domain")
    p.add_argument("-i", "--interface", help="Pasif dinleme ağ arayüzü (örn: eth0)")
    p.add_argument("--duration", type=int, default=60, help="Pasif dinleme süresi (sn)")
    p.add_argument("--profile", choices=list(PROFILES), default="safe",
                   help="Tarama profili (varsayılan: safe)")
    p.add_argument("--engine", choices=["native", "nmap", "both"], default="native",
                   help="Tarama motoru: native (saf-Python) / nmap (ICS NSE) / both")
    p.add_argument("--nmap-udp", action="store_true",
                   help="nmap motorunda UDP/BACnet taraması (root gerekir)")
    p.add_argument("--oui-file",
                   help="IEEE OUI kayıt dosyası (oui.csv / nmap-mac-prefixes) — "
                        "üretici kapsamını genişletir")
    p.add_argument("--no-enrich", dest="enrich", action="store_false",
                   help="Sınıflandırma ve CVE zenginleştirmeyi kapat")
    p.add_argument("--offline", action="store_true",
                   help="Çevrimiçi CVE (CIRCL) sorgusunu kapat; sadece Shodan vulns")
    p.add_argument("--censys-id", help="Censys API ID (OSINT genişletme)")
    p.add_argument("--censys-secret", help="Censys API Secret")
    p.add_argument("--fofa-email", help="FOFA hesap e-postası")
    p.add_argument("--fofa-key", help="FOFA API anahtarı")
    p.add_argument("--passive-only", action="store_true",
                   help="Dış ağda aktif paket gönderme; sadece OSINT")
    p.add_argument("--out", default="workspaces", help="Çıktı kök dizini")
    return p


def main(argv: list[str] | None = None) -> int:
    print(BANNER)
    print(LEGAL + "\n")
    args = build_parser().parse_args(argv)

    targets = [t.strip() for t in args.target.split(",")] if args.target else []
    if args.workflow in ("external", "internal-active", "full") and not (targets or args.domain):
        print("[!] Bu iş akışı için -t (hedef) veya -d (domain) gerekli.", file=sys.stderr)
        return 2

    ws_dir = Path(args.out) / args.workspace
    ws_dir.mkdir(parents=True, exist_ok=True)

    if args.oui_file:
        from .oui_loader import load_oui, merge_into_signatures
        added = merge_into_signatures(load_oui(args.oui_file))
        print(f"[*] OUI kaydı yüklendi: +{added} üretici ön eki eklendi.")

    print(f"[*] '{args.workflow}' iş akışı başlıyor (profil: {args.profile}, motor: {args.engine})...")
    osint_creds = {}
    if args.censys_id and args.censys_secret:
        osint_creds.update(censys_id=args.censys_id, censys_secret=args.censys_secret)
    if args.fofa_email and args.fofa_key:
        osint_creds.update(fofa_email=args.fofa_email, fofa_key=args.fofa_key)

    result = run_workflow(
        args.workspace, args.workflow,
        targets=targets, domain=args.domain, interface=args.interface,
        duration=args.duration, profile_name=args.profile, passive_only=args.passive_only,
        engine=args.engine, nmap_udp=args.nmap_udp,
        enrich=args.enrich, cve_online=not args.offline,
        osint_creds=osint_creds or None,
    )
    for note in result.parameters.get("notes", []):
        print(f"    [i] {note}")
    print(f"    [+] Tamamlandı: {len(result.ot_hosts())} OT/BMS adayı / "
          f"{result.total_scanned} hedef tarandı.")

    store = Store(ws_dir / "ot_medeus.db")
    scan_id = store.save_scan(result)
    diff = store.diff(args.workspace, scan_id)
    store.close()

    json_p = write_json(result, ws_dir / f"scan_{scan_id}.json")
    md_p = write_markdown(result, diff, ws_dir / f"scan_{scan_id}.md")
    html_p = write_html(result, diff, ws_dir / f"scan_{scan_id}.html")

    if diff.has_changes:
        print("    [!] Önceki taramaya göre DEĞİŞİKLİK var "
              f"(yeni cihaz: {len(diff.new_hosts)}, kaybolan: {len(diff.removed_hosts)}).")

    print(f"\n[✓] Çıktılar (scan #{scan_id}):")
    print(f"    ├── JSON : {json_p}")
    print(f"    ├── MD   : {md_p}")
    print(f"    └── HTML : {html_p}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
