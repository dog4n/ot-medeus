"""Teşhis testleri — DURUM.md'deki bulguların her biri için bir test.

Bu testler kasıtlı olarak ŞU AN KIRMIZI (başarısız). Her bulgu düzeltildikçe
ilgili test yeşile döner. Bir düzeltme "bitti" sayılmadan önce:
    python3 -m unittest discover -s tests -v
çalıştırılmalı ve hiçbir eski test kırılmamalıdır.

Ağ veya root gerektirmez: tüm trafik 127.0.0.1 üzerinde, dış servisler mock'lanır.
"""

from __future__ import annotations

import http.server
import json
import socket
import sys
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from ot_medeus import classify, probes  # noqa: E402
from ot_medeus.models import Host, Service  # noqa: E402
from ot_medeus.ratelimit import NullLimiter  # noqa: E402
from ot_medeus.scanners import external as ext  # noqa: E402
from ot_medeus.scanners import nmap_ics  # noqa: E402
from ot_medeus.workflow import _merge_hosts, run_workflow  # noqa: E402


# ---------------------------------------------------------------- yardımcılar
def _http_server(body: str):
    """127.0.0.1 üzerinde verilen HTML'i dönen geçici HTTP sunucusu."""
    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            data = body.encode()
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_address[1]


def _raw_server(reply: bytes, port: int = 0):
    """Bağlantı sayan, verilen ham baytları dönen TCP sunucusu."""
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", port))
    s.listen(20)
    hits: list[int] = []

    def loop():
        while True:
            try:
                c, _ = s.accept()
            except OSError:
                return
            hits.append(1)
            try:
                c.settimeout(0.5)
                c.recv(1024)
                if reply:
                    c.sendall(reply)
            except OSError:
                pass
            c.close()

    t = threading.Thread(target=loop, daemon=True)
    t.start()

    class _Closer:
        """close(): accept'te bekleyen thread'i uyandırıp portu hemen serbest bırakır."""
        def close(self):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            s.close()
            t.join(timeout=2)

    return _Closer(), s.getsockname()[1], hits


# ------------------------------------------------------------- KRİTİK bulgular
class K1_PasifProfil(unittest.TestCase):
    """K1: 'passive' profili hedefe tek paket bile göndermemeli."""

    def test_passive_profil_aktif_baglanti_acmaz(self):
        try:
            srv, _, hits = _raw_server(b"", port=44818)   # EtherNet/IP portu
        except OSError:
            self.skipTest("44818 portu bu makinede kullanılamıyor")
        with mock.patch.object(ext, "query_shodan_internetdb", return_value={}):
            run_workflow("test", "external", targets=["127.0.0.1"],
                         profile_name="passive", enrich=False)
        srv.close()
        self.assertEqual(len(hits), 0, "passive profil hedefe TCP bağlantısı açtı")

    def test_passive_profil_ile_ic_ag_aktif_tarama_reddedilir(self):
        for wf in ("internal-active", "full"):
            with self.subTest(workflow=wf), self.assertRaises(ValueError):
                run_workflow("test", wf, targets=["127.0.0.1/32"],
                             profile_name="passive", enrich=False)


def _fake_resolve(ip="192.0.2.1"):
    """crt.sh testlerinde gerçek DNS'e çıkmamak için gethostbyname_ex taklidi."""
    return mock.patch.object(ext.socket, "gethostbyname_ex",
                             side_effect=lambda name: (name, [], [ip]))


class K2_Kapsam(unittest.TestCase):
    """K2: Kullanıcının vermediği IP'ler aktif taranmaz; 'aday' olarak listelenir."""

    def test_benzer_isimli_baska_domain_alinmaz(self):
        fake = [{"name_value": "vpn.kurum.com.tr\nnotkurum.com.tr\nx.evilkurum.com.tr"}]
        resp = mock.MagicMock()
        resp.__enter__.return_value.read.return_value = json.dumps(fake).encode()
        with mock.patch.object(ext.urllib.request, "urlopen", return_value=resp), _fake_resolve():
            subs = ext.fetch_crt_sh_subdomains("kurum.com.tr")
        self.assertEqual(sorted(subs), ["vpn.kurum.com.tr"])

    def _run_with_discovery(self, *, targets, scan_discovered=False, osint=None,
                            subs=None):
        """127.0.0.1:44818'i dinleyip keşif kaynaklarını mock'layarak external akışı çalıştırır."""
        try:
            srv, _, hits = _raw_server(b"", port=44818)
        except OSError:
            self.skipTest("44818 portu bu makinede kullanılamıyor")
        subs = subs if subs is not None else {
            "www.kurum.com.tr": {"ip": "127.0.0.1", "canonical": "www.kurum.com.tr.cdn.cloudflare.net",
                                 "ot_keyword_match": False}}
        patches = [mock.patch.object(ext, "fetch_crt_sh_subdomains", return_value=subs),
                   mock.patch.object(ext, "query_shodan_internetdb", return_value={})]
        if osint is not None:
            patches.append(mock.patch("ot_medeus.osint.discover", return_value=osint))
        for p in patches:
            p.start()
        try:
            res = run_workflow("test", "external", targets=targets, domain="kurum.com.tr",
                               profile_name="thorough", enrich=False,
                               scan_discovered=scan_discovered,
                               osint_creds={"censys_id": "x", "censys_secret": "y"} if osint else None)
        finally:
            for p in patches:
                p.stop()
            srv.close()
        return res, hits

    def test_crtsh_ip_varsayilan_olarak_taranmaz_ama_aday_listelenir(self):
        res, hits = self._run_with_discovery(targets=[])
        self.assertEqual(len(hits), 0, "crt.sh'tan gelen IP izinsiz tarandı")
        cand = {c["ip"]: c for c in res.candidates}
        self.assertIn("127.0.0.1", cand)
        self.assertFalse(cand["127.0.0.1"]["in_scope"])
        self.assertFalse(cand["127.0.0.1"]["scanned"])
        self.assertEqual(cand["127.0.0.1"]["owner_hint"], "Cloudflare")

    def test_osint_ip_varsayilan_olarak_taranmaz(self):
        res, hits = self._run_with_discovery(targets=[], subs={}, osint={"censys": ["127.0.0.1"]})
        self.assertEqual(len(hits), 0, "Censys'ten gelen IP izinsiz tarandı")
        self.assertIn("censys", res.candidates[0]["sources"])

    def test_scan_discovered_bayragi_ile_taranir(self):
        res, hits = self._run_with_discovery(targets=[], scan_discovered=True)
        self.assertGreater(len(hits), 0)
        self.assertTrue(res.candidates[0]["scanned"])

    def test_kullanici_hedefindeki_aday_kapsamda_sayilir(self):
        res, hits = self._run_with_discovery(targets=["127.0.0.1/32"])
        self.assertGreater(len(hits), 0)
        self.assertTrue(res.candidates[0]["in_scope"])

    def test_sahip_ipucu(self):
        self.assertEqual(ext.owner_hint("104.16.1.1", "", {}), "Cloudflare")
        self.assertIn("Azure", ext.owner_hint("203.0.113.5", "x.azureedge.net", {}))
        self.assertIn("CDN", ext.owner_hint("203.0.113.5", "", {"tags": ["cdn"]}))
        self.assertEqual(ext.owner_hint("203.0.113.5", "vpn.kurum.com.tr", {}), "")


class K3_BacnetGlobalYayin(unittest.TestCase):
    """K3: BACnet Who-Is tekil (unicast) ve yerel olmalı; global yayın (DNET=FFFF) olmamalı."""

    def test_who_is_global_yayin_degil(self):
        sent = {}

        class FakeSock:
            def __init__(self, *a, **k): pass
            def settimeout(self, t): pass
            def sendto(self, data, addr): sent["data"] = data
            def recvfrom(self, n): raise socket.timeout()
            def close(self): pass

        with mock.patch.object(probes.socket, "socket", FakeSock):
            probes.probe_bacnet_udp("192.0.2.5", 0.1, NullLimiter())
        data = sent["data"]
        self.assertEqual(data[1], 0x0A, "BVLC tipi Original-Unicast-NPDU (0x0A) olmalı")
        npdu_control = data[5]
        self.assertFalse(npdu_control & 0x20, "NPDU hedef ağ (DNET) taşımamalı — yayılır")


# ------------------------------------------------------------ YÜKSEK bulgular
class Y1_HttpCokmesi(unittest.TestCase):
    """Y1: Web portunda HTTP olmayan bir servis taramayı çökertmemeli."""

    def test_http_olmayan_servis_cokertmez(self):
        srv, port, _ = _raw_server(b"\x00\x01 binary OT protocol\r\n\r\n")
        try:
            probes.probe_http_service("127.0.0.1", port, 2, NullLimiter())
        except Exception as e:  # noqa: BLE001
            self.fail(f"yakalanmayan hata: {type(e).__name__}")
        finally:
            srv.close()


class Y2_NmapScriptleri(unittest.TestCase):
    """Y2: nmap bilinmeyen script adında hata verip çıkar; liste sadece resmi script içermeli."""

    # nmap/nmap master 'scripts/' klasöründe doğrulandı (10.11.2026).
    RESMI = {"modbus-discover", "s7-info", "enip-info", "bacnet-info", "omron-info",
             "pcworx-info", "fox-info", "iec-identify"}

    def test_sadece_resmi_scriptler(self):
        self.assertEqual(set(nmap_ics.ICS_SCRIPTS) - self.RESMI, set())


class Y3_YanlisPozitifImza(unittest.TestCase):
    """Y3: Sıradan web sayfaları OT imzası eşleşmemeli; gerçek OT panelleri eşleşmeli."""

    SIRADAN = ("<html><title>Kurum A.Ş.</title><a href='/privacy'>Privacy Policy</a>"
               "<p>Innovation for a better future. Enjoy our services.</p>"
               "<div class='carousel-item'>Project milestone reached</div>"
               "<footer>Digital transformation</footer></html>")

    def test_siradan_sayfa_eslesmez(self):
        srv, port = _http_server(self.SIRADAN)
        info = probes.probe_http_service("127.0.0.1", port, 2, NullLimiter())
        srv.shutdown(); srv.server_close()
        self.assertEqual((info or {}).get("matched_signatures", []), [])

    def test_gercek_ot_paneli_eslesir(self):
        srv, port = _http_server("<title>SIMATIC S7-1200 Web Server</title>Siemens AG")
        info = probes.probe_http_service("127.0.0.1", port, 2, NullLimiter())
        srv.shutdown(); srv.server_close()
        self.assertIn("SIMATIC", (info or {}).get("matched_signatures", []))

    def test_alt_alan_anahtar_kelimeleri(self):
        names = ["hotmail.kurum.com.tr", "support.kurum.com.tr", "agent.kurum.com.tr",
                 "groups.kurum.com.tr", "scada.kurum.com.tr", "bms01.kurum.com.tr"]
        fake = [{"name_value": "\n".join(names)}]
        resp = mock.MagicMock()
        resp.__enter__.return_value.read.return_value = json.dumps(fake).encode()
        with mock.patch.object(ext.urllib.request, "urlopen", return_value=resp), _fake_resolve():
            subs = ext.fetch_crt_sh_subdomains("kurum.com.tr")
        hits = sorted(n for n, v in subs.items() if v["ot_keyword_match"])
        self.assertEqual(hits, ["bms01.kurum.com.tr", "scada.kurum.com.tr"])


class Y4_Siniflandirma(unittest.TestCase):
    """Y4: Sınıflandırma ve birleştirme doğruluğu."""

    def test_iec104_rtu_olarak_siniflanir(self):
        h = Host(ip="10.0.0.1", services=[Service(2404, "TCP", "IEC 60870-5-104 (Enerji/SCADA)")])
        classify.classify(h)
        self.assertEqual(h.device_type, "RTU / SCADA Telemetri")

    def test_yanitsiz_modbus_yuksek_guven_almaz(self):
        h = Host(ip="10.0.0.2", services=[Service(502, "TCP", "Modbus TCP",
                                                  detail="Modbus TCP Portu Açık")])
        classify.classify(h)
        self.assertNotEqual(h.classification_confidence, "yüksek")

    def test_nmap_ureticisi_ezilmez(self):
        a = Host(ip="10.0.0.3", vendor="Bilinmiyor", source="active")
        b = Host(ip="10.0.0.3", mac="00:1B:1B:00:00:01", vendor="Siemens AG", source="nmap")
        self.assertEqual(_merge_hosts([a], [b])[0].vendor, "Siemens AG")


# -------------------------------------------------------------- ORTA bulgular
class O2_HedefListesi(unittest.TestCase):
    """O2: run_workflow çağıranın hedef listesini değiştirmemeli."""

    def test_hedef_listesi_degismez(self):
        targets = ["192.0.2.0/30"]
        with mock.patch("ot_medeus.osint.discover", return_value={"censys": ["198.51.100.9"]}), \
             mock.patch.object(ext, "fetch_crt_sh_subdomains", return_value={}), \
             mock.patch.object(ext, "query_shodan_internetdb", return_value={}), \
             mock.patch.object(ext, "run_external", return_value=([], 0)):
            run_workflow("t", "external", targets=targets, domain="kurum.com.tr",
                         enrich=False, osint_creds={"censys_id": "x", "censys_secret": "y"})
        self.assertEqual(targets, ["192.0.2.0/30"])


# --------------------------------------------------------------- BAKIM bulguları
class B1_ReadmeGuncel(unittest.TestCase):
    """B1: Her modül README'deki 'Yapı' bölümünde anlatılmalı (eskiyen not kontrolü)."""

    def test_her_modul_readmede(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        mods = [p.name for p in (ROOT / "ot_medeus").rglob("*.py")
                if p.name not in ("__init__.py", "__main__.py")]
        missing = sorted(m for m in mods if m not in readme)
        self.assertEqual(missing, [], f"README'de anlatılmayan modüller: {missing}")


if __name__ == "__main__":
    unittest.main()
