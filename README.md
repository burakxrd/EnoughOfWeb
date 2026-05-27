# EnoughOfWeb

**Adaptive CTF Web Exploitation Automation Tool**

CTF web challenge'larını otomatik olarak tarayıp exploit eden, hatalarından öğrenen bir Python CLI aracı.

## Özellikler

- 🎯 **9 Saldırı Modülü**: SQLi, SSTI, CMDi, LFI, XSS, JWT, SSRF, IDOR, Auth Bypass
- 🧠 **Öğrenen Beyin**: Her denemeden ders çıkarır, kendi kural kitabını yazar
- 🔌 **Burp Suite Proxy**: Tüm trafiği Burp üzerinden geçirebilir
- 🐧 **Kali SSH**: Harici araçları (sqlmap, ffuf) SSH üzerinden Kali'de çalıştırır
- 🚫 **Bottleneck Detection**: Takılma durumlarını tespit edip atlar
- 💾 **Session Saves**: Her tarama `saves/` klasörüne kaydedilir
- 🤖 **Agent-Friendly**: AI agent'lar tarafından kolayca parse edilebilen çıktı

## Kurulum

```bash
pip install -r requirements.txt
```

## Kullanım

```bash
# İlk çalıştırma (proxy/SSH ayarları sorulur)
python main.py scan --url http://target.com --i-have-permission

# Belirli bir modül ile tarama
python main.py scan --url http://target.com --module sqli --i-have-permission

# Burp Suite proxy ile
python main.py scan --url http://target.com --proxy burp --i-have-permission

# Özel flag formatı
python main.py scan --url http://target.com --flag-format "HTB\{.*?\}" --i-have-permission

# İstatistikleri görüntüle
python main.py stats

# Kural kitabını görüntüle
python main.py rulebook

# Kayıtlı oturumları listele
python main.py saves

# Ayarları sıfırla
python main.py setup
```

## Saldırı Modülleri

| # | Modül | Açıklama |
|---|-------|----------|
| 1 | **SQLi** | Union, Error, Boolean Blind, Time-based Blind |
| 2 | **SSTI** | Jinja2, Twig, Mako, FreeMarker engine tespiti + RCE |
| 3 | **CMDi** | OS Command Injection (9 separator, filter bypass) |
| 4 | **LFI** | Path Traversal, PHP Wrappers, Double Encoding |
| 5 | **XSS** | Reflected XSS (context-aware, filter bypass) |
| 6 | **JWT** | None Algorithm, Weak Secret, Claim Manipulation |
| 7 | **SSRF** | Localhost Bypass, Cloud Metadata, Protocol Smuggling |
| 8 | **IDOR** | ID Enumeration, Path-based, Response Anomaly |
| 9 | **Auth** | SQLi Login, Cookie Manip, Forced Browse, Default Creds |

## Mimari

```
Recon → Brain (Strateji) → Modül Loop → Flag Check → Brain (Öğrenme) → Rapor
```

## Etik Kullanım

Bu araç **yalnızca** CTF yarışmalarında ve izinli pentest ortamlarında kullanılmalıdır.
`--i-have-permission` flag'i zorunludur.

## Lisans

Eğitim amaçlıdır. Yasadışı kullanımdan kullanıcı sorumludur.
