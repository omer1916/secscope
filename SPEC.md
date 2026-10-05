# SecScope — Masaüstü Güvenlik, SEO ve Dayanıklılık Test Platformu
### Claude Code için Ürün ve Mühendislik Şartnamesi (SPEC.md)

> Bu dosya projenin tek doğruluk kaynağıdır. Kodlamaya başlamadan önce tamamını oku.
> Çalışma adı "SecScope"; kullanıcı isterse değiştirilebilir (tek yerden: `src/secscope/__about__.py`).
> Kullanıcıyla Türkçe konuş. Kod, değişken adı, commit mesajı ve kod yorumları İngilizce olsun.
> Arayüz metinleri Türkçe (varsayılan) ve İngilizce olacak şekilde i18n ile yazılsın.

---

## 0. Çalışma Kuralları (Claude Code için)

1. **Önce plan modu.** Kod yazmadan önce bu şartnameyi okuyup bana kısa bir uygulama planı sun: milestone sırası, riskler, sorular. Ben onaylamadan M0'dan öteye geçme.
2. **Milestone döngüsü:** her milestone için (a) tasarımı 10 satırda özetle, (b) testleri önce veya birlikte yaz, (c) uygula, (d) testleri ve linter'ı çalıştır, (e) Bölüm 14'teki "Bitti tanımı"nı kontrol et, (f) küçük, anlamlı commit'ler at. Bitti tanımı sağlanmadan sonraki milestone'a geçme.
3. **Dış araç bayraklarını varsayma.** Bu şartnamedeki CLI bayrakları ve JSON şemaları hafızadan/araştırmadan gelir ve sürümler arasında değişebilir. Bir aracı sarmalamadan önce `<araç> --help`, sürüm numarası ve gerçek örnek çıktı ile doğrula; doğruladığın bayrakları `docs/tool-notes/<araç>.md` dosyasına yaz.
4. **Hiçbir şeyi sessizce atlama.** Bir araç yoksa (Java, Node, Trivy…) o modül "SKIPPED: neden + nasıl kurulur" diye raporda görünür; uygulama çökmez, yalnızca eksik modülü gri gösterir.
5. **Kapsam koruması (Bölüm 4) bu projenin en önemli güvenlik özelliğidir.** Atlatılabilir hale getiren hiçbir değişiklik yapma, bunun için test yaz.
6. **Bağımlılıkları pinle** (`uv.lock`), her dış ikili dosyayı sürüm + SHA-256 ile sabitle (`tools/manifest.toml`).
7. **Her bulgu açıklanabilir olmalı:** ne bulundu, nerede, kanıt, neden risk, nasıl düzeltilir (kopyalanabilir kod ile), referans (CWE/OWASP).
8. Belirsizlikte tahmin yürütüp ilerleme; `docs/decisions/NNN-baslik.md` içinde kısa bir karar kaydı (ADR) yaz ve bana sor.
9. Gereksiz soyutlama yapma ama modül arayüzleri (Bölüm 5) kesin olsun; yeni tarayıcı eklemek = tek dosya + tek kayıt olmalı.

---

## 1. Ürün Tanımı

**Ne:** Kullanıcının kendi yazdığı web sitesi / web uygulaması / API için, kendi bilgisayarında çalışan masaüstü uygulaması. Kullanıcı proje klasörünü veya `.zip` dosyasını (ya da zaten çalışan bir `localhost` adresini) verir; uygulama:

1. Projeyi **statik olarak** inceler (kod, gizli anahtarlar, bağımlılıklar, yapılandırma),
2. Projeyi izole bir süreçte **çalıştırır** ve **dinamik olarak** saldırı simülasyonu yapar (DAST),
3. **Tarayıcı tabanlı** testler yapar (gerçek Chromium, JS hataları, CSP ihlalleri, erişilebilirlik),
4. **SEO ve Google görünürlüğü** denetimi yapar (teknik SEO, sayfa içi, yapısal veri, Core Web Vitals),
5. **Yük / stres / dayanıklılık** testi yapar (kırılma noktasını ve kaynak tüketimini bulur),
6. Sonuçları tek bir **rapor**da birleştirir: puanlar, önceliklendirilmiş bulgular, "şunu şöyle düzelt" çözümleri, iki tarama arası karşılaştırma.

**Kim için:** Kendi projesini yayına almadan önce test etmek isteyen geliştirici. **Yalnızca kendi sahip olduğu ve yerelde çalışan sistemler** hedeflenir.

**Başarı ölçütü:** Bilerek zafiyetli bırakılmış örnek uygulamalarda (Bölüm 12) tanımlı zafiyetlerin ≥ %90'ını bulmak, temiz örnek uygulamada ≤ %5 yanlış pozitif üretmek.

### Kapsam dışı (yapma)
- Uzak/üçüncü taraf siteleri tarama, internetten hedef bulma, port tarama (başka hostlara).
- Gerçek sistemlerde kalıcılık, veri sızdırma, gerçek exploit zincirleri, DoS'u başka hedeflere yöneltme.
- Kimlik bilgisi toplama/phishing özellikleri.
- Kapsam korumasını kapatan "gizli" ayar.

---

## 2. Teknoloji Kararları ve Gerekçeleri

Araştırma sonucu seçilen yığın. Gerekçeler "neden bu" sorusuna cevap verir; bir alternatife geçmeden önce ADR yaz.

| Katman | Seçim | Neden |
|---|---|---|
| Çekirdek dil | **Python 3.12+** | Tüm tarayıcıları (Semgrep, Bandit, Locust, Playwright) tek dilde orkestre eder; CLI araçlarını `subprocess` ile sarmak kolay; hızlı geliştirme. |
| Masaüstü arayüz | **PySide6 (Qt 6)** | Tek dil (Python), yerel görünüm, thread/QProcess desteği, grafik için pyqtgraph. LGPL. Electron: büyük paket, ikinci dil (Node). Tauri: Rust gerektirir, Python/CLI çağrıları için ek sarmalayıcı yazmak gerekir. Bu proje çok sayıda harici aracı çalıştırdığı için Python+Qt en az sürtünmeli yol. |
| Katman ayrımı | **Çekirdek (`secscope.core`) arayüzden bağımsız**, ayrı bir **worker süreç** | Tarama çökerse arayüz yaşar; aynı çekirdek `secscope` CLI'ı ile başsız (headless) çalışır → test ve CI kolaylaşır. Worker ↔ UI iletişimi: stdio üzerinden JSON-Lines olay akışı. |
| Veri modelleri | **Pydantic v2** | Doğrulama + JSON şema; bulgu/olay/yapılandırma tipleri. |
| HTTP istemcisi | **httpx (async)** | HTTP/1.1+2, zaman aşımı, bağlantı havuzu denetimi, asyncio yük üretimi. |
| HTML ayrıştırma | **selectolax** (hızlı) + **lxml** (sitemap/XML) | SEO analizi için binlerce sayfayı hızlı ayrıştırır. |
| Yapısal veri | **extruct** (JSON-LD, Microdata, RDFa, OG) | Google'ın tanıdığı formatların hepsini çıkarır. |
| robots.txt | **protego** (Google'ın RFC 9309 davranışına yakın) | `urllib.robotparser`'dan daha doğru. |
| Tarayıcı | **Playwright (Chromium)** | SPA tarama, konsol/ağ olayları, ekran görüntüsü, PDF rapor, Core Web Vitals ölçümü, axe-core ile erişilebilirlik. |
| SAST | **Semgrep** (CLI) + **Bandit** (Python) + kendi kural motorumuz | Semgrep çok dilli; JSON/SARIF çıktı verir. Kendi motorumuz araç yokken temel güvenceyi sağlar. |
| Sır tarama | **gitleaks** (ikili) + kendi entropi/regex tarayıcımız | Git geçmişini de tarar. |
| Bağımlılık (SCA) | **Trivy** (`fs`), **osv-scanner**, `pip-audit`, `npm audit`, `composer audit` (varsa) | Çapraz doğrulama; SBOM (CycloneDX) üretimi. |
| DAST (ana) | **OWASP ZAP** (daemon + REST API + Automation Framework) | Spider, AJAX spider, pasif+aktif tarama, kimlik doğrulama bağlamı, HTML/JSON rapor. Java 17+ gerekir. |
| DAST (şablon) | **Nuclei** (ikili, `-jsonl` çıktı) | Hızlı, şablon tabanlı; yanlış yapılandırma, açıkta dosya, teknoloji tespiti. |
| Kendi DAST kontrolleri | Python (httpx/Playwright) | Başlıklar, çerezler, CORS, yöntemler, oturum, yetki, hız sınırı vb. (Bölüm 6.3). |
| Yük/stres | **Locust** (headless, alt süreç, `LoadTestShape`) + **psutil** | Saf Python, CSV/JSON çıktı, adım adım yük artırma (shape) yazılabilir. k6 daha yüksek tek-düğüm verim sağlar → opsiyonel ikinci motor (eklenti). |
| Lighthouse | `lighthouse` npm CLI (Node varsa) | SEO/performans/erişilebilirlik/best-practices skorları. Yoksa Playwright ile kendi ölçümümüz. |
| Rapor | **Jinja2** → tek dosya HTML; PDF için Playwright `page.pdf()`; JSON + **SARIF 2.1.0** | Ek PDF bağımlılığı gerekmez. |
| Depolama | **SQLite** (`sqlite3`) + tarama başına klasör (`platformdirs`) | Geçmiş, karşılaştırma, regresyon. |
| Paketleme | **uv** (geliştirme), **PyInstaller** (dağıtım), araç yöneticisi | Windows/macOS/Linux; ikili araçları doğrulayarak indirir. |
| Kalite | ruff, pyright (strict), pytest, pytest-asyncio, pytest-qt, hypothesis, pre-commit, GitHub Actions | |

**Harici araç gereksinimleri (Araç Yöneticisi bunları algılar):** Java 17+ (ZAP), Node 20+ (Lighthouse, npm audit), Playwright Chromium, Trivy, gitleaks, Nuclei, osv-scanner, semgrep (pip). Eksikse uygulama "Kurulum Sihirbazı"nda tek tek önerir; indirilenler SHA-256 ile doğrulanır.

**Lisans notları (ADR yaz):** ZAP (Apache-2.0), Trivy (Apache-2.0), Nuclei ve şablonları (MIT), gitleaks (MIT), Locust (MIT), Playwright (Apache-2.0), PySide6 (LGPL: dinamik bağlama koşullarına uy). Semgrep motoru LGPL-2.1'dir ancak **Semgrep Registry kuralları ayrı, daha kısıtlı lisansla** gelir → kuralları yeniden dağıtmadan önce lisansı kontrol et; yoksa kendi kurallarımızı `rules/` altında yaz ve registry kurallarını yalnızca kullanıcının makinesinde, çevrimiçi iken çek.

---

## 3. Yüksek Seviye Mimari

```
┌────────────────────────── UI (PySide6) ───────────────────────────┐
│ Pano │ Yeni Tarama Sihirbazı │ Canlı İzleme │ Sonuçlar │ Geçmiş │ Ayarlar │
└──────────────▲───────────────────────────────┬─────────────────────┘
               │ JSON-Lines olayları (stdout)  │ komutlar (stdin)
┌──────────────┴───────────────────────────────▼─────────────────────┐
│                  Worker süreç  (secscope.worker)                    │
│  Orchestrator ── Scope Guard ── Sandbox Runner ── Tool Manager      │
│      │                                                              │
│  ┌───┴────── Modüller (hepsi aynı `ScanModule` arayüzü) ───────────┐│
│  │ intake │ sast │ secrets │ sca │ config │ dast_zap │ dast_nuclei  ││
│  │ dast_native │ browser │ seo │ perf_lighthouse │ load │ resilience││
│  └──────────────────────────────┬───────────────────────────────────┘│
│        Finding Normalizer → Dedup → Scoring → Remediation KB         │
│                         │                                            │
│                  Storage (SQLite) → Report Engine (HTML/PDF/JSON/SARIF)│
└──────────────────────────────────────────────────────────────────────┘
        ▲ aynı çekirdek:  `secscope` CLI (başsız mod, CI için)
```

### 3.1 Dizin yapısı

```
secscope/
├─ pyproject.toml   uv.lock   README.md   SPEC.md   CLAUDE.md
├─ tools/manifest.toml                 # ikili araçlar: sürüm, URL, sha256, platform
├─ rules/                              # kendi Semgrep/regex/ayar kurallarımız
├─ remediation/                        # YAML: kural_id -> açıklama, düzeltme, kod örnekleri
├─ src/secscope/
│  ├─ __about__.py  __main__.py  cli.py
│  ├─ core/        models.py events.py config.py scope_guard.py sandbox.py
│  │               orchestrator.py scoring.py dedup.py toolmgr.py logging.py
│  ├─ modules/     base.py registry.py
│  │               intake.py sast.py secrets.py sca.py config_audit.py
│  │               dast_zap.py dast_nuclei.py dast_native/  browser.py
│  │               seo/  perf_lighthouse.py  load/  resilience.py
│  ├─ reporting/   html.py pdf.py sarif.py json_export.py diff.py templates/
│  ├─ storage/     db.py migrations/ repo.py
│  ├─ ui/          app.py main_window.py pages/ widgets/ i18n/ (tr.json, en.json) theme/
│  └─ worker/      main.py ipc.py
├─ fixtures/                           # bilerek zafiyetli ve temiz örnek uygulamalar (Bölüm 12)
├─ tests/  unit/ integration/ e2e/ golden/
└─ packaging/      pyinstaller.spec  installers/
```

### 3.2 Olay akışı (worker → UI), JSON-Lines
Her satır bir olay: `{"v":1,"ts":..., "scan_id":..., "type": ...}`
`type` değerleri: `scan.started`, `module.started`, `module.progress` (`pct`, `message`), `module.log`, `finding`, `metric` (canlı grafik noktası: rps, p95, cpu, rss…), `module.skipped`, `module.finished`, `scan.finished`, `error`.
UI → worker komutları: `start`, `pause`, `resume`, `cancel`, `kill_target`. İptal edildiğinde tüm alt süreçler (ZAP, Locust, hedef uygulama) **süreç grubu** olarak sonlandırılır; zombi süreç kalmamalı (test et).

---

## 4. Kapsam Koruması (Scope Guard) — Pazarlık Konusu Değil

Amaç: araç yanlışlıkla (veya kötü niyetle) başka birine saldırmasın.

**Kurallar**
1. Dinamik modüllerin (ZAP, Nuclei, native DAST, browser, load, resilience) **tüm** ağ trafiği tek bir `ScopedHttpClient` / `ScopedSocket` katmanından geçer. Modüller doğrudan `httpx.Client` veya `socket` oluşturamaz (lint kuralı + test ile zorla).
2. İzinli hedefler **yalnızca loopback**: `localhost`, `127.0.0.0/8`, `::1`. (İleri seviye ayarda "kendi LAN adresim" seçeneği olabilir ama çift onay ister; varsayılan kapalı.)
3. **DNS yeniden bağlama / yönlendirme koruması:** her istekte hedef IP çözümlenir ve izin listesi ile karşılaştırılır; `Location` yönlendirmeleri dış hosta gidiyorsa **takip edilmez**, "kapsam dışı yönlendirme" olarak kaydedilir (bu aynı zamanda bir bulgudur: açık yönlendirme olabilir).
4. Harici araçlar (ZAP, Nuclei) için: ZAP'ın `Context` ve `Include/Exclude` regex'leri ile yalnızca hedef origin kapsama alınır; ZAP'ın proxy'si yalnızca `127.0.0.1`'e bağlanır; Nuclei yalnızca hedef URL ile çağrılır, `-no-interactsh` ile dış OAST sunucusuna gitmez, şablon güncellemeleri tarama sırasında yapılmaz.
5. Uygulama her taramadan önce **onay kutusu** gösterir: "Bu sistem bana aittir ve yalnızca yerel olarak test edilecektir." Onay, tarama kaydına yazılır.
6. Kapsam ihlali denemesi → istek **engellenir**, `scope.violation` olayı ve günlük kaydı oluşur; tarama devam eder.
7. **Birim testleri (zorunlu):** `http://example.com`, `http://127.0.0.1.evil.com`, `http://[::ffff:8.8.8.8]`, `http://0x7f000001` (izinli sayılır mı karar ver ve test et), `http://localhost@evil.com`, yönlendirme ile dışarı çıkış, DNS rebinding simülasyonu → hepsi doğru karar vermeli.

---

## 5. Modül Arayüzü ve Bulgu Modeli

```python
class ScanModule(Protocol):
    id: ClassVar[str]  # "sast", "seo", "load" ...
    title: ClassVar[LocalizedStr]
    category: ClassVar[Category]  # SECURITY | SEO | PERFORMANCE | RESILIENCE | QUALITY
    requires: ClassVar[Requirements]  # araçlar, "target_running": bool, "needs_source": bool

    def preflight(
        self, ctx: ScanContext
    ) -> PreflightResult: ...  # OK / SKIPPED(neden, kurulum ipucu)
    async def run(self, ctx: ScanContext, emit: Emitter) -> ModuleResult: ...
```

```python
class Finding(BaseModel):
    id: str  # kararlı parmak izi: sha256(rule_id + location + normalized_evidence)
    rule_id: str  # örn. "SEC-HDR-001"
    module: str
    category: Category
    title: LocalizedStr
    severity: Literal["critical", "high", "medium", "low", "info"]
    confidence: Literal["confirmed", "high", "medium", "low"]
    location: Location  # dosya:satır:sütun | URL + parametre + HTTP yöntemi
    evidence: (
        Evidence  # kod parçası, istek/yanıt (gizli bilgiler maskelenmiş), ekran görüntüsü yolu
    )
    description: LocalizedStr
    impact: LocalizedStr
    remediation: Remediation  # adımlar + stack'e özel kod örnekleri (Express/Flask/Django/PHP/Nginx/Apache/statik)
    references: list[Ref]  # CWE, OWASP Top 10 (2025) kategorisi, ASVS maddesi, Google dokümanı, MDN
    cwe: list[int]
    owasp: list[str]
    asvs: list[str]
    effort: Literal["S", "M", "L"]  # düzeltme eforu
    source_tool: str  # "semgrep", "zap", "native", ...
    first_seen_scan: str | None  # regresyon takibi için
```

**Kurallar:** Kanıttaki sırlar (token, parola) raporda **maskelenir** (`AKIA****…`). Aynı bulgu birden çok araçtan gelirse `dedup.py` birleştirir, `source_tool` listesi tutar ve güveni yükseltir (iki bağımsız araç = confidence artar). Her `rule_id` için `remediation/<rule_id>.yaml` bulunmalı; yoksa test başarısız olur (CI kuralı).

---

## 6. Güvenlik Modülleri

### 6.1 Proje Alımı (intake) ve Çalıştırma

**Girdi türleri:** klasör, `.zip`/`.tar.gz`, veya "zaten çalışan `http://localhost:PORT`" (bu durumda statik modüllerin kaynak kodu olmaz → yalnızca dinamik/SEO/yük).

**Güvenli açma (bu da bir saldırı yüzeyidir):**
- Zip Slip (`../`), mutlak yol, sembolik link, cihaz dosyası içeren girdileri reddet.
- Zip bombası: toplam açılmış boyut (varsayılan 2 GB), dosya sayısı (200 bin), sıkıştırma oranı (1:100) limiti.
- Orijinal dosyaları **asla değiştirme**; salt-okunur kopya `work/<scan_id>/src` altına açılır.
- `node_modules`, `.venv`, `vendor` büyük klasörler: statik koda dahil edilmez, ama bağımlılık taramasına girer.

**Proje parmak izi (fingerprint):** `package.json`, `requirements.txt`/`pyproject.toml`, `composer.json`, `index.html`, `Dockerfile`, `docker-compose.yml`, `.env*`, `next.config.*`, `vite.config.*`, `manage.py`, `app.py`, `artisan`, `wp-config.php` vb. dosyalardan **dil/framework/çalıştırma komutu** tahmin et: statik site, Express/Fastify/Next/Nuxt/Vite, Flask/FastAPI/Django, PHP (`php -S`), Laravel. Sonuç sihirbazda kullanıcıya **düzenlenebilir** gösterilir (çalıştırma komutu, port, çalışma dizini, ortam değişkenleri, hazır olma kontrolü URL'si, başlangıç zaman aşımı).

**Çalıştırma (SandboxRunner):**
- Statik site → yerleşik `http.server` benzeri güvenli sunucu (yalnızca 127.0.0.1, boş port).
- Sunuculu proje → kullanıcının verdiği komut alt süreçte; **127.0.0.1'e bağlan** (`HOST=127.0.0.1`, `PORT` ortam değişkeni), ortam değişkenleri **beyaz liste** ile geçirilir (kullanıcının gerçek sırları sızmasın), çalışma dizini kopya klasör, stdout/stderr günlüğe yazılır, **süreç grubu** ile başlatılıp iptalde tamamı öldürülür.
- Hazır olma: `GET /` (veya kullanıcının verdiği yol) 200–399 dönene kadar yoklama; zaman aşımında "başlatılamadı" + son 50 günlük satırı.
- **Veri güvenliği:** aktif tarama uygulamanın veritabanını bozabilir. Sihirbaz uyarır ve şunu önerir: SQLite dosyalarını tarama öncesi **otomatik anlık görüntü (snapshot) al, tarama sonunda geri yükle** seçeneği. Docker varsa "konteyner içinde çalıştır" (ağ yalnızca loopback, kaynak limitli) opsiyonu sun (M10).
- Kaynak izleme: hedef sürecin CPU/RSS/thread/açık dosya/ağ bağlantısı `psutil` ile 1 sn aralıkla `metric` olayı olarak yayımlanır (yük testi için de kullanılır).

### 6.2 Statik Analiz (kaynak kod gerekir)

| Alt modül | Araç | Kapsam / notlar |
|---|---|---|
| **SAST** | Semgrep (`semgrep scan --json …`, kural paketleri: owasp-top-ten, javascript, typescript, python, php, secrets…), Bandit (Python), kendi regex/AST kuralları | Enjeksiyon (SQL/NoSQL/komut/şablon/LDAP/XPath), XSS (`innerHTML`, `dangerouslySetInnerHTML`, `document.write`, şablonda `|safe`), SSRF, path traversal, güvensiz deserialization (`pickle`, `yaml.load`, `unserialize`), zayıf kripto (MD5/SHA1 parola, ECB, sabit IV, `Math.random` token), güvensiz rastgele, `eval/exec`, açık CORS, CSRF korumasının kapatılması, `debug=True`, sabit JWT sırrı, `verify=False` TLS, mass assignment, açık yönlendirme, güvensiz dosya yükleme, XXE. Semgrep yoksa kendi motor çalışır ve rapor "azaltılmış kapsam" notu düşer. |
| **Sır tarama** | gitleaks (`.git` geçmişi dahil) + kendi tarayıcı | API anahtarı, özel anahtar (`-----BEGIN … PRIVATE KEY`), DB bağlantı dizesi, `.env` commit'lenmiş, yüksek entropili dizeler (yanlış pozitifi azaltmak için bağlam + allowlist). Bulunan sır **raporda maskelenir**; öneri: anahtarı döndür (rotate) + geçmişten temizle (`git filter-repo`). |
| **Bağımlılık (SCA)** | Trivy `fs`, osv-scanner, `npm audit`, `pip-audit`, `composer audit` | CVE, CVSS, düzeltilmiş sürüm, doğrudan/dolaylı bağımlılık ayrımı, "kullanılmayan paket" ipucu, lisans uyarıları (GPL vb.), **SBOM (CycloneDX JSON)** çıktısı. Veri tabanları çevrimdışıysa: önbellek tarihi raporda göster, "güncelle" düğmesi sun. Typosquatting şüphesi (popüler paket adına çok yakın isim) + `postinstall` betiği içeren paketleri işaretle. |
| **Yapılandırma / altyapı** | Trivy `config`, kendi kurallarımız | `Dockerfile` (root kullanıcı, `latest` etiketi, `ADD` URL, sırrı `ENV`'de saklama), `docker-compose` (ayrıcalıklı mod, 0.0.0.0 port yayını), `nginx.conf`/`.htaccess` (başlık eksikliği, dizin listeleme), CI dosyaları (sırlar, `pull_request_target` riskleri), `.gitignore` eksikleri (`.env`, anahtarlar). |
| **Kod kalitesi/yapısal** | kendi kurallarımız | Hata ayıklama kodu, `console.log` ile hassas veri, geniş `except`, yorumda unutulmuş parola, test hesapları/varsayılan şifreler (`admin/admin`). |

### 6.3 Dinamik Analiz (çalışan uygulamaya) — DAST

Üç katman birlikte çalışır; sonuçlar birleştirilir ve tekilleştirilir.

**A) OWASP ZAP (`dast_zap`)**
- ZAP `-daemon` modunda, **rastgele API anahtarı** ve yalnızca `127.0.0.1` ile başlatılır (API anahtarını devre dışı bırakma; kullandığımız örneklerde `api.disablekey=true` görülür, biz bunu **yapmayız**).
- Tercih: **Automation Framework** planı (YAML) üret → `spider` → `spiderAjax` (SPA için) → `passiveScan-wait` → `activeScan` (politika: hızlı/standart/derin) → `report`. Alternatif: REST API (`/JSON/spider/action/scan/`, `/JSON/ascan/action/scan/`, `/JSON/core/view/alerts/`). Hangisinin kurulu sürümde stabil olduğunu doğrula (`docs/tool-notes/zap.md`).
- Kimlik doğrulamalı tarama: kullanıcı oturum bilgisini sihirbazda verir (form giriş: URL + alan adları + parola; veya `Authorization` başlığı; veya çerez). ZAP bağlamına (context) kullanıcı + "oturum açık/kapalı" göstergesi (regex) ile ekle. İki farklı rol (user/admin) verilirse **yatay/dikey yetki testleri** (Bölüm 6.3-C) yapılır.
- Bulgular `Finding`'e normalize edilir (ZAP `pluginId` → bizim `rule_id` eşlemesi `rules/zap_map.yaml`).
- Aktif tarama **yalnızca** kullanıcı onayıyla ve Scope Guard içinde çalışır; ZAP "attack mode" kapsam dışı hiçbir URL'ye gitmemeli (test et).

**B) Nuclei (`dast_nuclei`)**
- `nuclei -u <hedef> -jsonl -rl <hız sınırı> -c <eşzamanlılık> -severity … -tags …` (bayrakları sürümde doğrula). Varsayılan etiketler: `exposure`, `misconfig`, `tech`, `default-login` (yalnızca yerelde), `cve` (teknoloji tespit edilenlere). **Yıkıcı şablonları (dos, fuzz-bruteforce yoğun) varsayılan kapalı.**
- `-no-interactsh` (dış sunucuya çıkma), şablon güncellemesi tarama dışı ve açık kullanıcı eylemiyle.

**C) Kendi kontrollerimiz (`dast_native/`)** — her biri ayrı küçük dosya, ayrı `rule_id`, ayrı test:

| Grup | Kontroller |
|---|---|
| **Güvenlik başlıkları** (OWASP HTTP Headers Cheat Sheet'e göre) | `Content-Security-Policy` (yok / `unsafe-inline` / `unsafe-eval` / `*` / `object-src` eksik / `frame-ancestors` eksik; CSP'yi **ayrıştırıp** değerlendir), `Strict-Transport-Security` (`max-age` ≥ 1 yıl önerilir; OWASP örneği `max-age=63072000; includeSubDomains; preload` — yalnızca HTTPS'te anlamlı, yerelde "yayında HTTPS'e geç" notu), `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY` veya CSP `frame-ancestors`, `Referrer-Policy` (`strict-origin-when-cross-origin`), `Permissions-Policy` (gereksiz özellikleri kapat: `geolocation=(), camera=(), microphone=()`), `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy`, (COEP yalnızca ihtiyaç varsa; zorlama), `Cache-Control` (oturum/hassas sayfalarda `no-store`). **Kaldırılmalı:** `Server` sürüm bilgisi, `X-Powered-By`, `X-AspNet*`. **Kullanımdan kalkmış:** `X-XSS-Protection` (CSP'ye geç), `Expect-CT`, `Public-Key-Pins`. Düzeltme çıktısı: framework'e göre hazır kod (Express `helmet`, Flask `flask-talisman`, Django ayarları, PHP `header()`, Nginx `add_header … always`, Apache `Header always set`). |
| **Çerezler & oturum** | `Secure`, `HttpOnly`, `SameSite` (Lax/Strict), `__Host-` öneki, çerez kapsamı (`Domain`/`Path`), oturum kimliği entropisi (n örnek topla, tahmin edilebilirlik), giriş sonrası oturum kimliği yenileniyor mu (session fixation), çıkışta sunucu tarafı geçersiz kılma, çerezde hassas veri, eşzamanlı oturum, oturum zaman aşımı ipucu. |
| **CORS** | `Access-Control-Allow-Origin: *` + `Allow-Credentials: true`, gelen `Origin`'in olduğu gibi yansıtılması, `null` origin kabulü, regex gevşekliği (`evil-localhost`), `Allow-Methods/Headers` aşırı genişliği, preflight önbellek. Sahte `Origin` başlıklarıyla dene. |
| **HTTP yöntemleri & dizinler** | `OPTIONS` ile izinli yöntemler, `TRACE`, `PUT`/`DELETE` (yetkisiz), dizin listeleme (`Index of /`), yedek/artık dosyalar (`.bak`, `~`, `.old`, `.swp`, `.zip`, `.sql`), `.git/`, `.svn/`, `.env`, `.DS_Store`, `phpinfo.php`, `/admin`, `/debug`, `/actuator`, `/swagger`, `/graphql` (introspection açık mı), `source map` dosyaları (`*.js.map` üretimde açık). Yaygın yol listesi `data/paths.txt` (küçük, kaliteli; düşük hızda). |
| **Hata & bilgi sızıntısı** | Hatalı girdi/yol ile yığın izi (stack trace), SQL hatası, debug sayfası (Django/Flask/Laravel), sürüm bilgisi, iç IP/yol ifşası, yorumlarda hassas bilgi, `robots.txt` içinde gizli yol ipuçları. |
| **Girdi kaynaklı zafiyetler (güvenli kanıt)** | Yansıyan XSS: benzersiz zararsız **canary** dizesi (`secscope7f3a<>"'`) ile yansıma bağlamını çıkar (HTML/attr/JS/URL) ve **gerçek tarayıcıda** (Playwright) yürütme olup olmadığını doğrula (zararsız `window.__ss_xss=1` işareti; `alert()` kullanma). SQLi: hata tabanlı + boolean fark + **zaman tabanlı (kısa, ≤3 sn)** doğrulama; veri okuma/yazma payload'ı yok. Path traversal: kendi fixture dosyasını (`canary.txt`) okumayı dene; `/etc/passwd` okuma girişimi **yok** — yerine kontrollü işaret dosyası. Komut enjeksiyonu: zararsız zaman/echo işareti. SSRF: yalnızca yerel "canary dinleyici" (loopback'te kendi açtığımız port) ile. Açık yönlendirme, CRLF/başlık enjeksiyonu, Host header injection, SSTI (`{{7*7}}` benzeri aritmetik işaret), XXE (yerel canary). Bunların geniş taraması ZAP'a bırakılır; native kontroller **doğrulama ve düşük yanlış pozitif** içindir. |
| **Kimlik doğrulama & yetki** | Giriş sayfasında hız sınırı/hesap kilidi var mı (n başarısız deneme sonrası davranış; **yalnızca test hesabı** ile, sınırlı sayıda), kullanıcı adı numaralandırma (farklı hata mesajı/süre), varsayılan kimlik bilgileri listesi (küçük), parola politikası ipucu, parola sıfırlama akışı ipuçları, JWT (`alg:none`, zayıf HS256 sırrı sözlük denemesi — yalnızca yerel, kısa sözlük, `exp` yok, hassas veri), **IDOR/BOLA**: iki kullanıcı verilmişse A'nın kaynağına B oturumuyla erişim denemesi (GET kimlikleri değiştir), **yetkisiz erişim**: oturumsuz isteğin korumalı yola erişimi, rol yükseltme: user oturumuyla admin yolları. |
| **CSRF** | Durum değiştiren formlarda token var mı, `SameSite` ile birlikte değerlendirme, `Origin/Referer` doğrulaması var mı (sahte Origin ile POST). |
| **TLS (yerelde HTTPS varsa)** | Protokol sürümleri (TLS 1.0/1.1 kapalı olmalı), zayıf şifreler, sertifika geçerliliği/süresi, HSTS. (`ssl` + gerekirse `sslyze`.) Yerel HTTP ise: "yayında HTTPS zorunlu" öneri maddesi. |
| **API'ye özel** | OpenAPI/Swagger bulunursa uç noktaları içe aktar ve her biri için: kimlik doğrulama gereksinimi, yöntem/içerik türü doğrulaması, aşırı veri ifşası (yanıtta `password`, `hash`, `token`, `ssn` benzeri alan adı), sayfalama limiti yok, mass assignment ipucu (`isAdmin` alanı gönder), GraphQL derinlik/introspection. |

**Hız ve güvenlik:** varsayılan istek hızı sınırlı (ör. 20 rps), uygulama kritik hata oranına (≥ %20 5xx) ulaşırsa tarama **otomatik yavaşlar**; "Devre kesici" (circuit breaker) devreye girince kullanıcıya bildirir.

### 6.4 Tarayıcı Tabanlı Testler (`browser`)
- Playwright Chromium ile sayfaları gez (sitemap + bağlantı grafı + ZAP'ın bulduğu URL'ler, derinlik/limit ayarlı).
- Konsol hataları/uyarıları, yakalanmamış istisnalar, başarısız ağ istekleri, **karışık içerik** (HTTPS sayfada HTTP kaynak), **CSP ihlali** olayları (`securitypolicyviolation`), üçüncü taraf betik envanteri (dış hostlar, SRI `integrity` eksikliği — dış CDN'lerde), `target="_blank"` + `rel="noopener"` eksikliği, `localStorage`/`sessionStorage`'da token saklama ipucu, formlarda `autocomplete` ve parola alanı özellikleri, `postMessage` dinleyicilerinde origin kontrolü ipucu.
- **DOM XSS doğrulaması:** kaynak→sink izleme (URL hash/query → `innerHTML`) için canary kullanarak.
- Erişilebilirlik: **axe-core** enjekte et, WCAG ihlallerini `QUALITY` kategorisinde raporla (kontrast, alt metin, etiket, odak sırası). Bu bölüm SEO'yu da dolaylı etkiler.
- Her önemli sayfa için ekran görüntüsü (mobil + masaüstü görünüm), rapora eklenir.

---

## 7. SEO ve Google Görünürlük Modülü (`seo`)

**Önemli dürüstlük notu (rapora da yazılsın):** Google yerel (`localhost`) siteyi tarayamaz; bu modül **"yayına hazırlık / teknik SEO uygunluğu"** ölçer. Sıralama garantisi vermez; sıralama büyük ölçüde içerik kalitesi ve dış bağlantılara bağlıdır. Core Web Vitals için Google'ın kullandığı veri **saha verisidir** (CrUX, p75); yerelde yalnızca **laboratuvar** ölçümü yapılır ve bu rapor edilir.

### 7.1 Tarama ve veri toplama
- Başlangıç URL'si + `sitemap.xml` + iç bağlantılar; derinlik/sayfa limiti ayarlı (varsayılan 500 sayfa); `robots.txt`'ye **uy** (kendi sitemizde bile: Googlebot gibi davranıp engelli sayfaları "Google bunu göremez" olarak işaretle).
- İki kullanıcı ajanı ile getir: **Googlebot Smartphone benzeri** ve normal tarayıcı; **JS kapalı ham HTML** ile **JS çalışmış render edilmiş DOM** farkını çıkar (içerik/başlık/canonical yalnızca JS ile geliyorsa uyar — Google render eder ama gecikmeli ve riskli).
- Her sayfa için kaydet: durum kodu, yönlendirme zinciri, `Content-Type`, boyut, TTFB, HTML, render sonrası DOM özeti, tüm başlıklar (`X-Robots-Tag`, `Link: rel=canonical`).

### 7.2 Kontrol kataloğu (her biri `rule_id`, önem derecesi ve düzeltme önerisiyle)

**Tarama ve dizine alınabilirlik (en yüksek öncelik)**
| Kontrol | Eşik/kural |
|---|---|
| `robots.txt` var, geçerli, 200 döner; yanlışlıkla `Disallow: /` var mı | Kritik: üretimde tüm siteyi engelliyorsa |
| `<meta name="robots" content="noindex">` veya `X-Robots-Tag: noindex` önemli sayfalarda | Kritik |
| Önemli sayfa `robots.txt` ile engelli ama `noindex` bekleniyor (engelli sayfada noindex okunamaz) | Orta |
| `sitemap.xml`: var mı, `robots.txt`'de bildirilmiş mi, geçerli XML mi, ≤ 50.000 URL ve ≤ 50 MB (sıkıştırılmamış), URL'ler 200 mü, `noindex`/yönlendirmeli/canonical-farklı URL içeriyor mu, `lastmod` anlamlı mı | Yüksek/Orta |
| HTTP durum kodları: 4xx/5xx sayfalar, **soft 404** (200 dönen "bulunamadı" sayfası), yönlendirme zincirleri (>1 atlama), yönlendirme döngüsü, 302 yerine 301 | Yüksek/Orta |
| Canonical: var, kendine referans, mutlak URL, tek, dizine alınabilir sayfaya işaret, parametreli kopya URL'ler | Yüksek |
| Yetim sayfalar (sitemap'te var, iç bağlantı almıyor), tıklama derinliği > 4 | Orta |
| URL yapısı: büyük harf, `_`, çok uzun, çok parametre, oturum kimliği içeren URL | Düşük |
| `hreflang` (varsa): karşılıklılık, geçerli dil kodları, `x-default` | Orta |
| Sayfalama/faset navigasyon tekrarları, kopya içerik (içerik özeti hash'i/simhash) | Orta |
| HTTPS, www/non-www tutarlılığı, trailing slash tutarlılığı (yayın öncesi uyarı) | Orta |
| Özel 404 sayfası var ve gerçekten 404 mü | Orta |

**Sayfa içi**
| Kontrol | Eşik/kural |
|---|---|
| `<title>`: var, benzersiz, ~30–60 karakter (piksel ≈ 580 sınırı, kesin değil; "ipucu" düzeyi), anahtar niyeti yansıtıyor, marka tutarlılığı | Yüksek |
| `meta description`: var, benzersiz, ~70–160 karakter (Google bunu yeniden yazabilir → önem düşük/orta) | Orta |
| Tek `<h1>`, başlık hiyerarşisi atlamasız (`h2`→`h4` yok), boş başlık yok | Orta |
| `<html lang>`, `charset`, `viewport` (`width=device-width, initial-scale=1`) | Yüksek (viewport) |
| Görseller: `alt` (dekoratifte boş `alt=""`), açıklayıcı dosya adı, modern format (WebP/AVIF), **`width`/`height` öznitelikleri** (CLS), `loading="lazy"` (ilk ekran görseli hariç — LCP görselini lazy yükleme **uyarısı**), `srcset`, boyut/KB eşiği | Orta |
| İç bağlantılar: boş/`#`/`javascript:` bağlantı metni, "buraya tıklayın" gibi zayıf çapa metni, kırık iç/dış bağlantı (dış bağlantılar için **yalnızca kullanıcı onayıyla** ve nazik hız ile `HEAD`), `nofollow` kullanımı | Orta |
| İçerik: çok ince içerik (kelime sayısı eşiği, ayarlanabilir), metin/HTML oranı, tekrarlayan şablon metni, okunabilirlik (Türkçe ve İngilizce için basit ölçüt) | Düşük/Orta |
| Favicon, `manifest`, `theme-color` | Düşük |

**Paylaşım ve yapısal veri**
| Kontrol | Not |
|---|---|
| Open Graph (`og:title`, `og:description`, `og:image` boyutu ≥ 1200×630 önerisi, `og:url`, `og:type`), Twitter/X card | Sosyal önizleme |
| **Schema.org JSON-LD** (Google'ın önerdiği format): ayrıştır, JSON geçerliliği, `@type`'a göre **zorunlu/önerilen özellik** kontrolü (Organization, WebSite, Article/BlogPosting, Product, BreadcrumbList, LocalBusiness, Event…). Kurallar: işaretleme **sayfada görünen içerikle eşleşmeli**; görünmeyen/yanıltıcı içerik işaretlenmez; Google zengin sonuç garantisi vermez | Orta |
| Eksik yapısal veri için **hazır JSON-LD şablonu üret** (sitenin başlık/açıklama/logo verisiyle doldurulmuş) | Düzeltme çıktısı |
| Not: FAQ/HowTo gibi bazı zengin sonuçların Google'da kısıtlandığı/kaldırıldığı bilinmektedir → bu türleri **önerme**; önermeden önce güncel Google dokümanını kontrol et ve `docs/tool-notes/seo-rich-results.md` içine tarihli not düş | |

**Performans ve Core Web Vitals (laboratuvar)**
| Metrik | İyi | Geliştirilmeli | Kötü |
|---|---|---|---|
| LCP | ≤ 2,5 sn | ≤ 4,0 sn | > 4,0 sn |
| INP | ≤ 200 ms | ≤ 500 ms | > 500 ms |
| CLS | ≤ 0,1 | ≤ 0,25 | > 0,25 |
- Ölçüm yöntemi: Playwright + `PerformanceObserver` (LCP, CLS) ve **web-vitals** kütüphanesi enjekte edilerek; **INP için** betikli etkileşim (tıklama, yazma, menü açma) uygula; Lighthouse varsa **5 çalıştırmanın medyanı** al ve Total Blocking Time'ı INP vekili olarak raporla. Mobil profil: Moto G Power benzeri CPU yavaşlatma + 4G ağ kısıtı; masaüstü profil ayrı. Metrik "75. yüzdelik" saha verisi değildir — raporda **"laboratuvar"** etiketi taşısın.
- Ek: sayfa ağırlığı, istek sayısı, render-blocking CSS/JS, kullanılmayan JS/CSS, görsel optimizasyonu, önbellek başlıkları (`Cache-Control`, `ETag`), sıkıştırma (gzip/br), HTTP/2, font yükleme (`font-display`), `preload` LCP görseli, üçüncü taraf betik maliyeti. Lighthouse SEO/Performans/Erişilebilirlik/Best-practices skorlarını ham olarak da göster.

**Yapay zeka tarayıcıları (opsiyonel bölüm):** `robots.txt`'de GPTBot, ClaudeBot, Google-Extended, CCBot gibi ajanlar için kullanıcı tercihini sorup (izin ver/engelle) doğru `robots.txt` satırlarını üret. Karar kullanıcınındır; varsayılan öneri yapma.

### 7.3 "Google'da Görünürlük" Raporu
Rapor bölümü şunları içerir:
1. **SEO Puanı (0–100)** ve alt puanlar (Tarama/Dizine alma, Sayfa içi, Yapısal veri, Performans, Mobil).
2. **Yayına almadan önce yapılacaklar listesi** (etki/efor matrisiyle sıralı): "noindex'i kaldır", "canonical ekle", "sitemap oluştur", "LCP görselini önceden yükle" gibi.
3. **Üretilen dosyalar:** `robots.txt` taslağı, `sitemap.xml` taslağı (bulunan sayfalardan), sayfa başına önerilen `<title>`/`description` **şablonları** (yapay yazım değil, eksik/uzun olanlar için düzenlenebilir öneri), JSON-LD şablonları.
4. **Yayın sonrası kontrol listesi** (uygulama bunları yerelde test edemez, kullanıcıyı yönlendirir): Google Search Console'a mülk ekle ve doğrula, sitemap gönder, URL Denetimi ile ana sayfaları dizine almayı iste, "Sayfa Dizine Alma" ve "Core Web Vitals" raporlarını izle, Bing Webmaster Tools, kırık bağlantıları izle, Google Business Profile (yerel işletme ise).
5. Sınırlar notu (yukarıdaki dürüstlük metni).

---

## 8. Yük, Stres ve Dayanıklılık (`load`, `resilience`)

### 8.1 Hedef ve trafik modeli
- **Trafik profili otomatik üretilir:** tarama/SEO modülünün bulduğu URL'lerden ağırlıklı bir kullanıcı akışı (`locustfile.py` şablonla üretilir; kullanıcı düzenleyebilir). Form/POST akışları ve kimlik doğrulamalı oturumlar için "kayıtlı senaryo" (HAR/Playwright kaydı içe aktarma) — M7 sonrası opsiyonel.
- Yük **yalnızca Scope Guard** üzerinden loopback'e gider. Yük üretici (Locust) ve hedef aynı makinede olduğundan **sonuçlar göreli**dir: raporda "üretici ve hedef aynı makineyi paylaşıyor; mutlak kapasite tahmini değil, **darboğaz ve kırılma davranışı** göstergesi" notu yer alsın. CPU çekirdek ayrımı (affinity) opsiyonu sun.

### 8.2 Test profilleri
| Profil | Amaç | Desen |
|---|---|---|
| **Smoke** | Temel doğrulama | 1–5 kullanıcı, 30 sn |
| **Load** | Beklenen yükte davranış | Hedef VU'ya yavaş çıkış, 5 dk plato |
| **Stress** | Kırılma noktası | **Adım adım artış** (`LoadTestShape`): her adımda +N VU, her adım M sn; **durma koşulları**: hata oranı > %5, p95 gecikme > eşik (örn. 3 sn), RSS > limit, süreç çöktü |
| **Spike** | Ani yük ve toparlanma | Tabandan 10× ani sıçrama, sonra geri dön; toparlanma süresini ölç |
| **Soak (kısaltılmış)** | Bellek sızıntısı, kaynak sızıntısı | Orta yükte 15–60 dk; RSS/handle/thread eğilimi doğrusal regresyonla analiz |
| **Breakpoint** | Kapasite sınırı | Hata/gecikme eşiğine kadar sürekli artır; "en yüksek sağlıklı RPS" raporla |

### 8.3 Ölçümler (canlı grafik + rapor)
RPS, eşzamanlı kullanıcı, p50/p90/p95/p99 gecikme, hata oranı (4xx/5xx/timeout/bağlantı sıfırlama ayrı), iş hacmi (KB/s), **hedef süreç CPU/RSS/thread/açık fd/bağlantı sayısı** (`psutil`), olay döngüsü gecikmesi ipucu (Node için `/health` yanıt süresi), GC duraklamaları (varsa). **Diz noktası (knee)** tespiti: gecikme eğrisinin ivmelendiği RPS. Çıktı: "Sağlıklı kapasite ≈ X rps; Y rps üzerinde p95 Z ms'i aşıyor; Y2 rps'te hata başlıyor; darboğaz belirtisi: CPU doygun / bellek artıyor / DB kilidi ipucu".
- Otomatik **yorum motoru**: kural tabanlı (örn. "CPU %95 + gecikme artışı → CPU-bound; DB sorgusu/N+1, önbellek, sıkıştırma, üretim modunda çalıştırma öner", "RSS sürekli artıyor → sızıntı şüphesi", "bağlantı sıfırlamaları → keep-alive/worker sayısı/limit ayarı", "404/500 oranı artıyor → hata işleme"). Dev sunucusu (örn. `flask run`, `vite dev`) ile test ediliyorsa **uyarı**: üretim sunucusu (gunicorn/uvicorn workers, `NODE_ENV=production`, nginx) ile yeniden test öner.
- Eşik **SLO'ları** kullanıcı ayarlar (varsayılan: p95 < 500 ms, hata < %1).

### 8.4 Dayanıklılık (resilience) — kontrollü, yalnızca yerel
- **Yavaş istemci** (slow headers/slow body) davranışı, **çok sayıda açık bağlantı**, **büyük gövde** (1 MB–50 MB, sınırlı) ve **büyük başlık** kabulü, hatalı biçimli JSON/UTF-8/çok derin iç içe JSON, çok uzun URL, çok sayıda parametre, çok büyük çoklu dosya yükleme, hata içeren HTTP (`Content-Length` uyuşmazlığı) → uygulama çökmeden 4xx dönüyor mu?
- **Hız sınırlama var mı** (aynı uç noktaya burst) → yoksa bulgu; **zaman aşımı** ayarları; **bağımlılık arızası** (DB kapalı simülasyonu isteğe bağlı; kullanıcı onayıyla).
- **Çökme ve toparlanma:** süreç öldüğünde otomatik yeniden başlıyor mu (yalnızca uygulama bunu destekliyorsa), hata mesajı sızıntısı.
- Her test **zaman kutulu** ve **iptal edilebilir**; sonunda hedefin sağlığı kontrol edilir (`/` 200?). Hedef çökerse "kırılma noktası" olarak kaydedilir ve yeniden başlatma ayrı bir adım.

---

## 9. Puanlama

Puanlar **şeffaf ve yeniden üretilebilir** olmalı; formül `docs/scoring.md` içinde yazılı, birim testli.

**Güvenlik puanı (0–100):** 100'den başla. Her bulgu için ceza: `critical 25 · high 10 · medium 4 · low 1 · info 0`. Aynı `rule_id`'nin tekrarında ilk örnek tam ceza, sonrakiler %25 (aynı tür hatayı 40 kez bulmak puanı sıfırlamasın). Güven çarpanı: `confirmed 1.0 · high 0.8 · medium 0.5 · low 0.25`. Alt sınır 0. **Kural:** doğrulanmış (`confirmed`) bir kritik bulgu varsa harf notu en fazla "D" olabilir.
**SEO puanı:** ağırlıklar → Tarama/dizine alma 30, Sayfa içi 25, Yapısal veri 10, Performans (CWV lab) 25, Mobil 10. Her alt kategori kendi kontrol listesinin ağırlıklı geçme oranıdır; Kritik dizine alma engeli (`noindex`/`Disallow: /`) toplamı en fazla 40'a sabitler.
**Dayanıklılık puanı:** SLO uyumu (p95, hata oranı), kırılma noktası/hedef kapasite oranı, toparlanma süresi, sızıntı eğilimi, hata işleme (çökmeden 4xx).
**Kalite (erişilebilirlik, konsol hataları):** ayrı, genel puana %10 katkı.
**Genel puan:** Güvenlik %45 · SEO %20 · Dayanıklılık %20 · Kalite %10 · Bağımlılık sağlığı %5. Harf notu A–F. Ağırlıklar ayarlardan değiştirilebilir ama varsayılana "sıfırla" düğmesi bulunur.

---

## 10. Çözüm Bilgi Tabanı (Remediation KB)

`remediation/<rule_id>.yaml`:

```yaml
rule_id: SEC-HDR-001
title: {tr: "Content-Security-Policy başlığı yok", en: "Missing Content-Security-Policy"}
why: {tr: "...", en: "..."}
fix_steps: {tr: ["...", "..."], en: [...]}
snippets:
  express:  {lang: js,     code: "app.use(helmet.contentSecurityPolicy({...}))"}
  flask:    {lang: python, code: "Talisman(app, content_security_policy={...})"}
  django:   {lang: python, code: "..."}
  php:      {lang: php,    code: "header(\"Content-Security-Policy: ...\");"}
  nginx:    {lang: nginx,  code: "add_header Content-Security-Policy \"...\" always;"}
  apache:   {lang: apache, code: "Header always set Content-Security-Policy \"...\""}
  static:   {lang: html,   code: "<meta http-equiv=\"Content-Security-Policy\" content=\"...\">"}
verify: {tr: "Tarama sonrası bu madde 'Düzeltildi' olarak görünmeli", en: "..."}
references: [{type: cwe, id: 1021}, {type: owasp, id: "A02:2025"}, {type: url, href: "https://cheatsheetseries.owasp.org/..."}]
effort: S
```

- Düzeltme önerisi **tespit edilen stack'e göre** filtrelenir (Express projesine Nginx önerisi ilk sırada gelmez).
- Bulgu ekranında "Kopyala" düğmesi; mümkün olan basit durumlarda (başlık ekleme, `robots.txt`/`sitemap.xml`/JSON-LD üretme) **"Yama dosyası üret"** (kullanıcının kaynağına dokunmadan `patches/` altına `.diff` veya yeni dosya).
- **OWASP Top 10 (2025) eşlemesi:** OWASP Top 10'un 2025 sürümü yayımlandı; kategori adlarını ve numaralarını resmi kaynaktan doğrula ve `docs/owasp-mapping.md` oluştur (eski 2021 adlarını hafızadan kullanma). CWE ve ASVS eşlemesi de aynı dosyada.

---

## 11. Rapor, Arayüz ve CLI

### 11.1 Rapor (`reporting/`)
- **HTML (tek dosya, çevrimdışı çalışır):** Yönetici özeti (genel puan, 4 alt puan, "en önemli 5 aksiyon"), kategori sekmeleri, filtrelenebilir bulgu tablosu (önem, modül, durum, arama), bulgu detayı (kanıt, istek/yanıt, düzeltme, referanslar), grafikler (satır içi SVG; harici CDN yok), yük testi grafikleri (RPS/gecikme/CPU-RSS zaman serisi, diz noktası işareti), SEO sayfa tablosu, ekran görüntüleri, tarama meta verisi (araç sürümleri, süre, kapsam onayı, atlanan modüller + nedenleri). **Sırlar maskeli.**
- **PDF:** aynı HTML'den Playwright ile; yazdırma stili ayrı.
- **JSON (tam, şema sürümlü)** ve **SARIF 2.1.0** (IDE/CI entegrasyonu için), **CSV** (bulgu listesi), **SBOM (CycloneDX)**.
- **Karşılaştırma (diff):** iki tarama arası `yeni / düzelen / kalıcı / gerileyen` bulgular; puan farkı; "bu sürümde 3 yeni yüksek risk". Kararlı bulgu parmak izine dayanır.
- **Kullanıcıya özel Düzeltme Planı:** bulguları `etki × efor` ile sıralı (hızlı kazanımlar önce), gruplanmış ("tüm güvenlik başlıkları tek yamada").

### 11.2 Masaüstü Arayüzü (PySide6)
Genel: koyu/açık tema, Türkçe/İngilizce, klavye erişilebilirliği, ana iş parçacığı **asla bloklanmaz** (tüm iş worker süreçte), yüksek DPI uyumlu, pencere boyutu/konumu hatırlanır.

1. **Pano:** son tarama puanları (halka göstergeler), puan trendi (zaman serisi), açık kritik/yüksek bulgu sayısı, "Yeni Tarama" ve "Son Raporu Aç".
2. **Yeni Tarama Sihirbazı (5 adım):**
   - *Kaynak:* klasör/zip sürükle-bırak veya `localhost` adresi; zip güvenli açılış ilerlemesi.
   - *Algılanan proje:* dil/framework, çalıştırma komutu, port, ortam değişkenleri, hazır olma URL'si (düzenlenebilir), "çalıştır ve dene" düğmesi.
   - *Kimlik doğrulama (opsiyonel):* giriş formu/başlık/çerez, ikinci rol (yetki testi için).
   - *Profil ve modüller:* Hızlı / Standart / Derin / Özel; modül listesi (eksik araç varsa kırmızı rozet + "Kur" düğmesi); yük profili seçimi (Smoke/Load/Stress/Spike/Soak/Breakpoint) ve SLO eşikleri; tahmini süre.
   - *Güvenlik onayı:* "Bu sistem bana aittir, yalnızca yerelde test edilecek" + veri anlık görüntüsü seçeneği + özet.
3. **Canlı İzleme:** modül kartları (durum, yüzde, süre), akan bulgu listesi (anında düşer), günlük konsolu (filtrelenebilir), **canlı grafikler** (RPS, p95, hata oranı, hedef CPU/RSS), Duraklat/Durdur/İptal, devre kesici bildirimi.
4. **Sonuçlar:** üstte puan kartları; solda kategori ağacı; ortada bulgu tablosu (sıralama/filtre/çoklu seçim, "yanlış pozitif" olarak işaretle → baskılama listesine yazılır, gerekçe ister); sağda bulgu detay paneli (kanıt, düzeltme sekmeleri stack'e göre, "Kopyala", "Yama üret", referanslar). SEO sekmesi: sayfa tablosu + "Google'da Görünürlük" kontrol listesi. Performans sekmesi: CWV kartları + yük testi grafikleri.
5. **Geçmiş ve Karşılaştırma:** taramalar listesi, iki taramayı seç → diff görünümü.
6. **Ayarlar:** Araç Yöneticisi (sürüm, durum, kur/güncelle, SHA-256 doğrulama), hız sınırları, varsayılan SLO'lar, rapor dili, tema, veri klasörü, baskılama listesi (suppressions) yönetimi, günlük seviyesi, "tüm taramaları sil".
- Metinler `i18n/tr.json`/`en.json`; koda gömülü metin yasak (otomatik test: kaynak koddaki Türkçe/İngilizce literalleri tara).

### 11.3 CLI (başsız)
```
secscope scan --path ./proj [--zip x.zip | --url http://localhost:3000]
              --profile quick|standard|deep|custom --modules sast,sca,seo,load
              --run "npm start" --port 3000 --ready-path /health
              --auth-form ... --out ./reports --format html,json,sarif,pdf
              --fail-on high --accept-scope-statement
secscope tools list|install|verify
secscope diff <scanA> <scanB>
secscope report <scan_id> --format pdf
```
`--fail-on` çıkış kodu CI için kullanılır. Kapsam beyanı bayrağı olmadan dinamik modüller çalışmaz.

---

## 12. Test Stratejisi ve Örnek Uygulamalar (Fixtures)

**Piramit:** birim testleri (çok) → araç sarmalayıcı sözleşme testleri (kaydedilmiş gerçek araç çıktıları = "golden") → entegrasyon (gerçek araçlarla, fixture uygulamalarda) → e2e (CLI + `pytest-qt` ile ekran dumanı, `QT_QPA_PLATFORM=offscreen`).

**Fixture uygulamaları (`fixtures/`, yalnızca loopback'e bağlanır, README'de büyük uyarı):**
| Fixture | İçerik | Beklenen sonuç dosyası |
|---|---|---|
| `vuln-flask` | SQLi (string birleştirme), yansıyan XSS, `debug=True`, kodda sabit sır, zayıf JWT sırrı, açık yönlendirme, path traversal (kontrollü canary dosyası), IDOR, çerez bayraksız, CORS yansıtma, giriş hız sınırı yok, eski bağımlılık sürümü, `.env`/yedek dosya açıkta, yığın izi sızıntısı | `expected.yaml` (rule_id listesi) |
| `vuln-express` | NoSQL enjeksiyon, komut enjeksiyonu, `eval`, DOM XSS (`innerHTML`), CORS yansıtma, açık source map, `alg:none` JWT, eski `lodash` | `expected.yaml` |
| `vuln-php` | SQLi, LFI, `unserialize`, `phpinfo.php`, dizin listeleme | `expected.yaml` |
| `static-seo-bad` | title yok/yinelenen, `noindex`, 2×`h1`, alt yok, kırık link, 3 atlamalı yönlendirme, `Disallow: /`, sitemap'te 404, viewport yok, soft 404, boyutsuz görsel (CLS), lazy yüklenen LCP görseli, devasa görsel | `expected.yaml` |
| `static-seo-good` | Tüm SEO kontrollerini geçer | "0 kritik/yüksek" |
| `clean-flask`, `clean-express` | Doğru başlıklar, parametreli sorgu, çıktı kodlama | **Yanlış pozitif bütçesi: ≤ 5%** |
| `slow-app` | CPU-bağımlı uç nokta, bellek sızdıran uç nokta, sınırlı thread havuzu, belirli RPS'te çöküş | Diz noktası ± %20 ve sızıntı tespiti |

**Kural-başı test:** her `rule_id` için en az bir **pozitif** (bulmalı) ve bir **negatif** (bulmamalı) fixture; CI'da kural kapsama raporu.
**Ek testler:** Scope Guard saldırı listesi (Bölüm 4); zip slip/bomba fuzz; süreç iptali sonrası zombi/açık port kalmaması (Windows/macOS/Linux); CSP ayrıştırıcı için `hypothesis`; sitemap/robots uç durumları; SEO tarayıcı 10.000 sayfalık sahte site üzerinde bellek/süre bütçesi; yük üretici ile ölçülen RPS'in doğrulanması (bilinen yavaş uç nokta); sır maskeleme (rapor/günlükte düz sır **yok**); i18n anahtar eşitliği; 10.000 bulguyla arayüz akıcılığı.
**Karşılaştırma ölçümü (opsiyonel, kullanıcı kendi kurar):** OWASP Juice Shop / DVWA / WebGoat'ı yerelde Docker ile çalıştırıp tespit oranı yol haritası; sonuçlar `docs/benchmarks.md`.
**CI:** GitHub Actions matrisi (Windows/macOS/Linux × Python 3.12/3.13); ruff, pyright strict, pytest, kapsam ≥ %80 çekirdek, güvenlik: `pip-audit` ve kendi `secscope` ile kendi kodunu tara (kendini test etme = "dogfooding").

---

## 13. Dağıtım, Ayarlar, Gizlilik ve Kalite Gereksinimleri

- **Paketleme:** PyInstaller (one-folder), imza (Windows: Authenticode, macOS: Developer ID + notarization — kullanıcı sertifikası gerekir; yoksa imzasız yayın notu), kurulum paketleri (Inno Setup/MSI, `.dmg`, AppImage). Büyük harici araçlar (ZAP, Chromium, Trivy, Nuclei…) **gömülmez**: ilk çalıştırmada **Araç Yöneticisi** `tools/manifest.toml`'daki sürüm+SHA-256 ile indirir/doğrular; çevrimdışı kurulum için "araç paketi" içe aktarma.
- **Gizlilik:** telemetri **yok**. Ağ trafiği yalnızca (a) hedef loopback, (b) kullanıcı başlatınca araç/veritabanı güncellemeleri, (c) kullanıcı onayıyla dış bağlantı kontrolü (SEO kırık dış link). Alt araçların telemetri/güncelleme denetimlerini kapat (ör. Semgrep için metrikleri kapat; bayrakları doğrula).
- **Veri:** `platformdirs` kullanıcı veri klasörü; tarama bulguları SQLite; ham kanıt dosyaları; saklama politikası (varsayılan 90 gün / 50 tarama); tek tıkla sil. Kanıtta sırlar maskeli saklanır.
- **Dayanıklılık:** worker çökerse UI tarama durumunu "kesildi" gösterir ve kısmi sonuçları kurtarır; ara sonuçlar tarama sırasında diske yazılır (yeniden başlatılabilir).
- **Performans (aracın kendisi):** UI donmaz (>50 ms bloklama yok), 10.000 bulguda tablo sanallaştırmalı, tarama belleği < 1,5 GB (ZAP hariç; ZAP için `-Xmx` sınırı ayar).
- **Günlük:** döngüsel dosya, seviyeler, gizli bilgi filtresi.
- **Erişilebilirlik:** klavye ile tam gezinme, ekran okuyucu etiketleri, yeterli kontrast.
- **Dokümantasyon:** `README` (kurulum, hızlı başlangıç), `docs/architecture.md`, `docs/modules/*.md` (her modül: ne yapar, neyi yapmaz, yanlış pozitif kaynakları), `docs/adding-a-module.md`, `docs/tool-notes/`, `docs/decisions/`, `docs/scoring.md`, kullanıcı kılavuzu (Türkçe + İngilizce).

---

## 14. Yol Haritası (Milestone'lar) ve "Bitti Tanımı"

> Her milestone sonunda: testler yeşil, linter/pyright temiz, `docs/` güncel, demo komutu çalışıyor.

**M0 — Temel (iskelet)**
`uv` projesi, `pyproject`, ruff/pyright/pytest/pre-commit, CI, `CLAUDE.md` (proje kuralları: bu dosyanın Bölüm 0 özeti), `models.py` (Finding/Event/Config), `events.py`, `config.py`, loglama, `storage/db.py` (+migration), **`scope_guard.py` + saldırı testleri**.
*Kabul:* Scope Guard test listesi %100 geçer; `Finding` JSON şeması üretilir; boş `secscope --version` çalışır.

**M1 — Orchestrator, Worker, CLI, Araç Yöneticisi iskeleti**
`ScanModule` arayüzü, kayıt defteri, orchestrator (bağımlılık sırası, paralel/seri, zaman aşımı, iptal), worker süreç + JSON-Lines IPC, sahte (fake) modüllerle uçtan uca, `tools/manifest.toml` + algılama (`which`/sürüm), `secscope tools list`, **minimal UI penceresi** olayları listeler (duman testi).
*Kabul:* sahte modüllerle tarama başlar/ilerler/iptal edilir; iptalde alt süreç ve port kalmaz (3 platform CI); eksik araç → `SKIPPED` olayı.

**M2 — Proje alımı ve çalıştırıcı**
Güvenli zip/tar açma, parmak izi, SandboxRunner (süreç grubu, ortam beyaz listesi, hazır olma, kaynak izleme), statik site sunucusu, SQLite anlık görüntü/geri yükleme. Fixture iskeletleri.
*Kabul:* zip slip/bomba reddedilir; `vuln-flask`, `vuln-express`, `static-seo-*` otomatik algılanıp başlatılır; kapatma sonrası port serbest.

**M3 — Statik analiz**
Kendi kural motoru (temel 30+ kural), Semgrep + Bandit sarmalayıcı, gitleaks + kendi sır tarayıcı (maskeleme!), Trivy/osv/npm audit/pip-audit + SBOM, yapılandırma denetimi, normalizasyon + dedup.
*Kabul:* fixture `expected.yaml`'daki statik kuralların ≥ %90'ı bulunur; `clean-*`'ta yanlış pozitif ≤ %5; araç yokken kendi motor çalışır ve "azaltılmış kapsam" notu düşer; rapor/günlükte düz sır yok.

**M4 — Yerel DAST + Tarayıcı modülü**
`ScopedHttpClient`, başlık/çerez/CORS/yöntem/dizin/hata/oturum/CSRF/TLS kontrolleri, girdi kaynaklı zafiyet **canary** doğrulamaları, kimlik doğrulama + IDOR, Playwright gezgini (konsol/CSP/karışık içerik/axe), ekran görüntüleri.
*Kabul:* ilgili `expected.yaml` kuralları ≥ %90; tüm istekler Scope Guard'dan geçer (dışarı istek denemesi testi engellenir); devre kesici testi.

**M5 — ZAP ve Nuclei**
ZAP daemon yönetimi (rastgele API anahtarı, loopback, bellek sınırı), Automation Framework planı üretimi veya REST, kimlik doğrulama bağlamı, ilerleme olayları, alert normalizasyonu + `zap_map.yaml`; Nuclei çıktı ayrıştırma, güvenli şablon seçimi, hız sınırı.
*Kabul:* ZAP ve Nuclei fixture'larda bulguları üretir ve dedup ile native sonuçlarla birleşir; kapsam dışı URL'ye istek yok (ZAP günlüğüyle doğrula); iptalde Java süreci ölür.

**M6 — SEO ve Google görünürlük**
Tarayıcı + render/ham fark, tüm kontrol kataloğu (Bölüm 7), CWV laboratuvar ölçümü (Playwright + web-vitals, opsiyonel Lighthouse), `robots.txt`/`sitemap.xml`/JSON-LD üreticileri, yayın öncesi/sonrası kontrol listeleri.
*Kabul:* `static-seo-bad` beklenen tüm maddeleri bulur; `static-seo-good` kritik/yüksek yok; 10.000 sayfalık sahte sitede süre/bellek bütçesi içinde; üretilen `sitemap.xml` geçerli.

**M7 — Yük ve dayanıklılık**
Locust sarmalayıcı (alt süreç, `LoadTestShape` ile adım/spike/soak/breakpoint), otomatik trafik profili, psutil ölçümleri, canlı `metric` olayları, diz noktası ve sızıntı analizi, yorum motoru, resilience test seti, durma koşulları.
*Kabul:* `slow-app`'te diz noktası ±%20 ve bellek sızıntısı tespit edilir; yük testi iptalde temiz biter; dev sunucusu uyarısı çıkar; "üretici ve hedef aynı makine" notu rapordadır.

**M8 — Puanlama, Çözüm Bilgi Tabanı, Raporlama, Diff**
Puan formülleri + testleri, `remediation/*.yaml` (her `rule_id` için), HTML/PDF/JSON/SARIF/CSV, diff, yama dosyası üreticileri, düzeltme planı sıralaması.
*Kabul:* her `rule_id` için KB kaydı (CI testi); HTML rapor tek dosya ve çevrimdışı; SARIF geçerli şema; iki tarama diff'i doğru sınıflandırır.

**M9 — Tam masaüstü arayüz**
Bölüm 11.2'deki tüm ekranlar, i18n, tema, canlı grafikler (pyqtgraph), baskılama listesi, ayarlar/Araç Yöneticisi arayüzü.
*Kabul:* sihirbazdan rapora tam akış `pytest-qt` ile otomatik; UI 10.000 bulguda akıcı; hardcoded metin testi geçer; ekran görüntüleri `docs/screenshots/`.

**M10 — Paketleme, sertleştirme, belgeler**
PyInstaller, kurulum paketleri, imza notları, çevrimdışı araç paketi, Docker ile opsiyonel hedef izolasyonu, dogfooding taraması, son güvenlik gözden geçirmesi (kendi uygulamamızın tehdit modeli: kötü niyetli zip, kötü niyetli hedef yanıtı, rapor XSS'i — hedefin döndürdüğü içerik rapora **HTML-escape** edilerek konur!), kullanıcı kılavuzu.
*Kabul:* temiz bir Windows/macOS/Linux makinede kurulum → ilk tarama → rapor akışı, kılavuzdaki adımlarla çalışır.

### Genel "Bitti Tanımı" (her görev için)
- [ ] Kod + testler + tür denetimi + linter temiz
- [ ] Yeni kural → pozitif ve negatif fixture + KB kaydı + referanslar
- [ ] Dış araç çağrısı → sürüm doğrulaması + zaman aşımı + iptal + hata yakalama + `SKIPPED` davranışı
- [ ] Hiçbir yeni ağ yolu Scope Guard'ı atlamıyor
- [ ] Kanıtlarda sır maskeli, hedeften gelen içerik raporda escape edilmiş
- [ ] Belge güncellendi, ADR gerekiyorsa yazıldı

---

## 15. Doğrulanması Gereken Varsayımlar (Claude Code: bunları ilk fırsatta kontrol et)

1. **ZAP:** kurulu sürümde Automation Framework iş (job) adları/parametreleri, REST uç noktaları (`/JSON/spider/…`, `/JSON/ascan/…`, `/JSON/core/view/alerts/`), `-daemon` ve API anahtarı yapılandırması, rapor üretimi. Eski `python-owasp-zap-v2.4` kütüphanesinin bakım durumu — yoksa doğrudan REST (httpx) kullan.
2. **Nuclei:** `-jsonl`, `-rl`, `-c`, `-severity`, `-tags`, `-no-interactsh` (ve güncelleme/telemetri kapatma bayrakları), DAST/fuzz şablon modu; çıktı alan adları.
3. **Semgrep:** çevrimdışı/yerel kural yapılandırması, metrik kapatma, `--json` şeması, çıkış kodları; Registry kural lisansı.
4. **Trivy:** `fs`/`config` alt komutları, `--format json`, çevrimdışı DB (`--skip-db-update` vb.), SBOM biçimi; **gitleaks** v8 bayrakları; **osv-scanner** sürüm-sürüm CLI farkı.
5. **Locust:** `--headless`, CSV/JSON çıktı bayrakları, `LoadTestShape` API'si, çok işlemli çalışma (`--processes`) Windows desteği.
6. **Playwright:** mobil cihaz tanımları, CPU yavaşlatma/ağ kısıtı için CDP (`Emulation.setCPUThrottlingRate`, `Network.emulateNetworkConditions`), `page.pdf()`.
7. **Lighthouse CLI:** bayraklar, JSON şeması, `--only-categories`, Node sürümü.
8. **OWASP Top 10:2025** kategori adları/numaraları ve ASVS sürümü; CWE eşlemeleri.
9. **Google dokümanları:** hangi zengin sonuç türlerinin şu an desteklendiği (FAQ/HowTo vb. kısıtlamalar), başlık/açıklama uzunluğu için resmi bir sınır olmadığı (ipucu düzeyi), Core Web Vitals eşikleri (LCP 2,5 sn / INP 200 ms / CLS 0,1) — her birini resmi kaynaktan teyit et ve tarihli not düş.
10. **PySide6/LGPL** dağıtım gereklilikleri; PyInstaller + Qt + Playwright birlikte çalışması (Chromium'u gömmeden indirme).

---

## 16. Başlıca Riskler ve Önlemler

| Risk | Önlem |
|---|---|
| Kullanıcının yüklediği kodu çalıştırmak (zararlı içerik olabilir) | Yalnızca kendi kodu uyarısı, env beyaz listesi, loopback, süreç izolasyonu; M10'da Docker izolasyonu; ağ erişimini kısıtlama önerisi |
| Aktif tarama uygulama verisini bozar | Anlık görüntü/geri yükleme, test hesabı/veritabanı önerisi, devre kesici |
| Yanlış pozitifler güveni sarsar | İki araç doğrulaması, `confidence`, canary ile gerçek doğrulama, baskılama listesi, fixture bütçesi |
| Araç sürüm kayması | `manifest.toml` sabit sürüm, sözleşme (golden) testleri, sürüm algılama + uyarı |
| Windows'ta süreç ağacı öldürme | Job Object / `psutil` ile çocuk süreçleri öldür; 3 platform CI testi |
| Yük üretici ve hedef aynı makinede | Çekirdek ayrımı opsiyonu, sonuçları "göreli" etiketle |
| ZAP/Chromium yüksek kaynak tüketimi | Bellek limitleri, sıralı çalıştırma seçeneği, "düşük kaynak" profili |
| Rapor XSS'i (hedefin içeriği rapora girer) | Tüm hedef kaynaklı alanlar escape + rapora CSP; test et |
| Antivirüs yanlış alarmı (PyInstaller + tarayıcı) | İmza, VirusTotal kontrolü notu, one-folder dağıtım |
| Kapsam şişmesi | Milestone sırası; M6/M7 çekirdek, "ileri" özellikler (HAR içe aktarma, k6 motoru, Docker izolasyonu) sonraya |

---

## 17. Araştırma Kaynakları (karar dayanakları)

- OWASP HTTP Security Response Headers Cheat Sheet — https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
- ZAP ile API/otomasyon taraması (daemon, spider, aktif tarama, rapor, CI) — https://oneuptime.com/blog/post/2026-01-25-owasp-zap-api-security/view
- Nuclei dokümantasyonu — https://docs.projectdiscovery.io/opensource/nuclei/overview
- Semgrep CLI (yerel tarama, JSON/SARIF) — https://docs.semgrep.dev/getting-started/cli
- Trivy — https://github.com/aquasecurity/trivy
- k6 ve Locust karşılaştırması — https://qaskills.sh/blog/k6-vs-locust-2026
- Yük/stres/spike/soak test türleri — https://qaskills.sh/blog/load-vs-stress-vs-soak-vs-spike-testing-2026
- Core Web Vitals 2026 (LCP/INP/CLS eşikleri, laboratuvar–saha farkı, CI) — https://qaskills.sh/blog/core-web-vitals-testing-guide-2026
- Google yapısal veri genel yönergeleri — https://developers.google.com/search/docs/appearance/structured-data/sd-policies
- Masaüstü çatı karşılaştırması (Electron/Tauri/…) — https://www.pkgpulse.com/guides/best-desktop-app-frameworks-2026

*Not: Yukarıdaki kaynakların bir kısmı üçüncü taraf blog/özetlerdir; kritik her bilgi (bayraklar, eşikler, kategori adları) Bölüm 15'teki gibi resmi dokümandan teyit edilmelidir.*
