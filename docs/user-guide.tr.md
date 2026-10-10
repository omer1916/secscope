# SecScope kullanıcı kılavuzu (Türkçe)

SecScope, **kendi** web sitenizi veya web uygulamanızı **kendi bilgisayarınızda** yayına almadan önce
denetler: kaynak kod güvenliği, gizli anahtarlar, bağımlılık açıkları, yapılandırma hataları ve
Google'da görünürlük için teknik SEO. Sonuç, düzeltme kodlarıyla birlikte tek bir rapordur.

> Yalnızca size ait projeleri tarayın. SecScope ağ trafiğini yalnızca kendi bilgisayarınıza
> (localhost, 127.0.0.1, ::1) gönderir; bu kısıtlama kapatılamaz.

## 1. Kurulum

**Paketlenmiş sürüm (Windows):** `SecScope` klasörünü istediğiniz yere kopyalayın ve
`SecScopeApp.exe` dosyasını çalıştırın. Komut satırı için aynı klasördeki `secscope.exe` kullanılır.

**Kaynak koddan:** Python 3.12+ ve [uv](https://docs.astral.sh/uv/) gerekir.

```bash
uv sync
uv run secscope-gui        # masaüstü uygulaması
uv run secscope --help     # komut satırı
```

## 2. İsteğe bağlı araçlar

SecScope kendi motorlarıyla her zaman çalışır. Ek araçlar kapsamı genişletir:

| Araç | Ne kazandırır | Nasıl kurulur |
|---|---|---|
| Semgrep | Ek SAST kuralları (veri akışı) | `uv tool install semgrep` |
| gitleaks | Git geçmişindeki sırlar | Ayarlar > Araç yöneticisi > Kur, veya `secscope tools install gitleaks` |
| Trivy, osv-scanner | Bağımlılık açıkları (çevrimdışı veritabanı) | `secscope tools install trivy osv-scanner` ardından `secscope tools update-db` |

İndirilen her dosya sabitlenmiş sürüm ve SHA-256 ile doğrulanır. Araç eksikse ilgili kısım
raporda "ATLANDI" veya "azaltılmış kapsam" olarak görünür; tarama durmaz.

## 3. İlk tarama (masaüstü)

1. **Yeni tarama**'ya tıklayın.
2. **Kaynak:** proje klasörünü veya arşivini seçin (sürükleyip bırakabilirsiniz) ya da zaten
   çalışan `http://localhost:PORT` adresini girin.
3. **Algılanan proje:** SecScope yapıyı (statik site, Express, Flask, Django, PHP…) ve çalıştırma
   komutunu önerir; gerekirse düzenleyin. "Yayındaki adres" alanına sitenin gerçek adresini
   yazarsanız sitemap ve canonical kontrolleri buna göre yapılır (bu adrese bağlanılmaz).
4. **Profil ve modüller:** Hızlı / Standart / Derin veya Özel.
5. **Onay:** "Bu sistem bana aittir…" kutusunu işaretleyip **Taramayı başlat**'a basın.

**Canlı izleme** sayfasında modüllerin ilerlemesini, bulunan sorunları ve günlüğü görürsünüz;
duraklatabilir veya iptal edebilirsiniz. Bitince **Sonuçlar** açılır.

## 4. Sonuçları okumak

- **Genel puan ve not (A–F):** güvenlik %45, SEO %20, dayanıklılık %20, kalite %10, bağımlılıklar
  %5 ağırlıkla. Ölçülmeyen alanların ağırlığı diğerlerine dağıtılır. Ayrıntı: `docs/scoring.md`.
- Her bulguda: ne bulundu, nerede, kanıt (sırlar maskelenmiş), neden risk, **sizin yapınıza
  göre** düzeltme kodu ve referanslar (CWE, OWASP Top 10:2025).
- **Düzeltmeyi kopyala** düğmesi adımları ve kodu panoya alır.
- Gerçek bir sorun değilse **Yanlış pozitif olarak işaretle**; gerekçe zorunludur, sonraki
  taramalarda gizlenir (Ayarlar'dan geri alınabilir).
- **HTML raporu aç** çevrimdışı çalışan tek dosyalık raporu açar. **Dışa aktar** HTML, JSON,
  SARIF (IDE/CI için) ve CSV üretir.
- **Yapay zekâ için kopyala** tüm bulguları kodu ve düzeltme önerileriyle birlikte panoya kopyalar;
  ChatGPT/Claude gibi bir yapay zekâya yapıştırıp "bu hataları düzelt" diyebilirsin (CLI: `--format ai`).

### Çalışan uygulama kontrolleri (dinamik)

Uygulaman çalışırken (localhost'ta) ona bakıp yalnızca çalışma anında görünen açıkları bulur: eksik güvenlik başlıkları, korumasız çerezler, yanlış CORS, açıkta kalmış `.git`/`.env`/yedek dosyalar, hata sayfası sızıntısı, dizin listeleme. Saldırı yükü göndermez — normal istek atıp yanıta bakar. Ayrıca zararsız işaretlerle doğrulama yapar: GET parametrelerine zararsız bir işaret gönderip yansıyan XSS, şablon enjeksiyonu ({{7*9}}→63) ve açık yönlendirmeyi tespit eder. Saldırı yükü göndermez, POST formlarını denemez. Yalnızca kapsam beyanını onayladığında ve yalnızca kendi localhost adresine çalışır.

### Google'da görünürlük bölümü

Google yerel siteyi tarayamaz; bu bölüm yayına hazırlığı ölçer, sıralama garantisi vermez.
SecScope `robots.txt`, `sitemap.xml`, yapısal veri (JSON-LD) ve başlık önerisi taslakları üretir;
bunlar raporda ve `patches/` klasöründedir. Kaynak kodunuza dokunulmaz. Yayından sonra
Search Console kontrol listesini izleyin.

## 5. Geçmiş ve karşılaştırma

**Geçmiş** sayfasında iki tarama seçip **Karşılaştır**'a basın: yeni, düzelen, kalıcı ve
gerileyen bulgular ile puan farkı gösterilir.

## 6. Komut satırı ve CI

```bash
secscope scan --path ./proje --accept-scope-statement --format html,json,sarif --fail-on high
secscope report <tarama-id> --format pdf
secscope diff <eski-id> <yeni-id>
secscope suppress --rule SEO-OG-001 --reason "Sosyal önizleme gerekmiyor"
```

`--fail-on high` yüksek veya kritik bulgu varsa 3 çıkış koduyla biter (CI için).

```bash
secscope scan --path . --exclude docs --exclude "legacy/" --changed-since origin/main --fail-on high
```

- `--exclude` (veya sihirbazdaki **Hariç tutulacak yollar**): bu yollar kopyalanmaz, taranmaz ve
  çalıştırılmaz; raporun **Kapsam** bölümünde listelenir.
- `--changed-since`: yalnızca bu git referansından sonra değişen dosyalardaki kod bulgularını
  raporlar (pull request incelemeleri için).

### Rapordaki ek bölümler

- **Kapsam:** kaç dosyanın incelendiği, hariç tutulanlar, analiz edilmeyen bağımlılık klasörleri.
  Temiz bir sonuç neyin incelendiğini de söyler.
- **Test ve fixture kodu:** `tests/`, `fixtures/`, `*.test.js` gibi dosyalardaki kod bulguları
  "bilgi" düzeyinde gösterilir ve puana katılmaz. Gizli anahtarlar istisnadır: test dosyasında bile
  gerçek görünen bir anahtar tam önemiyle raporlanır.
- **Saldırı yüzeyi:** koddan çıkarılan uç nokta listesi ve her birinde yetki kontrolünün görünüp
  görünmediği. Veri değiştiren ve kontrolü görünmeyen uç noktalar vurgulanır. Bu bir envanterdir,
  bulgu değildir.
- **Commit:** proje bir git deposuysa raporun hangi commit'i anlattığı (commit edilmemiş değişiklikler
  dahilse belirtilir). SecScope'un oluşturduğu rapor klasörlerine `.gitignore` eklenir.

## 7. Gizlilik

Telemetri yoktur. Ağ trafiği yalnızca: hedef (localhost), sizin başlattığınız araç/veritabanı
indirmeleri ve "bağımlılıkları kur" seçeneğinde projenizin paket deposu erişimidir.

## 8. Bu sürümde olmayanlar

Yıkıcı saldırı simülasyonu (saldırı yükleri, ZAP/Nuclei, istismar üretimi), yük/stres testi ve
laboratuvar Core Web Vitals ölçümü bu sürümde yoktur. Güvenli dinamik kontroller ve zararsız işaretle
doğrulama ise vardır (çalışan uygulama kontrolleri) (`docs/decisions/009-scope-of-this-build.md`).
