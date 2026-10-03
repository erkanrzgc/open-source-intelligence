# Güvenilirlik değerlendirmesi ve birleşik araştırma hedefi

Değerlendirme tarihi: 2026-10-02. Temel commit: `1bcaa9d`; aşağıdaki
iyileştirmeler bu commit üzerindeki yerel çalışma ağacına aittir.

## Sonuç

**Araştırmacı destekli OSINT MVP'si olarak değerlendirmem: 7/10.** Bu puan
öznel bir mühendislik değerlendirmesidir; doğruluk yüzdesi veya bağımsız ürün
sertifikası değildir. Kamuya açık profil araştırması için kullanılabilir.
Eksiksiz kapsama, otomatik kişi teşhisi veya tüm platformların çalıştığı iddia
edilmiyor. Katalog büyüklüğü, doğrulanabilir kaynak sayısıyla aynı şey değildir.

| Boyut | Puan | Gerekçe |
|---|---:|---|
| Mimari ve test edilebilirlik | 8/10 | Ortak ScanConfig, merkezi HTTP, izole fazlar, çevrimdışı testler |
| Kanıt izlenebilirliği | 8/10 | Kaynak URL, kontrol zamanı, HTTP sonucu, sözleşme sürümü ve neden kodları |
| Kimlik doğruluğunun gösterilmesi | 6/10 | Muhafazakâr kurallar var; bağımsız gerçek-vaka benchmark'ı yok |
| Kaynak sürekliliği | 7/10 | Haftalık contract smoke mevcut; burada yalnız altı açık sağlayıcı canlı doğrulandı |
| Araştırma deneyimi | 6/10 | CLI/REST/MCP ve raporlar var; modüller henüz bütünleşik vaka iş akışı değil |

## Bu çalışmada düzeltilenler

- Geçmiş listeleme eksik argüman hatası giderildi; kullanıcı adı filtresi
  LIMIT'ten önce uygulanıyor, eski kayıtlar ilk 100 kaydın dışında kaybolmuyor.
- AI korelasyonu alias `profiles` alanını okuyor. Çıktı, deterministik özetten
  ayrı `identity_analysis` alanında saklanıyor; kaydetme sırasında silinmiyor
  ve kimlik verdict'lerini yükseltmiyor. MCP seçeneği de aynı ayara bağlandı.
- Genel sayfa/footer linkleri sahiplik kanıtı olmaktan çıkarıldı. `rel=me`
  ve Person `sameAs` self-link olarak kullanılırken bio içindeki bahsetmeler
  yalnız keşfe katılıyor. Bu muhafazakâr seçim bazı gerçek linkleri kaçırabilir.
- Doğrudan linkler platform + hesap bazında eşleştiriliyor. GitHub'daki
  `alice` bağlantısı, yalnız Hugging Face'te bulunan `alice` hesabını doğrulamaz.
- Aynı avatar URL'si güçlü kanıt değil; açıkça varsayılan olmadığı belirtilmiş
  perceptual hash gereklidir. Alias fazı şu anda otomatik bu hash'i üretmiyor;
  bu sinyalin uçtan uca avatar iş akışına bağlanması sonraki iştir.
- Aynı dış hesabın URL ve handle gösterimleri bağımsız iki kanıt sayılmıyor.
- Export kimlik doğrulama token'ı URL'den kaldırıldı; HTTP Authorization
  başlığıyla indirme yapılıyor. JS indirme akışı ağsız testle denetlendi.
- Gözlem zamanı ve HTTP durumu JSON round-trip'te korunuyor; HTML kaynakları,
  kontrol zamanlarını ve kanıt nedenlerini gösteriyor. Eski zamanlar uydurulmuyor.

## Tekrarlanabilir ölçümler

2026-10-02 temel iyileştirmeleri sonrası tam koşu: **1045 passed, 1 skipped;
84,61 saniye**. Ruff ve Bandit
temiz; Mypy 3.10, 3.11 ve 3.12 hedeflerinde geçti. Bu, üç ayrı Python runtime'ında
pytest çalıştırıldığı anlamına gelmez; çoklu-runtime koşuları CI matrisine aittir.
Wheel üretildi; benchmark JSON'u ve evaluation sözleşmesi paket içinde kontrol
edildi. CI workflow güncellendi, ancak bu yerel değişiklikler henüz push edilmedi.

```bash
.venv/bin/python -m pytest -q --timeout=30
.venv/bin/ruff check core modules utils scripts tests mcp_server.py
.venv/bin/mypy --ignore-missing-imports core modules utils scripts/provider_contract_smoke.py scripts/identity_benchmark.py
.venv/bin/bandit -r core modules utils mcp_server.py scripts/provider_contract_smoke.py scripts/identity_benchmark.py -q
.venv/bin/python -m scripts.identity_benchmark --check --output reports/identity-benchmark.json
```

Etiketli set: 24 **sentetik geliştirme** kimlik çifti (12 aynı kişi / 12 farklı
kişi) ve 8 alias keşif örneği. Etiketler kurgusal hesap sahipliğini ifade eder;
iki hesabın kamusal metadata'sı eksik bırakılmış örnekler özellikle korunur.
Bu set scorer geliştirmek için kullanılmıştır; bağımsız holdout değildir.

| Ölçüm | Sonuç | Yorum |
|---|---:|---|
| Güçlü doğru eşleşme | 8/12 | `likely_same` veya `confirmed_same` |
| Yanlış güçlü eşleşme | 0/12 negatif | Bu küçük set için; saha garantisi değil |
| Güçlü eşleşme precision | 8/8 (%100) | Küçük ve sentetik payda açıkça gösterilmelidir |
| Güçlü eşleşme recall | 8/12 (%66,7) | Dört eksik kanıtlı pozitif örnek kaçırılıyor |
| Karar vermekten kaçınma | 16/24 | `possible_same`/`uncertain`, farklı kişi kararı değildir |
| Alias top-12 / top-24 | 6/8 / 6/8 | Sayı eki kaldırılan ve ilişkisiz alias kaçırılıyor |

Skorlar kalibre edilmiş olasılık değildir. Sentetik sonuçlar, HTTP endpoint
kapsaması ve gerçek kimlik doğruluğu birbirinden ayrı tutulmalıdır. Skorlayıcıya
verilen sentetik direct-link ve doğrulanmış iletişim kanıtlarının edinimi bu
benchmark tarafından test edilmez; ilgili engine ve provider testleri ayrıdır.

Canlı contract smoke: GitHub, Dev.to, GitLab, Hacker News, Keybase ve Bluesky'de
bir bilinen pozitif ve bir rastgele negatif handle, toplam **12 istek; 6/6
sağlayıcı geçti**. Bu yalnız kontrol anındaki endpoint sözleşmesini doğrular;
iki hesabın aynı kişi olduğunu veya tüm katalog kapsamını doğrulamaz. Ücretli/
kimlik doğrulamalı kaynaklar bu koşuya dahil edilmedi. Ham yanıtlar ve token'lar
rapora yazılmaz. Yerel çıktılar:

- `reports/identity-benchmark-2026-10-02.json`
- `reports/provider-contract-2026-10-02.json`

## “God Eye” yönünde bir sonraki ürün dilimi

2026-10-03 güncellemesi: bu yol haritasının ilk dikey dilimi olan
[vaka çalışma alanı](case-workbench.md) eklendi: kaynaklı graph, snapshot
timeline, ayrı analist kararları ve açıkça başlatılan bütçeli profil takipleri.
Aşağıdaki geniş hedeflerin tamamının bittiği anlamına gelmez.

Bu dilim sonrası tam yerel koşu: **1075 passed, 1 skipped; 77,24 saniye**.
Ruff ve Bandit temiz; Mypy 3.10/3.11/3.12 hedefleri geçti. Wheel ayrı dizine
kurularak modül importları, 100/500 katalog sayıları ve yeni web/sözleşme
dosyaları doğrulandı. Chromium testi ağsız olarak kanıt listesi, açıkça
başlatılan takip, iptal ve Authorization başlığını denetliyor; CDN grafik
çiziminin görsel doğrulaması değildir. Yeni API testleri salt-okunur rolü,
kısmi sonuç kalıcılığını, yeniden başlatmada tekrar çalıştırmama davranışını
ve Python/REST/MCP/CLI veri eşitliğini kapsıyor. Bu tur canlı profil taraması
yapılmadı; yukarıdaki canlı smoke önceki koşuya aittir.

Hedef, kamuya açık kaynaklar üzerinde **tek vaka içinde çoklu ipucu araştırması**.
Mevcut entity graph, history, watchlist, domain ve kimlik modüllerinin ortak
bir iş akışında birleşmesi gerekir; aşağıdaki maddeler henüz tamamlandı demek değildir.

1. **Kanıt grafiği + çelişki görünümü.** Profil, handle, domain, organizasyon
   ve kamusal bağlantılar ayrı varlıklar olsun. Her kenarda kaynak, zaman,
   kanıt tipi ve deterministik verdict bulunsun. Aynı isimli farklı kişiler
   otomatik birleşmesin; analist kabul/ret kararları ayrı saklansın.
2. **Bütçeli keşif kuyruğu.** Bir doğrulanmış bulgudan yeni kamuya açık
   ipuçlarına kontrollü geçiş: kapsam, derinlik, istek bütçesi, tekrar önleme
   ve neden bu ipucunun takip edildiği görünür olsun. Mevcut recursive tarama
   vaka seviyesinde denetlenebilir hale getirilsin.
3. **Zaman çizelgesi + kaynak sağlığı.** Snapshot farkları, değişen bio/handle/
   linkler ve erişilemeyen kaynaklar aynı ekranda görülsün. Kaynak erişilemezliği
   hesap silindi sonucuyla karıştırılmasın. Opt-in izleme mevcut watchlist'e bağlansın.

Bir sonraki saha kabulü için rızalı/kendi kontrolümüzdeki gerçek hesaplardan,
scorer geliştirmede kullanılmamış etiketli bir holdout seti gerekir. Önceden
tanımlı vakalarda yanlış güçlü eşleşmeler, kaçırılan aliaslar, kaynak başına
kullanılabilirlik, HTTP bütçesi ve uçtan uca süre birlikte raporlanmalı.
Yeni platform sayısını artırmak tek başına bu kabul koşulunu sağlamaz.
