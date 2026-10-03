# Birleşik vaka çalışma alanı

Bu sürüm kayıtlı taramaları vaka içinde birleştirir: kanıt grafiği, gözlem zaman
çizelgesi, analist değerlendirmesi ve kontrollü kullanıcı adı takibi. Vaka açmak
veya grafiği okumak ağ taraması başlatmaz.

## Kullanım

1. Web arayüzünde **Cases** altında bir vaka oluştur/seç. Yeni taramayı bu
   vakaya kaydet veya geçmişteki bir taramayı vakaya bağla.
2. Vaka detayında **Evidence workbench** açılır. Grafikte bir bağlantıya tıkla
   ya da **Evidence list** üzerinden seç: kaynak URL, kontrol zamanı, HTTP
   durumu, sağlayıcı sözleşmesi ve karar gerekçeleri görünür.
3. **accepted / rejected / unreviewed** ile gerekçeli analist değerlendirmesi
   kaydet. Bu not otomatik kimlik verdict'ini değiştirmez.
4. **Controlled public-profile leads** altında platformları ve istek sınırını
   seçip yalnız istediğin ipucunda **Run this lead** kullan. Sonuç aynı vakaya
   kaydedilir. **Refresh evidence / jobs** sonucu yeniler, **Cancel** işi durdurur.

CLI ve MCP salt-okunur görünümü de aynı çekirdeği kullanır:

```bash
osint workbench 1
```

MCP: `get_case_workbench` girdisi `{"case_id": 1}`.

## REST sözleşmesi

| Yol | İşlev |
|---|---|
| `GET /cases/{id}/workbench` | Vaka kapsamındaki graph, timeline, leads, pivots, budget |
| `PUT /cases/{id}/edges/{edge_id}/review` | `decision` ve isteğe bağlı `note` |
| `POST /cases/{id}/pivots` | Dönen bir `lead_id`, `platforms`, `request_budget`; 202 + job |
| `POST /scan-jobs/{job_id}/cancel` | Kuyruktaki veya çalışan işi iptal eder |

Kimlik doğrulama açıksa mevcut rol kuralları geçerlidir: viewer yazamaz;
Bearer token yalnız Authorization başlığında kullanılır. Mevcut uygulama
çok-kiracılı vaka sahipliği sunmaz; bu sürüm de öyle bir garanti eklemez.

## Kanıt anlamı

- `query` düğümü bir araştırma girdisidir, tek başına bir kişi değildir.
  Aynı görünen ad iki hesabı birleştirmez. Profil kimliği platform, host ve
  canonical/queried handle üzerinden ayrılır.
- `identity_candidate` bir hipotezdir; `uncertain` veya `possible_same`
  bağlantılar doğrulanmış sahiplik gibi gösterilmez. Site/organizasyon
  bağlantıları beyan edilen ilişkilerdir, sahiplik ispatı değildir.
- Timeline tarihleri tarama gözlem zamanlarıdır; hesap açılış tarihi veya
  gerçek dünyadaki olay tarihi değildir. Eski eksik `checked_at` uydurulmaz.
  Parser'ın döndürmediği metadata alanı silinmiş sayılmaz; değişiklik yalnız
  iki gözlemde de açıkça döndürülen değerler arasında karşılaştırılır.
- `coverage_lost`: engel, erişim sorunu veya belirsizlik. `absence_observed`:
  sağlayıcı açıkça NOT_FOUND döndürdü; bu bile tek başına silinme kanıtı değildir.
  Sonraki taramada hiç kontrol edilmeyen platformdan silinme sonucu çıkarılmaz.
- Eksik geçmiş kayıtları ve kırpılan görünüm uyarıyla belirtilir. En fazla
  200 bağlı snapshot, 100 ipucu; arayüz ilk 100 zaman olayı / 150 kanıt bağlantısı
  gösterir. Tam yüklenen timeline API'den okunur. 500 düğüm üzerindeki grafikte
  çizim kapatılır; kanıt listesi çalışır. Grafik CDN'si yoksa da liste kullanılabilir.

## Takip kapsamı ve bütçe

Her iş ayrı kullanıcı eylemi gerektirir. Şimdilik yalnız şu kamuya açık kesin
profil sağlayıcıları desteklenir: GitHub, GitLab, Dev.to, Hacker News, Keybase,
Bluesky. E-posta/telefon, alan adı taraması, geolocation, breach, LLM ve otomatik
recursive takip bu iş akışında etkinleştirilmez.

- İş başına varsayılan 8, azami 20 HTTP denemesi; retry'lar da sayılır.
- Vaka başına azami 10 iş ve toplam 120 rezerve HTTP denemesi.
- En fazla 2 takip seviyesi. Aynı kullanıcı adı bir vakada tekrar kuyruğa alınmaz.
- Rezervasyonlar SQLite işlemiyle atomiktir; eşzamanlı istekler sınırı aşamaz.
- Sınırlandırılmış HTTP istemcisi yönlendirme ve ikinci TLS taşıyıcısını
  kapatır; istekler görünmeyen takipler üzerinden bütçeyi aşamaz.
- Bütçesi biten tamamlanmış iş `partial` gösterilir. İptal/hata rezervasyonu
  iade etmez: kaç isteğin gönderildiği belirsiz olduğunda güvenli üst sınır korunur.
- İş kuyruğu bellek içindedir. Yeniden başlatma sonrası yarım kalan işler
  `interrupted` gösterilir; otomatik yeniden çalıştırılmaz. Yalnız hiçbir iş
  kabul edilmeden kuyruk dolu hatası alınırsa rezervasyon bırakılır.

`ScanConfig.platform_names` platform tarama kapsamını daraltır;
`http_request_budget` merkezi HTTPClient denemelerini sınırlar. REST/MCP aynı
alanları, CLI `--platform` ve `--http-request-budget` seçeneklerini sunar.
Bu genel HTTP limiti, bağımsız ağ kullanan bütün opsiyonel modüller için küresel
bir kota değildir; vaka takibi bu modülleri özellikle kapatır.

## Kapsam dışında kalanlar

Sürekli izleme için mevcut watchlist/scheduler ayrı kalır; bu sürüm arka planda
otomatik takip başlatmaz. Kalıcı worker kuyruğu, analist karar revizyon geçmişi,
çelişki çözümleme ve çok-kiracılı vaka yetkilendirmesi sonraki dilimlerdir.
Bu çalışma, bağımsız gerçek-vaka doğruluk benchmark'ının yerine geçmez.
