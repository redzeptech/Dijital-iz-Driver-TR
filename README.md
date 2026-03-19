# Dijital İz Sürücü (DİZ)

<p align="center">
  <strong>Python tabanlı DFIR framework</strong> — disk, bellek, ağ, bulut ve mobil kanıtları <strong>tek SuperTimeline</strong> ve <strong>profesyonel HTML/PDF rapor</strong> altında birleştirir.
</p>

<p align="center">
  <a href="https://www.python.org/downloads/"><img src="https://img.shields.io/badge/python-3.10+-blue.svg" alt="Python 3.10+"></a>
  <a href="https://www.apache.org/licenses/LICENSE-2.0"><img src="https://img.shields.io/badge/License-Apache%202.0-blue.svg" alt="License Apache 2.0"></a>
  <img src="https://img.shields.io/badge/rapor-HTML%20%2B%20Plotly-111d2e?style=flat&color=00f0ff" alt="Report HTML Plotly">
  <img src="https://img.shields.io/badge/KVKK-DİZ--Mask-111d2e?style=flat&color=f0b429" alt="KVKK masking">
</p>

---

## Kurulum (Installation)

Yerelde çalıştırmak için sırayla şu adımları izleyin:

1. **Depoyu klonlayın**
   ```bash
   git clone https://github.com/redzeptech/Dijital-iz-Driver-TR
   cd Dijital-iz-Driver-TR
   ```

2. **Python paketlerini yükleyin**
   ```bash
   pip install -r requirements.txt
   ```

3. **Ortam ve kurallar** — Araçları ve Sigma kurallarını hazırlar.
   ```bash
   python setup_env.py
   ```

4. **Dashboard** — Streamlit arayüzünü başlatır.
   ```bash
   streamlit run ui/app.py
   ```

---

## Örnek Rapor / Sample Report

Bu bölüm, **`main.py --report`** ve isteğe bağlı **`--pdf`** ile üretilen **Storyline** (HTML/PDF) çıktısının okuma düzenini ve örnek bir **saldırı örgüsünü** özetler. Amaç: yerel **dava / KVKK** disiplini ile **küresel** tehdit modellemesinin (ör. **MITRE ATT&CK**) aynı rapor üzerinden sunulması.

### Saldırı Senaryosu (örnek zincir)

Aşağıdaki tablo, *hayali fakat tipik* bir **kill chain** akışını katman sırasıyla gösterir: **Mobil** ile ilk temas → **RAM**’de gizlenme → **Bulut**’ta yetki kökü → **Ağ** üzerinden veri sızdırma. Gerçek raporda olaylar `core/correlator.py` ile birleştirilir; MITRE teknik kimlikleri transcript’te **ATT&CK** sütununda görünebilir.

| Adım | Katman | Saldırı senaryosu (özet) | Rapor / motor karşılığı |
|------|--------|---------------------------|-------------------------|
| **1** | **Mobil** | Saldırgan, mesajlaşma kanalıyla kurbanı **iş teklifi** veya kötü amaçlı ek ile yönlendirir (ilk temas / sosyal mühendislik). | `mobile_findings.json` · çok kaynaklı zaman hizalaması · Storyline **hikaye akışı** satırları |
| **2** | **RAM** | Uygulama veya script sonrası **bellekte** enjeksiyon / şüpheli süreç; disk logundan bağımsız gizlenme. | Volatility (**malfind**, **pslist**, **netscan**) · **Disk+RAM çakışması** (PDF/ HTML tabloda kırmızı çerçeve) |
| **3** | **Bulut** | Çalınan veya otomasyonla kazanılan kimlikle **IAM / API** üzerinden yetki veya snapshot/dışa aktarma. | `cloud_findings.json` · **ATO (Account Takeover)** korelasyonu · CloudTrail benzeri özetler |
| **4** | **Ağ** | Kurumsal egress veya tunneled kanal ile **yoğun çıkış trafiği**; hedef genelde dış C2 veya depolama. | Zeek/PCAP → `network_analysis.json` · **üçlü korelasyon (exfil)** · beaconing / DNS şüphesi |

> **TR / EN:** Rapor metinleri ve arayüz **Türkçe** odaklıdır (KVKK, yerel müşteri ve ekipler için); teknik sütunlar ve **ATT&CK** kodları **İngilizce standart** ile uyumludur — böylece yerel operasyon ile **global IOC/ATT&CK** ekosistemi arasında köprü kurulur.  
> **KVKK:** IP, kullanıcı adı ve benzeri alanlar **`core/masking.py`** ile maskeleme modunda güvenli sunulur.

### Rapor görsel yapısı (wireframe)

Aşağıdaki şema, **`templates/report.html`** tabanlı çıktının üstten alta yaklaşık **bilgi mimarisini** betimler (PDF’te bölüm sırası aynıdır; Plotly grafikleri statik olmayabilir):

```
+------------------------------------------------------------------+
|  KAPAK — Başlık ("Otomatik Olay Müdahale Analizi" / CLI ile)      |
|  SHA-256 doğrulama özeti (ham kanıt manifest parmak izi)         |
|  Meta: olay sayısı, Tam-Saha / Exfil / Disk+RAM sayaçları       |
+------------------------------------------------------------------+
|  STORYLINE                                                         |
|    · AI analist girişi (detective_report / attack_scenario .md) |
|    · Hikaye akışı [HH:MM - Mobil|Disk|RAM|Ağ|Bulut]             |
|    · Kill chain (Keşif → Sızma → Sızıntı)                        |
|    · Dikey olay örgüsü (ikonlu)                                  |
|    · İlişki şeması (SVG — IP / dosya / bulut kimliği)            |
|    · Adli özet — Analist notu (bölüm altı)                        |
+------------------------------------------------------------------+
|  MITRE ATT&CK ilerleme özeti    →    Analist notu                |
|  Uzman görüşü (not defteri)     →    Analist notu                |
+------------------------------------------------------------------+
|  KRİTİK BULGULAR — korelasyon kartları + kanıt matrisi           |
|  Zaman hizalama metni            →    Analist notu                |
+------------------------------------------------------------------+
|  Saldırı haritası (swimlane)     →    Analist notu               |
|  İnteraktif zaman çizelgesi (Plotly)  →  Analist notu             |
+------------------------------------------------------------------+
|  Birleşik olay tablosu (çakışma satırları kalın/kırmızı çerçeve)  |
|  → Analist notu                                                  |
+------------------------------------------------------------------+
|  BÜTÜNLÜK MÜHRÜ — Kanıt doğrulama tablosu (JSON/CSV SHA-256)     |
+------------------------------------------------------------------+
|  Rapor Doğrulama Özeti — HTML gövdesi SHA-256 (dijital imza)    |
+------------------------------------------------------------------+
```

PDF üretimi: `python main.py -i <evtx> --pdf` → `data/results/diz_vaka_raporu_001.pdf` (HTML: `diz_vaka_raporu_001.html` veya `--report` yolu). Ayrıntılı zaman çizelgesi ve **swimlane** açıklaması için aşağıdaki paragrafı inceleyin.

### Büyük rapor: zaman çizelgesi ve uç nokta hizası

HTML raporda (**`--report`**) iki görsel katman üst üste biner: **`İnteraktif saldırı zaman çizelgesi`**, tarayıcıda **Plotly.js** ile çizilir; yatay eksende zaman, dikey eksende **kanıt şeridi** (Disk/EVTX, RAM, **Ağ**, correlator **Mobil** / **Bulut** küme işaretleri). **`Saldırı haritası (zaman – kaynak katmanı)`** bölümü **swimlane** ile aynı örgüyü özetler — pratikte **Arkime** tarzı “kim, ne zaman, kime konuştu?” sorusunu rapor yüzeyine taşır.

<p align="center">
  <em>Örnek rapor akışı: kapak + bütünlük özeti → Storyline → MITRE → kritik korelasyon → swimlane / Plotly → KVKK maskeli tablo → kanıt hash tablosu → gövde SHA-256</em>
</p>

---

<details>
<summary><strong>Tasarım dili</strong> (kurumsal referans)</summary>

README ve rapor şablonu (**`templates/report.html`**), bilgi yoğunluğunda **Arkime** ve **Timesketch** ekosistemlerini; ton, başlık hiyerarşisi ve kanıt sunumunda ise **Cellebrite** kalıbındaki kurumsal rapor disiplinini hedefler — sansasyon değil, tekrarlanabilir özet ve savunulabilir görünüm.

</details>

---

## 🚀 Neden Dijital İz Sürücü (DİZ)?

- **Hibrit Analiz**: Türkiye'de ilk defa Disk, RAM ve Ağ verilerini tek bir yapay zeka destekli motorla korele eden açık kaynaklı framework.

- ☁️ & 📱 **Hibrit Adli Bilişim**: Türkiye'nin hem Bulut (AWS/Azure) hem de Mobil (Android/iOS) verilerini disk, RAM ve ağ verileriyle aynı anda işleyebilen tek yerli platformu.

- **Adli Standartlar**: Magnet AXIOM ve EnCase kalitesinde raporlama, Plaso derinliğinde analiz.

- **KVKK Dostu**: Analiz raporlarında hassas verileri otomatik maskeleyen (DİZ-Mask) yerli teknoloji.

---

## 🇹🇷 Yerli ve Milli Teknik Özellikler

| Özellik | Açıklama |
|---------|----------|
| 🔍 **Çok Katmanlı İz Sürme** | Disk, RAM ve Network verilerini aynı saniyede birleştiren ilk yerli motor. |
| ☁️📱 **Bulut + Mobil Full-Spectrum** | AWS/Azure günlükleri ve Android/iOS yedekleri; disk, RAM ve ağ ile **aynı panelde** (Streamlit DİZ-Map / lateral movement). |
| 🎭 **Akıllı Maskeleme (DİZ-Mask)** | KVKK uyumluluğu için analiz sırasında hassas verileri otomatik maskeleme. |
| 📊 **Profesyonel Raporlama** | Magnet AXIOM kalitesinde PDF ve interaktif HTML çıktıları. |
| 🛠️ **Açık Kaynak Entegrasyonu** | Dünyanın en iyi 10+ adli bilişim aracını tek komutla yönetme. |

---

## Neden Farklı?

| Özellik | Açıklama |
|---------|----------|
| **Çift Motorlu Analiz** | Hayabusa'nın hızı ile Chainsaw'un keskin Sigma kurallarını harmanlar. |
| **Akıllı Maskeleme** | Analiz sırasında hassas verileri (PII) otomatik gizleyerek KVKK uyumlu raporlar sunar. *(Ref: Magnet AXIOM Style)* |
| **Görsel Kanıt Yönetimi** | Karmaşık logları, Timesketch kalitesinde HTML ve PDF raporlara dönüştürür. |
| **Hibrit İnceleme** | Windows logları + Volatility (bellek) + Zeek/Tshark (ağ) — hepsi tek SuperTimeline'da. |
| **Full-Spectrum** | Bulut (AWS/Azure) + Mobil (Android/iOS SQLite) + kurumsal disk/RAM/ağ — **tek yerli platformda** birlikte. |

---

## Neden "Konuşuyorlar" Diyoruz?

DİZ, iki farklı analiz yaklaşımını **tek komutla** birleştirir:

| Araç | Rol | Ne Yapar? |
|------|-----|-----------|
| **Hayabusa** | Standart Analiz | *"Kanka, 14:05'te birisi Admin kullanıcısıyla login olmaya çalışmış."* |
| **Chainsaw** | Tehdit Avcılığı | *"Ben de baktım, o esnada bir Sigma kuralı 'Brute Force' uyarısı verdi!"* |
| **DİZ** | Korelasyon | *"İkiniz de haklısınız, işte o anın tam raporu burada!"* |

Sadece bir **klasör yolu** veriyorsun; DİZ arka planda her iki aracı çalıştırıp sonuçları **tek bir timeline**'da birleştiriyor.

---

## Çift Koldan Analiz

```
EVTX Klasörü  ──►  Hayabusa (JSON)  ──┐
                    "Standart analiz"   │
                                       ├──►  DİZ  ──►  Birleşik Timeline
EVTX Klasörü  ──►  Chainsaw (Sigma)  ──┘
                    "Tehdit avcılığı"
```

- **Hayabusa**: Windows Event Log'lardan anomali tespiti, logon olayları, şüpheli aktivite
- **Chainsaw**: Sigma kuralları ile bilinen saldırı pattern'lerini avlama
- **Korelasyon**: İki kaynağın verisi `Timestamp`, `Level`, `RuleTitle`, `Details` formatında normalize edilip tek listede sunulur

---

## Hızlı Başlangıç

```bash
# Linux / macOS — tek komut kurulum (Sigma + Chainsaw mappings + pip)
chmod +x diz_setup.sh && ./diz_setup.sh
```

```bash
# 1. Kurulum (manuel)
pip install -r requirements.txt
python setup_env.py

# Alternatif — paket olarak kurulum (bağımlılıklar requirements.txt ile hizalı; geliştirici: +dev)
pip install -e ".[dev]"
pytest
# ruff check tests

# 2. Binary'leri yerleştir (Hayabusa + Chainsaw)
# Proje kök dizinine hayabusa.exe ve chainsaw.exe atın

# 3. Analiz (+ Storyline HTML; isteğe bağlı PDF)
python main.py --input C:/path/to/evtx_folder --report data/results/diz_report.html
python main.py --input C:/path/to/evtx_folder --pdf   # → data/results/diz_vaka_raporu_001.pdf
```

Windows’ta sürükle-bırak kolaylığı: proje kökünden **`diz_run.bat`** (klasör yolunu sorar, raporu `data\results\diz_report.html` üretir).

---

## Kullanım

### Ana Pipeline (EVTX Analizi)

```bash
python main.py --input data/raw
# veya
python main.py -i C:/Windows/System32/winevt/Logs
```

Çıktı: **Timestamp**'e göre sıralanmış, Hayabusa + Chainsaw birleşik tablo.

### Tam Pipeline (Disk + Bellek + Ağ)

```bash
python main.py -i data/evtx/ -m memory.raw -p capture.pcap -r rapor.html
```

Tek komutla EVTX, bellek imajı ve PCAP analizi — üçlü korelasyon ile veri sızıntısı tespiti.

### Gelişmiş Kullanım

```python
# Python API
from core.engine import DFIREngine
engine = DFIREngine()
engine.run_module("hayabusa", evidence_path="data/raw")
engine.run_module("ai_analyst", evidence_path="data/supertimeline")
```

```bash
# Streamlit web arayüzü
streamlit run ui/streamlit_app.py

# Profesyonel Dashboard (Plotly + Tehdit Haritası)
streamlit run ui/dashboard.py
```

---

## Klasör Yapısı

```
Dijital-iz-Driver-TR/
├── core/              # Motor ve yardımcılar
│   ├── engine.py
│   ├── module_manager.py
│   └── utils.py          # normalize_event, birleştirme
├── modules/
│   ├── hayabusa_module.py # Standart analiz
│   ├── chainsaw_wrapper.py # Sigma tehdit avcılığı
│   ├── cloud_wrapper.py   # AWS/Azure + hibrit IP
│   ├── mobile_wrapper.py  # Mobil SQLite / WhatsApp / GPS / carving
│   ├── ai_analyst.py      # AI raporlama
│   └── ...
├── config.py          # Merkezi yapılandırma
├── setup_env.py       # Ortam kurulumu
├── main.py            # Orkestra başlatıcı
└── data/results/      # Birleşik çıktılar
```

---

## Gereksinimler

| Bileşen | Açıklama |
|---------|----------|
| **Hayabusa** | [GitHub](https://github.com/Yamato-Security/hayabusa) |
| **Chainsaw** | [GitHub](https://github.com/WithSecureLabs/chainsaw) |
| **Volatility 3** | Bellek analizi (opsiyonel) |
| **Zeek / Tshark** | Ağ analizi (opsiyonel) |
| **Sigma Kuralları** | `setup_env.py` ile otomatik indirilir |
| **Python 3.10+** | `pip install -r requirements.txt` |

---

## Özellikler

- **Çift koldan analiz**: Hayabusa + Chainsaw tek komutta
- **Üçlü korelasyon**: Disk + Bellek + Ağ → Veri sızıntısı tespiti (Türkiye Siber Güvenlik Standartları)
- **SuperTimeline**: EVTX, Volatility netscan/pslist, Zeek conn — tek zaman çizelgesi
- **DİZ-Mask**: KVKK uyumlu otomatik maskeleme (e-posta, IP, kullanıcı adı)
- **Streamlit Dashboard**: Plotly Attack Timeline + Tehdit Haritası
- ☁️📱 **Bulut & mobil**: `cloud_wrapper` (CloudTrail/Azure + hibrit IP) + `mobile_wrapper` (WhatsApp, arama, GPS, SQLite carving) — **disk/RAM/ağ ile birlikte** tek dashboard
- **AI Analyst**: OpenAI/Ollama ile şüpheli aktivite özeti

---

## License

**Copyright © 2026 Recep Şenel — RedzepTech.**

**This project is licensed under the Apache License 2.0.**

See the [`LICENSE`](LICENSE) file in the repository root for the full license text.

Net, şeffaf ve endüstride yaygın kabul gören **Apache License 2.0** seçimi; kurumsal güvenlik ve satın alma süreçlerinde sıkça istenen **patent koruma** ve **yeniden kullanım koşullarının** açıkça yazılı olmasını sağlar. Bu da projenin **profesyonel ve kurumsal imajını** güçlendirir: paydaşlar (tedarikçi, müşteri, açık kaynak topluluğu) hukuki çerçeveyi tek bir standart belgeyle hızlıca doğrulayabilir.

> *Apache 2.0*, Microsoft, Google ve çok sayıda kurumsal ve açık kaynak projede kullanılan dengeyi (hem kullanım özgürlüğü hem yükümlülük netliği) yansıtır; DİZ gibi **DFIR / güvenlik** araçları için uygun bir varsayılan lisans katmanıdır.
