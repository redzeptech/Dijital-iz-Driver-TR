# Katkıda bulunma / Contributing

**Dijital İz Sürücü (DİZ)** açık kaynaklı bir DFIR / olay müdahalesi projesidir. Katkılarınız (hata düzeltmesi, dokümantasyon, test, özellik) memnuniyetle karşılanır.

**Telif / imtiyaz:** Projeye katkı vererek, katkınızın **Apache License 2.0** ile uyumlu şekilde lisanslanmasını kabul etmiş olursunuz. Ayrıntılar için kök dizindeki [`LICENSE`](LICENSE) dosyasına bakın.

---

## Geliştirme ortamı

```bash
git clone <repo-url>
cd Dijital-iz-Driver-TR
python -m venv .venv
# Windows: .venv\Scripts\activate
# Linux/macOS: source .venv/bin/activate
pip install -e ".[dev]"
```

- **Üretim benzeri tam bağımlılık:** `pip install -r requirements.txt` veya `pip install -e .` — paket listesi `pyproject.toml` ile hizalıdır. (Harici araçlar: Hayabusa, Chainsaw, wkhtmltopdf vb. ayrı kurulur.)
- **PDF raporu:** `weasyprint` ve `pdfkit` zaten çekirdek bağımlılıktadır; `pdfkit` için sistemde **wkhtmltopdf** kurulu olmalıdır.

---

## Test ve lint

```bash
pytest
ruff check tests
```

- CI şu an **`tests/`** üzerinde **ruff** çalıştırır; tüm kod tabanında lint sıkılaştırması hedeflenmektedir.
- Yeni özellikler için mümkün olduğunca **küçük, deterministik pytest** ekleyin (ağ harici araç çağırmayan).

---

## Pull request disiplini

1. **Dal:** `feature/kisa-aciklama` veya `fix/issue-konusu`
2. **Commit mesajları:** Türkçe veya İngilizce, net ve geçmişe uygun (tercihen imperatif: *Add*, *Fix*).
3. **PR açıklaması:** Ne değişti, nasıl test edildi, ilgili issue varsa numara.
4. **Kırıcı değişiklik:** README veya `CHANGELOG` güncellemesi önerilir.

---

## Güvenlik

Olası güvenlik açıklarını lütfen **herkese açık issue** yerine sorumlu açıklama kanalıyla paylaşın (repo ayarlarına göre güvenlik politikası eklenebilir).

---

## İletişim / maintainer

**Recep Şenel — RedzepTech**  
Copyright © 2026 Recep Şenel RedzepTech — Apache License 2.0

---

## English summary

- Contributions are welcome under **Apache-2.0** (see `LICENSE`).
- Set up with `pip install -e ".[dev]"`, run `pytest` and `ruff check tests`.
- Open PRs with a clear description and tests where feasible.

Maintaining a clear **contribution and licensing path** strengthens the project’s **professional, enterprise-facing** posture alongside the chosen Apache 2.0 terms.
