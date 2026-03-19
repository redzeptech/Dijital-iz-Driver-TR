# Entegre vaka çalışması (5 kanat)

Bu klasör, **Disk, RAM, Ağ, Bulut, Mobil** kanıtlarının aynı anda işlenmesi için kullanılır.

## Yapı

| Yol | Açıklama |
|-----|----------|
| `artifacts/` | Önceden üretilmiş JSON (`case_study_generator.py` ile). `main.py --case-study` bunları `data/results/` altına kopyalar. |
| `evtx/` | İsteğe bağlı Windows günlükleri (`*.evtx`). Boşsa disk kanalı yalnızca `artifacts/hayabusa_output.json` üzerinden yüklenir. |

## Artefaktları üretme

```bash
python tests/case_study_generator.py --out-dir tests/case_study/artifacts
```

## Tam analiz + correlator zaman hizalaması + DİZ-Analist (dedektif)

```bash
python main.py --case-study tests/case_study --ai-detective
```

- `--ai-detective`: LLM’e dedektif uslubu talimat (başlangıç / ilerleyiş / sonuç) + `correlator` çok kaynaklı zaman özeti gönderilir.
- `--diz-ai` ile birlikte kullanılabilir; yalnız `--ai-detective` de LLM çağrısını tetikler.
- LLM için: `OPENAI_API_KEY` veya yerel **Ollama**.

## Çıktılar

- `data/results/cross_source_alignment.json` — beş kanat zaman kümesi özeti
- `data/results/correlation_results.json` — içinde `cross_source_alignment`
- `data/results/diz_analyst/detective_report.md` — dedektif raporu (`--ai-detective` ile)
