"""
Streamlit Web Arayüzü
"""

import sys
from pathlib import Path

# Proje kökünü path'e ekle
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st
from core.engine import DFIREngine


def main() -> None:
    st.set_page_config(
        page_title="Dijital İz Sürücü",
        page_icon="🔍",
        layout="wide",
    )

    st.title("🔍 Dijital İz Sürücü")
    st.caption("DFIR Framework - Digital Forensics and Incident Response")

    engine = DFIREngine()

    # Sidebar
    with st.sidebar:
        st.header("Modüller")
        modules = engine.list_available_modules()
        for m in modules:
            st.write(f"• **{m['name']}**: {m['description']}")

    tab1, tab2, tab3, tab4 = st.tabs(["Modül Çalıştır", "Pipeline", "SuperTimeline", "AI Analyst"])

    with tab1:
        st.subheader("Tek Modül Çalıştır")
        col1, col2 = st.columns(2)
        with col1:
            module_name = st.selectbox(
                "Modül",
                options=[m["name"] for m in modules],
                key="module_select",
            )
        with col2:
            evidence_path = st.text_input(
                "Kanıt Yolu",
                placeholder="data/raw veya dosya yolu",
                value="data/raw",
            )

        if st.button("Çalıştır"):
            with st.spinner("Modül çalışıyor..."):
                try:
                    result = engine.run_module(
                        module_name,
                        Path(evidence_path) if evidence_path else None,
                    )
                    st.success(f"Tamamlandı: {result['module']}")
                    st.json(result)
                except Exception as e:
                    st.error(str(e))

    with tab2:
        st.subheader("Pipeline Çalıştır")
        selected_modules = st.multiselect(
            "Modüller (sırayla çalışır)",
            options=[m["name"] for m in modules],
            default=[m["name"] for m in modules[:2]],
        )
        pipeline_evidence = st.text_input(
            "Kanıt Yolu",
            value="data/raw",
            key="pipeline_evidence",
        )
        merge_timeline = st.checkbox("SuperTimeline'a birleştir", value=True)

        if st.button("Pipeline Başlat"):
            if not selected_modules:
                st.warning("En az bir modül seçin.")
            else:
                with st.spinner("Pipeline çalışıyor..."):
                    try:
                        result = engine.run_pipeline(
                            modules=selected_modules,
                            evidence_path=Path(pipeline_evidence) if pipeline_evidence else None,
                            parse_to_supertimeline=merge_timeline,
                        )
                        st.success("Pipeline tamamlandı!")
                        st.json(result)
                    except Exception as e:
                        st.error(str(e))

    with tab3:
        st.subheader("SuperTimeline Görüntüleyici")
        timeline_path = engine.supertimeline_dir / "merged_timeline.csv"
        if timeline_path.exists():
            import pandas as pd

            df = pd.read_csv(timeline_path, nrows=1000)
            st.dataframe(df, use_container_width=True)
        else:
            st.info("Henüz SuperTimeline oluşturulmamış. Önce pipeline çalıştırın.")

    with tab4:
        st.subheader("AI Analyst - Şüpheli Aktivite Analizi")
        st.caption("SuperTimeline'ı OpenAI veya Ollama ile analiz eder, saldırı senaryosu raporu üretir.")
        tl_path = st.text_input(
            "SuperTimeline Yolu",
            value=str(engine.supertimeline_dir),
            key="ai_timeline_path",
        )
        col1, col2 = st.columns(2)
        with col1:
            provider = st.selectbox("Provider", ["openai", "ollama"], key="ai_provider")
        with col2:
            model = st.text_input(
                "Model",
                value="gpt-4o-mini" if provider == "openai" else "llama3.2",
                key="ai_model",
            )
        if st.button("AI Analizi Başlat"):
            with st.spinner("AI analiz yapılıyor..."):
                try:
                    result = engine.run_module(
                        "ai_analyst",
                        evidence_path=Path(tl_path),
                        provider=provider,
                        model=model,
                    )
                    if result.get("status") == "success":
                        report_path = result.get("report_path") or result.get("output_path")
                        if report_path and Path(report_path).exists():
                            st.success("Analiz tamamlandı!")
                            st.markdown(Path(report_path).read_text(encoding="utf-8"))
                        else:
                            st.json(result)
                    else:
                        st.error(result.get("error", "Bilinmeyen hata"))
                        st.json(result)
                except Exception as e:
                    st.error(str(e))


if __name__ == "__main__":
    main()
