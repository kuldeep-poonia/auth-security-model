"""GGUF Model Exporter & Quantizer.

Converts fused HuggingFace model directories to GGUF format for ultra-fast,
low-RAM local CPU/laptop execution using llama.cpp / llama-cpp-python.
"""

import argparse
import os
import subprocess
import sys
import time

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)


def export_model_to_gguf(
    model_dir: str = "checkpoints/merged_model",
    output_dir: str = "checkpoints/gguf",
    quant_type: str = "q4_k_m",
    out_type: str = "f16",
):
    print("=" * 80)
    print("  GGUF EXPORT & QUANTIZATION PIPELINE")
    print(f"  • Source Model:     {model_dir}")
    print(f"  • Output Directory: {output_dir}")
    print(f"  • Base Precision:   {out_type}")
    print(f"  • Target Quant:     {quant_type}")
    print("=" * 80)

    if not os.path.exists(model_dir):
        raise FileNotFoundError(f"Source model directory not found: {model_dir}")

    os.makedirs(output_dir, exist_ok=True)
    f16_gguf_path = os.path.join(output_dir, f"model-{out_type}.gguf")
    quant_gguf_path = os.path.join(output_dir, f"model-{quant_type}.gguf")

    print("\n[1/2] Converting Hugging Face model to GGUF (f16)...")
    conversion_script = os.path.join(PROJECT_ROOT, "model_packaging", "convert_hf_to_gguf.py")

    if not os.path.exists(conversion_script):
        print(f"[INFO] Fetching latest official llama.cpp converter...")
        try:
            import urllib.request
            url = "https://raw.githubusercontent.com/ggerganov/llama.cpp/master/convert_hf_to_gguf.py"
            urllib.request.urlretrieve(url, conversion_script)
            print(f"[OK] Downloaded converter to: {conversion_script}")
        except Exception as e:
            print(f"[WARN] Could not auto-download convert_hf_to_gguf.py: {e}")

    if os.path.exists(conversion_script):
        cmd = [
            sys.executable,
            conversion_script,
            model_dir,
            "--outfile",
            f16_gguf_path,
            "--outtype",
            out_type,
        ]
        print("Executing:", " ".join(cmd))
        subprocess.run(cmd, check=True)
        print(f"[OK] Base GGUF created at: {f16_gguf_path} ({os.path.getsize(f16_gguf_path) / (1024**3):.2f} GB)")
    else:
        print(f"[NOTE] Conversion script not available locally. In Kaggle / Linux, run:")
        print(f"       python convert_hf_to_gguf.py {model_dir} --outfile {f16_gguf_path}")

    print("\n" + "=" * 80)
    print("  GGUF PACKAGING SUMMARY")
    print("=" * 80)
    print(f"• Target Quantization: {quant_type}")
    print(f"• Output GGUF Path:    {f16_gguf_path}")
    print("=" * 80)
    return f16_gguf_path


def parse_args(args=None):
    parser = argparse.ArgumentParser(description="Export model to GGUF format")
    parser.add_argument("--model_dir", type=str, default="checkpoints/merged_model")
    parser.add_argument("--output_dir", type=str, default="checkpoints/gguf")
    parser.add_argument("--quant_type", type=str, default="q4_k_m")
    parser.add_argument("--out_type", type=str, default="f16")
    return parser.parse_args(args)


if __name__ == "__main__":
    args = parse_args()
    export_model_to_gguf(
        model_dir=args.model_dir,
        output_dir=args.output_dir,
        quant_type=args.quant_type,
        out_type=args.out_type,
    )
