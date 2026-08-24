"""Upload trained LoRA adapter & Model Card to Hugging Face Model Hub."""

import argparse
import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from huggingface_hub import HfApi, create_repo


MODEL_CARD_CONTENT = """---
license: mit
library_name: peft
base_model: Qwen/Qwen2.5-Coder-1.5B-Instruct
tags:
- security
- sast
- idor
- authorization
- authentication
- vulnerability-detection
- code-analysis
pipeline_tag: text-generation
language:
- en
metrics:
- accuracy
- f1
---

# 🛡️ AuthGuard-1.5B: Autonomous AI Security Auditor

**AuthGuard-1.5B** is an open-source, ultra-specialized LLM adapter fine-tuned on top of `Qwen/Qwen2.5-Coder-1.5B-Instruct` for **Static Application Security Testing (SAST)** of authentication and authorization vulnerabilities.

## 🎯 Benchmark Performance
- **Hardcore Adversarial Benchmark (60 Multi-Language Cases):** **98.33% Accuracy (59 / 60)**
- **Security Recall (Flaws Caught):** **100.00% (32 / 32 - 0 False Negatives)**
- **False Positive Rate:** **3.57% (Only 1 False Alarm across 28 clean baselines)**
- **F1-Score:** **0.9846**

## 🌐 Supported Languages & Frameworks
- **Python:** FastAPI, Django REST Framework, Flask, Strawberry GraphQL, SQLAlchemy
- **Go:** Gin, Chi, Fiber, GORM
- **TypeScript / JavaScript:** Next.js 14 Server Actions, NestJS, Express, Sequelize
- **Java:** Spring Boot (Method Security & SpEL), Quarkus Panache
- **C# / .NET:** ASP.NET Core Minimal APIs, Entity Framework Core
- **PHP:** Laravel Eloquent, Symfony, Slim Framework

## 🚀 Quick Start & Usage

```python
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from peft import PeftModel

base_model_id = "Qwen/Qwen2.5-Coder-1.5B-Instruct"
adapter_id = "{repo_id}"

tokenizer = AutoTokenizer.from_pretrained(base_model_id, trust_remote_code=True)
base_model = AutoModelForCausalLM.from_pretrained(
    base_model_id,
    torch_dtype=torch.float16,
    device_map="auto",
    trust_remote_code=True
)

model = PeftModel.from_pretrained(base_model, adapter_id)

code_snippet = '''
@app.get("/api/user/{user_id}/documents/{doc_id}")
def get_doc(user_id: int, doc_id: int, db: Session = Depends(get_db)):
    return db.query(Document).filter(Document.id == doc_id).first()
'''

prompt = f"<|im_start|>system\\nYou are an expert security auditor specialized in web application authentication and authorization vulnerabilities.\\nOutput valid JSON.\\n<|im_end|>\\n<|im_start|>user\\nLanguage: python\\n\\nCode:\\n```python\\n{code_snippet}\\n```<|im_end|>\\n<|im_start|>assistant\\n"

inputs = tokenizer(prompt, return_tensors="pt").to(model.device)
outputs = model.generate(**inputs, max_new_tokens=256, do_sample=False)
print(tokenizer.decode(outputs[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True))
```

## 📄 License
MIT License. Free for commercial and research use.
"""


def upload_model(
    adapter_dir: str = "checkpoints_1.5b/final_adapter",
    repo_id: str = "kuldeep-poonia/authguard-1.5b",
    hf_token: str = None,
    private: bool = False,
):
    print("=" * 80)
    print("  HUGGING FACE MODEL HUB UPLOAD PIPELINE")
    print(f"  • Source Adapter Dir: {adapter_dir}")
    print(f"  • Target Repo ID:     {repo_id}")
    print(f"  • Visibility:         {'Private' if private else 'Public'}")
    print("=" * 80)

    if not os.path.exists(adapter_dir):
        raise FileNotFoundError(f"Adapter directory not found: {adapter_dir}")

    # Initialize API
    api = HfApi(token=hf_token)

    print("\n[1/3] Creating/verifying Hugging Face repository...")
    create_repo(
        repo_id=repo_id,
        token=hf_token,
        private=private,
        exist_ok=True,
        repo_type="model",
    )
    print(f"[OK] Repository ready: https://huggingface.co/{repo_id}")

    # Generate Model Card README
    readme_path = os.path.join(adapter_dir, "README.md")
    with open(readme_path, "w", encoding="utf-8") as f:
        f.write(MODEL_CARD_CONTENT.format(repo_id=repo_id))
    print("[2/3] Generated Model Card README.md")

    print(f"[3/3] Uploading adapter files to https://huggingface.co/{repo_id}...")
    api.upload_folder(
        folder_path=adapter_dir,
        repo_id=repo_id,
        repo_type="model",
        token=hf_token,
    )

    print("\n" + "=" * 80)
    print("  UPLOAD SUCCESSFUL! 🚀")
    print(f"  • Model URL: https://huggingface.co/{repo_id}")
    print("=" * 80)


def main():
    parser = argparse.ArgumentParser(description="Upload AuthGuard LoRA adapter to Hugging Face")
    parser.add_argument("--adapter_dir", type=str, default="checkpoints_1.5b/final_adapter")
    parser.add_argument("--repo_id", type=str, required=True, help="Your HF username/model_name (e.g. your_username/authguard-1.5b)")
    parser.add_argument("--hf_token", type=str, default=None, help="Hugging Face Write Token (or login via huggingface-cli)")
    parser.add_argument("--private", action="store_true", help="Make repository private")
    args = parser.parse_args()

    upload_model(
        adapter_dir=args.adapter_dir,
        repo_id=args.repo_id,
        hf_token=args.hf_token,
        private=args.private,
    )


if __name__ == "__main__":
    main()
