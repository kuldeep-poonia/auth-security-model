"""Standalone Local Inference Engine for Auth Security Auditor.

Supports inference across:
1. Merged HuggingFace model (`checkpoints/merged_model`)
2. Base model + LoRA adapter (`checkpoints_1.5b/final_adapter`)
3. GGUF model via llama-cpp-python (CPU optimized)
"""

import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import torch
from transformers import AutoModelForCausalLM, AutoTokenizer

# PEFT torchao workaround for Windows / Kaggle
try:
    import peft.import_utils
    peft.import_utils.is_torchao_available = lambda: False
    if hasattr(peft.import_utils, "is_torch_ao_available"):
        peft.import_utils.is_torch_ao_available = lambda: False
    import peft.tuners.lora.torchao
    peft.tuners.lora.torchao.dispatch_torchao = lambda *args, **kwargs: None
    peft.tuners.lora.torchao.is_torchao_available = lambda: False
except Exception:
    pass

from peft import PeftModel
from training.dataset_formatter import SYSTEM_PROMPT, format_user_prompt
from evaluation.eval_model import extract_json_from_response


LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".go": "go",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".cs": "csharp",
    ".php": "php",
    ".rb": "ruby",
    ".rs": "rust",
}


class AuthSecurityDetector:
    """Production inference detector for auditing code against authorization vulnerabilities."""

    def __init__(
        self,
        model_path: str = "checkpoints_1.5b/final_adapter",
        base_model_id: str = "Qwen/Qwen2.5-Coder-1.5B-Instruct",
        device: Optional[str] = None,
        use_gguf: bool = False,
    ):
        self.model_path = model_path
        self.base_model_id = base_model_id
        self.use_gguf = use_gguf

        if device is None:
            self.device = "cuda" if torch.cuda.is_available() else "cpu"
        else:
            self.device = device

        self.model = None
        self.tokenizer = None
        self._load_engine()

    def _load_engine(self):
        # Auto-detect latest reinforced adapter if available
        if self.model_path == "checkpoints_1.5b/final_adapter":
            reinforced_path = os.path.join(PROJECT_ROOT, "checkpoints_1.5b_reinforced", "final_adapter")
            if os.path.exists(reinforced_path) and os.path.exists(os.path.join(reinforced_path, "adapter_model.safetensors")):
                print(f"[INFO] Auto-resolved latest reinforced adapter: {reinforced_path}")
                self.model_path = reinforced_path

        print(f"[INFO] Initializing AuthSecurityDetector on device: {self.device}")
        start = time.time()

        # Case 1: GGUF model via llama_cpp
        if self.use_gguf or self.model_path.endswith(".gguf"):
            try:
                from llama_cpp import Llama
                print(f"[INFO] Loading GGUF model: {self.model_path}")
                self.model = Llama(
                    model_path=self.model_path,
                    n_ctx=2048,
                    n_threads=os.cpu_count() or 4,
                    verbose=False,
                )
                self.tokenizer = None
                print(f"[OK] GGUF engine ready ({time.time() - start:.2f}s)")
                return
            except ImportError:
                print("[WARN] llama-cpp-python not installed. Falling back to PyTorch engine.")

        # Case 2: Merged standalone HuggingFace model
        if os.path.exists(os.path.join(self.model_path, "model.safetensors")) or os.path.exists(os.path.join(self.model_path, "config.json")):
            print(f"[INFO] Loading fused model from: {self.model_path}")
            self.tokenizer = AutoTokenizer.from_pretrained(self.model_path, trust_remote_code=True)
            dtype = torch.float16 if self.device == "cuda" else torch.float32
            self.model = AutoModelForCausalLM.from_pretrained(
                self.model_path,
                torch_dtype=dtype,
                device_map=self.device if self.device == "cuda" else None,
                trust_remote_code=True,
            )
        # Case 3: Base model + LoRA adapter
        else:
            print(f"[INFO] Loading base model ({self.base_model_id}) + LoRA ({self.model_path})")
            try:
                self.tokenizer = AutoTokenizer.from_pretrained(self.model_path, trust_remote_code=True)
            except Exception as e:
                print(f"[INFO] Loading canonical tokenizer from {self.base_model_id} (fallback: {e})")
                self.tokenizer = AutoTokenizer.from_pretrained(self.base_model_id, trust_remote_code=True)
            dtype = torch.float16 if self.device == "cuda" else torch.float32
            base = AutoModelForCausalLM.from_pretrained(
                self.base_model_id,
                torch_dtype=dtype,
                device_map=self.device if self.device == "cuda" else None,
                trust_remote_code=True,
            )
            if os.path.exists(self.model_path):
                self.model = PeftModel.from_pretrained(base, self.model_path)
            else:
                self.model = base

        if self.tokenizer.pad_token is None:
            self.tokenizer.pad_token = self.tokenizer.eos_token

        print(f"[OK] Detector engine loaded in {time.time() - start:.2f}s")

    def audit_code(self, code: str, language: str = "python") -> Dict[str, Any]:
        """Audit a single code snippet and return structured vulnerability report."""
        if not code or not code.strip():
            return {
                "is_vulnerable": False,
                "vulnerability_class": "none",
                "confidence": 0.0,
                "explanation": "Empty or whitespace-only code provided.",
                "flagged_lines": [],
                "latency_ms": 0.0,
            }

        start_time = time.time()
        user_prompt = format_user_prompt(code, language)

        # GGUF Inference Path
        if self.use_gguf and self.model is not None:
            full_prompt = (
                f"<|im_start|>system\n{SYSTEM_PROMPT}<|im_end|>\n"
                f"<|im_start|>user\n{user_prompt}<|im_end|>\n"
                f"<|im_start|>assistant\n"
            )
            response = self.model(
                full_prompt,
                max_tokens=256,
                temperature=0.0,
                stop=["<|im_end|>"],
            )
            raw_text = response["choices"][0]["text"].strip()

        # PyTorch Inference Path
        else:
            messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ]
            if hasattr(self.tokenizer, "apply_chat_template"):
                prompt_text = self.tokenizer.apply_chat_template(messages, tokenize=False, add_generation_prompt=True)
            else:
                prompt_text = (
                    f"<|im_start|>system\n{SYSTEM_PROMPT}<|im_end|>\n"
                    f"<|im_start|>user\n{user_prompt}<|im_end|>\n"
                    f"<|im_start|>assistant\n"
                )

            inputs = self.tokenizer(prompt_text, return_tensors="pt").to(self.device)

            with torch.no_grad():
                outputs = self.model.generate(
                    **inputs,
                    max_new_tokens=256,
                    do_sample=False,
                    pad_token_id=self.tokenizer.pad_token_id,
                    eos_token_id=self.tokenizer.eos_token_id,
                )

            gen_tokens = outputs[0][inputs["input_ids"].shape[1]:]
            raw_text = self.tokenizer.decode(gen_tokens, skip_special_tokens=True).strip()

        elapsed_ms = round((time.time() - start_time) * 1000, 2)
        parsed = extract_json_from_response(raw_text)

        return {
            "is_vulnerable": bool(parsed.get("is_vulnerable", False)),
            "vulnerability_class": str(parsed.get("vulnerability_class", "none")),
            "confidence": float(parsed.get("confidence", 0.0)),
            "explanation": str(parsed.get("explanation", "")),
            "flagged_lines": parsed.get("flagged_lines", []),
            "latency_ms": elapsed_ms,
            "raw_output": raw_text,
        }

    def audit_file(self, file_path: str) -> Dict[str, Any]:
        """Audit a file on disk, automatically detecting language from extension."""
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")

        _, ext = os.path.splitext(file_path)
        lang = LANGUAGE_EXTENSIONS.get(ext.lower(), "python")

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            code_content = f.read()

        result = self.audit_code(code_content, language=lang)
        result["file_path"] = file_path
        result["language"] = lang
        return result
