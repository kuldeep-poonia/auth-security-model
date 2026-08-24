"""Unit tests for packaging and inference modules."""

import os
import pytest
from inference.detector import LANGUAGE_EXTENSIONS, AuthSecurityDetector
from model_packaging.merge_lora import parse_args as parse_merge_args
from model_packaging.export_gguf import parse_args as parse_gguf_args


def test_language_extension_mappings():
    assert LANGUAGE_EXTENSIONS[".py"] == "python"
    assert LANGUAGE_EXTENSIONS[".go"] == "go"
    assert LANGUAGE_EXTENSIONS[".js"] == "javascript"
    assert LANGUAGE_EXTENSIONS[".ts"] == "typescript"
    assert LANGUAGE_EXTENSIONS[".java"] == "java"
    assert LANGUAGE_EXTENSIONS[".cs"] == "csharp"
    assert LANGUAGE_EXTENSIONS[".php"] == "php"


def test_merge_lora_args_defaults():
    args = parse_merge_args([])
    assert args.base_model_id == "Qwen/Qwen2.5-Coder-1.5B-Instruct"
    assert args.adapter_path == "checkpoints_1.5b/final_adapter"
    assert args.output_dir == "checkpoints/merged_model"


def test_export_gguf_args_defaults():
    args = parse_gguf_args([])
    assert args.model_dir == "checkpoints/merged_model"
    assert args.quant_type == "q4_k_m"
    assert args.out_type == "f16"
