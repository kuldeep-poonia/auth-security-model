"""Targeted Punishment & Contrastive Error-Correction Fine-Tuner.

Loads mined failure instances from `data/adversarial_error_mined.json`, applies
a 4.0x gradient penalty multiplier on failure cases with contrastive diagnostic
critiques, and executes rapid targeted reinforcement fine-tuning to eliminate model blindspots.
"""

import argparse
import json
import os
import sys
import time
from typing import Any, Dict, List, Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

import torch
from torch.utils.data import Dataset
from transformers import (
    AutoModelForCausalLM,
    AutoTokenizer,
    BitsAndBytesConfig,
    DataCollatorForSeq2Seq,
    Trainer,
    TrainingArguments,
)

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

from peft import LoraConfig, PeftModel, get_peft_model, prepare_model_for_kbit_training
from training.dataset_formatter import SYSTEM_PROMPT, format_user_prompt
from training.logger import ExperimentLogger


class MinedErrorDataset(Dataset):
    """Dataset for training on mined adversarial error samples with target penalty weights."""

    def __init__(self, error_items: List[Dict[str, Any]], tokenizer: Any, max_length: int = 512):
        self.examples = []
        for item in error_items:
            code = item["code"]
            lang = item["language"]
            user_prompt = format_user_prompt(code, lang)
            assistant_target = item["corrected_response"]
            penalty_weight = float(item.get("penalty_weight", 4.0))

            context_messages = [
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ]

            if hasattr(tokenizer, "apply_chat_template"):
                context_text = tokenizer.apply_chat_template(context_messages, tokenize=False, add_generation_prompt=True)
            else:
                context_text = f"<|im_start|>system\n{SYSTEM_PROMPT}<|im_end|>\n<|im_start|>user\n{user_prompt}<|im_end|>\n<|im_start|>assistant\n"

            assistant_text = f"{assistant_target}<|im_end|>\n"

            assistant_tokens = tokenizer(assistant_text, truncation=True, max_length=192, add_special_tokens=False)["input_ids"]
            assistant_len = len(assistant_tokens)

            max_ctx_len = max(max_length - assistant_len, 64)
            context_tokens = tokenizer(context_text, truncation=True, max_length=max_ctx_len, add_special_tokens=False)["input_ids"]

            input_ids = (context_tokens + assistant_tokens)[:max_length]
            context_len = len(context_tokens)

            labels = ([-100] * context_len + list(assistant_tokens))[:len(input_ids)]
            attention_mask = [1] * len(input_ids)

            self.examples.append({
                "input_ids": input_ids,
                "attention_mask": attention_mask,
                "labels": labels,
                "penalty_weight": penalty_weight,
            })

    def __len__(self):
        return len(self.examples)

    def __getitem__(self, idx):
        return self.examples[idx]


class CustomPenaltyCollator:
    """Collator preserving custom per-sample penalty weights."""

    def __init__(self, tokenizer: Any):
        self.tokenizer = tokenizer

    def __call__(self, batch: List[Dict[str, Any]]) -> Dict[str, torch.Tensor]:
        input_ids = [torch.tensor(b["input_ids"], dtype=torch.long) for b in batch]
        attention_mask = [torch.tensor(b["attention_mask"], dtype=torch.long) for b in batch]
        labels = [torch.tensor(b["labels"], dtype=torch.long) for b in batch]
        penalties = torch.tensor([b.get("penalty_weight", 4.0) for b in batch], dtype=torch.float32)

        padded_input_ids = torch.nn.utils.rnn.pad_sequence(
            input_ids, batch_first=True, padding_value=self.tokenizer.pad_token_id or 0
        )
        padded_attention_mask = torch.nn.utils.rnn.pad_sequence(
            attention_mask, batch_first=True, padding_value=0
        )
        padded_labels = torch.nn.utils.rnn.pad_sequence(
            labels, batch_first=True, padding_value=-100
        )

        return {
            "input_ids": padded_input_ids,
            "attention_mask": padded_attention_mask,
            "labels": padded_labels,
            "penalty_weight": penalties,
        }


class PenaltyWeightedTrainer(Trainer):
    """Trainer applying explicit sample-level loss penalties on past model failure cases."""

    def compute_loss(self, model, inputs, return_outputs=False, num_items_in_batch=None):
        penalties = inputs.pop("penalty_weight", None)
        labels = inputs.get("labels")
        outputs = model(**inputs)

        if penalties is not None and labels is not None and hasattr(outputs, "logits"):
            logits = outputs.logits
            shift_logits = logits[..., :-1, :].contiguous()
            shift_labels = labels[..., 1:].contiguous()

            loss_fct = torch.nn.CrossEntropyLoss(reduction="none", ignore_index=-100)
            token_loss = loss_fct(shift_logits.view(-1, shift_logits.size(-1)), shift_labels.view(-1)).view(shift_labels.size())

            valid_mask = (shift_labels != -100).float()
            per_sample_loss = (token_loss * valid_mask).sum(dim=-1) / (valid_mask.sum(dim=-1) + 1e-8)

            penalties_tensor = penalties.to(logits.device)
            weighted_loss = (per_sample_loss * penalties_tensor).mean()
            return (weighted_loss, outputs) if return_outputs else weighted_loss

        loss = outputs.get("loss") if isinstance(outputs, dict) else outputs.loss
        return (loss, outputs) if return_outputs else loss


def train_punish_and_correct(args):
    """Execute targeted punishment fine-tuning on mined failure instances."""
    logger = ExperimentLogger(run_name="punish_and_correct", log_dir=args.output_dir)
    logger.log_event("init", {"model_id": args.model_id, "mined_file": args.mined_file})

    if not os.path.exists(args.mined_file):
        print(f"[ERROR] Mined error file not found at: {args.mined_file}")
        print("Please run `python evaluation/adversarial_error_miner.py` first to discover failure cases.")
        return

    with open(args.mined_file, "r", encoding="utf-8") as f:
        mined_items = json.load(f)

    if not mined_items:
        print("[SUCCESS] No failure cases found in mined file! Model already performs 100% on the benchmark.")
        return

    print("=" * 80)
    print(f"  TARGETED PUNISHMENT & REINFORCEMENT FINE-TUNING ON {len(mined_items)} MINED FAILURES")
    print("=" * 80)

    tokenizer = AutoTokenizer.from_pretrained(
        args.adapter_path if os.path.exists(args.adapter_path) else args.model_id,
        trust_remote_code=True,
    )
    if tokenizer.pad_token is None:
        tokenizer.pad_token = tokenizer.eos_token

    device_map = "auto" if torch.cuda.is_available() else None
    compute_dtype = torch.float16 if torch.cuda.is_available() else torch.float32

    if args.use_qlora and torch.cuda.is_available():
        bnb_config = BitsAndBytesConfig(
            load_in_4bit=True,
            bnb_4bit_quant_type="nf4",
            bnb_4bit_compute_dtype=compute_dtype,
            bnb_4bit_use_double_quant=True,
        )
        base_model = AutoModelForCausalLM.from_pretrained(
            args.model_id,
            quantization_config=bnb_config,
            device_map=device_map,
            trust_remote_code=True,
        )
        base_model = prepare_model_for_kbit_training(base_model)
    else:
        base_model = AutoModelForCausalLM.from_pretrained(
            args.model_id,
            torch_dtype=compute_dtype,
            device_map=device_map,
            trust_remote_code=True,
        )

    # Load existing adapter or create new PEFT adapter
    if os.path.exists(args.adapter_path):
        print(f"[INFO] Loading existing adapter weights from: {args.adapter_path}")
        model = PeftModel.from_pretrained(base_model, args.adapter_path, is_trainable=True)
    else:
        lora_config = LoraConfig(
            r=16,
            lora_alpha=32,
            target_modules=["q_proj", "k_proj", "v_proj", "o_proj", "gate_proj", "up_proj", "down_proj"],
            lora_dropout=0.05,
            bias="none",
            task_type="CAUSAL_LM",
        )
        model = get_peft_model(base_model, lora_config)

    train_dataset = MinedErrorDataset(mined_items, tokenizer=tokenizer, max_length=args.max_length)
    collator = CustomPenaltyCollator(tokenizer=tokenizer)

    training_args = TrainingArguments(
        output_dir=args.output_dir,
        per_device_train_batch_size=args.batch_size,
        gradient_accumulation_steps=args.gradient_accumulation_steps,
        learning_rate=args.learning_rate,
        num_train_epochs=args.epochs,
        logging_steps=1,
        save_strategy="no",
        fp16=torch.cuda.is_available(),
        remove_unused_columns=False,
        report_to="none",
    )

    trainer = PenaltyWeightedTrainer(
        model=model,
        args=training_args,
        train_dataset=train_dataset,
        data_collator=collator,
    )

    print("[INFO] Beginning targeted reinforcement training...")
    trainer.train()

    final_adapter_dir = os.path.join(args.output_dir, "final_adapter")
    trainer.save_model(final_adapter_dir)
    tokenizer.save_pretrained(final_adapter_dir)

    print(f"[OK] Reinforcement complete! Updated adapter saved to: {final_adapter_dir}")


def parse_args():
    parser = argparse.ArgumentParser(description="Targeted Punishment Fine-Tuner")
    parser.add_argument("--model_id", type=str, default="Qwen/Qwen2.5-Coder-1.5B-Instruct")
    parser.add_argument("--adapter_path", type=str, default="checkpoints_1.5b/final_adapter")
    parser.add_argument("--mined_file", type=str, default="data/adversarial_error_mined.json")
    parser.add_argument("--output_dir", type=str, default="checkpoints_1.5b_reinforced")
    parser.add_argument("--epochs", type=int, default=5)
    parser.add_argument("--learning_rate", type=float, default=3e-4)
    parser.add_argument("--batch_size", type=int, default=2)
    parser.add_argument("--gradient_accumulation_steps", type=int, default=4)
    parser.add_argument("--max_length", type=int, default=512)
    parser.add_argument("--use_qlora", action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    train_punish_and_correct(parse_args())
