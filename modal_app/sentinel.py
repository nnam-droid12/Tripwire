"""Tripwire Sentinel: a small open-weight scam detector, fine-tuned on Modal.

Meta's Llama 3.2 1B Instruct (open weights) is fine-tuned with LoRA to read a
phone call so far and answer "scam" or "safe". It is small enough to run on
the protected person's own laptop: a first line that works offline, costs
nothing per call, and escalates to the cloud CaseJudge when a call turns
suspicious. It never triggers a full stop on its own.

Data discipline: training and threshold selection use only the training split
of BothBosu/scam-dialogue (Apache-2.0); the test split is scored once, with
the threshold fixed beforehand.

Usage (from the repo root, after ``python -m modal setup``)::

    python -m modal run modal_app/sentinel.py::timing     # seconds per step on CPU
    python -m modal deploy modal_app/sentinel.py
    python -m modal run modal_app/sentinel.py::launch     # train + threshold, entirely in the cloud
    python -m modal run modal_app/sentinel.py::fetch      # once it has finished
    python -m modal run modal_app/sentinel.py::evaluate
    python -m modal run modal_app/sentinel.py::export_scores  # per-turn scores for eval/run_external.py --sentinel

The deployed ``SentinelService`` class serves live scores (``core/sentinel_client.py``).

Training runs on Modal CPU containers (GPUs require a card on file).
"""

from __future__ import annotations

import json
import random
from pathlib import Path

import modal

BASE_MODEL = "unsloth/Llama-3.2-1B-Instruct"  # ungated mirror of Meta's Llama 3.2 1B Instruct (Llama 3.2 license)
VOLUME_PATH = "/vol"
ADAPTER_DIR = f"{VOLUME_PATH}/sentinel-lora-full"
TIMING_DIR = f"{VOLUME_PATH}/timing-lora"  # short timing runs never overwrite the real adapter
META_PATH = f"{VOLUME_PATH}/sentinel-meta.json"
MAX_CHARS = 1200  # keep the most recent turns that fit; a call is judged on what was just said
CPUS = 16  # GPUs on Modal need a card on file; CPU containers don't, so Sentinel trains on CPUs

app = modal.App("tripwire-sentinel")
volume = modal.Volume.from_name("tripwire-sentinel", create_if_missing=True)
image = (
    modal.Image.debian_slim(python_version="3.12")
    .pip_install("torch==2.5.1", index_url="https://download.pytorch.org/whl/cpu")
    .pip_install("transformers==4.46.3", "peft==0.13.2", "accelerate==1.1.1")
)


def prompt(turns: list[list[str]]) -> str:
    """The last turns of the call that fit, oldest first, as the model sees them."""
    lines, size = [], 0
    for speaker, text in reversed(turns):
        line = f"{'Caller' if speaker == 'A' else 'Person'}: {text}"
        if size + len(line) > MAX_CHARS and lines:
            break
        lines.append(line)
        size += len(line)
    call = "\n".join(reversed(lines))
    return (
        "You protect older people from phone scams. Read the call so far and answer with one word: scam or safe.\n\n"
        f"{call}\n\nAnswer:"
    )


def prefixes(conv: dict) -> list[tuple[str, str]]:
    """Training examples: the call halfway through and at the end, with the call's label."""
    turns, label = conv["turns"], "scam" if conv["is_scam"] else "safe"
    cuts = sorted({max(2, len(turns) // 2), len(turns)})
    return [(prompt(turns[:k]), label) for k in cuts]


def _train(train_convs: list[dict], adapter_dir: str, epochs: int = 1, lr: float = 2e-4, batch: int = 8, max_examples: int | None = None) -> dict:
    """LoRA fine-tuning (runs inside a Modal container)."""
    import torch
    from peft import LoraConfig, get_peft_model
    from transformers import AutoModelForCausalLM, AutoTokenizer

    import time

    torch.set_num_threads(CPUS)
    tok = AutoTokenizer.from_pretrained(BASE_MODEL)
    tok.pad_token = tok.eos_token
    model = AutoModelForCausalLM.from_pretrained(BASE_MODEL, torch_dtype=torch.float32)
    model = get_peft_model(model, LoraConfig(r=16, lora_alpha=32, lora_dropout=0.05, target_modules=["q_proj", "k_proj", "v_proj", "o_proj"], task_type="CAUSAL_LM"))
    examples = [ex for c in train_convs for ex in prefixes(c)]
    random.Random(0).shuffle(examples)
    examples = examples[:max_examples] if max_examples else examples
    started = time.time()
    answer_ids = {lab: tok(" " + lab, add_special_tokens=False).input_ids[0] for lab in ("scam", "safe")}
    opt = torch.optim.AdamW([p for p in model.parameters() if p.requires_grad], lr=lr)
    model.train()
    losses = []
    for _epoch in range(epochs):
        for i in range(0, len(examples), batch):
            chunk = examples[i:i + batch]
            enc = tok([p for p, _ in chunk], return_tensors="pt", padding=True, truncation=True, max_length=480, padding_side="left")
            target = torch.tensor([answer_ids[lab] for _, lab in chunk])
            logits = model(**enc).logits[:, -1, :]  # next token after "Answer:"
            loss = torch.nn.functional.cross_entropy(logits.float(), target)
            loss.backward()
            opt.step()
            opt.zero_grad()
            losses.append(loss.item())
            if len(losses) % 20 == 0:
                print(f"step {len(losses)} loss {sum(losses[-20:]) / 20:.4f} ({(time.time() - started) / len(losses):.1f} s/step)", flush=True)
    model.save_pretrained(adapter_dir)
    tok.save_pretrained(adapter_dir)
    volume.commit()
    k = min(10, len(losses))
    return {"examples": len(examples), "steps": len(losses), "first_loss": round(sum(losses[:k]) / k, 4), "last_loss": round(sum(losses[-k:]) / k, 4),
            "seconds_per_step": round((time.time() - started) / max(1, len(losses)), 2)}


def _score(convs: list[dict], adapter_dir: str, batch: int = 16) -> list[list[float]]:
    """P(scam) after every turn of every conversation, streaming as it would live (runs inside a container)."""
    import torch
    from peft import PeftModel
    from transformers import AutoModelForCausalLM, AutoTokenizer

    torch.set_num_threads(CPUS)
    tok = AutoTokenizer.from_pretrained(adapter_dir)
    tok.pad_token = tok.eos_token
    base = AutoModelForCausalLM.from_pretrained(BASE_MODEL, torch_dtype=torch.float32)
    model = PeftModel.from_pretrained(base, adapter_dir).eval()
    scam_id = tok(" scam", add_special_tokens=False).input_ids[0]
    safe_id = tok(" safe", add_special_tokens=False).input_ids[0]
    jobs = [(ci, k, prompt(c["turns"][:k])) for ci, c in enumerate(convs) for k in range(1, len(c["turns"]) + 1)]
    out = [[0.0] * len(c["turns"]) for c in convs]
    with torch.no_grad():
        for i in range(0, len(jobs), batch):
            chunk = jobs[i:i + batch]
            enc = tok([p for _, _, p in chunk], return_tensors="pt", padding=True, truncation=True, max_length=480, padding_side="left")
            logits = model(**enc).logits[:, -1, :].float()
            probs = torch.softmax(logits[:, [scam_id, safe_id]], dim=-1)[:, 0].tolist()
            for (ci, k, _), p in zip(chunk, probs):
                out[ci][k - 1] = round(p, 4)
    return out


def choose_threshold(val: list[dict], scores: list[list[float]]) -> dict:
    """Lowest alarm threshold with at most 1% of held-out legitimate calls ever crossing it."""
    legit_max = sorted(max(sc) for c, sc in zip(val, scores) if not c["is_scam"])
    threshold = round(legit_max[int(len(legit_max) * 0.99) - 1] + 0.01, 3) if legit_max else 0.5
    threshold = min(threshold, 0.99)
    caught = [any(p >= threshold for p in sc) for c, sc in zip(val, scores) if c["is_scam"]]
    return {"threshold": threshold, "val_detection": round(sum(caught) / len(caught), 3), "val_size": len(val)}


@app.function(image=image, cpu=CPUS, memory=32768, volumes={VOLUME_PATH: volume}, timeout=8 * 3600)
def train_remote(train_convs: list[dict], max_examples: int | None = None) -> dict:
    return _train(train_convs, TIMING_DIR, max_examples=max_examples)


@app.function(image=image, cpu=CPUS, memory=32768, volumes={VOLUME_PATH: volume}, timeout=4 * 3600)
def score_remote(convs: list[dict]) -> list[list[float]]:
    volume.reload()
    return _score(convs, ADAPTER_DIR)


@app.function(image=image, cpu=CPUS, memory=32768, volumes={VOLUME_PATH: volume}, timeout=12 * 3600)
def pipeline_remote(train_convs: list[dict], val_convs: list[dict]) -> dict:
    """Train, choose the threshold on held-out data, and save it all: entirely in the cloud.

    Started with ``.spawn()`` on the deployed app, so it finishes even if the
    machine that started it goes offline.
    """
    stats = _train(train_convs, ADAPTER_DIR)
    meta = {**choose_threshold(val_convs, _score(val_convs, ADAPTER_DIR)), "training": stats}
    Path(META_PATH).write_text(json.dumps(meta, indent=2))
    volume.commit()
    return meta


@app.cls(image=image.env({"HF_HOME": f"{VOLUME_PATH}/hf"}), cpu=8, memory=16384, volumes={VOLUME_PATH: volume},
         scaledown_window=600, timeout=600)
class SentinelService:
    """The live service: P(scam) for a call so far, one prompt at a time (~1 s warm on 8 CPUs).

    The model loads once per container; containers stay warm for 10 minutes after the
    last call, and callers warm one up when a call starts.
    """

    @modal.enter()
    def load(self) -> None:
        import os

        import torch
        from peft import PeftModel
        from transformers import AutoModelForCausalLM, AutoTokenizer

        torch.set_num_threads(8)
        cached = os.path.isdir(f"{VOLUME_PATH}/hf")
        self.torch = torch
        self.tok = AutoTokenizer.from_pretrained(ADAPTER_DIR)
        base = AutoModelForCausalLM.from_pretrained(BASE_MODEL, torch_dtype=torch.float32)
        self.model = PeftModel.from_pretrained(base, ADAPTER_DIR).eval()
        self.ids = [self.tok(w, add_special_tokens=False).input_ids[0] for w in (" scam", " safe")]
        if not cached:
            volume.commit()  # keep the base weights on the volume: later cold starts skip the download

    @modal.method()
    def score(self, turns: list[list[str]]) -> float:
        enc = self.tok(prompt(turns), return_tensors="pt", truncation=True, max_length=480)
        with self.torch.no_grad():
            logits = self.model(**enc).logits[0, -1, :].float()
        return round(self.torch.softmax(logits[self.ids], dim=-1)[0].item(), 4)

    @modal.method()
    def ping(self) -> bool:
        return True


def _convs(split: str) -> list[dict]:
    import sys

    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from eval.run_external import load

    return [{"source": c.source, "kind": c.kind, "is_scam": c.is_scam, "turns": [list(t) for t in c.turns]} for c in load(split=split)]


def score_parallel(convs: list[dict], workers: int = 8) -> list[list[float]]:
    """Score conversations across several CPU containers at once."""
    chunks = [convs[i::workers] for i in range(workers)]
    results = list(score_remote.map(chunks))
    out: list[list[float]] = [[] for _ in convs]
    for w, scores in enumerate(results):
        for j, s in enumerate(scores):
            out[w + j * workers] = s
    return out


@app.local_entrypoint()
def timing() -> None:
    """A short run to measure seconds per training step on CPU."""
    print(train_remote.remote(_convs("train")[:40], max_examples=64))


@app.local_entrypoint()
def launch() -> None:
    """Start the full pipeline on the *deployed* app (``modal deploy modal_app/sentinel.py`` first)."""
    convs = _convs("train")
    random.Random(1).shuffle(convs)
    val = convs[:128]  # held out from training: used only to choose the alarm threshold (see val_convs)
    pipeline = modal.Function.from_name("tripwire-sentinel", "pipeline_remote")
    call = pipeline.spawn(convs[128:], val)
    print(f"started: {call.object_id}")


@app.local_entrypoint()
def fetch() -> None:
    """Copy the threshold chosen in the cloud into eval/results."""
    meta = json.loads(b"".join(volume.read_file("sentinel-meta.json")))
    out = Path(__file__).resolve().parent.parent / "eval" / "results" / "sentinel_threshold.json"
    out.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(meta)


def conv_key(turns: list) -> str:
    """A stable id for a conversation, shared with the eval harness."""
    import hashlib

    return hashlib.sha1(json.dumps([list(t) for t in turns]).encode("utf-8")).hexdigest()[:16]


def val_convs() -> list[dict]:
    """The 128 training-split calls held out from training (same shuffle as ``launch``)."""
    convs = _convs("train")
    random.Random(1).shuffle(convs)
    return convs[:128]


@app.local_entrypoint()
def export_scores() -> None:
    """P(scam) after every turn, for the held-out validation calls and the test split.

    Scoring is deterministic, so the eval harness can replay these exactly as the
    live service would return them, without calling Modal once per turn.
    """
    convs = val_convs() + _convs("test")
    scores = score_parallel(convs)
    out = {conv_key(c["turns"]): [round(p, 4) for p in sc] for c, sc in zip(convs, scores)}
    path = Path(__file__).resolve().parent.parent / "eval" / "results" / "sentinel_scores.json"
    path.write_text(json.dumps(out), encoding="utf-8")
    print(f"{len(out)} conversations scored")


@app.local_entrypoint()
def evaluate() -> None:
    root = Path(__file__).resolve().parent.parent
    threshold = json.loads((root / "eval" / "results" / "sentinel_threshold.json").read_text())["threshold"]
    convs = _convs("test")
    scores = score_parallel(convs)
    runs = []
    for c, s in zip(convs, scores):
        stop = next((i + 1 for i, p in enumerate(s) if p >= threshold), None)
        runs.append({"source": c["source"], "kind": c["kind"], "is_scam": c["is_scam"], "turns": len(s), "flag_turn": stop,
                     "flag_fraction": round(stop / len(s), 2) if stop else None, "max_p": max(s)})

    def rate(xs):
        return round(sum(xs) / len(xs), 3) if xs else None

    summary = {"threshold": threshold}
    for name, sel in (("youtube_real", "youtube"), ("dialogue", "dialogue")):
        rs = [r for r in runs if r["source"] == sel]
        scam, legit = [r for r in rs if r["is_scam"]], [r for r in rs if not r["is_scam"]]
        fr = sorted(r["flag_fraction"] for r in scam if r["flag_fraction"] is not None)
        summary[name] = {"scam": len(scam), "benign": len(legit), "detection_rate": rate([r["flag_turn"] is not None for r in scam]),
                         "false_alarm_rate": rate([r["flag_turn"] is not None for r in legit]),
                         "median_flag_fraction": fr[len(fr) // 2] if fr else None}
    (root / "eval" / "results" / "sentinel.json").write_text(json.dumps({"summary": summary, "runs": runs}, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))
