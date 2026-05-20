"""Push MODEL_CARD.md to Maximuz23/Text-OSINT on HuggingFace.

Run from anywhere with HF_TOKEN set:
    export HF_TOKEN=hf_xxxxx
    python scripts/push_model_card.py

Or on Kaggle (token comes from Kaggle Secrets):
    from kaggle_secrets import UserSecretsClient
    os.environ["HF_TOKEN"] = UserSecretsClient().get_secret("HF_TOKEN")
    !python scripts/push_model_card.py
"""

import os
from pathlib import Path
from huggingface_hub import HfApi

REPO_ID = "Maximuz23/Text-OSINT"
CARD_PATH = Path(__file__).parent.parent / "MODEL_CARD.md"

token = os.environ.get("HF_TOKEN")
if not token:
    raise SystemExit("HF_TOKEN not set in environment")

if not CARD_PATH.exists():
    raise SystemExit(f"Card file missing: {CARD_PATH}")

api = HfApi(token=token)
api.upload_file(
    path_or_fileobj=str(CARD_PATH),
    path_in_repo="README.md",
    repo_id=REPO_ID,
    repo_type="model",
    commit_message="Update model card for v2.3 (CC BY-SA 3.0, Wikipedia attribution)",
)
print(f"Pushed MODEL_CARD.md to {REPO_ID} as README.md")
