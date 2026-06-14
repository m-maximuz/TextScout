# Text OSINT AI demo — Docker Space (CPU). Runs the Streamlit app.
# For a GPU Space, swap the base for an NVIDIA CUDA image (e.g.
# nvidia/cuda:12.4.1-runtime-ubuntu22.04 + python), install bitsandbytes,
# and the app's USE_GPU path loads the 4-bit base automatically.
FROM python:3.12-slim

# curl is used by the Streamlit healthcheck below
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

# Non-root user (HF Spaces best practice — keeps the HF model cache writable)
RUN useradd -m -u 1000 user
USER user
ENV HOME=/home/user \
    PATH=/home/user/.local/bin:$PATH \
    HF_HOME=/home/user/.cache/huggingface

WORKDIR $HOME/app

COPY --chown=user requirements.txt ./
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

COPY --chown=user . .

EXPOSE 8501
HEALTHCHECK CMD curl --fail http://localhost:8501/_stcore/health || exit 1

ENTRYPOINT ["streamlit", "run", "app.py", \
            "--server.port=8501", "--server.address=0.0.0.0", \
            "--server.headless=true"]
