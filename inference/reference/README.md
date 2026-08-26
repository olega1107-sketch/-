# Internal inference reference

This service is the protected boundary between Agent Gateway and the local
`llama.cpp` runtime. It exposes only the Dirizhor `/v1/generate` protocol over
TLS 1.3 with mutual TLS and bearer authentication. The model runtime listens on
Pod loopback and has no direct Service or network egress.

Pilot model selection:

- model: `Qwen3-4B-GGUF`, `Q4_K_M`;
- model revision: `bc640142c66e1fdd12af0bd68f40445458f3869b`;
- GGUF SHA-256: `7485fe6f11af29433bc51cab58009521f205840f5b4ae3a32fa7f92e8534fdf5`;
- runtime image: `ghcr.io/ggml-org/llama.cpp:server@sha256:db8e923e6edc9241ad788979af79543a1e1ba55dbb7d41e62490ef0d0ad3c8e7`.

The model image is assembled during the protected OCI release. BuildKit checks
the GGUF digest before the layer is accepted. Runtime starts with `--offline`;
the Pod policy denies all egress.
