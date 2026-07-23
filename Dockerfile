FROM ghcr.io/astral-sh/uv:0.11.31@sha256:ecd4de2f060c64bea0ff8ecb182ddf46ba3fcccdc8a60cfdbaf20d1a047d7437 AS uv

FROM python:3.12-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b AS builder

COPY --from=uv /uv /uvx /bin/
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PROJECT_ENVIRONMENT=/opt/forgeward
WORKDIR /build
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
COPY templates ./templates
COPY skills ./skills
RUN uv sync --locked --no-dev --no-install-project \
    && uv build --wheel --out-dir /wheels \
    && uv pip install --python /opt/forgeward/bin/python --no-deps /wheels/*.whl

FROM python:3.12-slim-bookworm@sha256:d50fb7611f86d04a3b0471b46d7557818d88983fc3136726336b2a4c657aa30b AS runtime

ENV PATH=/opt/forgeward/bin:$PATH \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
RUN apt-get update \
    && apt-get install --yes --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 forgeward
COPY --from=builder /opt/forgeward /opt/forgeward
USER forgeward
WORKDIR /workspace
ENTRYPOINT ["forgeward"]
CMD ["--help"]
