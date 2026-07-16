FROM ghcr.io/astral-sh/uv:0.11.8@sha256:3b7b60a81d3c57ef471703e5c83fd4aaa33abcd403596fb22ab07db85ae91347 AS uv

FROM python:3.14-slim-bookworm@sha256:86f975aca15cf04a40b399eebede9aea7c82eae084d1f1a0a6ef6bcaae871a30 AS builder

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

FROM python:3.14-slim-bookworm@sha256:86f975aca15cf04a40b399eebede9aea7c82eae084d1f1a0a6ef6bcaae871a30 AS runtime

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
