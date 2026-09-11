from __future__ import annotations

import json
import os
import time
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

class Telemetry:
    def __init__(self, path: Path | None = None):
        self.path = path or Path(os.getenv("GITOPSMEDIC_RUN_LOG", ".gitops-medic/runs.jsonl"))
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._tracer = None
        if os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT"):
            try:
                from opentelemetry import trace
                from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
                from opentelemetry.sdk.resources import Resource
                from opentelemetry.sdk.trace import TracerProvider
                from opentelemetry.sdk.trace.export import BatchSpanProcessor
                provider = TracerProvider(resource=Resource.create({"service.name": "gitops-medic"}))
                provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
                trace.set_tracer_provider(provider)
                self._tracer = trace.get_tracer("gitops-medic")
            except Exception:
                self._tracer = None

    def event(self, name: str, **attrs):
        record = {"ts": datetime.now(timezone.utc).isoformat(), "event": name, **attrs}
        with self.path.open("a", encoding="utf-8") as f:
            f.write(json.dumps(record, sort_keys=True) + "\n")

    @contextmanager
    def span(self, name: str, **attrs):
        start = time.perf_counter()
        otel_cm = self._tracer.start_as_current_span(name) if self._tracer else None
        span = otel_cm.__enter__() if otel_cm else None
        try:
            if span:
                for k, v in attrs.items():
                    span.set_attribute(k, str(v))
            yield
            status = "PASS"
        except Exception:
            status = "FAIL"
            raise
        finally:
            if otel_cm:
                otel_cm.__exit__(None, None, None)
            self.event(name, status=status, duration_ms=round((time.perf_counter()-start)*1000, 2), **attrs)
