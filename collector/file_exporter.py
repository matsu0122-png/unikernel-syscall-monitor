"""Span exporter writing one JSON object per span (collector --otel file).

For offline checks of the trace grouping without a running Jaeger.
"""

import json

from opentelemetry.sdk.trace.export import SpanExporter, SpanExportResult


class JsonLinesSpanExporter(SpanExporter):
    def __init__(self, path):
        self.f = open(path, "w", buffering=1)

    def export(self, spans):
        for s in spans:
            ctx = s.get_span_context()
            self.f.write(json.dumps({
                "name": s.name,
                "trace_id": f"{ctx.trace_id:032x}",
                "span_id": f"{ctx.span_id:016x}",
                "parent_id": f"{s.parent.span_id:016x}" if s.parent else None,
                "start_ns": s.start_time,
                "end_ns": s.end_time,
                "status": s.status.status_code.name,
                "attributes": dict(s.attributes or {}),
            }) + "\n")
        return SpanExportResult.SUCCESS

    def shutdown(self):
        self.f.close()
