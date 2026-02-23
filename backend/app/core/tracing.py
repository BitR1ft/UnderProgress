"""
OpenTelemetry distributed tracing configuration.
"""
import logging
import os
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

logger = logging.getLogger(__name__)


def configure_tracing(
    app=None,
    service_name: str = "autopentestai-api",
    service_version: str = "0.1.0",
) -> trace.Tracer:
    """
    Configure OpenTelemetry tracing.

    If OTEL_EXPORTER_OTLP_ENDPOINT is set, export to that collector endpoint.
    Otherwise fall back to the console exporter for local development.

    Args:
        app: FastAPI application instance (optional). When provided, auto-instruments it.
        service_name: Logical service name recorded in every span.
        service_version: Service version recorded in every span.

    Returns:
        A :class:`opentelemetry.trace.Tracer` for the given service name.
    """
    resource = Resource.create({
        SERVICE_NAME: service_name,
        SERVICE_VERSION: service_version,
    })

    provider = TracerProvider(resource=resource)

    otlp_endpoint = os.getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
    if otlp_endpoint:
        # Allow disabling TLS only when explicitly requested (never default in prod)
        insecure = os.getenv("OTEL_EXPORTER_OTLP_INSECURE", "false").lower() == "true"
        exporter = OTLPSpanExporter(endpoint=otlp_endpoint, insecure=insecure)
        logger.info("OpenTelemetry: exporting traces to OTLP endpoint %s (insecure=%s)", otlp_endpoint, insecure)
    else:
        exporter = ConsoleSpanExporter()
        logger.info("OpenTelemetry: exporting traces to console (no OTLP endpoint configured)")

    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

    if app is not None:
        FastAPIInstrumentor.instrument_app(app, tracer_provider=provider)
        logger.info("OpenTelemetry: FastAPI auto-instrumentation enabled")

    return trace.get_tracer(service_name)
