package observability

import (
	"context"
	"fmt"
	"os"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

const serviceNameEnv = "SERVICE_NAME"

func InitTracing(ctx context.Context) (func(context.Context) error, error) {
	svcName := os.Getenv(serviceNameEnv)
	if svcName == "" {
		svcName = "api-failure-analyzer"
	}

	opts := []otlptracehttp.Option{}
	if endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"); endpoint != "" {
		sanitized, useInsecure := normalizeOTLPEndpoint(endpoint)
		opts = append(opts, otlptracehttp.WithEndpoint(sanitized))
		if useInsecure {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
	} else {
		opts = append(opts, otlptracehttp.WithEndpoint("localhost:4318"),
			otlptracehttp.WithInsecure(),
		)
	}

	exporter, err := otlptracehttp.New(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("create otlp trace exporter: %w", &err)
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(svcName),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("build otel resource: %w", &err)
	}

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	return tp.Shutdown, nil
}

func Tracer(name string) trace.Tracer {
	return otel.Tracer(name)
}

func normalizeOTLPEndpoint(raw string) (string, bool) {
	endpoint := strings.TrimSpace(raw)
	if endpoint == "" {
		return "localhost:4318", true
	}

	if strings.HasPrefix(endpoint, "http://") {
		return strings.TrimPrefix(endpoint, "http://"), true
	}

	if strings.HasPrefix(endpoint, "https://") {
		return strings.TrimPrefix(endpoint, "https://"), false
	}

	return endpoint, false
}
