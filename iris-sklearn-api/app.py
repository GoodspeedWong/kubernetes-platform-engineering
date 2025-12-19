# app.py
from fastapi import FastAPI
from pydantic import BaseModel, conlist
import joblib
import numpy as np
import os
from opentelemetry import trace
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

MODEL_PATH = "model.joblib"

app = FastAPI(title="Iris Sklearn Inference API")

# -------------------------
# OpenTelemetry 初始化（平台级模板）
# -------------------------
SERVICE_NAME = os.getenv("SERVICE_NAME", "iris-sklearn-api")
SERVICE_VERSION = os.getenv("SERVICE_VERSION", "v1.0.0")
DEPLOYMENT_ENV = os.getenv("DEPLOYMENT_ENVIRONMENT", "dev")
OTEL_EXPORTER_OTLP_ENDPOINT = os.getenv(
    "OTEL_EXPORTER_OTLP_ENDPOINT",
    "http://otel-gateway.monitoring:4318/v1/traces",
)

resource = Resource(
    attributes={
        "service.name": SERVICE_NAME,
        "service.version": SERVICE_VERSION,
        "deployment.environment": DEPLOYMENT_ENV,
    }
)

provider = TracerProvider(resource=resource)
processor = BatchSpanProcessor(
    OTLPSpanExporter(endpoint=OTEL_EXPORTER_OTLP_ENDPOINT)
)
provider.add_span_processor(processor)

trace.set_tracer_provider(provider)

# 显式将 TracerProvider 绑定给 FastAPI Instrumentor
FastAPIInstrumentor.instrument_app(
    app,
    tracer_provider=provider,
)

# 加载模型（实际生产可以加异常处理 / 热更新等）
model = joblib.load(MODEL_PATH)

tracer = trace.get_tracer(__name__)

class IrisInput(BaseModel):
    # 单个样本：4维特征
    features: conlist(float, min_length=4, max_length=4)

class IrisBatchInput(BaseModel):
    # 批量样本
    batch: list[conlist(float, min_length=4, max_length=4)]

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/predict")
def predict(input_data: IrisInput):
    with tracer.start_as_current_span("model.predict"):
        X = np.array(input_data.features).reshape(1, -1)
        pred = model.predict(X)[0]
        proba = model.predict_proba(X)[0].tolist()
    return {
        "prediction": int(pred),
        "probabilities": proba
    }

@app.post("/predict_batch")
def predict_batch(input_data: IrisBatchInput):
    with tracer.start_as_current_span("model.predict_batch"):
        X = np.array(input_data.batch)
        preds = model.predict(X).tolist()
        probas = model.predict_proba(X).tolist()
    return {
        "predictions": [int(p) for p in preds],
        "probabilities": probas
    }