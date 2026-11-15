FROM python:3.12-slim
WORKDIR /app
ENV OTEL_SDK_DISABLED=true
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY contracts/ ./contracts/
COPY agentcore_runtime/ ./agentcore_runtime/
USER 1000:1000
EXPOSE 8080
CMD ["python", "-m", "agentcore_runtime.http_server"]