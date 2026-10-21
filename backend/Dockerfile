# ==========================================
# ETAPA 1: Compilar el código de Go
# ==========================================
FROM golang:1.21-alpine AS builder

WORKDIR /app/go_worker

# Copiar archivos de Go y compilarlos
COPY go_worker/go.mod go_worker/go.sum ./
RUN go mod download
COPY go_worker/ ./
# Compilamos los archivos de Go
RUN go build -o enc_bin enc.go && go build -o desc_bin desc.go

# ==========================================
# ETAPA 2: Crear la imagen de Python
# ==========================================
FROM python:3.11-slim

WORKDIR /app

# Instalar dependencias del sistema
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copiar e instalar requerimientos de Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# ✅ CORREGIDO: Instalamos gunicorn, gevent y gevent-websocket
RUN pip install gunicorn gevent gevent-websocket

# Copiar el resto del proyecto
COPY . .

# Copiar los binarios compilados de Go desde la ETAPA 1
COPY --from=builder /app/go_worker/enc_bin /app/go_worker/enc_bin
COPY --from=builder /app/go_worker/desc_bin /app/go_worker/desc_bin
RUN chmod +x /app/go_worker/enc_bin /app/go_worker/desc_bin

# Exponer el puerto
EXPOSE 5000

# Comando de producción (Gunicorn con Gevent para SocketIO)
CMD ["gunicorn", "-k", "geventwebsocket.gunicorn.workers.GeventWebSocketWorker", "-w", "1", "--bind", "0.0.0.0:5000", "app.run:app"]