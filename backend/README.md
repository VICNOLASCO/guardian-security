<div align="center">

# 🛡️ GUARDIAN · Digital Security

**Centro de comando y gestión segura para equipos remotos.**

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-3.0-green.svg)](https://flask.palletsprojects.com)
[![MongoDB](https://img.shields.io/badge/MongoDB-7.0-green.svg)](https://mongodb.com)
[![Docker](https://img.shields.io/badge/Docker-enabled-blue.svg)](https://docker.com)
[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8.svg)](https://go.dev)

</div>

---

## 📖 Descripción

**Guardian** es un sistema de administración remota y ciberseguridad desarrollado para entornos de alta exigencia. Permite cifrar archivos con AES-256, conectarse por SSH a servidores remotos, monitorear actividad en tiempo real y visualizar estadísticas 3D.

## ✨ Características Principales

- 🔐 **Cifrado AES-256**: Protección de archivos individuales y carpetas completas con clave maestra.
- 🖥️ **Terminal SSH Interactiva**: Conexión remota y ejecución de comandos en tiempo real.
- 📊 **Dashboard 3D**: Visualización de datos con ECharts GL.
- 👥 **Gestión de Usuarios**: Sistema de roles (Admin/User) con autenticación JWT.
- 🐳 **Dockerizado**: Despliegue rápido con un solo comando.
- 📍 **Geolocalización**: Registro de ubicación de accesos.

## 🚀 Tecnologías Utilizadas

- **Backend**: Python (Flask), Go (Módulos de cifrado), MongoDB, Socket.IO, JWT, Bcrypt.
- **Frontend**: HTML5, Vanilla JS, Leaflet, ECharts.
- **DevOps**: Docker, Docker Compose, Ngrok.

## 🛠️ Instalación y Uso

### Opción 1: Con Docker (Recomendado)

1. Clona el repositorio:
   ```bash
   git clone https://github.com/tu-usuario/guardian.git
   cd guardian/backend