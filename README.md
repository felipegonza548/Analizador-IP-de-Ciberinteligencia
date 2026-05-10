cat > README.md << 'EOF'
# Analizador-IP-de-ciberinteligencia

Herramienta de Threat Intelligence desarrollada en Python para automatizar el análisis y enriquecimiento de direcciones IP, generando reportes estructurados en JSON y HTML orientados a entornos Blue Team y automatización SOC.

---

## Descripción

Este proyecto permite analizar direcciones IP públicas mediante consultas OSINT, obteniendo información relevante como:

- País
- Región
- Ciudad
- ASN
- ISP
- Organización
- Timezone
- Clasificación inicial de riesgo

Además, la herramienta genera reportes automáticos en:

- JSON
- HTML

---

## Tecnologías utilizadas

- Python 3
- Requests
- Colorama
- JSON
- HTML
- Linux (Kali Linux)

---

## Funcionalidades

- Enriquecimiento de IOC IP
- Clasificación básica de riesgo
- Exportación JSON
- Generación de reportes HTML
- Automatización de análisis
- Interfaz CLI profesional
- Detección de IPs privadas y especiales

---

## Ejecución

```bash
python3 analyzer.py
