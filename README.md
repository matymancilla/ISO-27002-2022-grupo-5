# Laboratorio ISO/IEC 27002:2022 - Grupo 5

**Proyecto:** Implementación y Auditoría de Controles Tecnológicos (8.1, 8.2, 8.8 y 8.9)  
**Caso de Estudio:** Seguridad en la Nube Universitaria  
**Autora:** Maty Mancilla  

## Contenido del Repositorio

- `schema_and_audit.sql`: Esquema de base de datos en PostgreSQL (`users`, `roles`, `user_roles`, `access_logs`, `assets`, `vulnerabilities`, `incidents`, `events`, `students`), carga de datos de prueba y consultas de auditoría para el Control 8.2 (privilegios excesivos y revisión de accesos permitidos/denegados).
- `security_controls_eval.py`: Script en Python para la evaluación del Control 8.1 (cifrado en endpoints), Control 8.8 (priorización de vulnerabilidades por severidad y exposición) y Control 8.9 (comparación de configuración contra línea base segura).
- `REPORTE_EVIDENCIA_LABORATORIO.md`: Documentación de fichas técnicas (5 atributos del apartado 27), pruebas realizadas, resultados, medición de eficacia, brechas, mejoras y matrices de riesgos y evaluación.
- `block-01/` y `block-02/`: Entregables organizados por bloque de trabajo.

## Instrucciones de Ejecución

Para ejecutar las pruebas de los controles en Python:

```bash
python3 security_controls_eval.py
```

Para cargar el esquema y ejecutar las consultas de auditoría en PostgreSQL:

```bash
psql -U postgres -d nube_universitaria -f schema_and_audit.sql
```
