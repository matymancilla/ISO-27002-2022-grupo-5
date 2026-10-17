# Reporte de Laboratorio: Controles Tecnológicos ISO/IEC 27002:2022
**Caso de Estudio:** Seguridad en la Nube Universitaria (5,000 estudiantes, infraestructura virtualizada)  
**Grupo:** Grupo 5  
**Autora:** Maty Mancilla  
**Controles Evaluados:** 8.2 (Derechos de acceso privilegiado), 8.8 (Gestión de vulnerabilidades técnicas), 8.9 (Gestión de la configuración) y 8.1 (Dispositivos de usuario final).

---

## 1. Fichas de Controles y Análisis de los Cinco Atributos (Apartado 27)

### Control 8.2: Derechos de acceso privilegiado
**Objetivo:** Restringir y gestionar la asignación y uso de derechos de acceso privilegiado bajo el principio de mínimo privilegio y segregación de funciones.

| Atributo ISO/IEC 27002:2022 | Valor | Aplicación en el Caso de Estudio |
| :--- | :--- | :--- |
| **Tipo de control** | Preventivo | Restringe la asignación de permisos antes de que ocurra un uso indebido de cuentas administrativas. |
| **Propiedades de seguridad** | Confidencialidad, Integridad, Disponibilidad | Protege los registros de calificaciones, datos personales de 5,000 alumnos y la infraestructura virtualizada. |
| **Conceptos de ciberseguridad** | Proteger (Protect) | Aplicación de control de acceso basado en roles (RBAC) y revisión de privilegios. |
| **Capacidades operativas** | Gestión de identidad y acceso | Control sobre el alta, modificación, revisión periódica y baja de roles privilegiados. |
| **Dominios de seguridad** | Protección | Resguardo de las cuentas administrativas que operan la nube universitaria y las bases de datos. |

---

### Control 8.8: Gestión de vulnerabilidades técnicas
**Objetivo:** Obtener información oportuna sobre vulnerabilidades técnicas, evaluar la exposición institucional y ejecutar acciones de mitigación o parchado.

| Atributo ISO/IEC 27002:2022 | Valor | Aplicación en el Caso de Estudio |
| :--- | :--- | :--- |
| **Tipo de control** | Preventivo | Identifica y prioriza la corrección de fallas técnicas antes de su explotación. |
| **Propiedades de seguridad** | Confidencialidad, Integridad, Disponibilidad | Previene ejecución remota de código (RCE), extracción de bases de datos e interrupción de servicios web. |
| **Conceptos de ciberseguridad** | Identificar (Identify), Proteger (Protect) | Identifica activos vulnerables expuestos y prioriza su remediación según el nivel de riesgo. |
| **Capacidades operativas** | Gestión de vulnerabilidades técnicas | Evaluación combinada de severidad CVSS, exposición a Internet y disponibilidad de exploits. |
| **Dominios de seguridad** | Defensa, Protección | Disminución de la superficie de ataque en servidores perimetrales e internos. |

---

### Control 8.9: Gestión de la configuración
**Objetivo:** Establecer, documentar, implementar, monitorear y revisar las configuraciones de seguridad en hardware, software, servicios y redes.

| Atributo ISO/IEC 27002:2022 | Valor | Aplicación en el Caso de Estudio |
| :--- | :--- | :--- |
| **Tipo de control** | Preventivo, Detectivo | Define una línea base segura de endurecimiento y detecta desviaciones en los servidores. |
| **Propiedades de seguridad** | Confidencialidad, Integridad, Disponibilidad | Evita intrusiones derivadas de servicios mal configurados, puertos expuestos o cifrado débil. |
| **Conceptos de ciberseguridad** | Proteger (Protect), Detectar (Detect) | Asegura la configuración base y detecta cambios no autorizados en los parámetros de operación. |
| **Capacidades operativas** | Seguridad de sistemas y red, Gestión de activos | Verificación de parámetros en SSH, TLS, firewall local, auditoría y puertos abiertos. |
| **Dominios de seguridad** | Protección, Defensa | Mantenimiento de configuraciones homogéneas y seguras en los servidores universitarios. |

---

## 2. Esquema de Base de Datos Compartido (`schema_and_audit.sql`)

Se implementó el esquema relacional en PostgreSQL con las 9 tablas requeridas para las pruebas del grupo:
1. `users`: Registro de personal administrativo, docente, soporte y auditoría.
2. `roles`: Catálogo de roles con niveles `LOW`, `MEDIUM`, `HIGH` y `CRITICAL`.
3. `user_roles`: Relación de roles asignados por usuario y fuente de autorización.
4. `assets`: Inventario de servidores, bases de datos, endpoints y equipos de red.
5. `access_logs`: Bitácora de intentos de acceso permitidos (`ALLOWED`) y denegados (`DENIED`).
6. `vulnerabilities`: Registro de CVEs asociados a los activos del inventario.
7. `incidents`: Registro de incidentes de seguridad detectados.
8. `events`: Eventos técnicos recolectados de sistemas de monitoreo.
9. `students`: Tabla de estudiantes con matrícula, carrera, semestre, promedio y estado financiero.

---

## 3. Pruebas, Resultados, Interpretación, Eficacia, Brechas y Mejoras

### 3.1 Control 8.2: Derechos de acceso privilegiado (`schema_and_audit.sql`)

* **Prueba realizada:**
  - Consulta analítica (` HAVING COUNT(ur.role_id) > 3`) para identificar usuarios con acumulación excesiva de roles.
  - Consulta sobre `access_logs` para verificar el bloqueo de accesos no autorizados (`DENIED`) y revisar los accesos permitidos (`ALLOWED`).
* **Resultado:**
  - Se detectó que el usuario `cmendoza` (Carlos Mendoza, TI) tiene **5 roles asignados** (`ROLE_HYPERVISOR_ADMIN`, `ROLE_DB_SYSADMIN`, `ROLE_DOMAIN_ADMIN`, `ROLE_FINANCE_OPERATOR`, `ROLE_GRADES_EDITOR`), dos de ellos originados por tickets de soporte temporal no revocados.
  - En `access_logs`, se comprobaron 3 accesos denegados correctamente por la política RBAC y 1 acceso permitido indebido donde `cmendoza` modificó un registro de calificaciones (`ALTER_STUDENT_GRADE_RECORD`) usando el rol residual.
* **Interpretación:** El control RBAC bloquea correctamente a usuarios sin permisos, pero existe acumulación de privilegios en cuentas de TI por falta de revocación oportuna de permisos temporales.
* **Medición de eficacia:**
  - Cumplimiento de mínimo privilegio en cuentas activas: **83.33%** (5 de 6 usuarios dentro del umbral).
  - Bloqueo de intentos sin rol asignado: **100%** (3 de 3 intentos denegados).
* **Brechas y mejoras:** Falta de caducidad automática en asignaciones temporales y uso de una misma cuenta para funciones técnicas y administrativas. Se requiere implementar cuentas separadas para administración y caducidad automática de permisos temporales.

---

### 3.2 Control 8.8: Gestión de vulnerabilidades técnicas (`security_controls_eval.py`)

* **Prueba realizada:** Ejecución de la función `prioritize_vulnerabilities_control_8_8()` que calcula un puntaje contextual combinando severidad, CVSS ($\times 1.5$), exposición a Internet ($+30$ puntos) y disponibilidad de exploit ($+15$ puntos).
* **Resultado:**
  1. `CVE-2024-21762` en `gw-vpn-campus.nubeuni.local` (CRITICAL, CVSS 9.8, Expuesto a Internet) $\rightarrow$ **99.70/100 (SLA P1 < 24h)**.
  2. `CVE-2023-38545` en `srv-lms-moodle-01.nubeuni.local` (CRITICAL, CVSS 9.8, Expuesto a Internet) $\rightarrow$ **84.70/100 (SLA P2 < 72h)**.
  3. `CVE-2023-44487` en `srv-portal-web-01.nubeuni.local` (HIGH, CVSS 7.5, Expuesto a Internet) $\rightarrow$ **81.25/100 (SLA P2 < 72h)**.
  4. `CVE-2024-1086` en `db-academico-prod.nubeuni.local` (HIGH, CVSS 7.8, Red Interna) $\rightarrow$ **51.70/100 (SLA P3 < 7 días)**.
  5. `CVE-2024-30088` en `lap-rectoria-04.nubeuni.local` (HIGH, CVSS 7.0, Red Interna) $\rightarrow$ **35.50/100 (SLA P4 < 30 días)**.
* **Interpretación:** Al considerar la exposición a Internet, la vulnerabilidad del Portal Web (`CVSS 7.5`, expuesta) recibe mayor prioridad (`81.25`) que la vulnerabilidad de la base de datos interna (`CVSS 7.8`, en red privada con `51.70`), optimizando el orden de parchado.
* **Medición de eficacia:** **100%** de las vulnerabilidades en activos expuestos a Internet fueron clasificadas dentro de los niveles de atención prioritaria P1 y P2 (< 72 horas).
* **Brechas y mejoras:** Presencia de vulnerabilidades críticas abiertas en equipos perimetrales. Se recomienda automatizar la aplicación de parches y aplicar reglas de mitigación en el WAF.

---

### 3.3 Control 8.9: Gestión de la configuración (`security_controls_eval.py`)

* **Prueba realizada:** Comparación de 8 parámetros de configuración en 3 servidores del laboratorio frente a la configuración segura de referencia (`SECURE_BASELINE_CONFIG`) mediante la función `evaluate_configuration_drift_control_8_9()`.
* **Resultado:**
  - Cumplimiento global respecto a la línea base: **62.5%** (**37.5%** de desviación).
  - `srv-portal-web-01.nubeuni.local`: **37.5%** de cumplimiento (5 desviaciones: `ssh_permit_root_login: True`, autenticación por contraseña activa, `TLSv1.2`, actualizaciones automáticas desactivadas y puertos `[22, 80, 443, 8080]` abiertos).
  - `db-academico-prod.nubeuni.local`: **50.0%** de cumplimiento (4 desviaciones: firewall local desactivado, escucha en todas las IPs, `auditd` inactivo y puerto `5432` expuesto).
  - `srv-lms-moodle-01.nubeuni.local`: **100.0%** de cumplimiento (sin desviaciones).
* **Interpretación:** Existen modificaciones manuales en los servidores web y de base de datos que se apartan de la configuración segura establecida.
* **Medición de eficacia:** Índice de cumplimiento de configuración segura del **62.5%** frente a la meta del 95%. (Complementariamente, en el Control 8.1 se obtuvo un **60.0%** de cumplimiento de cifrado en endpoints al detectar 2 portátiles sin cifrado activo).
* **Brechas y mejoras:** Falta de control automatizado de cambios en servidores. Se recomienda aplicar plantillas de configuración con herramientas como Ansible para corregir desviaciones de forma programada.

---

## 4. Matrices de Riesgos y de Evaluación

### 4.1 Matriz de Riesgos

| ID | Activo | Amenaza | Vulnerabilidad | Probabilidad (1-5) | Impacto (1-5) | Riesgo Inherente | Control ISO 27002:2022 | Prob. Residual | Imp. Residual | Riesgo Residual | Tratamiento |
| :---: | :--- | :--- | :--- | :---: | :---: | :---: | :--- | :---: | :---: | :---: | :--- |
| **R-01** | `db-academico-prod` / Directorio IAM | Modificación no autorizada de calificaciones o información financiera por abuso de cuenta privilegiada | Acumulación de 5 roles en el usuario `cmendoza` sin segregación de funciones | 4 | 5 | **20 (Extremo)** | **Control 8.2:** Derechos de acceso privilegiado | 2 | 4 | **8 (Medio)** | Mitigar |
| **R-02** | `gw-vpn-campus` / `srv-portal-web-01` | Ejecución remota de código (RCE) o interrupción de servicio desde Internet | Vulnerabilidades críticas y altas abiertas en servicios expuestos (`CVE-2024-21762`, `CVE-2023-44487`) | 5 | 5 | **25 (Extremo)** | **Control 8.8:** Gestión de vulnerabilidades técnicas | 2 | 4 | **8 (Medio)** | Mitigar |
| **R-03** | `srv-portal-web-01` / `db-academico-prod` | Acceso por fuerza bruta SSH a cuenta root y conexión directa al motor de base de datos | Desviación de configuración del 37.5% respecto a la línea base segura | 4 | 4 | **16 (Alto)** | **Control 8.9:** Gestión de la configuración | 1 | 4 | **4 (Bajo)** | Mitigar |
| **R-04** | `lap-rectoria-04` / `lap-finanzas-02` | Exposición de información institucional por robo o extravío de equipos portátiles | Almacenamiento sin cifrado de disco activo (`disk_encrypted: False`) | 4 | 4 | **16 (Alto)** | **Control 8.1:** Dispositivos de usuario final | 1 | 3 | **3 (Bajo)** | Mitigar |

---

### 4.2 Matriz de Evaluación de Controles

| Control ISO/IEC 27002:2022 | Archivo de Prueba | Indicador / Métrica | Resultado Obtenido | Meta | Estado de Cumplimiento | Acción de Mejora |
| :--- | :--- | :--- | :---: | :---: | :--- | :--- |
| **8.2 Derechos de acceso privilegiado** | `schema_and_audit.sql` | % de usuarios activos dentro del límite de roles ($\le 3$) y bloqueo de accesos no autorizados | 83.33% en límite de roles; 100% de bloqueos RBAC en intentos sin permiso | 100% | Parcialmente Conforme | Revocar roles `ROLE_FINANCE_OPERATOR` y `ROLE_GRADES_EDITOR` en cuenta de TI y definir vigencia en permisos temporales. |
| **8.8 Gestión de vulnerabilidades técnicas** | `security_controls_eval.py` | Priorización de vulnerabilidades críticas/altas en activos expuestos a Internet | 100% de activos expuestos priorizados en niveles P1 y P2 (< 72h) | 100% | Conforme en diseño / Brecha en parchado | Aplicar parche prioritario en `gw-vpn-campus` (`CVE-2024-21762`) y `srv-lms-moodle-01`. |
| **8.9 Gestión de la configuración** | `security_controls_eval.py` | Índice de cumplimiento de línea base segura en servidores | 62.5% de cumplimiento (37.5% de desviación) | $\ge 95\%$ | No Conforme | Deshabilitar `ssh_permit_root_login`, activar firewall local en BD y cerrar puertos no requeridos. |
| **8.1 Dispositivos de usuario final** | `security_controls_eval.py` | Tasa de cumplimiento de cifrado de disco en endpoints (ECR) | 60.0% (3 de 5 equipos cifrados) | 100% | No Conforme | Activar BitLocker y agente EDR en `lap-rectoria-04` y `lap-finanzas-02`. |
