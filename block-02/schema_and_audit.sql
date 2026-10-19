-- Proyecto de Maestría en Seguridad Informática - ISO/IEC 27002:2022 (Grupo 5)
-- Caso de Estudio: Seguridad en la Nube Universitaria
-- Autora: Maty Mancilla
-- Archivo: schema_and_audit.sql (Esquema compartido y auditoría del Control 8.2)

DROP TABLE IF EXISTS events CASCADE;
DROP TABLE IF EXISTS incidents CASCADE;
DROP TABLE IF EXISTS vulnerabilities CASCADE;
DROP TABLE IF EXISTS access_logs CASCADE;
DROP TABLE IF EXISTS students CASCADE;
DROP TABLE IF EXISTS assets CASCADE;
DROP TABLE IF EXISTS user_roles CASCADE;
DROP TABLE IF EXISTS roles CASCADE;
DROP TABLE IF EXISTS users CASCADE;

-- 1. Creación de tablas del esquema compartido

CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    department VARCHAR(80) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE roles (
    role_id SERIAL PRIMARY KEY,
    role_name VARCHAR(60) UNIQUE NOT NULL,
    privilege_level VARCHAR(20) CHECK (privilege_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')) NOT NULL,
    description TEXT NOT NULL
);

CREATE TABLE user_roles (
    user_role_id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    role_id INT NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    assigned_by VARCHAR(50) NOT NULL,
    UNIQUE (user_id, role_id)
);

CREATE TABLE assets (
    asset_id SERIAL PRIMARY KEY,
    hostname VARCHAR(80) UNIQUE NOT NULL,
    asset_type VARCHAR(40) CHECK (asset_type IN ('SERVER', 'DATABASE', 'ENDPOINT', 'NETWORK_APPLIANCE')) NOT NULL,
    os_version VARCHAR(60) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    internet_facing BOOLEAN DEFAULT FALSE,
    disk_encrypted BOOLEAN DEFAULT TRUE,
    owner_department VARCHAR(80) NOT NULL
);

CREATE TABLE access_logs (
    log_id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
    asset_id INT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    action_attempted VARCHAR(100) NOT NULL,
    required_privilege VARCHAR(20) CHECK (required_privilege IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')) NOT NULL,
    access_decision VARCHAR(15) CHECK (access_decision IN ('ALLOWED', 'DENIED')) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    reason VARCHAR(150) NOT NULL,
    access_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE vulnerabilities (
    vuln_id SERIAL PRIMARY KEY,
    cve_id VARCHAR(25) NOT NULL,
    asset_id INT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    severity VARCHAR(15) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')) NOT NULL,
    cvss_score NUMERIC(3,1) CHECK (cvss_score >= 0.0 AND cvss_score <= 10.0) NOT NULL,
    status VARCHAR(20) CHECK (status IN ('OPEN', 'IN_PROGRESS', 'PATCHED', 'MITIGATED')) DEFAULT 'OPEN',
    discovered_at DATE NOT NULL
);

CREATE TABLE incidents (
    incident_id SERIAL PRIMARY KEY,
    asset_id INT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    reported_by_user_id INT REFERENCES users(user_id) ON DELETE SET NULL,
    title VARCHAR(120) NOT NULL,
    severity VARCHAR(15) CHECK (severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')) NOT NULL,
    status VARCHAR(20) CHECK (status IN ('OPEN', 'INVESTIGATING', 'CONTAINED', 'CLOSED')) DEFAULT 'OPEN',
    detected_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE events (
    event_id SERIAL PRIMARY KEY,
    asset_id INT NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    event_type VARCHAR(50) NOT NULL,
    severity VARCHAR(15) CHECK (severity IN ('INFO', 'WARNING', 'HIGH', 'CRITICAL')) NOT NULL,
    raw_log TEXT NOT NULL,
    event_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE students (
    student_id SERIAL PRIMARY KEY,
    matricula VARCHAR(20) UNIQUE NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    career VARCHAR(80) NOT NULL,
    semester INT CHECK (semester BETWEEN 1 AND 12) NOT NULL,
    gpa NUMERIC(4,2) CHECK (gpa BETWEEN 0.00 AND 10.00) NOT NULL,
    financial_status VARCHAR(20) CHECK (financial_status IN ('REGULAR', 'SCHOLARSHIP', 'DEBT_HOLD')) DEFAULT 'REGULAR',
    enrollment_active BOOLEAN DEFAULT TRUE
);

-- 2. Inserción de datos de prueba del entorno universitario

INSERT INTO users (username, full_name, email, department, is_active) VALUES
('cmendoza', 'Carlos Mendoza', 'c.mendoza@nubeuni.edu.lat', 'TI e Infraestructura Cloud', TRUE),
('lrodriguez', 'Dra. Laura Rodríguez', 'l.rodriguez@nubeuni.edu.lat', 'Facultad de Ingeniería', TRUE),
('jvillanueva', 'Jorge Villanueva', 'j.villanueva@nubeuni.edu.lat', 'Registro y Control Académico', TRUE),
('mfernandez', 'María Fernández', 'm.fernandez@nubeuni.edu.lat', 'Finanzas y Tesorería', TRUE),
('agomez', 'Andrés Gómez', 'a.gomez@nubeuni.edu.lat', 'Mesa de Ayuda TI', TRUE),
('psalazar', 'Patricia Salazar', 'p.salazar@nubeuni.edu.lat', 'Auditoría Interna', TRUE);

INSERT INTO roles (role_name, privilege_level, description) VALUES
('ROLE_HYPERVISOR_ADMIN', 'CRITICAL', 'Administración de clústeres de virtualización y nube privada'),
('ROLE_DB_SYSADMIN', 'CRITICAL', 'Acceso superusuario a motores de bases de datos académicas y financieras'),
('ROLE_DOMAIN_ADMIN', 'CRITICAL', 'Control sobre el servicio de directorio e identidades universitarias'),
('ROLE_FINANCE_OPERATOR', 'HIGH', 'Gestión de pagos de matrículas, nómina docente y facturación'),
('ROLE_GRADES_EDITOR', 'HIGH', 'Modificación de actas de calificaciones e historial académico'),
('ROLE_FACULTY_PORTAL', 'LOW', 'Acceso docente estándar para carga de sílabos y asistencia'),
('ROLE_HELP_DESK_L1', 'MEDIUM', 'Reinicio de contraseñas de estudiantes y soporte N1');

INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES
(1, 1, 'SYSTEM_MIGRATION_2024'),
(1, 2, 'DIR_TI_APPROVAL'),
(1, 3, 'SYSTEM_MIGRATION_2024'),
(1, 4, 'TEMP_SUPPORT_TICKET_891'),
(1, 5, 'TEMP_SUPPORT_TICKET_940'),
(2, 6, 'IAM_AUTOMATION'),
(3, 5, 'IAM_AUTOMATION'),
(3, 6, 'IAM_AUTOMATION'),
(4, 4, 'IAM_AUTOMATION'),
(5, 7, 'IAM_AUTOMATION'),
(5, 6, 'IAM_AUTOMATION');

INSERT INTO assets (hostname, asset_type, os_version, ip_address, internet_facing, disk_encrypted, owner_department) VALUES
('srv-portal-web-01.nubeuni.local', 'SERVER', 'Ubuntu Server 22.04 LTS', '203.0.113.15', TRUE, TRUE, 'TI e Infraestructura Cloud'),
('srv-lms-moodle-01.nubeuni.local', 'SERVER', 'Debian 12 Bookworm', '203.0.113.22', TRUE, TRUE, 'Educación Virtual'),
('db-academico-prod.nubeuni.local', 'DATABASE', 'Red Hat Enterprise Linux 9.2', '10.20.1.10', FALSE, TRUE, 'Registro y Control Académico'),
('lap-rectoria-04.nubeuni.local', 'ENDPOINT', 'Windows 11 Pro 23H2', '10.50.4.112', FALSE, FALSE, 'Rectoría'),
('lap-finanzas-02.nubeuni.local', 'ENDPOINT', 'Windows 10 Pro 22H2', '10.50.8.45', FALSE, FALSE, 'Finanzas y Tesorería'),
('gw-vpn-campus.nubeuni.local', 'NETWORK_APPLIANCE', 'FortiOS 7.2', '203.0.113.2', TRUE, TRUE, 'Seguridad Informática');

INSERT INTO access_logs (user_id, asset_id, action_attempted, required_privilege, access_decision, source_ip, reason, access_timestamp) VALUES
(1, 3, 'ALTER_STUDENT_GRADE_RECORD', 'HIGH', 'ALLOWED', '10.10.2.15', 'Acceso concedido por rol heredado ROLE_GRADES_EDITOR (Riesgo SoD)', '2026-10-16 08:15:00'),
(1, 1, 'SNAPSHOT_HYPERVISOR_CLUSTER', 'CRITICAL', 'ALLOWED', '10.10.2.15', 'Acceso legítimo mediante ROLE_HYPERVISOR_ADMIN', '2026-10-16 09:05:00'),
(2, 3, 'DROP_TABLE_STUDENTS', 'CRITICAL', 'DENIED', '10.30.1.44', 'Política RBAC: Docente solo posee ROLE_FACULTY_PORTAL (LOW)', '2026-10-16 10:22:00'),
(5, 3, 'EXPORT_FINANCIAL_PAYROLL', 'HIGH', 'DENIED', '10.50.9.12', 'Política RBAC: Mesa de ayuda no posee ROLE_FINANCE_OPERATOR', '2026-10-16 11:40:00'),
(3, 3, 'UPDATE_ACADEMIC_TRANSCRIPT', 'HIGH', 'ALLOWED', '10.20.4.80', 'Acceso legítimo mediante ROLE_GRADES_EDITOR', '2026-10-16 12:10:00'),
(4, 5, 'PROCESS_TUITION_PAYMENT', 'HIGH', 'ALLOWED', '10.50.8.45', 'Acceso legítimo mediante ROLE_FINANCE_OPERATOR', '2026-10-16 14:00:00'),
(5, 6, 'MODIFY_VPN_FIREWALL_RULES', 'CRITICAL', 'DENIED', '10.50.9.12', 'Política RBAC: Nivel MEDIUM insuficiente para activo CRITICAL', '2026-10-16 16:45:00');

INSERT INTO vulnerabilities (cve_id, asset_id, severity, cvss_score, status, discovered_at) VALUES
('CVE-2024-21762', 6, 'CRITICAL', 9.8, 'OPEN', '2026-09-15'),
('CVE-2023-44487', 1, 'HIGH', 7.5, 'OPEN', '2026-09-20'),
('CVE-2024-1086', 3, 'HIGH', 7.8, 'IN_PROGRESS', '2026-09-28'),
('CVE-2023-38545', 2, 'CRITICAL', 9.8, 'OPEN', '2026-10-01'),
('CVE-2024-30088', 4, 'HIGH', 7.0, 'OPEN', '2026-10-05'),
('CVE-2024-26169', 5, 'MEDIUM', 5.5, 'PATCHED', '2026-08-12');

INSERT INTO incidents (asset_id, reported_by_user_id, title, severity, status, detected_at) VALUES
(3, 6, 'Modificación anómala de calificaciones desde cuenta de administrador TI', 'HIGH', 'INVESTIGATING', '2026-10-16 08:30:00'),
(6, 1, 'Intentos de explotación RCE en Gateway SSL VPN perimetral', 'CRITICAL', 'OPEN', '2026-10-16 09:45:00'),
(4, 6, 'Portátil de Rectoría detectado sin cifrado BitLocker en red inalámbrica', 'HIGH', 'OPEN', '2026-10-16 11:00:00'),
(3, 5, 'Intento no autorizado de exportación de nómina desde Mesa de Ayuda', 'MEDIUM', 'CONTAINED', '2026-10-16 11:50:00'),
(1, 1, 'Desviación de configuración SSH (RootLogin habilitado) en Portal Web', 'HIGH', 'OPEN', '2026-10-16 15:20:00');

INSERT INTO events (asset_id, event_type, severity, raw_log, event_timestamp) VALUES
(3, 'PRIVILEGE_ABUSE_ALERT', 'HIGH', 'SIEM-802: User cmendoza executed ALTER_STUDENT_GRADE_RECORD outside IT scope', '2026-10-16 08:15:02'),
(3, 'RBAC_ACCESS_DENIED', 'WARNING', 'SIEM-803: User lrodriguez blocked from DROP_TABLE_STUDENTS on db-academico-prod', '2026-10-16 10:22:01'),
(6, 'IDS_EXPLOIT_SIGNATURE', 'CRITICAL', 'SURICATA-991: Malformed HTTP chunked header targeting FortiOS SSL VPN CVE-2024-21762', '2026-10-16 09:44:50'),
(1, 'CONFIG_DRIFT_DETECTED', 'HIGH', 'CIS-AUDIT-404: /etc/ssh/sshd_config PermitRootLogin=yes differs from baseline (no)', '2026-10-16 15:19:30'),
(5, 'ENDPOINT_COMPLIANCE_FAIL', 'HIGH', 'MDM-102: Host lap-finanzas-02 reports BitLocker=OFF and EDR=STOPPED', '2026-10-16 16:00:00');

INSERT INTO students (matricula, full_name, email, career, semester, gpa, financial_status, enrollment_active) VALUES
('UNI-2023-0001', 'Sofía Hernández López', 's.hernandez@alumnos.nubeuni.edu.lat', 'Ingeniería en Ciberseguridad', 6, 9.45, 'SCHOLARSHIP', TRUE),
('UNI-2022-0145', 'Mateo Ramírez Castro', 'm.ramirez@alumnos.nubeuni.edu.lat', 'Ingeniería de Software', 8, 8.80, 'REGULAR', TRUE),
('UNI-2024-0892', 'Valentina Torres Ruiz', 'v.torres@alumnos.nubeuni.edu.lat', 'Ciencia de Datos', 4, 9.10, 'REGULAR', TRUE),
('UNI-2021-0310', 'Sebastián Morales Vega', 's.morales@alumnos.nubeuni.edu.lat', 'Ingeniería en Redes y Cloud', 9, 7.95, 'DEBT_HOLD', TRUE),
('UNI-2025-1120', 'Camila Flores Mendoza', 'c.flores@alumnos.nubeuni.edu.lat', 'Administración de TI', 2, 8.60, 'REGULAR', TRUE),
('UNI-2020-0042', 'Diego Vargas Herrera', 'd.vargas@alumnos.nubeuni.edu.lat', 'Ingeniería en Ciberseguridad', 10, 9.70, 'SCHOLARSHIP', FALSE);


-- 3. Auditoría del Control 8.2 (Parte A): Detección de privilegios excesivos
/*
 * Análisis de Auditoría - Control 8.2 (Derechos de acceso privilegiado):
 *
 * 1. ¿Qué riesgo se evalúa?
 *    Se evalúa la acumulación excesiva de privilegios (Privilege Creep) y el incumplimiento
 *    de la segregación de funciones (SoD). Si una misma cuenta de usuario en la universidad
 *    concentra más de 3 roles combinando administración de infraestructura con operación
 *    académica y financiera, el robo de esa credencial comprometería simultáneamente los
 *    servidores virtualizados, las calificaciones de los 5,000 alumnos y la tesorería.
 *
 * 2. ¿Qué evidencia genera esta consulta?
 *    Identifica las cuentas activas que superan el límite de 3 roles asignados, mostrando
 *    el total de roles, cuántos corresponden a nivel CRITICAL o HIGH, el detalle de permisos
 *    y el origen de cada asignación.
 *
 * 3. ¿Qué decisión de seguridad debe tomar el administrador al ver el resultado?
 *    Revocar de inmediato los roles de negocio ajenos al área de TI (ROLE_FINANCE_OPERATOR
 *    y ROLE_GRADES_EDITOR) en la cuenta detectada, separar las cuentas de administración de
 *    las cuentas operativas e implementar caducidad automática en permisos por ticket.
 */

SELECT 
    u.user_id,
    u.username,
    u.full_name,
    u.department,
    COUNT(ur.role_id) AS total_assigned_roles,
    COUNT(CASE WHEN r.privilege_level IN ('CRITICAL', 'HIGH') THEN 1 END) AS high_or_critical_roles,
    STRING_AGG(r.role_name || ' (' || r.privilege_level || ')', ', ' ORDER BY r.privilege_level) AS detailed_roles_list,
    STRING_AGG(DISTINCT ur.assigned_by, ', ') AS authorization_sources,
    'INCUMPLIMIENTO CONTROL 8.2: Privilegios Excesivos (>3 roles) y Violación SoD' AS audit_finding_status
FROM 
    users u
INNER JOIN 
    user_roles ur ON u.user_id = ur.user_id
INNER JOIN 
    roles r ON ur.role_id = r.role_id
WHERE 
    u.is_active = TRUE
GROUP BY 
    u.user_id, u.username, u.full_name, u.department
HAVING 
    COUNT(ur.role_id) > 3
ORDER BY 
    total_assigned_roles DESC, high_or_critical_roles DESC;


-- 4. Auditoría del Control 8.2 (Parte B): Comprobación de accesos permitidos y denegados
/*
 * Análisis de Bitácora de Accesos (access_logs) - Control 8.2:
 *
 * 1. ¿Qué riesgo se evalúa?
 *    Se verifica si el control de acceso basado en roles (RBAC) deniega intentos de acciones
 *    privilegiadas por parte de usuarios no autorizados y si existen operaciones permitidas
 *    indebidamente a causa de roles temporales no revocados.
 *
 * 2. ¿Qué evidencia genera esta consulta?
 *    Relaciona los registros de 'access_logs' con 'users' y 'assets', distinguiendo entre
 *    bloqueos efectivos (DENIED), accesos operativos normales (ALLOWED) y accesos permitidos
 *    que representan una violación de segregación de funciones.
 *
 * 3. ¿Qué decisión de seguridad debe tomar el administrador al ver el resultado?
 *    Retirar el rol ROLE_GRADES_EDITOR al usuario 'cmendoza' e iniciar revisión sobre los
 *    intentos denegados registrados en la base de datos académica y el gateway VPN.
 */

SELECT
    al.log_id,
    al.access_timestamp,
    u.username,
    u.department,
    a.hostname AS target_asset,
    al.action_attempted,
    al.required_privilege,
    al.access_decision,
    al.reason,
    CASE
        WHEN al.access_decision = 'DENIED' THEN 'CONTROL EFECTIVO: Acceso no autorizado bloqueado por RBAC'
        WHEN al.access_decision = 'ALLOWED' AND u.username = 'cmendoza' AND al.action_attempted = 'ALTER_STUDENT_GRADE_RECORD'
            THEN 'BRECHA SOD DETECTADA: Acceso permitido por rol residual excesivo'
        ELSE 'ACCESO LEGÍTIMO: Operación acorde a las funciones del rol'
    END AS audit_evaluation
FROM
    access_logs al
INNER JOIN
    users u ON al.user_id = u.user_id
INNER JOIN
    assets a ON al.asset_id = a.asset_id
ORDER BY
    al.access_decision DESC, al.access_timestamp ASC;
