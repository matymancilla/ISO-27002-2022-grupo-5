"""
Proyecto de Maestría en Seguridad Informática - ISO/IEC 27002:2022 (Grupo 5)
Caso de Estudio: Seguridad en la Nube Universitaria
Autora: Maty Mancilla
Archivo: security_controls_eval.py

Evaluación técnica de controles del Bloque Tecnológico:
- Control 8.1: Dispositivos de usuario final.
- Control 8.8: Gestión de vulnerabilidades técnicas.
- Control 8.9: Gestión de la configuración.
"""

from typing import Any


SIMULATED_ENDPOINTS: list[dict[str, Any]] = [
    {
        "asset_id": "END-001",
        "hostname": "lap-rectoria-04.nubeuni.local",
        "user_owner": "rector@nubeuni.edu.lat",
        "department": "Rectoría",
        "os": "Windows 11 Pro 23H2",
        "disk_encrypted": False,
        "edr_active": True,
        "screen_lock_timeout_min": 5,
    },
    {
        "asset_id": "END-002",
        "hostname": "lap-finanzas-02.nubeuni.local",
        "user_owner": "m.fernandez@nubeuni.edu.lat",
        "department": "Finanzas y Tesorería",
        "os": "Windows 10 Pro 22H2",
        "disk_encrypted": False,
        "edr_active": False,
        "screen_lock_timeout_min": 30,
    },
    {
        "asset_id": "END-003",
        "hostname": "mac-ing-docente01.nubeuni.local",
        "user_owner": "l.rodriguez@nubeuni.edu.lat",
        "department": "Facultad de Ingeniería",
        "os": "macOS Sonoma 14.6",
        "disk_encrypted": True,
        "edr_active": True,
        "screen_lock_timeout_min": 5,
    },
    {
        "asset_id": "END-004",
        "hostname": "wks-registro-01.nubeuni.local",
        "user_owner": "j.villanueva@nubeuni.edu.lat",
        "department": "Registro y Control Académico",
        "os": "Ubuntu Desktop 22.04 LTS",
        "disk_encrypted": True,
        "edr_active": True,
        "screen_lock_timeout_min": 10,
    },
    {
        "asset_id": "END-005",
        "hostname": "lap-auditoria-01.nubeuni.local",
        "user_owner": "p.salazar@nubeuni.edu.lat",
        "department": "Auditoría Interna",
        "os": "Windows 11 Enterprise",
        "disk_encrypted": True,
        "edr_active": True,
        "screen_lock_timeout_min": 5,
    },
]

SIMULATED_VULNERABILITIES: list[dict[str, Any]] = [
    {
        "vuln_id": "VULN-101",
        "cve_id": "CVE-2024-21762",
        "description": "FortiOS Out-of-bound Write SSL VPN (RCE sin autenticación)",
        "hostname": "gw-vpn-campus.nubeuni.local",
        "asset_type": "NETWORK_APPLIANCE",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "internet_facing": True,
        "exploit_available": True,
    },
    {
        "vuln_id": "VULN-102",
        "cve_id": "CVE-2024-1086",
        "description": "Linux Kernel netfilter: nf_tables Use-After-Free (Escalación local)",
        "hostname": "db-academico-prod.nubeuni.local",
        "asset_type": "DATABASE",
        "severity": "HIGH",
        "cvss_score": 7.8,
        "internet_facing": False,
        "exploit_available": True,
    },
    {
        "vuln_id": "VULN-103",
        "cve_id": "CVE-2023-44487",
        "description": "HTTP/2 Rapid Reset Attack (Denegación de Servicio en Portal Web)",
        "hostname": "srv-portal-web-01.nubeuni.local",
        "asset_type": "SERVER",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "internet_facing": True,
        "exploit_available": True,
    },
    {
        "vuln_id": "VULN-104",
        "cve_id": "CVE-2023-38545",
        "description": "curl SOCKS5 Heap Buffer Overflow en plataforma Moodle",
        "hostname": "srv-lms-moodle-01.nubeuni.local",
        "asset_type": "SERVER",
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "internet_facing": True,
        "exploit_available": False,
    },
    {
        "vuln_id": "VULN-105",
        "cve_id": "CVE-2024-30088",
        "description": "Windows Kernel Elevation of Privilege en estación de trabajo",
        "hostname": "lap-rectoria-04.nubeuni.local",
        "asset_type": "ENDPOINT",
        "severity": "HIGH",
        "cvss_score": 7.0,
        "internet_facing": False,
        "exploit_available": False,
    },
]

SECURE_BASELINE_CONFIG: dict[str, Any] = {
    "ssh_permit_root_login": False,
    "ssh_password_authentication": False,
    "tls_min_version": "TLSv1.3",
    "host_firewall_enabled": True,
    "db_public_listen_all_ips": False,
    "auditd_logging_enabled": True,
    "unattended_security_upgrades": True,
    "open_tcp_ports": [443],
}

LAB_SERVERS_CONFIG: list[dict[str, Any]] = [
    {
        "hostname": "srv-portal-web-01.nubeuni.local",
        "role": "Portal Web Institucional",
        "config": {
            "ssh_permit_root_login": True,
            "ssh_password_authentication": True,
            "tls_min_version": "TLSv1.2",
            "host_firewall_enabled": True,
            "db_public_listen_all_ips": False,
            "auditd_logging_enabled": True,
            "unattended_security_upgrades": False,
            "open_tcp_ports": [22, 80, 443, 8080],
        },
    },
    {
        "hostname": "db-academico-prod.nubeuni.local",
        "role": "Base de Datos Académica PostgreSQL (5,000 alumnos)",
        "config": {
            "ssh_permit_root_login": False,
            "ssh_password_authentication": False,
            "tls_min_version": "TLSv1.3",
            "host_firewall_enabled": False,
            "db_public_listen_all_ips": True,
            "auditd_logging_enabled": False,
            "unattended_security_upgrades": True,
            "open_tcp_ports": [443, 5432],
        },
    },
    {
        "hostname": "srv-lms-moodle-01.nubeuni.local",
        "role": "Servidor Aula Virtual Moodle",
        "config": {
            "ssh_permit_root_login": False,
            "ssh_password_authentication": False,
            "tls_min_version": "TLSv1.3",
            "host_firewall_enabled": True,
            "db_public_listen_all_ips": False,
            "auditd_logging_enabled": True,
            "unattended_security_upgrades": True,
            "open_tcp_ports": [443],
        },
    },
]


def evaluate_endpoint_security_control_8_1(
    endpoints: list[dict[str, Any]],
) -> dict[str, Any]:
    """Evalúa el cumplimiento de la política de seguridad en dispositivos de usuario final (Control 8.1).

    Revisa el inventario de endpoints verificando el cifrado de disco completo (FDE),
    el estado del agente EDR y el bloqueo de pantalla, generando alertas sobre los
    equipos que no cuentan con cifrado activo.

    Métrica extraída:
        Tasa de Cumplimiento de Cifrado en Endpoints (ECR): porcentaje de dispositivos
        con cifrado de disco activo respecto al total evaluado.

    Reducción de la superficie de ataque:
        El cifrado de disco evita la extracción directa de información sensible (registros
        académicos y financieros de la universidad) en caso de robo o extravío físico de
        equipos portátiles.
    """
    total_endpoints = len(endpoints)
    if total_endpoints == 0:
        return {"error": "No se proporcionaron endpoints para auditar."}

    encrypted_count = 0
    fully_compliant_count = 0
    security_breach_alerts: list[dict[str, Any]] = []

    for ep in endpoints:
        is_encrypted = bool(ep.get("disk_encrypted", False))
        has_edr = bool(ep.get("edr_active", False))
        lock_timeout = int(ep.get("screen_lock_timeout_min", 999))
        lock_compliant = lock_timeout <= 10

        if is_encrypted:
            encrypted_count += 1

        if is_encrypted and has_edr and lock_compliant:
            fully_compliant_count += 1

        if not is_encrypted:
            additional_gaps = []
            if not has_edr:
                additional_gaps.append("Agente EDR inactivo")
            if not lock_compliant:
                additional_gaps.append(f"Bloqueo de pantalla excesivo ({lock_timeout} min)")

            security_breach_alerts.append(
                {
                    "asset_id": ep.get("asset_id"),
                    "hostname": ep.get("hostname"),
                    "department": ep.get("department"),
                    "os": ep.get("os"),
                    "user_owner": ep.get("user_owner"),
                    "alert_level": "CRITICAL_BREACH",
                    "finding": (
                        "INCUMPLIMIENTO CONTROL 8.1: Dispositivo sin cifrado de disco activo (FDE). "
                        "Riesgo de exposición de datos sensibles ante pérdida o robo."
                    ),
                    "secondary_gaps": additional_gaps,
                    "remediation_action": "Habilitar cifrado de disco (BitLocker/FileVault/LUKS) por política central y restringir acceso a red administrativa.",
                }
            )

    encryption_compliance_rate = round((encrypted_count / total_endpoints) * 100, 2)
    full_posture_compliance_rate = round((fully_compliant_count / total_endpoints) * 100, 2)

    return {
        "control_id": "ISO/IEC 27002:2022 - Control 8.1 (Dispositivos de usuario final)",
        "total_audited_endpoints": total_endpoints,
        "encrypted_endpoints": encrypted_count,
        "unencrypted_breaches_count": len(security_breach_alerts),
        "encryption_compliance_rate_pct": encryption_compliance_rate,
        "full_posture_compliance_rate_pct": full_posture_compliance_rate,
        "alerts": security_breach_alerts,
    }


def prioritize_vulnerabilities_control_8_8(
    vulnerabilities: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Prioriza las vulnerabilidades técnicas combinando severidad, CVSS y exposición a Internet (Control 8.8).

    Métrica extraída:
        Índice de Priorización Contextual de Vulnerabilidades (CRPS): puntaje de 0 a 100
        que suma la base por severidad (CRITICAL=40, HIGH=25, MEDIUM=10, LOW=5), el puntaje
        CVSS ponderado (x1.5), +30 puntos si el activo está expuesto a Internet
        (internet_facing: True) y +15 puntos si existe exploit disponible.

    Reducción de la superficie de ataque:
        Permite enfocar el parchado inmediato (<24h a 72h) sobre los servidores accesibles
        desde Internet (VPN, Moodle y Portal Web), reduciendo la ventana de exposición en
        el perímetro universitario antes de atender equipos aislados en la red interna.
    """
    severity_base_points: dict[str, float] = {
        "CRITICAL": 40.0,
        "HIGH": 25.0,
        "MEDIUM": 10.0,
        "LOW": 5.0,
    }

    INTERNET_EXPOSURE_PENALTY = 30.0
    EXPLOIT_AVAILABLE_PENALTY = 15.0

    prioritized_list: list[dict[str, Any]] = []

    for vuln in vulnerabilities:
        severity = str(vuln.get("severity", "LOW")).upper()
        cvss = float(vuln.get("cvss_score", 0.0))
        is_internet_facing = bool(vuln.get("internet_facing", False))
        has_exploit = bool(vuln.get("exploit_available", False))

        base_points = severity_base_points.get(severity, 5.0)
        cvss_weighted = round(cvss * 1.5, 2)
        exposure_points = INTERNET_EXPOSURE_PENALTY if is_internet_facing else 0.0
        exploit_points = EXPLOIT_AVAILABLE_PENALTY if has_exploit else 0.0

        total_risk_score = round(
            min(100.0, base_points + cvss_weighted + exposure_points + exploit_points),
            2,
        )

        if total_risk_score >= 85.0:
            priority_tier = "P1 - EMERGENCIA (Parchear o aislar en < 24 horas)"
        elif total_risk_score >= 60.0:
            priority_tier = "P2 - ALTA PRIORIDAD (Parchear en < 72 horas)"
        elif total_risk_score >= 40.0:
            priority_tier = "P3 - PRIORIDAD MEDIA (Ventana de mantenimiento < 7 días)"
        else:
            priority_tier = "P4 - BAJA PRIORIDAD (Ciclo mensual regular < 30 días)"

        prioritized_list.append(
            {
                "vuln_id": vuln.get("vuln_id"),
                "cve_id": vuln.get("cve_id"),
                "hostname": vuln.get("hostname"),
                "asset_type": vuln.get("asset_type"),
                "severity": severity,
                "cvss_score": cvss,
                "internet_facing": is_internet_facing,
                "exploit_available": has_exploit,
                "contextual_risk_score": total_risk_score,
                "score_breakdown": (
                    f"Base({base_points}) + CVSS*1.5({cvss_weighted}) + "
                    f"InternetFacing({exposure_points}) + Exploit({exploit_points})"
                ),
                "recommended_sla": priority_tier,
            }
        )

    prioritized_list.sort(
        key=lambda item: (item["contextual_risk_score"], item["cvss_score"]),
        reverse=True,
    )

    return prioritized_list


def evaluate_configuration_drift_control_8_9(
    baseline: dict[str, Any],
    servers: list[dict[str, Any]],
) -> dict[str, Any]:
    """Compara la configuración de los servidores del laboratorio contra la línea base segura (Control 8.9).

    Métrica extraída:
        Índice de Cumplimiento de Configuración Segura (CBCR): porcentaje de parámetros
        que coinciden con la configuración segura definida y porcentaje de desviación (drift).

    Reducción de la superficie de ataque:
        Identifica parámetros inseguros como el acceso directo de root por SSH, firewalls
        locales desactivados o puertos de base de datos expuestos, permitiendo corregirlos
        antes de que faciliten un acceso no autorizado.
    """
    total_params_per_server = len(baseline)
    server_reports: list[dict[str, Any]] = []
    total_checks_global = 0
    total_compliant_global = 0

    for srv in servers:
        hostname = srv.get("hostname", "unknown")
        role = srv.get("role", "General Server")
        current_cfg = srv.get("config", {})

        drifts: list[dict[str, Any]] = []
        compliant_params = 0

        for param_key, expected_val in baseline.items():
            total_checks_global += 1
            actual_val = current_cfg.get(param_key)

            if actual_val == expected_val:
                compliant_params += 1
                total_compliant_global += 1
            else:
                if param_key in ("ssh_permit_root_login", "host_firewall_enabled", "db_public_listen_all_ips", "open_tcp_ports"):
                    drift_severity = "CRITICAL_DRIFT"
                elif param_key in ("ssh_password_authentication", "auditd_logging_enabled"):
                    drift_severity = "HIGH_DRIFT"
                else:
                    drift_severity = "MEDIUM_DRIFT"

                drifts.append(
                    {
                        "parameter": param_key,
                        "expected_secure_value": expected_val,
                        "actual_lab_value": actual_val,
                        "drift_severity": drift_severity,
                    }
                )

        compliance_pct = round((compliant_params / total_params_per_server) * 100, 2)
        server_reports.append(
            {
                "hostname": hostname,
                "role": role,
                "total_parameters": total_params_per_server,
                "compliant_parameters": compliant_params,
                "drift_count": len(drifts),
                "compliance_rate_pct": compliance_pct,
                "status": "COMPLIANT" if len(drifts) == 0 else "NON_COMPLIANT (DRIFT DETECTED)",
                "drifts": drifts,
            }
        )

    global_compliance_pct = (
        round((total_compliant_global / total_checks_global) * 100, 2)
        if total_checks_global > 0
        else 0.0
    )

    return {
        "control_id": "ISO/IEC 27002:2022 - Control 8.9 (Gestión de la configuración)",
        "global_baseline_compliance_pct": global_compliance_pct,
        "global_drift_rate_pct": round(100.0 - global_compliance_pct, 2),
        "total_servers_audited": len(servers),
        "server_reports": server_reports,
    }


if __name__ == "__main__":
    print("-" * 88)
    print(" AUDITORIA DE CONTROLES TECNOLOGICOS - SEGURIDAD EN LA NUBE UNIVERSITARIA")
    print(" Norma de Referencia: ISO/IEC 27002:2022 (Controles 8.1, 8.8 y 8.9)")
    print("-" * 88)

    report_8_1 = evaluate_endpoint_security_control_8_1(SIMULATED_ENDPOINTS)
    print(f"\n[+] {report_8_1['control_id']}")
    print(f"    Endpoints auditados                : {report_8_1['total_audited_endpoints']}")
    print(f"    Endpoints con cifrado activo (FDE) : {report_8_1['encrypted_endpoints']}")
    print(f"    Cumplimiento de cifrado (ECR)      : {report_8_1['encryption_compliance_rate_pct']}%")
    print(f"    Cumplimiento integral de postura   : {report_8_1['full_posture_compliance_rate_pct']}%")
    print(f"    Equipos sin cifrado detectados     : {report_8_1['unencrypted_breaches_count']}")

    for alert in report_8_1["alerts"]:
        print(f"\n    [!] {alert['alert_level']} -> Host: {alert['hostname']} ({alert['department']})")
        print(f"        Usuario  : {alert['user_owner']} | SO: {alert['os']}")
        print(f"        Hallazgo : {alert['finding']}")
        if alert["secondary_gaps"]:
            print(f"        Adicional: {', '.join(alert['secondary_gaps'])}")
        print(f"        Accion   : {alert['remediation_action']}")

    print("\n" + "-" * 88)
    print("[+] ISO/IEC 27002:2022 - Control 8.8 (Gestión de vulnerabilidades técnicas)")
    print("    Priorización por severidad y exposición a Internet:")
    print("-" * 88)

    prioritized_vulns = prioritize_vulnerabilities_control_8_8(SIMULATED_VULNERABILITIES)
    for idx, v in enumerate(prioritized_vulns, start=1):
        exposure_tag = "EXP_INTERNET" if v["internet_facing"] else "RED_INTERNA"
        print(
            f" #{idx} | Score: {v['contextual_risk_score']:>5.2f}/100 | "
            f"{v['cve_id']:<15} | Sev: {v['severity']:<8} (CVSS {v['cvss_score']}) | "
            f"[{exposure_tag:<12}] | Host: {v['hostname']}"
        )
        print(f"      Calculo : {v['score_breakdown']}")
        print(f"      SLA     : {v['recommended_sla']}\n")

    print("-" * 88)
    report_8_9 = evaluate_configuration_drift_control_8_9(SECURE_BASELINE_CONFIG, LAB_SERVERS_CONFIG)
    print(f"[+] {report_8_9['control_id']}")
    print(f"    Servidores evaluados               : {report_8_9['total_servers_audited']}")
    print(f"    Cumplimiento global de linea base  : {report_8_9['global_baseline_compliance_pct']}%")
    print(f"    Porcentaje de desviacion (Drift)   : {report_8_9['global_drift_rate_pct']}%")
    print("-" * 88)

    for srv_rep in report_8_9["server_reports"]:
        print(
            f" -> Servidor: {srv_rep['hostname']} ({srv_rep['role']})\n"
            f"    Estado: {srv_rep['status']} | Cumplimiento: {srv_rep['compliance_rate_pct']}% "
            f"({srv_rep['compliant_parameters']}/{srv_rep['total_parameters']} parametros)"
        )
        if srv_rep["drifts"]:
            for d in srv_rep["drifts"]:
                print(
                    f"      [!] {d['drift_severity']:<14} | Parametro: '{d['parameter']}' "
                    f"| Esperado: {d['expected_secure_value']} "
                    f"| Actual: {d['actual_lab_value']}"
                )
        else:
            print("      [OK] Configuracion alineada con la linea base segura.")
        print()
