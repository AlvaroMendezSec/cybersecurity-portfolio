# Enterprise Security Monitoring Lab: Wazuh SIEM + Active Directory

## 📖 Descripción del Proyecto
Este laboratorio práctico simula un entorno corporativo diseñado para centralizar, analizar y detectar eventos de seguridad en tiempo real. La infraestructura integra un entorno de **Active Directory (AD)** basado en Windows Server con el SIEM de código abierto **Wazuh**, permitiendo el desarrollo de capacidades en el triaje de alertas, monitoreo avanzado de endpoints y Threat Hunting.

El objetivo principal de este proyecto es adquirir experiencia real en las tareas diarias de un **Analista de SOC (Security Operations Center)**, cubriendo desde la ingeniería de telemetría hasta la detección de tácticas y técnicas del marco MITRE ATT&CK.

---

## 🏗️ Arquitectura y Componentes del Laboratorio

| Componente / Rol | Sistema Operativo | Función Técnica |
| :--- | :--- | :--- | :--- |
| **Wazuh Manager** | Ubuntu Server 22.04 LTS  | Servidor central. Recolecta, parsea y correlaciona los logs recibidos a través de reglas de seguridad. |
| **Domain Controller** | Windows Server 2022  | Controlador de Dominio (KDC Kerberos / Active Directory). Gestión de identidades. |
| **Endpoint Víctima** | Windows 11 Enterprise | Estación de trabajo unida al dominio bajo monitoreo continuo del agente de Wazuh. |

---

## 🛠️ Ingeniería de Telemetría (Hardening de Auditoría)
Para evitar "puntos ciegos" en la red, se configuraron políticas avanzadas de auditoría en los sistemas operativos Windows, garantizando visibilidad completa sobre eventos críticos:

* **Monitoreo de Identidad (Kerberos & NTLM):** Activación de directivas avanzadas en `secpol.msc` para capturar eventos de validación de credenciales (**Event ID 4776**), inicios de sesión exitosos (**Event ID 4624**) y fallidos (**Event ID 4625**).
* **Visibilidad de Procesos Avanzada:** Activación del seguimiento detallado de procesos (**Event ID 4688**) y configuración del registro para incluir la **Línea de Comandos Completa (`commandLine`)**, permitiendo auditar los argumentos exactos ejecutados en consolas (CMD/PowerShell).

---

## ⚔️ Casos de Uso y Simulaciones de Ataque (MITRE ATT&CK)
