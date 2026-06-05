# Enterprise Security Monitoring Lab: Wazuh SIEM + Active Directory

## 📖 Descripción del Proyecto
Este laboratorio práctico simula un entorno corporativo diseñado para centralizar, analizar y detectar eventos de seguridad en tiempo real. La infraestructura integra un entorno de **Active Directory (AD)** basado en Windows Server con el SIEM de código abierto **Wazuh**, permitiendo el desarrollo de capacidades en el triaje de alertas, monitoreo avanzado de endpoints y Threat Hunting.

El objetivo principal de este proyecto es adquirir experiencia real en las tareas diarias de un **Analista de SOC (Security Operations Center)**, cubriendo desde la ingeniería de telemetría hasta la detección de tácticas y técnicas del marco MITRE ATT&CK.

---

## 🏗️ Arquitectura y Componentes del Laboratorio

| Componente / Rol | Sistema Operativo | Función Técnica |
| :--- | :--- | :--- | :--- |
| **Wazuh Manager** | Ubuntu Server 22.04 LTS  | Servidor central. Recolecta, parsea y correlaciona los logs recibidos a través de reglas de seguridad. |
| **Domain Controller** | Windows Server 2025  | Controlador de Dominio (KDC Kerberos / Active Directory). Gestión de identidades. |
| **Endpoint Víctima** | Windows 11 Enterprise | Estación de trabajo unida al dominio bajo monitoreo continuo del agente de Wazuh. |

---

## 🛠️ Ingeniería de Telemetría (Hardening de Auditoría)
Para evitar "puntos ciegos" en la red, se configuraron políticas avanzadas de auditoría en los sistemas operativos Windows, garantizando visibilidad completa sobre eventos críticos:

* **Monitoreo de Identidad (Kerberos & NTLM):** Activación de directivas avanzadas en `secpol.msc` para capturar eventos de validación de credenciales (**Event ID 4776**), inicios de sesión exitosos (**Event ID 4624**) y fallidos (**Event ID 4625**).
* **Visibilidad de Procesos Avanzada:** Activación del seguimiento detallado de procesos (**Event ID 4688**) y configuración del registro para incluir la **Línea de Comandos Completa (`commandLine`)**, permitiendo auditar los argumentos exactos ejecutados en consolas (CMD/PowerShell).

---

## ⚔️ Casos de Uso y Simulaciones de Ataque (MITRE ATT&CK)

Caso de Estudio: [Escaneo de puertos no autorizado]

Resumen 

Wazuh recolectó logs de un posible escaneo de puertos no autorizado

Qué ocurrió.
Cómo fue detectado.
Cuál era el objetivo del análisis.

Ejemplo:

"Se realizó un escaneo de puertos utilizando Nmap contra un servidor Windows Server 2025 monitoreado por Wazuh. El objetivo fue analizar la capacidad de detección del SIEM y evaluar qué evidencia quedó registrada en los logs del sistema."

Objetivos
Generar actividad sospechosa controlada.
Analizar la telemetría recolectada por Wazuh.
Identificar eventos relevantes.
Documentar el proceso de investigación.
Entorno de Laboratorio
Infraestructura
Equipo	Sistema Operativo	Función
Kali Linux	Kali Linux	Máquina atacante
Windows Server	Windows Server 2022	Objetivo
Ubuntu Server	Ubuntu Server	Wazuh Manager
Herramientas Utilizadas
Wazuh
Nmap
Windows Event Viewer
PowerShell
Sysmon (si aplica)
Descripción del Ataque

Explicar qué se hizo exactamente.

Ejemplo:

"Desde la máquina Kali Linux se ejecutó un escaneo TCP contra el servidor Windows para identificar puertos abiertos."

Evidencia Recopilada
Evidencia en Windows
Event ID observados.
Capturas relevantes.
Logs encontrados.
Evidencia en Wazuh
Alertas generadas.
Eventos observados.
Capturas del dashboard.
Investigación
Línea Temporal
Hora	Evento
10:00	Inicio del escaneo
10:01	Windows registra eventos
10:02	Wazuh recibe los eventos
10:03	Se genera alerta
Análisis

Responder:

¿Qué ocurrió?
¿Qué evidencia lo demuestra?
¿Qué información proporcionan los logs?
¿Qué limitaciones encontré?
MITRE ATT&CK
Técnica	Nombre
T1595	Active Scanning

Explicar brevemente por qué aplica.

Hallazgos
Eventos relevantes encontrados.
Información obtenida por el atacante.
Visibilidad proporcionada por Wazuh.
Recomendaciones
Mejoras de monitoreo.
Reglas adicionales.
Configuraciones recomendadas.
Lecciones Aprendidas

Esta es una sección que muchos olvidan y que suele llamar mucho la atención.

Ejemplo:

"Durante la investigación se descubrió que el Event ID 5152 estaba filtrado por la configuración del agente Wazuh, lo que impedía su visualización en el SIEM. Fue necesario revisar el archivo ossec.conf para analizar el comportamiento observado."

Conclusión

Resumen final de lo aprendido y de la efectividad de la detección.
