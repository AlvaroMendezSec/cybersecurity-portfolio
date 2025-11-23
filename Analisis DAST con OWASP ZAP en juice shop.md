Descripcion del laboratorio:

OWASP Juice shop es un sitio web vulnerable creado para aprender a detectar vulnerabilidades web comunes
OWASP ZAP es una herramienta de ciberseguridad diseñada para detectar vulnerabilidades en sitios web.

Este proyecto consiste en realizar un análisis de vulnerabilidades a la aplicación insegura OWASP Juice Shop utilizando la herramienta de deteccion de vulnerabilidades web OWASP ZAP. 
El objetivo es identificar vulnerabilidades comunes del OWASP Top 10, evaluarlas y proponer recomendaciones de mitigación.

Entorno y herramientas utilizadas:

OWASP Juice Shop en entorno local

OWASP ZAP (versión 2.16.1)

Kali linux

Durante la evaluación dinámica del entorno OWASP Juice Shop utilizando OWASP ZAP, se identificaron múltiples vulnerabilidades que afectan la seguridad, integridad y privacidad de la aplicación. 
Estas fallas abarcan desde problemas de configuración, exposición innecesaria de información y uso de librerías vulnerables, hasta debilidades que pueden permitir ataques más serios como SQL Injection o Clickjacking.

El objetivo de este reporte es presentar cada hallazgo, su impacto potencial y recomendaciones específicas de mitigación siguiendo buenas prácticas de seguridad, estándares OWASP y configuraciones seguras modernas.

Vulnerabilidades encontradas

1)SQL injection

Severidad: Alta
Descripcion: Se detectó que ciertos puntos de entrada permiten la inyeccion de codigo sql, lo podria manipular las consultas ejecutadas por la aplicacion

Impacto: 
- Acceso no autorizado a datos sensibles
- Manipulacion o borrado de informacion
- Posible escalacion a comprometer la base de datos completa

RecomendacionesÑ
- Utilizar consultas preparadas/parametrizadas
- Evitar concatenacion de entradas del usuario
- Implementar validaciones estrictas del lado del servidor
- Minimizar privilegios del usuario o base de datos
