# Análisis automático de correos con MAILINSPECTOR
La herramienta MailInspector permite analizar de forma automática los correos potencialmente sospechosos que nos lleguen a la bandeja de entrada.
De forma rápida la herramienta nos mostrará un análisis exhaustivo del mail haciéndonos un resumen de las cabeceras, URLs, hashes, detección de spoof en el remitente, análisis de los dominios e IOCs.

## Descripción del proyecto
El phishing es una de las prinicipales causas de incidentes de ciberseguridad a nivel mundial. Se calcula que más del 90% de los ciberataques exitosos comienzan con correos electrónicos phishing. Este proyecto tiene como objetivo principal reducir este porcentaje al automatizar el análisis de correos sospechosos. 

**Análisis de archivos .eml sospechosos:** El script escanea archivos .eml (correos electrónicos) para detectar posibles amenazas de phishing.

**Generación de informes detallados:** Crea un archivo .txt con un análisis completo que incluye:  

  **Cabeceras del correo:** Información detallada sobre las cabeceras del correo para identificar posibles manipulaciones.  
  **Análisis de hashes:** Verifica los hashes de los archivos adjuntos.  
  **Análisis de dominios del remitente:** Analiza los dominios del correo del remitente.  
  **Detección de email spoofing:** Detecta intentos de falsificación en las direcciones de correo electrónico del remitente.  
  **URLs sospechosas:** Escanea las URLs contenidas en el correo y las valida a través de las APIs de VirusTotal y URLscan.
  
**Integración con APIs:** Utiliza la API de VirusTotal (VT) y URLScan para obtener información adicional sobre hashes y URLs. NOTA: las APIs proporcionan un número límitado de peticiones.  
Optimización del tiempo de análisis: Automatiza el proceso de análisis, reduciendo el tiempo dedicado a la revisión manual de correos electrónicos y permitiendo a los analistas centrarse en tareas más críticas.

**Convertidor de archivo .msg a .eml:** Convierte archivos con la extensión .msg a .eml para optimizar tiempo a la hora de analizar el correo.

 **Análisis final no técnico:** Para evitar tecnicismos se ha implementado un resumen final, que sin entrar en detalle alberga todo el análisis completo del correo.

## Tecnologías utilizadas
**Python:** El script está desarrollado en Python, utilizando diversas bibliotecas para realizar el análisis de los correos .eml, procesar las cabeceras, realizar validaciones de URLs y hashes, y manejar la integración con las APIs externas.

## Instalación
#### 1. Instalación de Python3
Ve al sitio oficial de Python: https://www.python.org/downloads/
Verificar la versión de Python: python --version
#### 2. Clonar repositorio
`git clone <repositorio>`
#### 3. Crea un entorno virtual (opcional pero recomendado):
`python3 -m venv venv`

`source venv/bin/activate  # En sistemas Linux/MacOS`

`venv\Scripts\activate     # En Windows`

#### 4. Instalación de dependencias
 `pip install -r requirements.txt`
#### 5. Añadir las API KEYS de VT y URLSCAN
Para que funcione correctamente los análisis reputacionales es necesario añadir las API KEYs de VirusTotal y URLscan en las siguientes variables:
 - VT_API_KEY1, VT_API_KEY2, VT_API_KEY3 
 - URLscan_API_KEY1, URLscan_API_KEY2, URLscan_API_KEY3  


## Ejemplos de cómo usar el proyecto
La sintaxis para ejecutar correctamente el script es de la siguiente forma: python MailInspector.py

Una vez ha sido ejecutado preguntará si quieres convertir un correo .msg. Para elegir que **NO** puedes darle a cualquier tecla menos a la "y". En el caso que sí quieras convertir el correo con extensión .msg a .eml debes incluir el nombre del archivo al programa. Se puede añadir el nombre que quieras modificando la primera variable de la función **convert_msg_to_eml("correo.msg", "correo.eml")**. Asímismo, al haber realizado el conversión se tendrá que ejecutar una segunda vez para el análisis del correo.eml.

Al terminar la ejecución del script, se habrá creado los siguientes archivos .txt

- MailInspector.txt: Muestra el nálisis ténico con toda la información del correo.
- API_VT_url: Resultado de los escaneos de las URLs que pasan por la API de Virus Total. El análisis final de la API de VT de todas las URLs se pueden observar en el archivo anterior.
- urlLegit_path: Muestra las URLs que URLscan considera que son legítimas.
- URLsScanningResults: Muestra toda la información de las URLs que son escaneadas por URLScan.
- urlMaliciousDetected: Muestra las URLs que URLscan muestra como maliciosas.

**NOTA IMPORTANTE**: MailInspector está diseñado para analizar correos individuales, no hileras de correos.


## Contribución
Para contribuir al proyecto puedes mandar un correo electrónico indicando sugerencias de mejora o reporte de errores al correo:


## Contacto
Correo electrónico: 

Linkedin: 










