import re
import json
import urllib.request
#Extracción de URLs del email
import email
from email import policy
from email.parser import BytesParser
#URLscan
import requests
import time
import hashlib
from tqdm import tqdm  # Asegúrate de tener instalada esta biblioteca: pip install tqdm
import datetime
import threading
from pathlib import Path
import extract_msg #pip install extract_msg
import base64
from collections import Counter

from email.header import decode_header
import mimetypes
from email.message import EmailMessage
import concurrent.futures
import os
import threading

lock = threading.Lock()

eml_path = ""
#BUSCA por "MAILINSPECTOR" para saber qué cosas se guardarán en MAILINSPECTOR.txt
MailInspector="MailInspector.txt"

#----------------------API KEYS-------------------------------------
#VT
VT_API_KEY1 = ""
VT_API_KEY2 = ""
VT_API_KEY3 = ""
#URLSCAN
URLscan_API_KEY1 = ""
URLscan_API_KEY2 = ""
URLscan_API_KEY3 = ""


#----------------------VIRUS TOTAL (Analisis de dominios)-------------------------------------
#VT_API_KEY = ""
API_URL_DOMAIN = "https://www.virustotal.com/api/v3/domains/"

# API Key de URLScan.io
CONTADOR_IOCS = 0
#MSG_CONVERTER

#HILOS---------------------------
lock = threading.Lock()

def decidir_api_por_indice(indice):
    apis = ["URLSCAN_API_1", "URLSCAN_API_2", "URLSCAN_API_3"]
    return apis[indice % len(apis)]

def decidir_api_virustotal_por_indice(indice):
    # Las tres APIs de VirusTotal se asignan cíclicamente
    apis = ["VIRUSTOTAL_API_1", "VIRUSTOTAL_API_2", "VIRUSTOTAL_API_3"]
    return apis[indice % len(apis)]

def sanitize_header(value):
    """Limpia los valores de los encabezados para evitar errores de formato."""
    return value.replace("\n", " ").replace("\r", " ") if value else "Desconocido"

def convert_msg_to_eml(msg_file_path, output_eml_path):
    print("¿Quieres convertir un correo .msg a .eml? (escribe \"y\" para continuar)")
    respuesta = input().strip().lower()
    if respuesta == "y":
        try:
            # Leer el archivo .msg
            msg = extract_msg.Message(msg_file_path)
            msg_subject = msg.subject or "Sin asunto"
            msg_sender = msg.sender or "desconocido@dominio.com"
            msg_date = msg.date
            msg_to = msg.to or "destinatarios@dominio.com"
            msg_body = msg.body or ""

            # Crear el objeto EmailMessage
            eml = EmailMessage()
            eml['Subject'] = msg_subject
            eml['From'] = msg_sender
            eml['To'] = msg_to
            eml['Date'] = msg_date
            eml.set_content(msg_body)

            # Adjuntar archivos si existen
            for attachment in msg.attachments:
                attachment_data = attachment.data
                attachment_name = attachment.longFilename or attachment.shortFilename or "archivo_adjunto"
                eml.add_attachment(attachment_data, filename=attachment_name)

            # Guardar como .eml
            with open(output_eml_path, 'w', encoding='utf-8') as eml_file:
                eml_file.write(eml.as_string())

            print(f"✅ Conversión exitosa: {msg_file_path} -> {output_eml_path}")

        except Exception as e:
            print(f"❌ Error al convertir {msg_file_path}: {e}")
# Ejemplo de uso   

# Ejemplo de uso

#---------------------- URLSCAN (Analisis de URLs)--------------------------------------------
# URL base de la API de URLScan
URLSCAN_SUBMIT_URL = 'https://urlscan.io/api/v1/scan/'
URLSCAN_RESULT_URL = 'https://urlscan.io/api/v1/result/'
#----------------------------------------------------

#---------------------------------------
#Extraccion de Hahses
# Patrones para buscar MD5, SHA1, y SHA256 
HASH_PATTERNS = {
    "MD5": r"\b[a-fA-F0-9]{32}\b",
    "SHA1": r"\b[a-fA-F0-9]{40}\b",
    "SHA256": r"\b[a-fA-F0-9]{64}\b"
}
# CAMBIO DE TIEMPOS para el WHOIS de VT y dominios
def correct_time(timestamp):
    if timestamp is None:
        #print("❌ Error: No se recibió un valor para el timestamp.")
        return None  # Devuelve None si no hay timestamp
    
    if not isinstance(timestamp, (int, float)):
        #print("❌ Error: El timestamp debe ser un número (int o float).")
        return None  # Devuelve None si el tipo es incorrecto
    
    try:
        return datetime.fromtimestamp(timestamp, datetime.UTC).strftime('%d-%m-%Y')
    except (OverflowError, OSError) as e:
        #print(f"❌ Error: El timestamp está fuera de rango o es inválido. Detalle: {e}")
        return None
    except Exception as e:
        #print(f"❌ Error inesperado al procesar el timestamp: {e}")
        return None
#Ofuscación en URLs y dominios
def email_obfuscation(obfuscation):

    return obfuscation.replace('.','[.]')


def get_vt_detections(hash_value, vt_api_key):
    url = f"https://www.virustotal.com/api/v3/files/{hash_value}"
    headers = {
        "x-apikey": vt_api_key
    }

    try:
        response = requests.get(url, headers=headers)
        
        # Si la respuesta es 200, procesamos la detección
        if response.status_code == 200:
            result = response.json()

            # Recorrer los motores de detección para verificar la maliciosidad
            detections = 0
            total_engines = 0
            for engine, data in result['data']['attributes']['last_analysis_results'].items():
                total_engines += 1
                if data.get('category') == 'malicious':
                    detections += 1

            # Devolvemos el conteo de detecciones y motores totales
            if total_engines > 0:
                return detections, total_engines
            else:
                return None, None

        # Si el hash no se encuentra, se maneja el error 404 de manera específica
        elif response.status_code == 404:
            return None, None
        
        else:
            # Si otro tipo de error ocurre, se maneja aquí
            return None, None

    except requests.exceptions.RequestException as e:
        print(f"Error de red: {e}")
        return None, None
    
def VT_WHOIS(dom):
    url = f"https://www.virustotal.com/api/v3/domains/{dom}"
# Cabecera con la clave de API
    headers = {"x-apikey": VT_API_KEY1}
# Realizar la solicitud GET
    response = requests.get(url, headers=headers)
# Verificar el código de respuesta
    if response.status_code == 200:
        data = response.json()
        creation_date = data.get("data", {}).get("attributes", {}).get("creation_date")
        if creation_date:
            return correct_time(creation_date)  # Solo imprime la fecha
        else:
            return "No se encontró información de creación."
    else:
        return f"Error: {response.status_code} - {response.text}"

#Extraccion de Hahses
#---------------------------------------
def extract_hashes(file_path):
    try:
        with open(file_path, "rb") as f:
            # Parsear el correo .eml
            msg = BytesParser(policy=policy.default).parse(f)
            email_content = msg.as_string()  # Obtener todo el contenido del correo
            # Buscar hashes
            found_hashes = []
            for pattern in HASH_PATTERNS.values():
                found_hashes.extend(re.findall(pattern, email_content))
            return found_hashes
    except Exception as e:
        print(f"Error al procesar el correo: {e}")
        return []
def analizar_hashes_eml(eml_file_path, vt_api_key):
    # Extraer hashes del correo
    hashes = extract_hashes(eml_file_path)

    # Si se encontraron hashes
    if hashes:
        with open(MailInspector, "a", encoding="utf-8") as file:
            file.write("\n\nResultados de los hashes:\n")
        print("Resultados de los hashes:")
        for hash_value in hashes:
            # Consultar VirusTotal para cada hash
            detections, total_engines = get_vt_detections(hash_value, vt_api_key)
            
            # Formatear el resultado según el formato solicitado
            if detections is not None:
                with open(MailInspector, "a", encoding="utf-8") as file:
                    file.write(f"- ({hash_value}) - VT ({detections}/{total_engines}) detecciones\n")
                print(f"- ({hash_value}) - VT ({detections}/{total_engines}) detecciones")
            else:
                # Si el hash no se encuentra en la base de datos
                with open(MailInspector, "a", encoding="utf-8") as file:
                    file.write(f"- ({hash_value}) - Not found\n")
                print(f"- ({hash_value}) - Not found")
    else:
        #mailinspector
        with open(MailInspector, "a", encoding="utf-8") as file:
            file.write("\nNo se encontraron hashes en el correo.")

        print("No se encontraron hashes en el correo.")




def scan_url_with_URLSCAN(url, api):
    if not url:  # Verifica si la URL está vacía
        return None  # Si la URL está vacía, no hace nada y retorna None

    # Elige las cabeceras y la URL de la API correspondiente
    if api == "URLSCAN_API_1":
        URLSCAN_API = URLscan_API_KEY1
        URLSCAN_SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
    elif api == "URLSCAN_API_2":
        URLSCAN_API = URLscan_API_KEY2
        URLSCAN_SUBMIT_URL = "https://urlscan.io/api/v1/scan/"
    else:
        URLSCAN_API = URLscan_API_KEY3
        URLSCAN_SUBMIT_URL = "https://urlscan.io/api/v1/scan/"

    # Configuración de los headers y el payload
    headers = {'API-Key': URLSCAN_API, 'Content-Type': 'application/json'}
    payload = {
        "url": url,
        "visibility": "private"  # Puede ser "private" si tienes un plan de pago
    }

    # Realiza la solicitud POST para escanear la URL
    response = requests.post(URLSCAN_SUBMIT_URL, headers=headers, json=payload)
    
    if response.status_code == 200:
        scan_data = response.json()
        return scan_data['uuid']  # Devuelve el UUID del escaneo iniciado
    else:
        # Si hay un error en la respuesta, lo manejas aquí
        return None  # Retorna None si algo salió mal

#Esta función se ejecuta de la siguiente forma:
#A parte del escaneo con URLscan se va a escaner con VT:
#	- Verificar si existe un archivo que se llame "x". Si existe borrarlo y si no continuar.
	#-Que por cada URL agregue los datos a un archivo.txt
	#- por cada línea que intente hacer matches con las palabras "harmless" (no dañino), "undetected" (sin detectar), malicious.
	#- que cuente cada match por cada URL
	#- si da error la API de VT que la sinxtaxis añadirlo en la misma línea
	#- sintaxis final: 
    #URL: "harmless" (no dañino), "undetected" (sin detectar), "malicious", error
#def vt_url_matches():
def analizar_resultados_vt(url):
    file_path = "API_VT.txt"

    # Esperar hasta que el archivo tenga contenido válido
    timeout = 10  # Segundos de espera máxima
    start_time = time.time()
    
    while time.time() - start_time < timeout:
        if os.path.exists(file_path) and os.path.getsize(file_path) > 0:
            break
        time.sleep(1)  # Esperar 1 segundo antes de volver a revisar
    
    try:
        with lock:  # Bloqueo para evitar accesos simultáneos
            # Contadores para las palabras clave
            counts = Counter()
            keywords = ["harmless", "undetected", "malicious", "NotFoundError"]

            with open(file_path, "r") as file:
                for line in file:
                    for keyword in keywords:
                        if keyword in line:
                            counts[keyword] += 1

            # Construir la salida en una sola línea
            harmless_count = counts.get("harmless", 0)
            undetected_count = counts.get("undetected", 0)
            malicious_count = counts.get("malicious", 0)
            error_count = counts.get("NotFoundError", 0)
            url_ofuscado = email_obfuscation(url)

            # Guardar en MailInspector
            with open(MailInspector, "a", encoding="utf-8") as file:
                file.write("-------------------------------------------------------------------------------------------------------------------\n")
                file.write(f"URL: {url_ofuscado} ({harmless_count} harmless, {undetected_count} undetected, {malicious_count} malicious, {error_count} Error)\n")

            print(f"URL: {url_ofuscado} ({harmless_count} harmless, {undetected_count} undetected, {malicious_count} malicious, {error_count} Error)")

    except FileNotFoundError:
        print(f"❌ El archivo {file_path} no existe. Por favor, verifica la ruta.")
    except Exception as e:
        print(f"❌ Ocurrió un error: {e}")


def scan_url_with_virustotal(url, api):
    file_txt="API_VT.txt"
    api_keys = {
        "VIRUSTOTAL_API_1": VT_API_KEY1,
        "VIRUSTOTAL_API_2": VT_API_KEY2,
        "VIRUSTOTAL_API_3": VT_API_KEY3
    }

    api_key = api_keys.get(api)
    if not api_key:
        print(f"API key no encontrada para {api}")
        return None

    # URL base de la API de VirusTotal
    api_url = "https://www.virustotal.com/api/v3/urls/"
    # Codificar la URL en base64 (VirusTotal requiere la URL codificada)
    encoded_url = base64.urlsafe_b64encode(url.encode()).decode().strip("=")

    # Cabeceras para la solicitud, incluye la API Key
    headers = {
        "x-apikey": api_key
    }

    try:
        response = requests.get(api_url + encoded_url, headers=headers)

        if response.status_code == 200:
            json_response = response.json()

            # Bloquear el acceso al archivo para evitar conflictos entre hilos
            with lock:
                with open(file_txt, "a", encoding="utf-8") as file:
                    if "data" in json_response:
                        result = json_response["data"]["attributes"]["last_analysis_results"]
                        
                        file.write(f"\nAnálisis para la URL {url}:\n")
                        for engine, analysis in result.items():
                            file.write(f"{engine}: {analysis['category']} (Detector: {analysis['engine_name']})\n")

                    else:
                        file.write(f"Error en la respuesta para {url}: {json_response}\n")

        else:
            with lock:
                with open(file_txt, "a", encoding="utf-8") as file:
                    file.write(f"Error al consultar la URL {url}: {response.status_code} - {response.text}\n")

    except Exception as e:
        print(f"❌ Error al consultar VirusTotal para {url}: {e}")
            
#Todas las modificaciones importantes de los análisis de la API de URLscan
def get_scan_results(uuid, URL_legit_count=0, malicious_URL=0, error_URL=0):
    file_path = "URLsScanningResults.txt"
    legitURLPath = "urlLegit_path.txt"
    maliciousPath= "urlMaliciousDetected.txt"
    time.sleep(15)  # Esperar unos segundos para que termine el escaneo #MIRAR - antes habia 15
    response = requests.get(f"{URLSCAN_RESULT_URL}{uuid}/")

    if response.status_code == 200:
        
        results = response.json()
        
        # Extracción de los datos relevantes
        page_info = results['page']
        task_info = results['task']
        
        # Comprobación de si la URL está marcada como maliciosa
        is_malicious = "malicious" in page_info.get('tags', [])
        
        # Comprobación de si la URL redirige a otro sitio
        redirected_url = page_info.get('redirected', None)
        
        
        # TRIAJE BÁSICO DE URLS en ARCHIVO DE TEXTO
        
        with open(file_path, "a") as file:
        # Imprimir resultados - COMENTADO IMPORTANTE
            file.write("\n######### URLScan Results #########\n")
            file.write(f"URL: {page_info['url']}\n")
            file.write(f"Status: {page_info['status']}\n")
            file.write(f"Domain: {page_info['domain']}\n")
            file.write(f"Country: {page_info['country']}\n")
            file.write(f"City: {page_info['city']}\n")
            file.write(f"IP: {page_info['ip']}\n")
            file.write(f"ASN: {page_info['asn']}\n")
            file.write(f"Report URL: {task_info['reportURL']}\n")
            URL_URLSCAN_Report= (f"Report URL: {task_info['reportURL']}\n")
            file.write(f"UUID: {task_info['uuid']}\n")
        
        # Información adicional - SI ES MALICIOSA SI O NO
        #print(f"Maliciosa: {'Sí' if is_malicious else 'No'}")
        if not is_malicious:
            #valores
            URLSCAN_REPORT=task_info['reportURL']
            URL_legitima_ofuscada=email_obfuscation(page_info['url'])
            timestamp=VT_WHOIS(page_info['domain'])
            #ARREGLAR
            #if "Error" in timestamp or "No se encontró" in timestamp:
            #    timestamp = "Información no disponible"


            domain_=email_obfuscation(page_info['domain'])

            parrafo=f"[!] ALERTA: Se ha detectado las URLs LEGÍTIMAS: {URL_legitima_ofuscada}. La fecha de la creación del dominio {domain_} fue en {timestamp} (si es reciente se considera sospechoso) \n\n Link del scan en URLscan: {URL_URLSCAN_Report}\n\n"
            #print(parrafo)
            with open(legitURLPath, "a") as file:
                file.write(parrafo)
            #prints finales
        

            URL_legit_count = URL_legit_count + 1
# URL MALICIOSA DONDE SE EXPLICA EN DETALLE 
        else:
            #valores
            #valores
            URLSCAN_REPORT=task_info['reportURL']
            URL_maliciosa_ofuscada=email_obfuscation(page_info['url'])
            timestamp=VT_WHOIS(page_info['domain'])
            


            domain_=email_obfuscation(page_info['domain'])

            parrafo=f"[!] ALERTA: Se ha detectado la ULR MALICIOSA: {URL_maliciosa_ofuscada}. La fecha de la creación del dominio {domain_} fue en {timestamp} (si es reciente se considera sospechoso) \n\n Link del scan en URLscan: {URLSCAN_RESULT_URL}\n\n"
            print(parrafo)
            parrafo2=f" En el correo nos encontramos con la siguiente URL MALICIOSA: {URL_maliciosa_ofuscada}. La fecha de la creación del dominio {domain_} fue en {timestamp} (si es reciente se considera sospechoso) \n\n Link del scan en URLscan: {URLSCAN_RESULT_URL}\n\n"
            with open(maliciousPath, "a") as file:
                file.write(parrafo2)
            #prints finales
            malicious_URL += 1   
                  
        #print(is_malicious)
        #print(f"Redirección: {redirected_url if redirected_url else 'No'}")       
    else:
        error_URL += 1
        #print("- ⚠️ ADVERTENCIA: Se ha detectado un error en uno de las URLs. Mira más información en el triaje básico")
        time.sleep(5) #mirar antes habia 5
        with open(file_path, "a") as file:
            file.write("Error al obtener los resultados: {response.status_code}")
        
            error_=json.dumps(response.json(), indent=4)
            file.write(error_)
    return URL_legit_count, malicious_URL, error_URL
    #print(f"Categorizando las URLs analizadas:\n  - {URL_legit_count} URLs legítimas \n - {malicious_URL} URLs maliciosas \n - {error_URL} URLs no analizadas por error de la API de URLscan")
    
def fetch_data(domain):
    
    url = f"{API_URL_DOMAIN}{domain}"
    request = urllib.request.Request(url, headers={'x-apikey': VT_API_KEY1})
    try:
        with urllib.request.urlopen(request) as response:
            return json.load(response)
    except urllib.error.URLError as e:
        print(f"Error al obtener datos: {e}")
        return None
def check_domain_reputation(dominio):
    dominio_ofuscado=email_obfuscation(dominio)
    data = fetch_data(dominio)
    if not data:
        return
    
    attributes = data.get('data', {}).get('attributes', {})
    
    # Información clave
    reputation = attributes.get('reputation', 'N/A')
    categories = ", ".join(attributes.get('categories', {}).values())
    creation_date = attributes.get('creation_date', None)
    date=correct_time(creation_date)
    
    last_analysis_date = attributes.get('last_analysis_date', 'Desconocido')
    
    # Análisis de motores (detecciones)
    analysis_stats = attributes.get('last_analysis_stats', {})
    malicious = analysis_stats.get('malicious', 0)
    total = sum(analysis_stats.values())
    
    # IPs asociadas
    last_dns_records = attributes.get('last_dns_records', [])
    ip_addresses = [record['value'] for record in last_dns_records if record['type'] == 'A']

    # Mostrar resultados
    #MAILINSPECTOR
    with open(MailInspector, "a", encoding="utf-8") as file:
                file.write(f"\n--- Análisis del dominio: {dominio_ofuscado} ---\n")
                file.write(f"🔍 Reputación: {reputation}\n")
                file.write(f"📊 Detecciones: {malicious} / {total}\n")
                file.write(f"🏷️ Categorías: {categories}\n")
                file.write(f"📅 Fecha de creación: {date}\n")

    print(f"\n--- Análisis del dominio: {dominio_ofuscado} ---")

    print(f"🔍 Reputación: {reputation}")
    print(f"📊 Detecciones: {malicious} / {total}")
    print(f"🏷️ Categorías: {categories}")
    #ARREGLAR
    
    
    print(f"📅 Fecha de creación: {date}")
    #print(f"🌐 IPs asociadas: {', '.join(ip_addresses) if ip_addresses else 'Ninguna'}")
    #  
    print(f"\n🔗 Verificar en VirusTotal: https://www.virustotal.com/gui/domain/{dominio}")


#Objetivo que saque el resultado del SPF
def spf(spf_path):


    with open(spf_path, 'r', encoding='utf-8') as f:
        spf_encontrado = "None"
        I =4
        for linea in f:
#SPF--------------------------------------------------------------------------
            if "spf=" in linea:
                spf_encontrado = True
                #print(f"[INFO] Cabecera SPF encontrada:\n{linea.strip()}")
                
                # Análisis del resultado
                if "pass" in linea.lower():
                    I = 1
                    
                    #print("[RESULTADO] ✅ SPF pasa")

                elif "fail" in linea.lower():
                    I = 2
                
                    #print("[RESULTADO] ❌ SPF no pasa")
                elif "softfail" in linea.lower():
                    I = 3
                    
                    #print("[RESULTADO] ⚠️ SPF softfail (posible sospecha)")
                else:
                    I = 4
                    #print("[RESULTADO] ❓ SPF desconocido")
                break

                #print(f"[INFO] Cabecera SPF encontrada:\n{linea.strip()}")
    # Si no se encontró ninguna cabecera SPF
#    if spf_encontrado == "None":
        #TEXTO
        #print("[ALERTA] ⚠️ No se encontró información SPF en el correo.")
 #       print(f"[INFO] Cabecera SPF encontrada:\n{linea.strip()}")
 #       I = 4
    match I:
        case 1:
            #TEXTO

            print("- ✅ SPF pasa: (Sender Policy Framework) es un check de los correos para validar la autenticidad de un mensaje enviado")
            #MAILINSPECTOR
            with open(MailInspector, "a", encoding="utf-8") as file:
                file.write("- ✅ SPF pasa: (Sender Policy Framework) es un check de los correos para validar la autenticidad de un mensaje enviado (1)\n")
        case 2:
            
            print("- ❌ SPF no pasa: (Sender Policy Framework) es un check de los correos para validar la autenticidad de un mensaje enviado")
            #MAILINSPECTOR
            with open(MailInspector, "a", encoding="utf-8") as file:
                file.write("- ❌ SPF no pasa: (Sender Policy Framework) es un check de los correos para validar la autenticidad de un mensaje enviado (2)\n")
        case 3:
            
            print("- ❓ SPF desconocido: (Sender Policy Framework) es un check de los correos para validar la autenticidad de un mensaje enviado")
            #MAILINSPECTOR
            with open(MailInspector, "a",  encoding="utf-8") as file:
                file.write("- ❓ SPF desconocido: (Sender Policy Framework) es un check de los correos para validar la autenticidad de un mensaje enviado (3)\n")

        case 4:
            #TEXTO
            print("- ⚠️ No se encontró información SPF en el correo.")
            #MAILINSPECTOR
            with open(MailInspector, "a", encoding="utf-8") as file:
                file.write("- ⚠️ No se encontró información SPF en el correo.(4)\n")

#DKIM------------------------------------------------
def dkim(dkim_path):


    with open(dkim_path, 'r', encoding='utf-8') as f:
        I = 4
        dkim_encontrado = "None"
        for linea in f:

            if "dkim=" in linea:
                dkim_encontrado = True
                #print(f"[INFO] Cabecera DKIM encontrada:\n{linea.strip()}")
                
                # Análisis del resultado
                if "pass" in linea.lower():
                    I = 1
                    
                    #print("[RESULTADO] ✅ DKIM pasa")

                elif "fail" in linea.lower():
                    I = 2
                
                    #print("[RESULTADO] ❌  no pasa")
                elif "none" in linea.lower():
                    I = 3
                    
                    #print("[RESULTADO] ⚠️ DKIM softfail (posible sospecha)")
                else:
                    I = 4
                    #print("[RESULTADO] ❓ DKIM desconocido")
                break


                #print(f"[INFO] Cabecera SPF encontrada:\n{linea.strip()}")
    # Si no se encontró ninguna cabecera SPF
        #if dkim_encontrado == "None":
        #    I = 4
            #TEXTO
            #print("[ALERTA] ⚠️ No se encontró información DKIM en el correo.")
            #print(f"[INFO] Cabecera SPF encontrada:\n{linea.strip()}")

    match I:
            #TEXTO
        case 1:
            print("- ✅ DKIM pasa: (Domain Keys Identified Mail)  es otro check de los correos para validar la autenticidad de un mensaje enviado.")
            with open(MailInspector, "a", encoding="utf-8") as file:
                file.write("- ✅ DKIM pasa: (Domain Keys Identified Mail)  es otro check de los correos para validar la autenticidad de un mensaje enviado.(1)\n")

        case 2:
                print("- ❌ DKIM no pasa: (Domain Keys Identified Mail)  es otro check de los correos para validar la autenticidad de un mensaje enviado.")
                with open(MailInspector, "a", encoding="utf-8") as file:
                    file.write("- ❌ DKIM no pasa: (Domain Keys Identified Mail)  es otro check de los correos para validar la autenticidad de un mensaje enviado.(2)\n")

        case 3:
            print("- ❓ DKIM desconocido: (Domain Keys Identified Mail)  es otro check de los correos para validar la autenticidad de un mensaje enviado.")
            with open(MailInspector, "a", encoding="utf-8") as file:
                file.write("- ❓ DKIM desconocido: (Domain Keys Identified Mail)  es otro check de los correos para validar la autenticidad de un mensaje enviado.(3)\n")
        case 4:
            print("- ⚠️ No se encontró información DKIM en el correo.")
            with open(MailInspector, "a", encoding="utf-8") as file:
                file.write("- ⚠️ No se encontró información DKIM en el correo.(4)\n")
                

#DMARC----------------------------------------
def dmarc(dmarc_path):

    with open(dmarc_path, 'r', encoding='utf-8') as f:
        dmarc_encontrado = "None"
        I = 4
        for linea in f:

            if "dmarc=" in linea:
                dmarc_encontrado = True
                #print(f"[INFO] Cabecera DMARC encontrada:\n{linea.strip()}")
                
                # Análisis del resultado
                if "pass" in linea.lower():
                    I = 1
                    
                    #print("[RESULTADO] ✅ DMARC pasa")

                elif "fail" in linea.lower():
                    I = 2
                
                    #print("[RESULTADO] ❌ DMARC no pasa")
                elif "none" in linea.lower():
                    I = 3
                    
                    #print("[RESULTADO] ⚠️ DMARC softfail (posible sospecha)")
                else:
                    I = 4
                    #print("[RESULTADO] ❓ DMARC desconocido")
                break


                #print(f"[INFO] Cabecera SPF encontrada:\n{linea.strip()}")
    # Si no se encontró ninguna cabecera SPF
        #if dmarc_encontrado == "None":
            #I = 4
            #TEXTO
            #print("[ALERTA] ⚠️ No se encontró información DMARC en el correo.")
            #print(f"[INFO] Cabecera SPF encontrada:\n{linea.strip()}")

        match I:
            #TEXTO
            case 1:
                print("- ✅ DMARC pasa: (Domain-based Message Authentication, Reporting and Conformance) es el último de los check de los correos para validar la autenticidad de un mensaje.")
                with open(MailInspector, "a", encoding="utf-8") as file:
                    file.write("- ✅ DMARC pasa: (Domain-based Message Authentication, Reporting and Conformance) es el último de los check de los correos para validar la autenticidad de un mensaje.(1)\n")

            case 2:
                print("- ❌ DMARC no pasa: (Domain-based Message Authentication, Reporting and Conformance) es el último de los check de los correos para validar la autenticidad de un mensaje.")
                with open(MailInspector, "a", encoding="utf-8") as file:
                    file.write("- ❌ DMARC no pasa: (Domain-based Message Authentication, Reporting and Conformance) es el último de los check de los correos para validar la autenticidad de un mensaje.(2)\n")

            case 3:
                print(" ❓ DMARC desconocido: (Domain-based Message Authentication, Reporting and Conformance) es el último de los check de los correos para validar la autenticidad de un mensaje.")
                with open(MailInspector, "a", encoding="utf-8") as file:
                    file.write(" ❓ DMARC desconocido: (Domain-based Message Authentication, Reporting and Conformance) es el último de los check de los correos para validar la autenticidad de un mensaje.(3)\n")

            case 4:
                print("- ⚠️ No se encontró información DMARC en el correo.")
                with open(MailInspector, "a", encoding="utf-8") as file:
                    file.write("- ⚠️ No se encontró información DMARC en el correo.(4)\n")
#BUSQUEDA DEL REMITENTE VISIBLE




def spoof_check1(spoof_path):
    remitente_visible = None
    from_header = ""  # Acumulará el encabezado "From:"

    with open(spoof_path, 'r', encoding='utf-8') as f:
        for linea in f:
            linea = linea.strip()

            # Detectar "From:" y acumular líneas plegadas
            if re.match(r"^(From:|X-Dinascanner-From:)", linea, re.IGNORECASE):
                from_header = linea  # Iniciar acumulación
                continue  
            
            # Si hay líneas siguientes sin encabezado, las añadimos
            if from_header and not re.match(r"^\w+: ", linea):  
                from_header += " " + linea  # Agregar línea a la anterior
                continue  
            
            # Si llega otra cabecera (ej: "To:", "Subject:"), procesamos "From:"
            if from_header:
                break  

    # Decodificar MIME si es necesario
    if from_header:
        _, from_content = from_header.split(":", 1)
        decoded_parts = decode_header(from_content.strip())
        
        # Unir partes decodificadas
        from_email = " ".join(
            part.decode(encoding or "utf-8") if isinstance(part, bytes) else part
            for part, encoding in decoded_parts
        ).strip()

        # Extraer el correo ignorando texto adicional
        match = re.search(r'<([\w\.-]+@[\w\.-]+)>', from_email)
        if match:
            return match.group(1)  # Extraer solo el correo dentro de <>
        
        # Si no está entre <>, buscar directamente el correo
        match = re.search(r'[\w\.-]+@[\w\.-]+', from_email)
        if match:
            return match.group(0)

    return remitente_visible  # Retorna None si no encuentra correo

            
#BUSQUEDA DEL REMITENTE SPOOF
def spoof_check2(spoof2_path):
    i=0
    with open(spoof2_path, 'r', encoding='utf-8') as f:
        for linea in f:
            if re.match(r"^return-path:", linea, re.IGNORECASE):
                #prueba1 = next(f).strip()
                #return prueba1
# En este punto por lo que he podido comprobar existen 2 tipos de emails, uno con el spoof en la misma línea y otros que lo indica en la siguiente linea. 
                
                match = re.search(r'[\w\.-]+@[\w\.-]+', linea)
              
                if match:
                    spoof_email = match.group() # Si la expresión regular coincide guarda el resultado en la variable 
                    return spoof_email, True
                    break
                else:
                    spoof_email = next(f).strip()
                    #print (spoof_email)

                    return spoof_email, True
                    break
    return None, False


#Prueba para ver si el spoof ha sido efectivo o no
def spoof_check3(eml_path):
#   Para ver que devuelve el valor del remitente. En caso que falle descomentar el siguiente print.    
    #print(spoof_check1(eml_path))
#   Para ver que devuelve el valor del spoof. En caso que falle descomentar el siguiente print.    
    #print(spoof_check2(eml_path))
    # Obtener remitentes visibles y reales
    remitente_visible = spoof_check1(eml_path)
    remitente_spoof, si_no = spoof_check2(eml_path)
    
    #Archivo para el mensaje final
    spoof_file_path="spoof.txt"

    # Formatear y ofuscar el remitente visible
    remitente_visible_formateado = email_obfuscation(remitente_visible)
    dominio1 = remitente_visible.split('@')[-1] if remitente_visible else None

    # Caso 1: No hay remitente spoofing
    if remitente_spoof is None:
        print("[RESULTADO] ✅ No hay spoofing: El remitente no parece estar manipulado.")
        #MAILINSPECTOR
        with open(MailInspector, "a", encoding="utf-8") as file:
            file.write("\n[RESULTADO] ✅ No hay spoofing: El remitente no parece estar manipulado.\n")


        #print("No se ha detectado ningún spoofing. El remitente parece legítimo.")

        # Verificar reputación del dominio si está disponible
        if dominio1:
            #print(f"[INFO] Dominio extraído: {dominio1}")
            check_domain_reputation(dominio1)
        return

    # Caso 2: Hay remitente spoofing
    remitente_spoof_formateado = email_obfuscation(remitente_spoof)

    # Comparar remitente visible y remitente spoofing
    if remitente_visible == remitente_spoof:
        print("[RESULTADO] ✅ No hay spoofing: El remitente no parece estar manipulado.\n")
        #MAILINSPECTOR
        with open(MailInspector, "a", encoding="utf-8") as file:
            file.write("\n[RESULTADO] ✅ No hay spoofing: El remitente no parece estar manipulado.\n")

        

        if dominio1:
            check_domain_reputation(dominio1)
    else:
        
        print("[ALERTA] ❌ ¡Posible Spoofing detectado!\n")
        print(
            f"En el correo se puede apreciar el remitente visible {remitente_visible_formateado}."
            f"\n Sin embargo, se ha detectado spoofing en el correo. El remitente real es {remitente_spoof_formateado}."
        )

        with open(MailInspector, "a", encoding="utf-8") as file:
            file.write("\n[ALERTA] ❌ ¡Posible Spoofing detectado!\n")

            file.write(
            f"En el correo se puede apreciar el remitente visible {remitente_visible} ."
            f"Sin embargo, se ha detectado spoofing en el correo. El remitente real es {remitente_spoof_formateado}.\n\n")

        print("Análisis del dominio asociado:")
        if dominio1:
            check_domain_reputation(dominio1)
            
#--------------------------------------------------------------------------------------------------------------------------------------------------------------------------
        # Verificar dominio del remitente spoofing
        dominio_spoof = remitente_spoof.split('@')[-1] if remitente_spoof else None
        if dominio_spoof:
            check_domain_reputation(dominio_spoof)

    return

#CAMBIAR----------------------
#ANALISIS DE URLS----------------------------------------------------------------------------------
#Todos las URLs

def extraer_urls_de_eml(eml_path):
    try:
        # Función para extraer URLs con regex
        def extract_urls(text):
            url_pattern = re.compile(r'https?://[^\s<>"]+|www\.[^\s<>"]+')
            return url_pattern.findall(text)

        # Leer el archivo .eml
        with open(eml_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)

        # Extraer el cuerpo del correo
        body = ""
        if msg.is_multipart():
            for part in msg.walk():
                content_type = part.get_content_type()
                if content_type == "text/plain" or content_type == "text/html":
                    body += part.get_content()
        else:
            body = msg.get_payload()

        # Extraer URLs del cuerpo y eliminar duplicados usando un set
        unique_urls = set(extract_urls(body))  # Esto convierte las URLs en un conjunto (sin duplicados)
        
        # Guardar las URLs únicas en una variable global o de tu elección
        global urls_sin_duplicados  # Declaramos la variable global si la necesitas en otras partes del código
        urls_sin_duplicados = list(unique_urls)  # Convertimos el set a lista para uso posterior
        return urls_sin_duplicados

    except Exception as e:
        print(f"Error al procesar el archivo: {e}")
        return []
    

#Analizar URLS --- API URLScan


def urlMaliciousDetected_File():
    file_path = Path("urlMaliciousDetected.txt")  # Crear un objeto Path para la ruta
    if file_path.is_file():  # Verificar si el archivo existe y es un archivo regular
        with file_path.open("r") as file:  # Abrir el archivo usando el método open de Path
            for linea in file:
                print(linea.strip())
                with open(MailInspector, "a", encoding="utf-8") as file:
                    file.write(linea.strip())
                


lock = threading.Lock()

def analizar_urls_VT(urls):
    if not urls:
        return

    # Crear un executor para usar hilos
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:  # 👈 Solo 1 hilo a la vez
        for indice, linea_url in enumerate(urls):
            api = decidir_api_virustotal_por_indice(indice)  # Decide qué API usar cíclicamente
            
            # Limpiar archivo antes de analizar una nueva URL
            with open("API_VT.txt", "w") as file:
                pass  

            future = executor.submit(procesar_url, linea_url, api)
            result = future.result() 
            print("--------------------------------------------------------------------------------------------------------")
            #print(f"DEBUG: Resultado de {linea_url}: {result}") 
            if result:
                analizar_resultados_vt(result['url'])  
                time.sleep(3)




def verificar_presencia_en_archivo(file_path, url):
    """ Verifica si la URL ya ha sido escrita en el archivo. """
    if not os.path.exists(file_path):
        return False
    
    with open(file_path, "r") as file:
        for line in file:
            if url in line:
                return True
    return False



# Función para procesar cada URL
def procesar_url(url, api):
    scan_result = scan_url_with_virustotal(url, api)

    with open("API_VT.txt", "a", encoding="utf-8") as file:
        file.write(f"{scan_result}\n")  # 👈 Guardar el resultado

    return {"url": url, "resultado": scan_result}





def analizar_urls_URLSCAN(urlss):
    URL_legit_count = 0
    malicious_URL = 0
    error_URL = 0
    URL_COUNTS = 0
    analyzed_urls = set()  # Conjunto para almacenar las URLs ya analizadas
    
    if not urlss:
        with open(MailInspector, "a", encoding="utf-8") as file:
            file.write("El correo no presenta URLs para analizar, por lo que no se puede indagar más en este apartado.\n")
        print("El correo no presenta URLs para analizar, por lo que no se puede indagar más en este apartado.")
        return

# Calcular chunk_size de forma segura
    chunk_size = max(1, len(urlss) // 3)
    url_chunks = [urlss[i:i + chunk_size] for i in range(0, len(urlss), chunk_size)]

# Crear la barra de progreso
    pbar = tqdm(total=len(urlss), desc="Analizando las URLs con URLSCAN", unit="URL")

    # Función para analizar un grupo de URLs en cada hilo
    def analizar_chunk(url_chunk):
        nonlocal URL_legit_count, malicious_URL, error_URL, URL_COUNTS
        for indice, linea_url in enumerate(url_chunk):
            if linea_url in analyzed_urls:
                continue

            with lock:
                analyzed_urls.add(linea_url)
                URL_COUNTS += 1

            api = decidir_api_por_indice(indice)
            uuid = scan_url_with_URLSCAN(linea_url, api)
            if uuid:
                legit, mal, err = get_scan_results(uuid)
                with lock:
                    URL_legit_count += legit
                    malicious_URL += mal
                    error_URL += err
            else:
                with lock:
                    error_URL += 1

            if pbar:
                pbar.update(1)

    # Usar ThreadPoolExecutor para ejecutar las funciones en paralelo
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        # Distribuir las tareas entre los hilos
        executor.map(analizar_chunk, url_chunks)

    # Cerrar la barra de progreso al finalizar
    if pbar:
        pbar.close()

    # Escribir los resultados en el archivo
    with open(MailInspector, "a", encoding="utf-8") as file:
        file.write(f"Categorizando las URLs analizadas:\n  - {URL_legit_count} URLs legítimas \n - {malicious_URL} URLs maliciosas \n - {error_URL} URLs no analizadas por error de la API de URLscan\n")
        file.write(f"Número de URLs detectadas: {URL_COUNTS}")
        file.write("\n")
    
    # Imprimir resultados en consola
    print(f"\nCategorizando las URLs analizadas:\n  - {URL_legit_count} URLs legítimas \n - {malicious_URL} URLs maliciosas \n - {error_URL} URLs no analizadas por error de la API de URLscan")
    print("Número de URLs detectadas: ", URL_COUNTS, "")
#Cleaning the files
def clean_analysis_files():
    
    print("🛑 WARNING: Se procederá a borrar los datos del análisis anterior. \nEl creador del script no se hace responsable del uso indebido del mismo.")
    time.sleep(4)
    files_to_check = ["urlLegit_path.txt", "urlMaliciousDetected.txt", "URLsScanningResults.txt", "MailInspector.txt"]
    
    for file_name in files_to_check:
        file_path = Path(file_name)  # Convertir el nombre en un objeto Path
        
        if file_path.exists():  # Verificar si el archivo existe
            file_path.unlink()  # Borrar el archivo
            #print(f"Archivo eliminado: {file_name}")
            #print(f"El archivo no existe: {file_name}")



#AQUÍ ACABA EL ANALISIS DE URLS ----------------------------------------------------------------------------------------------------------------

#Valor de las URLs para analizar


#Mensaje de alerta-------------------------------------------------------------------
#TEXTO

convert_msg_to_eml("correo.msg", "correo.eml")
eml_path = input("Introduce el nombre del correo con su extensión (por ejemplo: mensaje.eml): ").strip()  #Ruta del EML
urls_extraidas = extraer_urls_de_eml(eml_path)

clean_analysis_files()
print("Buenos días \n Se adjunta en el informe de las cabeceras (DKIM, SPF, DMARC) si pasan o no el filtro de correo:\n")
#-------CABECERSAS-----------
spf(eml_path)
dkim(eml_path)
dmarc(eml_path)
print("\n")

#----SPOOF CHECK-----------
spoof_check3(eml_path)

with open(MailInspector, "a", encoding="utf-8") as file:
    file.write("**************************************************\n")
    file.write("**********        URLSCAN | URLS        **********\n")
    file.write("**************************************************\n")
#------ANALISIS URLS-------
analizar_urls_URLSCAN(urls_extraidas)

#------ANALISIS URLS VT-----
with open(MailInspector, "a", encoding="utf-8") as file:
    file.write("\n**************************************************\n")
    file.write("**********      VIRUS TOTAL - URLS      **********\n")
    file.write("**************************************************\n")
analizar_urls_VT(urls_extraidas)

#Análisis de URLs legítimas:
print("\n")
#Muestra por pantalla la info de las URLs maliciosas
urlMaliciousDetected_File()

analizar_hashes_eml(eml_path, VT_API_KEY1)

#TEXTO FINAL NO TECNICO ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
def print_separator(title="Posible notificación con tecnicismos"):
    width = 40  # Ancho fijo de la caja
    title = f" {title} "  # Espacios alrededor del título
    print("*" * width)
    print(f"*{title.center(width - 2)}*")
    print("*" * width)

# Ejemplo de uso
print("\n\n")
print_separator()



def AnalisisCabeceras():
    # Nombre del archivo
    file_name = "MailInspector.txt"

    try:
        # Abrir el archivo en modo lectura
        with open(file_name, "r", encoding="utf-8") as file:
            # Leer todas las líneas del archivo
            lines = file.readlines()

            # Variables para verificar anomalías
            anomalies_found = False

            # Expresión regular para extraer el valor entre paréntesis
            pattern = r"\(\d+\)$"  # Busca un número entre paréntesis al final de la línea

            # Analizar cada línea para identificar el estado de las verificaciones
            for line in lines:
                # Buscar el número entre paréntesis
                match = re.search(pattern, line.strip())
                if match:
                    status = match.group(0)  # Extraer el valor entre paréntesis
                    # Si no es "(1)", marcarlo como anomalía
                    if status != "(1)":
                        anomalies_found = True

            # Si se encontraron anomalías, indicar el mensaje correspondiente
            if anomalies_found:
                print(f"\nSe detectaron anomalías en las cabeceras del correo, lo que podría indicar problemas con las verificaciones de seguridad..\n")
            else:
                print("\nNo se encontraron problemas en las cabeceras del correo, lo que significa que el mensaje pasó correctamente las comprobaciones de seguridad.\n")

    except FileNotFoundError:
        print(f"El archivo '{file_name}' no se encontró.")

def separarDetecciones(sLinea):
    global CONTADOR_IOCS
    match_detecciones = re.search(r"Detecciones:\s*(\d+)\s*/\s*\d+", sLinea)
    if match_detecciones:
        detecciones = int(match_detecciones.group(1))
        if detecciones == 0 or detecciones == 1:
            return(f"Según fuentes abiertas de reputación, no se han identificado indicios de actividad maliciosa en el dominio del remitente.\n")
        elif detecciones >= 2:
            CONTADOR_IOCS = 1
            return(f"[ALERTA] Según fuentes abiertas de reputación, el dominio del remitente tiene {detecciones} detecciones en Virus Total, lo que indica actividad sospechosa! [ALERTA]")
        else:
            return("ERROR: El programa ha detectado un carácter no numérico o un número negativo.")
    else:
        return(" ERROR: No se encontró información sobre el número de detecciones.")

#TESTEAR 

def verificar_spoofing():
    # Nombre del archivo
    file_name = "MailInspector.txt"
    COUNT = 0

    try:
        # Abrir el archivo en modo lectura
        with open(file_name, "r", encoding="utf-8") as file:
            # Leer todas las líneas del archivo
            lines = file.readlines()

            # Recorrer las líneas y verificar si contiene "No hay spoofing:"
            for i, line in enumerate(lines):
                line = line.strip()  # Eliminar espacios y saltos de línea al principio y al final

                # Si se encuentra "No hay spoofing:"
                if "No hay spoofing:" in line:
                    print("El remitente no está siendo manipulado mediante técnicas de spoofing. Esto significa que el nombre del remitente es auténtico y no se está utilizando para enviar correos falsos o masivos de SPAM.")
                    COUNT = 1  # Activar el contador

                if COUNT == 1:
                    if "Detecciones: " in line:
                        sMensajeReputacion = separarDetecciones(line)
                        print(sMensajeReputacion)
                        COUNT = 0
                    
                # Verificar si se detecta "Posible Spoofing detectado!"
                if "¡Posible Spoofing detectado!" in line:
                    COUNT = 2
                    # Imprimir la línea siguiente con la información del remitente
                    sLineaRemitentes = lines[i + 1].strip()  # Línea siguiente al mensaje de alerta
                    # Limpiar la línea de ofuscaciones (por ejemplo, [.] se convierte en .)
                    sLineaRemitentes = sLineaRemitentes.replace("[.]", ".")
                    # Intentar hacer match con la expresión regular para capturar remitente visible y real
                    match_visible_spoof = re.search(
                        r"remitente visible\s([\w=.+-]+@[\w.-]+)\s.*remitente real es\s([\w=.+-]+@[\w.-]+)", 
                        sLineaRemitentes
                    )

                    if match_visible_spoof:
                        remitente_visible_ofuscado = email_obfuscation(match_visible_spoof.group(1))
                        remitente_real_ofuscado = email_obfuscation(match_visible_spoof.group(2))

                        print("> Se ha detectado un posible intento de suplantación de identidad (spoofing) en el correo. El nombre del remitente visible no corresponde al remitente real, lo que podría ser un intento de engaño para enviar spam o robar información.")
                    
                        sLineaReputacion1 = lines[i + 6].strip()
                        sMensajeReputacion1 = separarDetecciones(sLineaReputacion1)
                        print("\n> El remitente VISIBLE del correo ("+remitente_visible_ofuscado+"): "+sMensajeReputacion1)

                        sLineaReputacion2 = lines[i + 12].strip()
                        sMensajeReputacion2 = separarDetecciones(sLineaReputacion2)
                        print("\n> El remitente SPOOF del correo ("+remitente_real_ofuscado+"): "+sMensajeReputacion2+"\n")

    except FileNotFoundError:
        print(f"El archivo '{file_name}' no se encontró.")
    except Exception as e:
        print(f"Se ha producido un error: {e}")

#TESTEAR
def analizar_urls_APIvt():
    urls_maliciosas = []
    urls_legitimas = []

    with open("MailInspector.txt", "r", encoding="utf-8") as file:
        for linea in file:
            match = re.search(r"URL:\s(.+?)\s\(\d+\s+harmless, \d+\s+undetected, (\d+)\s+malicious", linea)
            if match:
                url = match.group(1)
                malicious_count = int(match.group(2))

                if malicious_count > 1:
                    urls_maliciosas.append(url)
                else:
                    urls_legitimas.append(url)

    # Mostrar resultados

    if urls_maliciosas:
        for url in urls_maliciosas:
            #Se podría ofuscar
            print(f"[WARNING] La URL {url} es maliciosa según Virus Total.")
    else:
        print("No hay URLs maliciosas tras el análisis utilizando la API de VT")

def analizar_urls():
    # Nombre del archivo de análisis
    file_name = "MailInspector.txt"

    # Variables para contar cada tipo de URL
    total_urls = 0
    urls_legitimas = 0
    urls_maliciosas = 0
    urls_no_analizadas = 0

    try:
        with open(file_name, "r", encoding="utf-8") as file:
            for line in file:
                line = line.strip()

                # Capturar URLs legítimas
                match_legitimas = re.search(r"(\d+)\sURLs legítimas", line)
                if match_legitimas:
                    urls_legitimas = int(match_legitimas.group(1))

                # Capturar URLs maliciosas
                match_maliciosas = re.search(r"(\d+)\sURLs maliciosas", line)
                if match_maliciosas:
                    urls_maliciosas = int(match_maliciosas.group(1))

                # Capturar URLs no analizadas
                match_no_analizadas = re.search(r"(\d+)\sURLs no analizadas", line)
                if match_no_analizadas:
                    urls_no_analizadas = int(match_no_analizadas.group(1))

                # Capturar total de URLs detectadas
                match_total = re.search(r"Número de URLs detectadas:\s(\d+)", line)
                if match_total:
                    total_urls = int(match_total.group(1))

        # Mensaje con los resultados
        #print(f"\nSe han detectado {total_urls} URLs totales en el correo. ")
        #print(f"- {urls_legitimas} se categorizan como no sospechosas.")
        #print(f"- {urls_maliciosas} se categorizan como maliciosas.")
        #print(f"- {urls_no_analizadas} no han podido ser catalogadas debido a limitaciones de la API de URLscan.")
        print(f"Se han detectado {total_urls} URLs en el correo, de las cuales {urls_legitimas} se categorizan como no sospechosas, {urls_maliciosas} son maliciosas y {urls_no_analizadas} no han podido ser catalogadas debido a limitaciones de la propia API de URLscan.")
    except FileNotFoundError:
        print(f"El archivo '{file_name}' no se encontró.")
    except Exception as e:
        print(f"Se ha producido un error: {e}")

# Ejecutar la función


def verificar_urls(archivo):
    try:
        with open(archivo, "r", encoding="utf-8") as file:
            contenido = file.read()  # Leer todo el archivo

            if "El correo no presenta URLs para analizar, por lo que no se puede indagar más en este apartado." in contenido:
                print("El análisis del correo no ha identificado URLs para su evaluación, lo que imposibilita una inspección más detallada en este apartado.")
            else:
                analizar_urls()
                analizar_urls_APIvt()

    except FileNotFoundError:
        print(f"El archivo '{archivo}' no se encontró.")
    except Exception as e:
        print(f"Se ha producido un error: {e}")

#CUIDADO CON EL "s90" del regex porque seguramente no sea ese
def analizar_hashes():
    # Bandera para indicar si se encontró la sección de hashes
    found_hash_section = False
    malicious_hash_count = 0
    file_name = "MailInspector.txt"
    with open(file_name, "r", encoding="utf-8") as file:
        lines = file.readlines()
        for line in lines:
            line = line.strip()  # Eliminar espacios y saltos de línea

            if "No se encontraron hashes en el correo." in line:
            # Si se detecta que no se encontraron hashes, no hacer nada
                return

            if "Resultados de los hashes:" in line:
                found_hash_section = True
                continue

            if found_hash_section:
            # Buscar hashes y sus resultados
                match = re.search(r"-\s\((\w+)\)\s-\sVT\s\((\d+)/(\d+)\)\s+detecciones", line)
                if match:
                    hash_value = match.group(1)
                    detections = int(match.group(2))
                    if detections > 2:
                        print(f"Hash malicioso encontrado: {hash_value}")
                        malicious_hash_count += 1

    if not malicious_hash_count:
        print("No se detectó actividad maliciosa en los hashes de los archivos adjuntos según el análisis de VirusTotal")

def CONTENCION():
    print("\n\nRECOMENDACIONES DE CONTENCIÓN:")
    print("- Si el remitente no es reconocido o el correo parece sospechoso, elimine el mensaje de la bandeja de entrada y vacíe la carpeta de \"Elementos eliminados\" de inmediato para evitar riesgos.")
    print("- No interactúe con correos que soliciten información personal, financiera o credenciales de acceso sin haber verificado su autenticidad.")
    print("- Si tiene dudas sobre la legitimidad de los enlaces o archivos adjuntos, no abra ningún enlace ni archivo")
    print("- Mantenga su software actualizado para mejorar la protección contra posibles amenazas.")



        #print("- Elimine el correo de la bandeja de entrada si el remitente no es reconocido o parece sospechoso, para mitigar riesgos de seguridad.")
        #print("- Evite interactuar con correos que soliciten información personal, financiera o credenciales de acceso sin verificar la autenticidad del mensaje.")
       
        #print("Evite interactuar con correos sospechosos que soliciten información personal, financiera o credenciales de acceso sin verificar su autenticidad.")

    
    

    #print("- Si el correo es sospechoso y no puede verificar su legitimidad, elimínelo inmediatamente y vacíe la carpeta de \"Elementos eliminados\" para evitar su recuperación no autorizada.")

# Llamar a las funciones
AnalisisCabeceras()
verificar_spoofing()
verificar_urls("MailInspector.txt")
analizar_hashes()
 
CONTENCION()

#-------------------------------------------------------------------------------------------------------------------------------------------------

def print_separator(title="Posible notificación sin tecnicismos"):
    width = 40  # Ancho fijo de la caja
    title = f" {title} "  # Espacios alrededor del título
    print("*" * width)
    print(f"*{title.center(width - 2)}*")
    print("*" * width)

# Ejemplo de uso
print("\n\n")
print_separator()


def separarDetecciones2(sLinea):
    global CONTADOR_IOCS 
    match_detecciones = re.search(r"Detecciones:\s(\d+)\s/\s(\d+)", sLinea)
    if match_detecciones:
        detecciones = int(match_detecciones.group(1))
        if detecciones == 0 or detecciones == 1:
            return 0
        elif detecciones >= 2:
            CONTADOR_IOCS+=1
            return 1
    return None

def analisis_detodo():
    global CONTADOR_IOCS
    # Estructura:
    # Primero verificar URLs maliciosas, si no pasar a lo siguiente:
    # Verificar hashes, si no pasar a lo siguiente:
    # Verificar cabeceras de correo
    file_name = "MailInspector.txt"
    urls_maliciosas = []
    
    CONTADOR_anomalias = 0
    with open(file_name, "r", encoding="utf-8") as file:
        lines = file.readlines()
        for linea in lines:
            match = re.search(r"URL:\s(.+?)\s\(\d+\s+harmless, \d+\s+undetected, (\d+)\s+malicious", linea)
            if match:
                url = match.group(1)
                malicious_count = int(match.group(2))

                if malicious_count > 1:
                    urls_maliciosas.append(url)
                    CONTADOR_IOCS +=1

        if urls_maliciosas:
            CONTADOR_IOCS +=1

# URLS URLSCAN
        for line in lines:
            line = line.strip()

                # Capturar URLs maliciosas
            match_maliciosas = re.search(r"(\d+)\sURLs maliciosas", line)
            if match_maliciosas:
                urls_maliciosas = int(match_maliciosas.group(1))
                if urls_maliciosas > 1:
                    CONTADOR_IOCS += 1

#analisis de hashes

        found_hash_section = False
        malicious_hash_count = 0
        
        for line in lines:
            line = line.strip()  # Eliminar espacios y saltos de línea
            if "Resultados de los hashes:" in line:
                found_hash_section = True
                
                if found_hash_section:
                # Buscar hashes y sus resultados
                    match = re.search(r"-\s\((\w+)\)\s-\sVT\s\((\d+)/(\d+)\)\s+detecciones", line)
                    if match:
                        hash_value = match.group(1)
                        detections = int(match.group(2))
                        if detections > 1:
                            CONTADOR_IOCS +=1
                 
#CABECERAS
            # Variables para verificar anomalías
        anomalies_found = False

            # Expresión regular para extraer el valor entre paréntesis
        pattern = r"\(\d+\)$"  # Busca un número entre paréntesis al final de la línea

            # Analizar cada línea para identificar el estado de las verificaciones
        for line in lines:
                # Buscar el número entre paréntesis
            match = re.search(pattern, line.strip())
            if match:
                status = match.group(0)  # Extraer el valor entre paréntesis
                # Si no es "(1)", marcarlo como anomalía
                if status != "(1)" and status !="(4)" :
                    anomalies_found = True
                    CONTADOR_anomalias +=1

                  
#Correo malicioso?
    if CONTADOR_IOCS > 0:
        #with open(MailInspector, "a", encoding="utf-8") as file_name:
         #   file_name.write("\nNo se encontraron hashes en el correo.")
        print(f"Estimado usuario,\n")
        print("\nQueremos informarle que hemos realizado un análisis en el correo electrónico recibido y hemos identificado características que podrían indicar que el mensaje es malicioso. Le recomendamos proceder con precaución y evitar interactuar con cualquier enlace o archivo adjunto.\n\n")
        CONTENCION()

        print(f"\n\nSi necesita asistencia adicional o tiene alguna pregunta, no dude en ponerse en contacto con nosotros.\n")
        print(f"\nMuchas gracias y un saludo.")


    else:
        #En este punto no se han detectado IOCs maliciosos
        if CONTADOR_anomalias > 0:
            
            print(f"\nLe informamos de que hemos detectado ciertas anomalías en el correo electrónico recibido. Estas anomalías podrían indicar un intento de suplantación o actividad sospechosa. Le recomendamos proceder con precaución y evitar interactuar con cualquier enlace o archivo adjunto.")

            CONTENCION()

            print(f"\n Estamos disponibles para brindarle el apoyo necesario y aclarar cualquier duda que pueda tener.")
            print(f"\nMuchas gracias, y un saludo.")
        else:
            #Si se llega a este punto, el correo podría ser legítimo
            print(f"\nTras realizar un análisis exhaustivo del correo electrónico recibido, no hemos encontrado ningún indicio de actividad sospechosa o maliciosa. Sin embargo, le recomendamos proceder con precaución.")
            print(f"\nSi el correo no era esperado o no reconoce al remitente, le sugerimos eliminar el mensaje de su bandeja de entrada para evitar cualquier posible riesgo en el futuro.")
            
            CONTENCION()

            print(f"\n Quedamos a su disposición para cualquier consulta adicional.")
            print(f"Muchas gracias, y un saludo.")

analisis_detodo()

