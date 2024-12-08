import json 
import nmap
import csv
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
import multiprocessing
import ipaddress
import re

# Clase para manejar la base de datos de vulnerabilidades desde un archivo JSON
class VulnerabilityDatabase:
    def __init__(self, archivo="vulnerabilidades.json"):
        self.archivo = archivo
        self.vulnerabilidades = self._cargar_vulnerabilidades_json()

    def _cargar_vulnerabilidades_json(self):
        try:
            with open(self.archivo, "r") as f:
                return json.load(f).get("vulnerabilities", [])
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print("Error al cargar el archivo de vulnerabilidades:", e)
            return []

    def obtener_vulnerabilidad_por_servicio(self, servicio):
        for vulnerabilidad in self.vulnerabilidades:
            if vulnerabilidad["service"] == servicio:
                return vulnerabilidad
        return {
            "risk_level": "Bajo",
            "description": "No se encontraron vulnerabilidades especificas.",
            "mitigation": "Actualizar servicios y cerrar puertos innecesarios."
        }

# Clase base para representar problemas de seguridad o conectividad
class SecurityIssues:
    def __init__(self, direccion_ip, tipo_problema, mitigacion):
        self.direccion_ip = direccion_ip
        self.tipo_problema = tipo_problema
        self.mitigacion = mitigacion
    
    def __repr__(self):
        return f"IP: {self.direccion_ip}, Tipo de Problema: {self.tipo_problema}, Mitigacion: {self.mitigacion}"

# Clase para representar problemas de conectividad
class ConnectionIssues(SecurityIssues):
    def __init__(self, direccion_ip, estado_conexion):
        mitigacion = "Revisar la conexion del dispositivo." if estado_conexion == "down" else "Conexion estable."
        super().__init__(direccion_ip, "Conectividad", mitigacion)
        self.estado_conexion = estado_conexion

    def ver_info(self):
        return {
            "IP": self.direccion_ip,
            "Puerto": "-",
            "Servicio": "Conectividad",
            "Nivel de Riesgo": "-",
            "Descripcion": f"Estado de Conexion: {self.estado_conexion}",
            "Mitigacion": self.mitigacion
        }

# Clase para representar vulnerabilidades detectadas
class Vulnerability(SecurityIssues):
    def __init__(self, direccion_ip, puerto, servicio, db):
        vulnerabilidad = db.obtener_vulnerabilidad_por_servicio(servicio)
        nivel_riesgo = vulnerabilidad["risk_level"]
        descripcion = vulnerabilidad["description"]
        mitigacion = vulnerabilidad["mitigation"]
        
        super().__init__(direccion_ip, "Vulnerabilidad", mitigacion)
        self.puerto = puerto
        self.servicio = servicio
        self.nivel_riesgo = nivel_riesgo
        self.descripcion = descripcion

    def ver_info(self):
        return {
            "IP": self.direccion_ip,
            "Puerto": self.puerto,
            "Servicio": self.servicio,
            "Nivel de Riesgo": self.nivel_riesgo,
            "Descripcion": self.descripcion,
            "Mitigacion": self.mitigacion
        }

    def __repr__(self):
        return (f"IP: {self.direccion_ip}, Tipo: {self.tipo_problema}, Puerto: {self.puerto}, "
                f"Servicio: {self.servicio}, Nivel de Riesgo: {self.nivel_riesgo}, "
                f"Descripcion: {self.descripcion}, Mitigacion: {self.mitigacion}")

# Función para dividir el rango de IPs
def dividir_rango_ip(rango_cidr, num_segmentos):
    """Divide un rango CIDR en subredes más pequeñas."""
    red = ipaddress.ip_network(rango_cidr, strict=False)
    subredes = list(red.subnets(new_prefix=(red.prefixlen + num_segmentos.bit_length())))
    return [str(subred) for subred in subredes]
    
# Clase principal para realizar el escaneo de red
class NetworkScanner:
    def __init__(self, rango_ip, tipo_escaneo, db):
        # Validar rango de IP antes de continuar
        try:
            self.rango_ip = str(ipaddress.ip_network(rango_ip, strict=False))
        except ValueError:
            raise ValueError(f"El rango de IP '{rango_ip}' es inválido. Use el formato CIDR (ejemplo: 192.168.0.0/24).")
        
        self.tipo_escaneo = tipo_escaneo
        self.db = db
        self.problemas = []

    def escanear_red(self):
        if self.tipo_escaneo == "vulnerabilidades":
            self.escanear_vulnerabilidades()
        elif self.tipo_escaneo == "conectividad":
            self.escanear_conectividad()
        else:
            raise ValueError(f"Tipo de escaneo '{self.tipo_escaneo}' no reconocido. Use 'vulnerabilidades' o 'conectividad'.")
    def escanear_conectividad(self):
        scanner = nmap.PortScanner()
        print(f"Iniciando escaneo de conectividad en el rango {self.rango_ip}...")
        try:
            scanner.scan(hosts=self.rango_ip, arguments='-sn')
            if not scanner.all_hosts():
                print(f"No se detectaron dispositivos en el rango {self.rango_ip}.")
            for ip in scanner.all_hosts():
                estado = scanner[ip].state()
                problema_conectividad = ConnectionIssues(ip, estado)
                self.problemas.append(problema_conectividad)
        except nmap.PortScannerError as e:
            print(f"Error específico de Nmap durante el escaneo de conectividad: {e}")
        except OSError as e:
            print(f"Error de sistema al intentar ejecutar Nmap en {self.rango_ip}: {e}")
        except Exception as e:
            print(f"Error inesperado durante el escaneo de conectividad en {self.rango_ip}: {e}")

    def escanear_subrango(self, subrango):
        scanner = nmap.PortScanner()
        problemas = []
        try:
            scanner.scan(hosts=subrango, arguments='-sS -p 1-2000 --max-retries 50 --host-timeout 100s')
            for ip in scanner.all_hosts():
                for proto in scanner[ip].all_protocols():
                    for puerto in scanner[ip][proto].keys():
                        service_info = scanner[ip][proto][puerto]
                        servicio = service_info['name']
                        problema_vulnerabilidad = Vulnerability(ip, puerto, servicio, self.db)
                        problemas.append(problema_vulnerabilidad)

        except nmap.PortScannerError as e:
            print(f"Error específico de Nmap durante el escaneo en {subrango}: {e}")
        except Exception as e:
            print(f"Error durante el escaneo en {subrango}: {e}")
        return problemas

    def escanear_vulnerabilidades(self):
        print(f"Iniciando escaneo de vulnerabilidades en el rango {self.rango_ip}...")
        subrangos = dividir_rango_ip(self.rango_ip, num_segmentos=4)
        if not subrangos:
            return
        # Número dinámico de procesos según los núcleos de la CPU
        num_procesos = min(4, multiprocessing.cpu_count())
        with multiprocessing.Pool(processes=num_procesos) as pool:
            resultados = pool.map(self.escanear_subrango, subrangos)
            
        for resultado in resultados:
            self.problemas.extend(resultado)

    def obtener_problemas(self):
        return self.problemas

# Clase para generar reportes
class ReportGenerator:
    def __init__(self, scanner):
        self.scanner = scanner
        self.report_data = [issue.ver_info() for issue in scanner.obtener_problemas()]

    def exportar_a_csv(self, nombre_archivo="reporte.csv"):
        try:
            ruta_archivo = os.path.join(os.getcwd(), nombre_archivo)
            with open(ruta_archivo, mode="w", newline="") as file:
                writer = csv.DictWriter(file, fieldnames=["IP", "Puerto", "Servicio", "Nivel de Riesgo", "Descripcion", "Mitigacion"])
                writer.writeheader()
                last_ip = None
                for data in self.report_data:
                    if last_ip and data["IP"] != last_ip:
                        writer.writerow({})
                    writer.writerow(data)
                    last_ip = data["IP"]
            print(f"Reporte CSV guardado como {nombre_archivo}")
        except (OSError, IOError) as e:
            print(f"Error al escribir el archivo CSV {nombre_archivo}: {e}")
        except Exception as e:
            print(f"Error inesperado al generar el reporte CSV: {e}")

    def exportar_a_html(self, nombre_archivo="reporte.html"):
        try:
            ruta_archivo = os.path.join(os.getcwd(), nombre_archivo)
            with open(ruta_archivo, mode="w") as file:
                file.write("<html><head><style>")
                file.write("table { width: 100%; border-collapse: collapse; }")
                file.write("th, td { padding: 10px; text-align: left; }")
                file.write("th { background-color: #4CAF50; color: white; }")
                file.write("tr:nth-child(even) { background-color: #f2f2f2; }")
                file.write("</style></head><body><h2>Reporte de Vulnerabilidades y Conectividad</h2>")
                
                last_ip = None
                for data in self.report_data:
                    if last_ip != data["IP"]:
                        if last_ip:
                            file.write("</table><br>")
                        file.write(f"<h3>IP: {data['IP']}</h3>")
                        file.write("<table border='1'><tr><th>Puerto</th><th>Servicio</th><th>Nivel de Riesgo</th><th>Descripcion</th><th>Mitigacion</th></tr>")
                        last_ip = data["IP"]
                        
                    file.write("<tr>" + "".join(f"<td>{data[campo]}</td>" for campo in data if campo != "IP") + "</tr>")
                file.write("</table>")
                file.write("<br><br><button onclick=\"window.location.href='/'\">Realizar otro escaneo</button>")
                file.write("</body></html>")
            print(f"Reporte HTML guardado como {nombre_archivo}")
        except (OSError, IOError) as e:
            print(f"Error al escribir el archivo HTML {nombre_archivo}: {e}")
        except Exception as e:
            print(f"Error inesperado al generar el reporte HTML: {e}")

    def exportar_a_txt(self, nombre_archivo="reporte.txt"):
        try:
            ruta_archivo = os.path.join(os.getcwd(), nombre_archivo)
            with open(ruta_archivo, mode="w") as file:
                last_ip = None
                for data in self.report_data:
                    if last_ip != data["IP"]:
                        if last_ip:
                            file.write("\n" + "-"*40 + "\n\n")
                        file.write(f"IP: {data['IP']}\n")
                        last_ip = data["IP"]
                    file.write(f"  Puerto: {data['Puerto']}, Servicio: {data['Servicio']}, Nivel de Riesgo: {data['Nivel de Riesgo']}\n")
                    file.write(f"  Descripcion: {data['Descripcion']}\n")
                    file.write(f"  Mitigacion: {data['Mitigacion']}\n\n")
            print(f"Reporte TXT guardado como {nombre_archivo}")
        except (OSError, IOError) as e:
            print(f"Error al escribir el archivo TXT {nombre_archivo}: {e}")
        except Exception as e:
            print(f"Error inesperado al generar el reporte TXT: {e}")

# Clase para enviar notificaciones:
class Notifier:
    def __init__(self, admin_contacto):
        if not self.validar_correo(admin_contacto):
            raise ValueError(f"Correo inválido: {admin_contacto}. Por favor, ingrese un correo válido.")
        self.admin_contacto = admin_contacto
        self.vulnerabilidades_criticas = []

    @staticmethod
    def validar_correo(correo):
        """Valida el formato del correo electrónico para cualquier dominio."""
        patron = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        return re.match(patron, correo) is not None

    def filtrar_VulCritica(self, scanner):
        """Filtra las vulnerabilidades críticas con nivel de riesgo 'Alto' o 'Medio'."""
        self.vulnerabilidades_criticas = [
            problema for problema in scanner.obtener_problemas()
            if isinstance(problema, Vulnerability) and problema.nivel_riesgo in ["Alto", "Medio"]
        ]
        print(f"Vulnerabilidades críticas encontradas: {len(self.vulnerabilidades_criticas)}")

    def enviar_notificacion(self, report_generator):
        """Envía los reportes generados al correo del administrador o un mensaje indicando 'Sin vulnerabilidades'."""
        # Configuración del correo
        remitente = "cuentaprueba96uni@gmail.com"
        destinatario = self.admin_contacto
        asunto = "Reporte de Vulnerabilidades Críticas"

        # Crear el mensaje
        mensaje = MIMEMultipart()
        mensaje["From"] = remitente
        mensaje["To"] = destinatario
        mensaje["Subject"] = asunto

        # Verificar si hay vulnerabilidades críticas
        if not self.vulnerabilidades_criticas:
            cuerpo = "Sin vulnerabilidades críticas detectadas."
            mensaje.attach(MIMEText(cuerpo, "plain"))
        else:
            cuerpo = "Se adjuntan los reportes generados del escaneo de red con las vulnerabilidades críticas."
            mensaje.attach(MIMEText(cuerpo, "plain"))

            # Adjuntar archivos
            archivos = [
                "reporte_vulnerabilidades.csv",
                "reporte_vulnerabilidades.html",
                "reporte_vulnerabilidades.txt"
            ]
            for archivo in archivos:
                ruta_archivo = os.path.join(os.getcwd(), archivo)
                if os.path.exists(ruta_archivo):
                    with open(ruta_archivo, "rb") as adjunto:
                        parte = MIMEBase("application", "octet-stream")
                        parte.set_payload(adjunto.read())
                        encoders.encode_base64(parte)
                        parte.add_header(
                            "Content-Disposition",
                            f"attachment; filename={archivo}",
                        )
                        mensaje.attach(parte)

        # Conexión al servidor SMTP de Gmail
        try:
            with smtplib.SMTP("smtp.gmail.com", 587) as servidor:
                servidor.starttls()
                servidor.login(remitente, "zskonccweaaflznc")
                servidor.send_message(mensaje)
                print(f"Notificación enviada a {destinatario}.")
        except Exception as e:
            print(f"Error al enviar el correo: {e}")


def ejecutar_escaner(rango_ips, tipo_escaneo, enviar_reporte, correo=None):
    # Instanciar la base de datos de vulnerabilidades
    vuln_db = VulnerabilityDatabase()
    scanner = NetworkScanner(rango_ips, tipo_escaneo, vuln_db)

    # Ejecutar el escaneo
    scanner.escanear_red()

    # Generar reportes
    report_generator = ReportGenerator(scanner)
    report_generator.exportar_a_csv("reporte_vulnerabilidades.csv")
    report_generator.exportar_a_html("reporte_vulnerabilidades.html")
    report_generator.exportar_a_txt("reporte_vulnerabilidades.txt")

    # Enviar reporte por correo si se seleccionó la opción "Sí"
    if enviar_reporte == 'si' and correo:
        notifier = Notifier(correo)
        notifier.filtrar_VulCritica(scanner)
        notifier.enviar_notificacion(report_generator)
        return f"Reporte enviado al correo: {correo}"
    else:
        return "Escaneo completado. Mostrando el reporte HTML en pantalla."












# Ejemplo de uso
#if __name__ == '__main__':
#    rango_ips = '192.168.181.0/24'
 #   tipo_escaneo = 'vulnerabilidades'  # Cambia a 'vulnerabilidades' para el escaneo de vulnerabilidades
#
 #   vuln_db = VulnerabilityDatabase()
  #  scanner = NetworkScanner(rango_ips, tipo_escaneo, vuln_db)

#    scanner.escanear_red()

 #   report_generator = ReportGenerator(scanner)
#  report_generator.exportar_a_csv("reporte_vulnerabilidades.csv")
 #   report_generator.exportar_a_html("reporte_vulnerabilidades.html")
  #  report_generator.exportar_a_txt("reporte_vulnerabilidades.txt")
    
   # notifier = Notifier("piero.aliaga.f@uni.pe")
    #notifier.filtrar_VulCritica(scanner)
    #notifier.enviar_notificacion(report_generator)
