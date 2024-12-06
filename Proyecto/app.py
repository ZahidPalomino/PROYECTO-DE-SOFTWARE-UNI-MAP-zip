from flask import Flask, request, render_template, send_file, flash, redirect, url_for
import os
import re  # Para la validación de correo y rango IP

# Importa tus clases del escáner de red
from escanerNMAP import VulnerabilityDatabase, NetworkScanner, ReportGenerator, Notifier

app = Flask(__name__)
app.secret_key = 'tu_clave_secreta'  # Necesario para usar 'flash()'

# Ruta para mostrar la página HTML
@app.route('/')
def index():
    return render_template('index.html')

# Ruta para manejar el envío del formulario
@app.route('/scan', methods=['POST'])
def scan():
    # Obtener datos del formulario
    rango_ips = request.form['rango_ip']
    tipo_escaneo = request.form['tipo_escaneo']
    enviar_reporte = request.form['enviar_reporte']
    correo = request.form.get('correo', None)

    try:
        # Validación del rango de IP (CIDR)
        if not re.match(r"^([0-9]{1,3}\.){3}[0-9]{1,3}\/([0-9]|[1-2][0-9]|3[0-2])$", rango_ips):
            # Si el formato del rango IP no es válido, mostramos un mensaje de error
            flash('Formato de rango IP incorrecto. Debe ser en formato CIDR (Ejemplo: 192.168.0.0/24)', 'error')
            return redirect(url_for('index'))  # Redirige a la misma página

        # Validación del correo (si el reporte se va a enviar por correo)
        if enviar_reporte == 'si' and correo:
            # Expresión regular para validar que el correo sea de tipo Gmail (más robusta)
            if not re.match(r"^[a-zA-Z0-9._%+-]+@gmail\.com$", correo):
                flash('Vuelve a ingresar tu correo (debe ser un correo válido de Gmail)', 'error')
                return redirect(url_for('index'))  # Redirige a la misma página

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

        # Verificar si se debe enviar el reporte por correo
        if enviar_reporte == 'si' and correo:
            notifier = Notifier(correo)
            notifier.filtrar_VulCritica(scanner)
            notifier.enviar_notificacion(report_generator)
            mensaje = f"Escaneo completado y reporte enviado al correo: {correo}."
        else:
            mensaje = "Escaneo completado. Mostrando el reporte en pantalla."

        # Mostrar el reporte HTML generado directamente
        return send_file("reporte_vulnerabilidades.html", as_attachment=False)

    except Exception as e:
        # Capturamos cualquier excepción que ocurra y la mostramos en el servidor
        print(f"Error al procesar la solicitud: {e}")
        flash('Ocurrió un error al procesar el escaneo. Por favor, intenta de nuevo.', 'error')
        return redirect(url_for('index'))

# Ruta para mostrar el reporte HTML
@app.route('/reporte')
def mostrar_reporte():
    return send_file("reporte_vulnerabilidades.html", as_attachment=False)

if __name__ == '__main__':
    app.run(host="0.0.0.0")
