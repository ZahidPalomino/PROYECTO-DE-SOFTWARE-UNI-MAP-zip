# Reciban nuestros cordiales saludos, nosotros el Grupo 5 nos complace presentar nuestro Proyecto del curso de Programación Orientada a Objetos, trabajado durante este ciclo académico 2024-2. 
# A continuación les presentamos una descripción del proyecto. Una aplicación web en Python que realice escaneos de red y reportes de vulnerabilidades de una red, con la opción de enviarlas por correo electrónico.



# Como 1er punto, mencionamos las "Importaciones de Módulos":

# Flask                           (framework creador de la aplicación)

  #   Request  
  #   Render_Template              (funciones de Flask utilizadas para manejar 
  #   Send_file                      \tsolicitudes HTTP, renderizar plantillas HTML,
  #   Flash                          \tenviar archivos al cliente, mostrar mensajes 
  #   Redirect                        \tde error y redirigir entre rutas)
  #   URL_for

# "os" y "er"                      (Módulos estándares de Python)

#                                  (Encargado de funcionalidades principales como la base 
# escanerNMAP                       de datos de vulnerabilidades, el escaneo de la red,
#                                   la generación de reportes y la notificación por correo) 
                                


# Luego, como 2do punto la "Configuración de Flask":

  #  app = Flask(__name__)          (Creación de la instalación de la aplicación)
  #  app.secret_key                 (Clase secreta que muestran mensajes de éxito o error) 



# A continuación, como 3er punto damos a conocer las "Rutas de la Aplicación":

# Ruta principal "/"                (Muestra la página HTML para introducir datos como el rango de IP a escanear, el tipo de escaneo y la opción de enviar un reporte por correo electrónico)
# Ruta "/scan"                      (Se activa cuando el usuario envía el formulario con los parámetros de escaneo) 

  #   Validación                    (Verifica que el formato del rango de IP esté en formato CIDR) 
  #   Instanciación de Clases       (Se crea una instancia de la base de datos de vulnerabilidades)
  #   Generación de Reportes        (Se crea un generador de reportes que exporta los resultados a archivos CSV, HTML y TXT)
  #   Notificación por Correo       (Si se seleccionó la opción de enviar el reporte, se filtran las vulnerabilidades críticas y se envía el reporte por correo)
  #   Manejo de Errores             (Si ocurre cualquier excepción durante el proceso, como un error de red, se captura y se muestra un mensaje de error al usuario)



# Y como 4to punto, se realiza la "Ejecución de la Aplicación":

#   (El servidor web se ejecuta en el host [0.0.0.0], lo que significa que la aplicación estará disponible en todas las interfaces de red de la máquina)
    







