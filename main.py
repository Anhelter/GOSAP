import os
from flask import Flask, render_template, request, redirect, send_file, url_for, flash, session, make_response
from flask_session import Session
import pyotp
from werkzeug.utils import secure_filename
from pdf2image import convert_from_path

app = Flask(__name__)
app.secret_key = "clave_secreta"  # Cambia esto por una clave segura en un entorno de producción
app.config["SESSION_TYPE"] = "filesystem"  # Almacenar sesiones en el sistema de archivos
app.config["SESSION_PERMANENT"] = False  # Las sesiones no son permanentes
app.config["SESSION_USE_SIGNER"] = True  # Firma las sesiones para mayor seguridad
app.config["SESSION_KEY_PREFIX"] = "tu_prefijo_de_sesion"  # Prefijo personalizado para las sesiones
app.config["SESSION_COOKIE_NAME"] = "tu_app_session"
app.config["PERMANENT_SESSION_LIFETIME"] = 900  # Configura el tiempo de vencimiento en segundos (15 minutos)
Session(app)
UPLOAD_FOLDER = "pdfs"
ALLOWED_EXTENSIONS = {"pdf"}
# Crear una clave secreta única para cada usuario
# Esto debería generarse cuando se registra un nuevo usuario
SECRET_KEY = "3HKGI7RMR2WV3T6CRO4XCVMUYLTSGIIO"  # Debe ser único para cada usuario

def disable_cache(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response

# Función para verificar extensiones de archivo permitidas
def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route("/")
def home():
    return redirect(url_for("login"))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        
        # Aquí deberías realizar la autenticación de usuarios con tu propia lógica
        
        if username == "123" and password == "123":
            # Verificar la autenticación de dos factores (2FA)
            if "2fa_verified" not in session:
                return redirect(url_for("verify_2fa"))
            session["username"] = username
            flash("Inicio de sesión exitoso", "success")
            return redirect(url_for("admin"))
        else:
            flash("Credenciales incorrectas", "danger")

    response = make_response(render_template("login.html"))
    return disable_cache(response)

@app.route("/verify_2fa", methods=["GET", "POST"])
def verify_2fa():
    if request.method == "POST":
        user_otp = request.form["otp"]
        user_secret = SECRET_KEY  # Obtén la clave secreta del usuario desde tu base de datos

        totp = pyotp.TOTP(user_secret)
        
        if totp.verify(user_otp):
            session["2fa_verified"] = True
            flash("Autenticación de dos factores (2FA) exitosa", "success")
            return redirect(url_for("admin"))
        else:
            flash("Código de autenticación incorrecto", "danger")

    response = make_response(render_template("verify_2fa.html"))
    return disable_cache(response)


@app.route("/admin", methods=["GET", "POST"])
def admin():
    if "2fa_verified" in session:
        # Aquí puedes implementar la lógica para mostrar la página de administración
        # y trabajar con archivos PDF.
        pdf_files = [f for f in os.listdir("pdfs") if f.endswith(".pdf")]
        if request.method == "POST":
            if request.form["action"] == "logout":
                return redirect(url_for("logout"))
            elif request.form["action"] == "upload":
                return redirect(url_for("upload"))
            elif request.form["action"] == "apdfs":
                return redirect(url_for("apdfs"))
            elif request.form["action"] == "delete":
                filename = request.form["filename"]
                os.remove(os.path.join(UPLOAD_FOLDER, filename))
                flash("Archivo PDF eliminado correctamente", "success")
                return render_template("admin.html")
            elif request.form["action"] == "convert":
                filename = request.form["filename"]
                pages = convert_from_path(os.path.join(UPLOAD_FOLDER, filename), 500)
                for page in pages:
                    page.save(os.path.join(UPLOAD_FOLDER, filename + ".jpg"), "JPEG")
                flash("Archivo PDF convertido correctamente", "success")
                return render_template("admin.html")
        else:
            files = os.listdir(UPLOAD_FOLDER)
            return render_template("admin.html", pdf_files=pdf_files)
        
        response = make_response(render_template("admin.html"))
        return disable_cache(response)
    else:
        flash("Debes iniciar sesión y verificar 2FA primero", "warning")
        return redirect(url_for("login"))
    

@app.route("/logout")
def logout():
    # Eliminar la sesión del usuario, y cualquier dato de sesión que pueda haber
    session.pop("username", None)
    session.pop("2fa_verified", None)
    flash("Cierre de sesión exitoso", "info")
    return redirect(url_for("login"))

@app.route("/upload", methods=["GET", "POST"])
def upload():
    if request.method == "POST":
        # Comprobar si la petición tiene el archivo adjunto
        if "pdf_file" not in request.files:
            flash("No se encontró el archivo PDF", "danger")
            return redirect(request.url)
        pdf = request.files["pdf_file"]
        # Si el usuario no selecciona ningún archivo, el navegador
        # envía una parte vacía sin nombre de archivo.
        if pdf.filename == "":
            flash("No se seleccionó ningún archivo", "danger")
            return redirect(request.url)
        if pdf and allowed_file(pdf.filename):
            filename = secure_filename(pdf.filename)
            pdf.save(os.path.join(UPLOAD_FOLDER, filename))
            flash("Archivo PDF subido correctamente", "success")
            return redirect(url_for("admin"))

    return render_template("upload.html")

@app.route("/download/<filename>")
def download_pdf(filename):
    # Verificar si el archivo existe en la carpeta "pdfs"
    pdf_path = os.path.join("pdfs", filename)
    if os.path.exists(pdf_path):
        return send_file(pdf_path, as_attachment=True)
    else:
        return "El archivo PDF no existe.", 404


if __name__ == "__main__":
    app.run(debug=True)
