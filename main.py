from flask import Flask, render_template, request, redirect, url_for, send_from_directory, Response, flash
from flask_login import LoginManager, login_user, login_required, logout_user, current_user, UserMixin
import pymysql
import bcrypt
import os
from conexion_mikrotik import descargar_logs
import csv

app = Flask(__name__)
app.secret_key = 'clave_secreta_segura'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Config DB
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'sistema_logs'
}

LOG_FOLDER = 'app/logs'

class Usuario(UserMixin):
    def __init__(self, id_, nombre_usuario, rol):
        self.id = id_
        self.nombre = nombre_usuario
        self.rol = rol

@login_manager.user_loader
def load_user(user_id):
    conexion = pymysql.connect(**db_config)
    cursor = conexion.cursor()
    cursor.execute("SELECT id, nombre_usuario, rol FROM usuarios WHERE id = %s", (user_id,))
    resultado = cursor.fetchone()
    conexion.close()
    if resultado:
        return Usuario(resultado[0], resultado[1], resultado[2])
    return None

@app.route('/login', methods=['GET', 'POST'])
def login():
    mensaje = None
    if request.method == 'POST':
        usuario = request.form['usuario']
        contrasena = request.form['contrasena']
        conexion = pymysql.connect(**db_config)
        cursor = conexion.cursor()
        cursor.execute("SELECT id, nombre_usuario, contraseña, rol, temporal FROM usuarios WHERE nombre_usuario = %s", (usuario,))
        resultado = cursor.fetchone()
        conexion.close()

        if resultado and bcrypt.checkpw(contrasena.encode('utf-8'), resultado[2].encode('utf-8')):
            usuario_obj = Usuario(resultado[0], resultado[1], resultado[3])
            login_user(usuario_obj)

            if resultado[4]:  # Si la contraseña es temporal
                return redirect(url_for('cambiar_temporal'))

            return redirect(url_for('ver_routers'))
        else:
            mensaje = "Usuario o contraseña incorrectos."
    return render_template('login.html', mensaje=mensaje)





@app.route('/', endpoint='ver_routers')
@login_required
def ver_routers():
    filtro = request.args.get('filtro', '').lower()  # Agrega soporte a query param opcional

    conexion = pymysql.connect(**db_config)
    cursor = conexion.cursor()
    cursor.execute("SELECT * FROM routers")
    routers = cursor.fetchall()
    conexion.close()

    # Filtrar los que coinciden y ponerlos al principio
    if filtro:
        coincidencias = [r for r in routers if filtro in r[1].lower()]
        no_coinciden = [r for r in routers if filtro not in r[1].lower()]
        routers = coincidencias + no_coinciden

    return render_template('routers.html', routers=routers, usuario=current_user.nombre, rol=current_user.rol, filtro=filtro)




@app.route('/agregar-router', methods=['GET', 'POST'])
@login_required
def agregar_router():
    if request.method == 'POST':
        ip = request.form.get('ip')
        usuario = request.form.get('usuario')
        contrasena = request.form.get('contrasena')
        puerto = int(request.form.get('puerto', 22))

        nombre_router, nombre_archivo_virtual, contenido = descargar_logs(ip, usuario, contrasena, puerto)

        if nombre_router and contenido:
            conexion = pymysql.connect(**db_config)
            cursor = conexion.cursor()

            cursor.execute(
                "INSERT INTO routers (nombre, ip, puerto, usuario, contrasena, ubicacion) VALUES (%s, %s, %s, %s, %s, %s)",
                (nombre_router, ip, puerto, usuario, contrasena, '')
            )
            conexion.commit()
            cursor.execute("SELECT id FROM routers WHERE ip = %s ORDER BY id DESC LIMIT 1", (ip,))
            router_id = cursor.fetchone()[0]

            cursor.execute(
                "INSERT INTO logs (router_id, nombre_archivo, contenido, fecha) VALUES (%s, %s, %s, NOW())",
                (router_id, nombre_archivo_virtual, contenido)
            )
            conexion.commit()
            conexion.close()

            return redirect(url_for('ver_routers'))
        else:
            return "<h4>Error al conectar con el router. Verifica usuario, contraseña, puerto y que tu IP esté en la lista 'Available From'.</h4>"

    return render_template('agregar_router.html')

@app.route('/actualizar-logs/<int:router_id>', methods=['POST'])
@login_required
def actualizar_logs(router_id):
    usuario = request.form.get('usuario')
    contrasena = request.form.get('contrasena')
    puerto = request.form.get('puerto')

    conexion = pymysql.connect(**db_config)
    cursor = conexion.cursor()
    cursor.execute("SELECT nombre, ip, puerto, usuario, contrasena FROM routers WHERE id = %s", (router_id,))
    router_info = cursor.fetchone()
    conexion.close()

    if router_info:
        nombre_router, ip, puerto_db, usuario_db, contrasena_db = router_info
        usuario = usuario or usuario_db
        contrasena = contrasena or contrasena_db
        puerto = int(puerto or puerto_db or 22)

        nuevo_nombre, nombre_archivo_virtual, contenido = descargar_logs(ip, usuario, contrasena, puerto)

        if contenido:
            conexion = pymysql.connect(**db_config)
            cursor = conexion.cursor()
            cursor.execute("INSERT INTO logs (router_id, nombre_archivo, contenido, fecha) VALUES (%s, %s, %s, NOW())",
                           (router_id, nombre_archivo_virtual, contenido))
            conexion.commit()
            conexion.close()
            return redirect(url_for('ver_logs_router', router_id=router_id))

    return "<h4>Error al actualizar logs. Verifica usuario, contraseña y puerto.</h4>"

def generar_txt(logs):
    contenido = "\n\n".join(f"{log[0]} ({log[2]}):\n{log[1]}" for log in logs)
    return Response(
        contenido,
        mimetype='text/plain',
        headers={'Content-Disposition': 'attachment; filename=logs_filtrados.txt'}
    )

def generar_csv(logs):
    def generar():
        yield "Archivo,Fecha,Contenido\n"
        for archivo, contenido, fecha in logs:
            contenido_limpio = contenido.replace('\n', ' ').replace('\r', ' ')
            yield f'"{archivo}","{fecha}","{contenido_limpio}"\n'

    return Response(
        generar(),
        mimetype='text/csv',
        headers={'Content-Disposition': 'attachment; filename=logs_filtrados.csv'}
    )

@app.route('/logs-router/<int:router_id>', methods=['GET', 'POST'])
@login_required
def ver_logs_router(router_id):
    conexion = pymysql.connect(**db_config)
    cursor = conexion.cursor()

    busqueda = request.form.get('busqueda') if request.method == 'POST' else ''
    fecha = request.form.get('fecha') if request.method == 'POST' else ''

    consulta = "SELECT nombre_archivo, contenido, fecha FROM logs WHERE router_id = %s"
    valores = [router_id]

    if fecha:
        consulta += " AND DATE(fecha) = %s"
        valores.append(fecha)
    if busqueda:
        consulta += " AND contenido LIKE %s"
        valores.append(f"%{busqueda}%")

    # 🟢 Ordenar por fecha descendente (más nuevos primero)
    consulta += " ORDER BY fecha DESC"

    cursor.execute("SELECT nombre FROM routers WHERE id = %s", (router_id,))
    router_nombre = cursor.fetchone()[0]

    cursor.execute(consulta, tuple(valores))
    logs = cursor.fetchall()
    conexion.close()

    if request.method == 'POST':
        accion = request.form.get('accion')
        if accion == 'exportar_txt':
            return generar_txt(logs)
        elif accion == 'exportar_csv':
            return generar_csv(logs)

    return render_template('logs_db.html',
                           logs=logs,
                           router_nombre=router_nombre,
                           router_id=router_id,
                           busqueda=busqueda,
                           fecha=fecha)



@login_required
def descargar(nombre_archivo):
    return send_from_directory(LOG_FOLDER, nombre_archivo, as_attachment=True)

@app.route('/acciones-logs/<int:router_id>', methods=['POST'], endpoint='acciones_logs_seleccionados')
@login_required
def acciones_logs_seleccionados(router_id):
    seleccionados = request.form.getlist('seleccionados')
    accion = request.form.get('accion_masiva')

    if not seleccionados:
        flash("No seleccionaste ningún log.", "warning")
        return redirect(url_for('ver_logs_router', router_id=router_id))

    conexion = pymysql.connect(**db_config)
    cursor = conexion.cursor()

    if accion == 'eliminar':
        cursor.executemany("DELETE FROM logs WHERE router_id = %s AND nombre_archivo = %s",
                           [(router_id, archivo) for archivo in seleccionados])
        conexion.commit()
        conexion.close()
        flash("Logs eliminados correctamente.", "success")
        return redirect(url_for('ver_logs_router', router_id=router_id))

    cursor.execute("SELECT nombre_archivo, contenido, fecha FROM logs WHERE router_id = %s AND nombre_archivo IN %s",
                   (router_id, tuple(seleccionados)))
    logs = cursor.fetchall()
    conexion.close()

    if accion == 'exportar_txt':
        return generar_txt(logs)
    elif accion == 'exportar_csv':
        return generar_csv(logs)
    
    elif accion == 'buscar_criticos':
        topics_criticos = ['critical', 'error', 'system,error,critical']
        resultado = []

        for nombre_archivo, contenido, fecha in logs:
            coincidencias = []
            lineas = contenido.splitlines()

            for linea in lineas:
                if any(topic.lower() in linea.lower() for topic in topics_criticos):
                    coincidencias.append(linea.strip())

            resultado.append({
                'archivo': nombre_archivo,
                'coincidencias': coincidencias,
                'fecha': fecha
            })

        return render_template('resultado_logs_criticos.html', resultado=resultado, router_id=router_id)


@app.route('/registrar', methods=['GET', 'POST'])
@login_required
def registrar():
    if current_user.rol != 'admin':
        return "<h4>Acceso restringido: solo administradores.</h4>"
    mensaje = None
    if request.method == 'POST':
        usuario = request.form['usuario']
        correo = request.form['correo']  # <-- Aquí agregas esta línea
        contrasena = request.form['contrasena']
        rol = request.form['rol']
        contrasena_cifrada = bcrypt.hashpw(contrasena.encode('utf-8'), bcrypt.gensalt())
        try:
            conexion = pymysql.connect(**db_config)
            cursor = conexion.cursor()
            cursor.execute(
                "INSERT INTO usuarios (nombre_usuario, correo, contraseña, rol) VALUES (%s, %s, %s, %s)",
                (usuario, correo, contrasena_cifrada, rol)  # <-- Y aquí incluyes el correo
            )
            conexion.commit()
            mensaje = f"Usuario '{usuario}' creado correctamente."
        except pymysql.err.IntegrityError:
            mensaje = f"⚠️ El usuario '{usuario}' ya existe."
        finally:
            conexion.close()
    return render_template('registro.html', mensaje=mensaje)


@app.route("/exportar-log-unico/<int:router_id>/<path:archivo>/<formato>")
@login_required
def exportar_log_unico(router_id, archivo, formato):
    from flask import send_file
    import io, csv

    conexion = pymysql.connect(**db_config)
    cursor = conexion.cursor()

    cursor.execute("""
        SELECT contenido FROM logs 
        WHERE router_id = %s AND nombre_archivo = %s
        ORDER BY fecha DESC LIMIT 1
    """, (router_id, archivo))
    resultado = cursor.fetchone()
    conexion.close()

    if not resultado:
        return "Log no encontrado", 404

    contenido = resultado[0]

    if formato == 'txt':
        buffer = io.BytesIO()
        buffer.write(contenido.encode('utf-8'))
        buffer.seek(0)
        return send_file(buffer, as_attachment=True, download_name=archivo, mimetype='text/plain')

    elif formato == 'csv':
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        for linea in contenido.splitlines():
            writer.writerow([linea])
        output = io.BytesIO()
        output.write(buffer.getvalue().encode('utf-8'))
        output.seek(0)
        nombre_csv = archivo.replace('.txt', '.csv')
        return send_file(output, as_attachment=True, download_name=nombre_csv, mimetype='text/csv')

    return "Formato no válido", 400

@app.route('/eliminar-router/<int:router_id>', methods=['POST'])
@login_required
def eliminar_router(router_id):
    if current_user.rol != 'admin':
        return "<h4>Acceso restringido.</h4>"

    conexion = pymysql.connect(**db_config)
    cursor = conexion.cursor()

    cursor.execute("DELETE FROM logs WHERE router_id = %s", (router_id,))
    cursor.execute("DELETE FROM routers WHERE id = %s", (router_id,))

    conexion.commit()
    conexion.close()

    flash("✅ Router eliminado con éxito.", "success")
    return redirect(url_for('ver_routers'))







import csv
from werkzeug.utils import secure_filename

@app.route('/importar-csv', methods=['GET', 'POST'])
@login_required
def importar_csv():
    if request.method == 'POST':
        archivo = request.files['archivo']
        if archivo.filename.endswith('.csv'):
            filename = secure_filename(archivo.filename)
            archivo.save(filename)

            with open(filename, newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                conexion = pymysql.connect(**db_config)
                cursor = conexion.cursor()

                for row in reader:
                    nombre = row.get('Name')
                    ip = row.get('Addresses')
                    puerto = 9450
                    usuario = 'AccesoN0C7'
                    contrasena = 'N0c#2025&7.'
                    ubicacion = row.get('Map', '')

                    # Saltar si nombre o IP están vacíos
                    if not nombre or not ip:
                        continue

                    # Verifica si ya existe
                    cursor.execute("SELECT id FROM routers WHERE ip = %s", (ip,))
                    if cursor.fetchone():
                        continue

                    cursor.execute(
                        "INSERT INTO routers (nombre, ip, puerto, usuario, contrasena, ubicacion) VALUES (%s, %s, %s, %s, %s, %s)",
                        (nombre, ip, puerto, usuario, contrasena, ubicacion)
                    )

                conexion.commit()
                conexion.close()
            return redirect(url_for('ver_routers'))

    return render_template('importar_csv.html')








from flask import request, render_template
import difflib
import os

@app.route('/comparar-logs')
@login_required
def comparar_logs():
    from difflib import unified_diff

    log1_nombre = request.args.get('log1')
    log2_nombre = request.args.get('log2')

    if not log1_nombre or not log2_nombre:
        return "Faltan logs para comparar", 400

    conexion = pymysql.connect(**db_config)
    cursor = conexion.cursor()
    cursor.execute("""
        SELECT nombre_archivo, contenido FROM logs
        WHERE nombre_archivo = %s OR nombre_archivo = %s
    """, (log1_nombre, log2_nombre))
    resultados = cursor.fetchall()
    conexion.close()

    if len(resultados) != 2:
        return "No se encontraron ambos logs en la base de datos", 404

    contenido1 = ""
    contenido2 = ""

    for nombre_archivo, contenido in resultados:
        if nombre_archivo == log1_nombre:
            contenido1 = contenido.splitlines(keepends=True)
        elif nombre_archivo == log2_nombre:
            contenido2 = contenido.splitlines(keepends=True)

    diferencias = list(unified_diff(
        contenido1, contenido2,
        fromfile=log1_nombre,
        tofile=log2_nombre,
        lineterm=""
    ))

    # 👉 Resumen de cambios
    agregadas = sum(1 for l in diferencias if l.startswith('+') and not l.startswith('+++'))
    eliminadas = sum(1 for l in diferencias if l.startswith('-') and not l.startswith('---'))
    contexto = sum(1 for l in diferencias if not l.startswith(('+', '-', '@@', '+++', '---')))

    return render_template(
        "comparacion_logs.html",
        diferencias=diferencias,
        log1=log1_nombre,
        log2=log2_nombre,
        agregadas=agregadas,
        eliminadas=eliminadas,
        contexto=contexto
    )



import smtplib
import random
import string
from email.mime.text import MIMEText
from flask import render_template, request
import bcrypt
import pymysql

@app.route('/recuperar', methods=['GET', 'POST'])
def recuperar():
    mensaje = None

    if request.method == 'POST':
        correo = request.form['correo']
        conexion = pymysql.connect(**db_config)
        cursor = conexion.cursor()

        cursor.execute("SELECT id FROM usuarios WHERE correo = %s", (correo,))
        usuario = cursor.fetchone()

        if usuario:
            # 1. Generar contraseña temporal
            temp_pass = ''.join(random.choices(string.ascii_letters + string.digits, k=10))
            temp_hash = bcrypt.hashpw(temp_pass.encode('utf-8'), bcrypt.gensalt())

            # 2. Guardar en base de datos
            cursor.execute("UPDATE usuarios SET contraseña=%s, temporal=1 WHERE id=%s", (temp_hash, usuario[0]))
            conexion.commit()

            # 3. Enviar por correo
            try:
                remitente = "a20490721@itmexicali.edu.mx"
                password_app = "mgbwjrswfbhccrrj"

                msg = MIMEText(f'Tu contrasena temporal es: {temp_pass}')
                msg['Subject'] = 'Recuperación de contrasena sistema logs'
                msg['From'] = remitente
                msg['To'] = correo

                server = smtplib.SMTP('smtp.gmail.com', 587)
                server.starttls()
                server.login(remitente, password_app)
                server.sendmail(remitente, correo, msg.as_string())
                server.quit()

                mensaje = "✅ Se envió una contraseña temporal a tu correo."
            except Exception as e:
                mensaje = f"❌ Error al enviar correo: {e}"
        else:
            mensaje = "❌ El correo no está registrado."

        conexion.close()

    return render_template('recuperar.html', mensaje=mensaje)





@app.route('/cambiar-temporal', methods=['GET', 'POST'])
@login_required
def cambiar_temporal():
    mensaje = None
    if request.method == 'POST':
        actual = request.form['actual']
        nueva = request.form['nueva']
        conexion = pymysql.connect(**db_config)
        cursor = conexion.cursor()

        cursor.execute("SELECT contraseña FROM usuarios WHERE id = %s", (current_user.id,))
        resultado = cursor.fetchone()

        if resultado and bcrypt.checkpw(actual.encode('utf-8'), resultado[0].encode('utf-8')):
            nueva_hash = bcrypt.hashpw(nueva.encode('utf-8'), bcrypt.gensalt())
            cursor.execute("UPDATE usuarios SET contraseña = %s, temporal = 0 WHERE id = %s", (nueva_hash, current_user.id))
            conexion.commit()
            mensaje = "✅ Contraseña actualizada correctamente."
            return redirect(url_for('ver_routers'))
        else:
            mensaje = "❌ Contraseña actual incorrecta."

        conexion.close()

    return render_template('cambiar_temporal.html', mensaje=mensaje)






@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))





from flask import render_template, request, redirect, session, flash
from werkzeug.security import generate_password_hash
from functools import wraps

# Decorador para restringir acceso a admins
def admin_required(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'usuario_id' in session and session['rol'] == 'admin':
            return f(*args, **kwargs)
        else:
            flash("Acceso restringido solo para administradores.")
            return redirect('/')
    return wrap

@app.route('/crear-usuario', methods=['GET', 'POST'])
@admin_required
def crear_usuario():
    if request.method == 'POST':
        nombre = request.form['nombre']
        correo = request.form['correo']
        contrasena = generate_password_hash(request.form['contrasena'])
        rol = request.form['rol']

        conexion = pymysql.connect(**db_config)
        cursor = conexion.cursor()
        cursor.execute(
            "INSERT INTO usuarios (nombre_usuario, correo, contraseña, rol) VALUES (%s, %s, %s, %s)",
            (nombre, correo, contrasena, rol)
        )
        conexion.commit()
        conexion.close()

        flash('Usuario creado exitosamente')
        return redirect('/crear-usuario')

    return render_template('crear_usuario.html')




@app.route('/admin/usuarios')
@login_required
def admin_usuarios():
    if current_user.rol != 'admin':
        flash("Acceso denegado.", "danger")
        return redirect(url_for('ver_routers'))

    conexion = pymysql.connect(**db_config)
    cursor = conexion.cursor()
    cursor.execute("SELECT id, nombre_usuario, correo, rol FROM usuarios")
    usuarios = cursor.fetchall()
    conexion.close()

    return render_template('admin_usuarios.html', usuarios=usuarios)

@app.route('/admin/usuarios/editar/<int:id>', methods=['GET', 'POST'])
@login_required
def editar_usuario(id):
    if current_user.rol != 'admin':
        flash("Acceso denegado.", "danger")
        return redirect(url_for('ver_routers'))

    conexion = pymysql.connect(**db_config)
    cursor = conexion.cursor()

    if request.method == 'POST':
        nuevo_correo = request.form['correo']
        nuevo_rol = request.form['rol']
        cursor.execute("UPDATE usuarios SET correo = %s, rol = %s WHERE id = %s", (nuevo_correo, nuevo_rol, id))
        conexion.commit()
        conexion.close()
        flash("Usuario actualizado correctamente.", "success")
        return redirect(url_for('admin_usuarios'))

    cursor.execute("SELECT nombre_usuario, correo, rol FROM usuarios WHERE id = %s", (id,))
    usuario = cursor.fetchone()
    conexion.close()

    return render_template('editar_usuario.html', usuario=usuario, id=id)

@app.route('/admin/usuarios/eliminar/<int:id>')
@login_required
def eliminar_usuario(id):
    if current_user.rol != 'admin':
        flash("Acceso denegado.", "danger")
        return redirect(url_for('ver_routers'))

    conexion = pymysql.connect(**db_config)
    cursor = conexion.cursor()
    cursor.execute("DELETE FROM usuarios WHERE id = %s", (id,))
    conexion.commit()
    conexion.close()

    flash("Usuario eliminado correctamente.", "success")
    return redirect(url_for('admin_usuarios'))

if __name__ == '__main__':
   app.run(host='0.0.0.0', port=5000, debug=True)

