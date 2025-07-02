import pymysql
import bcrypt

# Configura tu conexión a la base de datos
conexion = pymysql.connect(
    host='localhost',
    user='root',
    password='',
    database='sistema_logs'
)

cursor = conexion.cursor()

# Datos del nuevo usuario
nombre_usuario = 'admin'
contrasena_plana = 'admin123'

# Cifrar y decodificar la contraseña
contrasena_cifrada = bcrypt.hashpw(contrasena_plana.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# Insertar en la base de datos
try:
    cursor.execute("INSERT INTO usuarios (nombre_usuario, contraseña, rol) VALUES (%s, %s, %s)",
                   (nombre_usuario, contrasena_cifrada, 'admin'))
    conexion.commit()
    print(f"[✔] Usuario '{nombre_usuario}' creado correctamente.")
except Exception as e:
    print(f"[✖] Error al insertar usuario: {e}")

conexion.close()
