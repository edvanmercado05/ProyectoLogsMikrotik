import pymysql
from datetime import datetime
from conexion_mikrotik import descargar_logs

# Configuración de base de datos
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'sistema_logs'
}

def tarea_descarga_logs():
    print(f"[⏰] Ejecutando descarga automática de logs... {datetime.now()}")

    try:
        conexion = pymysql.connect(**db_config)
        cursor = conexion.cursor()

        cursor.execute("SELECT id, ip, puerto, usuario, contrasena FROM routers")
        routers = cursor.fetchall()

        for router in routers:
            router_id, ip, puerto, usuario, contrasena = router
            print(f"➡ Descargando logs de {ip}:{puerto} ({usuario})")
            
            nombre_router, nombre_archivo_virtual, contenido = descargar_logs(ip, usuario, contrasena, puerto)

            if contenido:
                cursor.execute(
                    "INSERT INTO logs (router_id, nombre_archivo, contenido, fecha) VALUES (%s, %s, %s, NOW())",
                    (router_id, nombre_archivo_virtual, contenido)
                )
                conexion.commit()

                cursor.execute("SELECT id FROM logs WHERE router_id = %s ORDER BY fecha DESC", (router_id,))
                todos_los_logs = cursor.fetchall()

                if len(todos_los_logs) > 24:
                    ids_a_borrar = [str(row[0]) for row in todos_los_logs[24:]]
                    cursor.execute(f"DELETE FROM logs WHERE id IN ({','.join(ids_a_borrar)})")
                    conexion.commit()

                print(f"✔ Log guardado para router {ip}")
            else:
                print(f"❌ Error con router {ip}, no se pudo descargar el log.")

        conexion.close()

    except Exception as e:
        print(f"[❌ ERROR] {e}")

# ✅ Ejecutar solo una vez
tarea_descarga_logs()

