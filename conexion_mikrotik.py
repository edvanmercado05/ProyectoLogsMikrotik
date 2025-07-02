import paramiko
from datetime import datetime

def descargar_logs(ip, usuario, contrasena, puerto=22):
    try:
        cliente = paramiko.SSHClient()
        cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        cliente.connect(hostname=ip, username=usuario, password=contrasena, port=puerto, timeout=10)

        # Obtener logs
        stdin, stdout, stderr = cliente.exec_command('/log print without-paging')
        logs = stdout.read().decode('utf-8')
        cliente.close()

        # Obtener nombre del router
        cliente = paramiko.SSHClient()
        cliente.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        cliente.connect(hostname=ip, username=usuario, password=contrasena, port=puerto, timeout=10)

        stdin, stdout, stderr = cliente.exec_command("/system identity print")
        resultado = stdout.read().decode('utf-8')
        nombre_router = "ROUTER"
        for linea in resultado.splitlines():
            if "name:" in linea:
                nombre_router = linea.split("name:")[1].strip()
        cliente.close()

        # Crear nombre de archivo (ya no se guarda en disco)
        timestamp = datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        nombre_archivo_virtual = f"logs_{nombre_router.replace(' ', '_')}_{ip}_{timestamp}.txt"

        return nombre_router, nombre_archivo_virtual, logs

    except paramiko.ssh_exception.AuthenticationException:
        print("[❌] Error de autenticación SSH.")
        return None, None, None
    except paramiko.ssh_exception.SSHException as e:
        if "not allowed to connect" in str(e).lower():
            print("[❌] Acceso denegado: tu IP no está permitida en 'Available From'.")
        else:
            print(f"[❌] Error SSH: {e}")
        return None, None, None
    except Exception as e:
        print(f"[❌] Error general: {e}")
        return None, None, None
