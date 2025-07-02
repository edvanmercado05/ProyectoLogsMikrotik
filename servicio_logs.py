import win32serviceutil
import win32service
import win32event
import servicemanager
import subprocess
import time
import os
from datetime import datetime

class ServicioLogs(win32serviceutil.ServiceFramework):
    _svc_name_ = "ServicioLogsMikroTik"
    _svc_display_name_ = "Servicio de Descarga Automática de Logs MikroTik"
    _svc_description_ = "Este servicio descarga logs de routers MikroTik y los guarda en la base de datos automáticamente."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.running = True

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.running = False
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        servicemanager.LogInfoMsg("Iniciando ServicioLogsMikroTik...")

        # Cambiar al directorio del proyecto
        ruta_base = r"C:\Users\Rodrigo Barba\Desktop\ProyectoLogsMikrotik"
        os.chdir(ruta_base)

        while self.running:
            try:
                # Ejecutar el script de descarga
                subprocess.call(['python', 'descarga_automatica.py'])

                # ✅ Registro local de la ejecución (se puede quitar si no se desea)
                with open("registro_servicio.txt", "a", encoding="utf-8") as archivo:
                    archivo.write(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] Logs descargados correctamente.\n")
# ✅ Registro local de la ejecución (se puede quitar si no se desea)



            except Exception as e:
                servicemanager.LogErrorMsg(f"Error al ejecutar descarga: {e}")

            time.sleep(3600)  # ⏱️ Espera 1 hora entre cada ejecución

if __name__ == '__main__':
    win32serviceutil.HandleCommandLine(ServicioLogs)
