# 🗂️ Samba Web Manager

Panel de administración web moderno para gestionar recursos compartidos de Samba en Linux (Ubuntu/Debian).

## ✨ Características

- 🔐 **Autenticación segura** con roles Admin / Usuario
- 👥 **Gestión de usuarios** — crear, eliminar y cambiar contraseñas
- 📁 **Gestión de carpetas compartidas** — crear y eliminar recursos compartidos con explorador de directorios
- 🔑 **Control de permisos granular** — Solo Lectura o Lectura/Escritura por usuario y carpeta
- 📊 **Matriz de permisos** — vista de todos los usuarios × todas las carpetas de un vistazo
- 📂 **Explorador de archivos integrado** — navegar, subir, descargar, editar y eliminar archivos
- 🔍 **Descubrimiento de red automático** (via `wsdd2`) — visible en "Red" de Windows 10/11 sin configuración adicional
- 📋 **Registro de actividad** — auditoría de todas las acciones del sistema
- 🔄 **Cambio de contraseña forzado** en el primer inicio de sesión del admin
- 🛡️ **Rate limiting** en el login para prevenir ataques de fuerza bruta

## 🖥️ Requisitos del Sistema

- **Sistema Operativo:** Ubuntu 20.04+ o Debian 11+
- **Acceso:** `sudo` o root
- **Puertos:** 5000 (panel web), 445/139 (Samba SMB)

## 🚀 Instalación

```bash
# 0. Instalar git si no está disponible en el sistema
sudo apt update && sudo apt install -y git

# 1. Clonar el repositorio
git clone https://github.com/joseramirez63/samba-web-manager.git
cd samba-web-manager

# 2. Ejecutar el script de instalación (requiere root)
sudo bash install.sh
```

El script instalará automáticamente:
- `samba`, `nmbd`, `wsdd2` (descubrimiento de red para Windows 10/11)
- Python 3 y las dependencias (`flask`, `werkzeug`, `flask-limiter`)
- El servicio `samba-manager` en systemd
- Una `SECRET_KEY` aleatoria en `/etc/samba-manager/config.env`
- Los permisos necesarios en `sudoers`

## 🌐 Acceso al Panel

Una vez instalado, abre en tu navegador:

```
http://<IP-del-servidor>:5000
```

### Credenciales por defecto

| Usuario | Contraseña |
|---------|------------|
| `admin` | `admin123` |

> ⚠️ **Se te pedirá cambiar la contraseña en el primer inicio de sesión.**

## ⚙️ Gestión del Servicio

```bash
# Estado
sudo systemctl status samba-manager

# Reiniciar
sudo systemctl restart samba-manager

# Detener
sudo systemctl stop samba-manager

# Ver logs en tiempo real
sudo journalctl -u samba-manager -f
```

## 🔒 Seguridad

- La `SECRET_KEY` se genera aleatoriamente durante la instalación y se almacena en `/etc/samba-manager/config.env` (permisos 600).
- Las contraseñas se almacenan con hash usando Werkzeug (`pbkdf2:sha256`).
- El login tiene límite de 10 intentos por minuto por IP.
- La contraseña mínima es de 8 caracteres.
- El protocolo mínimo de Samba es SMB2 (más seguro que SMB1).

## 📁 Estructura del Proyecto

```
samba-web-manager/
├── app.py              # Aplicación Flask principal
├── install.sh          # Script de instalación automática
├── templates/
│   ├── index.html      # Panel de administración (SPA)
│   └── login.html      # Página de inicio de sesión
└── README.md
```

Los datos de la aplicación se almacenan en `/opt/samba-manager/data/`:
- `users.json` — usuarios y roles
- `shares.json` — carpetas compartidas
- `permissions.json` — permisos por usuario y carpeta
- `logs.json` — registro de actividad

## ⚠️ Problemas Conocidos

### Error de Windows al conectar dos usuarios distintos desde la misma PC

**Síntoma:** Al crear un segundo usuario y asignarle una carpeta compartida diferente, cuando ese usuario intenta conectarse desde un equipo Windows que ya tiene una conexión activa al mismo servidor con otro usuario, aparece el siguiente error:

> *"Las conexiones múltiples a un servidor o recurso compartido compatible por el mismo usuario, usando más de un nombre de usuario, no están permitidas. Desconecte todas las conexiones anteriores al servidor o recurso compartido e inténtelo de nuevo."*

**Causa:** Este es un comportamiento propio de Windows (error 1219 / `ERROR_SESSION_CREDENTIAL_CONFLICT`), **no un error de Samba Web Manager**. Windows solo permite un conjunto de credenciales activas por servidor (identificado por IP o nombre de host) al mismo tiempo. Si una sesión ya está autenticada como `usuario1` y se intenta abrir otra conexión al mismo servidor como `usuario2`, Windows bloquea la solicitud.

**Soluciones:**

1. **Desconectar la sesión activa antes de conectar con otro usuario**
   Abre el símbolo del sistema (`cmd`) y ejecuta:
   ```cmd
   net use * /delete /y
   ```
   Luego vuelve a conectarte con las credenciales del usuario que necesitas.

2. **Cada usuario usa su propia sesión de Windows**
   Windows gestiona las credenciales SMB por sesión de usuario local. Si dos personas distintas necesitan acceder al servidor simultáneamente desde la misma máquina física, deben iniciar sesión cada una con su propia cuenta de Windows (o usar sesiones de Escritorio Remoto independientes).

3. **Un solo usuario accede a varias carpetas**
   Si es una sola persona la que necesita acceder a múltiples carpetas compartidas, el administrador debe asignarle permisos sobre todas las carpetas necesarias a ese mismo usuario. De esta forma se usa un único juego de credenciales y Windows no detecta conflicto.

---

## 📜 Licencia

MIT License © 2025

## 🤝 Contribuciones

¡Las pull requests son bienvenidas! Abre un issue para reportar problemas o sugerir mejoras.
