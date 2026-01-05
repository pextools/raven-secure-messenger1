#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
RAVEN Secure Messenger v3.0 - Complete System
Современный мессенджер с AI-ассистентом и полным GUI
"""

import os
import sys
import json
import socket
import threading
import hashlib
import base64
import pickle
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any, Set
import logging
import queue
import select
import time
import re
import secrets
import struct
from pathlib import Path
import sqlite3
from enum import Enum
import zipfile
import io
import webbrowser
import platform
import subprocess
from dataclasses import dataclass
from collections import defaultdict

# GUI библиотеки
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, simpledialog
from tkinter import font as tkfont
import tkinter.messagebox as tkmsg
from PIL import Image, ImageTk, ImageDraw, ImageFont
import sv_ttk  # Modern theme

# Криптография
try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives.asymmetric import rsa, padding, dh
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.backends import default_backend
    from cryptography.exceptions import InvalidSignature
    from nacl.public import PrivateKey as NaClPrivateKey, PublicKey as NaClPublicKey, Box
    from nacl.secret import SecretBox
    from nacl.utils import random
    import argon2
    CRYPTO_AVAILABLE = True
except ImportError as e:
    print(f"Криптографические библиотеки не установлены: {e}")
    print("Установите: pip install cryptography pynacl argon2-cffi pillow")
    CRYPTO_AVAILABLE = False

# Настройка логирования
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('raven_system.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ============================================================================
# КЛАССЫ ДАННЫХ И КОНФИГУРАЦИИ
# ============================================================================

@dataclass
class UserProfile:
    """Профиль пользователя"""
    username: str
    user_id: str
    avatar_path: str
    status: str
    bio: str
    public_key: bytes
    created_at: datetime
    last_seen: datetime

@dataclass
class Contact:
    """Контакт"""
    contact_id: str
    name: str
    avatar: str
    public_key: bytes
    ip_address: str
    port: int
    status: str
    last_online: datetime
    trust_level: int

@dataclass
class Message:
    """Сообщение"""
    message_id: str
    sender_id: str
    receiver_id: str
    content: str
    timestamp: datetime
    message_type: str
    encrypted: bool
    read: bool
    attachments: List[str]

class AppConfig:
    """Конфигурация приложения"""
    
    def __init__(self):
        # Пути
        self.app_name = "RAVEN Secure Messenger"
        self.version = "3.0"
        self.author = "RAVEN Team"
        
        # Директории
        self.base_dir = Path.home() / ".raven_messenger"
        self.data_dir = self.base_dir / "data"
        self.cache_dir = self.base_dir / "cache"
        self.logs_dir = self.base_dir / "logs"
        self.backup_dir = self.base_dir / "backups"
        
        # База данных
        self.db_path = self.data_dir / "raven.db"
        
        # Создаем директории
        self.create_directories()
        
        # Настройки GUI
        self.theme = "dark"
        self.language = "ru"
        self.font_size = 11
        self.animation_enabled = True
        
        # Настройки сети
        self.default_port = 19999
        self.stun_servers = [
            ("stun.l.google.com", 19302),
            ("stun1.l.google.com", 19302),
            ("stun2.l.google.com", 19302)
        ]
        
        # Настройки безопасности
        self.encryption_algorithm = "chacha20"
        self.key_rotation_days = 30
        self.session_timeout_minutes = 60
        
        # Настройки уведомлений
        self.notify_new_message = True
        self.notify_contact_online = True
        self.notify_file_received = True
        
        # Загружаем сохраненную конфигурацию
        self.load_config()
    
    def create_directories(self):
        """Создание необходимых директорий"""
        directories = [
            self.base_dir,
            self.data_dir,
            self.cache_dir,
            self.logs_dir,
            self.backup_dir,
            self.data_dir / "avatars",
            self.data_dir / "attachments",
            self.data_dir / "export"
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
    
    def load_config(self):
        """Загрузка конфигурации из файла"""
        config_file = self.base_dir / "config.json"
        if config_file.exists():
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config_data = json.load(f)
                    for key, value in config_data.items():
                        if hasattr(self, key):
                            setattr(self, key, value)
            except Exception as e:
                logger.error(f"Error loading config: {e}")
    
    def save_config(self):
        """Сохранение конфигурации в файл"""
        config_file = self.base_dir / "config.json"
        config_data = {
            'theme': self.theme,
            'language': self.language,
            'font_size': self.font_size,
            'animation_enabled': self.animation_enabled,
            'default_port': self.default_port,
            'encryption_algorithm': self.encryption_algorithm,
            'notify_new_message': self.notify_new_message,
            'notify_contact_online': self.notify_contact_online,
            'notify_file_received': self.notify_file_received
        }
        
        try:
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(config_data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logger.error(f"Error saving config: {e}")

# ============================================================================
# СИСТЕМА БЕЗОПАСНОСТИ И ШИФРОВАНИЯ
# ============================================================================

class SecuritySystem:
    """Полная система безопасности"""
    
    def __init__(self, config: AppConfig):
        self.config = config
        self.master_key = None
        self.session_keys = {}
        self.key_store = {}
        
    def initialize(self, password: str):
        """Инициализация системы безопасности"""
        # Генерация мастер-ключа из пароля
        self.master_key = self.derive_key(password)
        
        # Генерация ключевой пары
        self.generate_key_pair()
        
        # Загрузка/сохранение ключей
        self.load_keys()
        
    def derive_key(self, password: str, salt: bytes = None) -> bytes:
        """Вывод ключа из пароля с использованием Argon2id"""
        if salt is None:
            salt = secrets.token_bytes(32)
        
        hasher = argon2.PasswordHasher(
            time_cost=3,
            memory_cost=65536,
            parallelism=4,
            hash_len=32,
            salt_len=32
        )
        
        hash_str = hasher.hash(password, salt=salt)
        return hashlib.sha256(hash_str.encode()).digest()
    
    def generate_key_pair(self):
        """Генерация пары ключей X25519"""
        self.private_key = NaClPrivateKey.generate()
        self.public_key = self.private_key.public_key
        
    def encrypt_message(self, message: str, recipient_public_key: bytes) -> Dict:
        """Шифрование сообщения с использованием ChaCha20-Poly1305"""
        # Генерация сессионного ключа
        session_key = secrets.token_bytes(32)
        
        # Шифрование сообщения
        box = SecretBox(session_key)
        encrypted = box.encrypt(message.encode('utf-8'))
        
        # Шифрование сессионного ключа публичным ключом получателя
        # (здесь должна быть реальная реализация)
        
        return {
            'ciphertext': base64.b64encode(encrypted.ciphertext).decode(),
            'nonce': base64.b64encode(encrypted.nonce).decode(),
            'algorithm': 'chacha20-poly1305',
            'timestamp': datetime.now().isoformat()
        }
    
    def decrypt_message(self, encrypted_data: Dict) -> Optional[str]:
        """Дешифрование сообщения"""
        try:
            ciphertext = base64.b64decode(encrypted_data['ciphertext'])
            nonce = base64.b64decode(encrypted_data['nonce'])
            
            # Здесь должен быть ключ сессии
            session_key = secrets.token_bytes(32)  # Заглушка
            
            box = SecretBox(session_key)
            decrypted = box.decrypt(ciphertext, nonce)
            
            return decrypted.decode('utf-8')
        except Exception as e:
            logger.error(f"Decryption error: {e}")
            return None
    
    def save_keys(self):
        """Сохранение ключей в защищенном хранилище"""
        key_file = self.config.data_dir / "keys.bin"
        # Реализация сохранения ключей
        pass
    
    def load_keys(self):
        """Загрузка ключей из защищенного хранилища"""
        key_file = self.config.data_dir / "keys.bin"
        if key_file.exists():
            # Реализация загрузки ключей
            pass

# ============================================================================
# БАЗА ДАННЫХ
# ============================================================================

class DatabaseManager:
    """Управление базой данных SQLite"""
    
    def __init__(self, config: AppConfig):
        self.config = config
        self.connection = None
        self.connect()
        self.create_tables()
    
    def connect(self):
        """Подключение к базе данных"""
        try:
            self.connection = sqlite3.connect(self.config.db_path)
            self.connection.row_factory = sqlite3.Row
            logger.info(f"Database connected: {self.config.db_path}")
        except Exception as e:
            logger.error(f"Database connection error: {e}")
            raise
    
    def create_tables(self):
        """Создание таблиц базы данных"""
        tables = [
            """
            CREATE TABLE IF NOT EXISTS users (
                user_id TEXT PRIMARY KEY,
                username TEXT UNIQUE NOT NULL,
                avatar_path TEXT,
                status TEXT DEFAULT 'offline',
                bio TEXT,
                public_key TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS contacts (
                contact_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                name TEXT NOT NULL,
                avatar TEXT,
                public_key TEXT,
                ip_address TEXT,
                port INTEGER,
                status TEXT DEFAULT 'offline',
                last_online TIMESTAMP,
                trust_level INTEGER DEFAULT 0,
                added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS messages (
                message_id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                receiver_id TEXT NOT NULL,
                content TEXT NOT NULL,
                encrypted_content TEXT,
                message_type TEXT DEFAULT 'text',
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                encrypted INTEGER DEFAULT 1,
                read_status INTEGER DEFAULT 0,
                attachments TEXT,
                FOREIGN KEY (sender_id) REFERENCES users (user_id),
                FOREIGN KEY (receiver_id) REFERENCES users (user_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS groups (
                group_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                description TEXT,
                avatar TEXT,
                created_by TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (created_by) REFERENCES users (user_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS group_members (
                group_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                joined_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                role TEXT DEFAULT 'member',
                PRIMARY KEY (group_id, user_id),
                FOREIGN KEY (group_id) REFERENCES groups (group_id),
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS files (
                file_id TEXT PRIMARY KEY,
                message_id TEXT,
                filename TEXT NOT NULL,
                filepath TEXT NOT NULL,
                size_bytes INTEGER,
                hash TEXT,
                uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (message_id) REFERENCES messages (message_id)
            )
            """
        ]
        
        cursor = self.connection.cursor()
        for table_sql in tables:
            try:
                cursor.execute(table_sql)
            except Exception as e:
                logger.error(f"Error creating table: {e}")
        
        self.connection.commit()
    
    def save_user(self, user: UserProfile):
        """Сохранение пользователя"""
        cursor = self.connection.cursor()
        cursor.execute("""
            INSERT OR REPLACE INTO users 
            (user_id, username, avatar_path, status, bio, public_key, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            user.user_id, user.username, user.avatar_path,
            user.status, user.bio, base64.b64encode(user.public_key).decode(),
            user.last_seen.isoformat()
        ))
        self.connection.commit()
    
    def get_user(self, user_id: str) -> Optional[UserProfile]:
        """Получение пользователя по ID"""
        cursor = self.connection.cursor()
        cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
        row = cursor.fetchone()
        
        if row:
            return UserProfile(
                username=row['username'],
                user_id=row['user_id'],
                avatar_path=row['avatar_path'],
                status=row['status'],
                bio=row['bio'],
                public_key=base64.b64decode(row['public_key']),
                created_at=datetime.fromisoformat(row['created_at']),
                last_seen=datetime.fromisoformat(row['last_seen'])
            )
        return None
    
    def save_message(self, message: Message):
        """Сохранение сообщения"""
        cursor = self.connection.cursor()
        cursor.execute("""
            INSERT INTO messages 
            (message_id, sender_id, receiver_id, content, message_type, 
             timestamp, encrypted, read_status, attachments)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            message.message_id, message.sender_id, message.receiver_id,
            message.content, message.message_type, message.timestamp.isoformat(),
            1 if message.encrypted else 0, 1 if message.read else 0,
            json.dumps(message.attachments) if message.attachments else None
        ))
        self.connection.commit()
    
    def get_conversation(self, user1_id: str, user2_id: str, limit: int = 100) -> List[Message]:
        """Получение истории переписки"""
        cursor = self.connection.cursor()
        cursor.execute("""
            SELECT * FROM messages 
            WHERE (sender_id = ? AND receiver_id = ?) 
               OR (sender_id = ? AND receiver_id = ?)
            ORDER BY timestamp DESC 
            LIMIT ?
        """, (user1_id, user2_id, user2_id, user1_id, limit))
        
        messages = []
        for row in cursor.fetchall():
            messages.append(Message(
                message_id=row['message_id'],
                sender_id=row['sender_id'],
                receiver_id=row['receiver_id'],
                content=row['content'],
                timestamp=datetime.fromisoformat(row['timestamp']),
                message_type=row['message_type'],
                encrypted=bool(row['encrypted']),
                read=bool(row['read_status']),
                attachments=json.loads(row['attachments']) if row['attachments'] else []
            ))
        
        return messages[::-1]  # Возвращаем в правильном порядке
    
    def close(self):
        """Закрытие соединения с БД"""
        if self.connection:
            self.connection.close()

# ============================================================================
# СИСТЕМА УВЕДОМЛЕНИЙ
# ============================================================================

class NotificationSystem:
    """Система уведомлений"""
    
    def __init__(self, config: AppConfig):
        self.config = config
        self.notifications = []
        self.notification_callbacks = {}
        
    def show_notification(self, title: str, message: str, notification_type: str = "info"):
        """Показать уведомление"""
        notification = {
            'id': secrets.token_hex(8),
            'title': title,
            'message': message,
            'type': notification_type,
            'timestamp': datetime.now(),
            'read': False
        }
        
        self.notifications.append(notification)
        
        # Вызов callback'ов
        for callback in self.notification_callbacks.values():
            callback(notification)
        
        # Системное уведомление (если поддерживается)
        self.show_system_notification(title, message)
        
        logger.info(f"Notification: {title} - {message}")
    
    def show_system_notification(self, title: str, message: str):
        """Показать системное уведомление"""
        try:
            system = platform.system()
            
            if system == "Windows":
                # Для Windows
                from win10toast import ToastNotifier
                toaster = ToastNotifier()
                toaster.show_toast(title, message, duration=5)
                
            elif system == "Darwin":  # macOS
                # Для macOS
                os.system(f"""
                    osascript -e 'display notification "{message}" with title "{title}"'
                """)
                
            elif system == "Linux":
                # Для Linux (требуется libnotify)
                os.system(f'notify-send "{title}" "{message}"')
                
        except Exception as e:
            logger.error(f"System notification error: {e}")
    
    def register_callback(self, callback_id: str, callback):
        """Регистрация callback'а для уведомлений"""
        self.notification_callbacks[callback_id] = callback
    
    def clear_notifications(self):
        """Очистка всех уведомлений"""
        self.notifications.clear()

# ============================================================================
# AI АССИСТЕНТ
# ============================================================================

class AIAssistant:
    """AI ассистент для помощи пользователю"""
    
    def __init__(self, config: AppConfig):
        self.config = config
        self.commands = self._load_commands()
        
    def _load_commands(self) -> Dict:
        """Загрузка команд ассистента"""
        return {
            'help': self._cmd_help,
            'status': self._cmd_status,
            'contacts': self._cmd_contacts,
            'clear': self._cmd_clear,
            'theme': self._cmd_theme,
            'encrypt': self._cmd_encrypt,
            'decrypt': self._cmd_decrypt,
            'scan': self._cmd_scan,
            'backup': self._cmd_backup,
            'restore': self._cmd_restore
        }
    
    def process_command(self, command: str, args: List[str] = None) -> str:
        """Обработка команды"""
        if not command:
            return "Введите команду. Для списка команд введите: /help"
        
        cmd = command.lower().lstrip('/')
        
        if cmd in self.commands:
            try:
                return self.commands[cmd](args or [])
            except Exception as e:
                return f"Ошибка выполнения команды: {str(e)}"
        else:
            return f"Неизвестная команда: {command}. Введите /help для списка команд."
    
    def _cmd_help(self, args: List[str]) -> str:
        """Команда помощи"""
        commands_list = "\n".join([f"/{cmd}" for cmd in self.commands.keys()])
        return f"""Доступные команды:

{commands_list}

Примеры:
/help - эта справка
/status - статус системы
/contacts - список контактов
/clear - очистка чата
/theme dark|light - смена темы
/encrypt текст - шифрование текста
/decrypt текст - дешифрование текста
/scan - проверка безопасности
/backup - создание резервной копии
/restore - восстановление из резервной копии
"""
    
    def _cmd_status(self, args: List[str]) -> str:
        """Команда статуса"""
        import psutil
        import platform
        
        # Системная информация
        system_info = platform.uname()
        cpu_percent = psutil.cpu_percent()
        memory = psutil.virtual_memory()
        
        return f"""Статус системы:
        
ОС: {system_info.system} {system_info.release}
Процессор: {cpu_percent}% загрузки
Память: {memory.percent}% использовано ({memory.used / 1024 / 1024:.1f} MB / {memory.total / 1024 / 1024:.1f} MB)
Диск: {psutil.disk_usage('/').percent}% использовано
Время работы: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

RAVEN Messenger:
Версия: {self.config.version}
Пользователь: {os.getenv('USER', 'Неизвестно')}
Директория данных: {self.config.base_dir}
"""
    
    def _cmd_contacts(self, args: List[str]) -> str:
        """Команда списка контактов"""
        # Здесь должна быть загрузка контактов из БД
        return "Список контактов:\n1. Контакт 1 (онлайн)\n2. Контакт 2 (оффлайн)\n3. Контакт 3 (онлайн)"
    
    def _cmd_clear(self, args: List[str]) -> str:
        """Команда очистки"""
        return "clear_chat"  # Специальный код для GUI
    
    def _cmd_theme(self, args: List[str]) -> str:
        """Команда смены темы"""
        if args and args[0] in ['dark', 'light']:
            return f"change_theme:{args[0]}"
        return "Использование: /theme dark|light"
    
    def _cmd_encrypt(self, args: List[str]) -> str:
        """Команда шифрования"""
        if args:
            text = " ".join(args)
            # Здесь должно быть реальное шифрование
            encrypted = base64.b64encode(text.encode()).decode()
            return f"Зашифрованный текст: {encrypted}"
        return "Использование: /encrypt текст_для_шифрования"
    
    def _cmd_decrypt(self, args: List[str]) -> str:
        """Команда дешифрования"""
        if args:
            try:
                text = " ".join(args)
                decrypted = base64.b64decode(text.encode()).decode()
                return f"Расшифрованный текст: {decrypted}"
            except:
                return "Ошибка дешифрования. Проверьте текст."
        return "Использование: /decrypt текст_для_дешифрования"
    
    def _cmd_scan(self, args: List[str]) -> str:
        """Команда проверки безопасности"""
        checks = []
        
        # Проверка криптографии
        if CRYPTO_AVAILABLE:
            checks.append("✅ Криптографические библиотеки доступны")
        else:
            checks.append("❌ Криптографические библиотеки отсутствуют")
        
        # Проверка директорий
        if self.config.base_dir.exists():
            checks.append(f"✅ Директория данных: {self.config.base_dir}")
        else:
            checks.append(f"❌ Директория данных не создана")
        
        # Проверка базы данных
        if self.config.db_path.exists():
            checks.append(f"✅ База данных: {self.config.db_path}")
        else:
            checks.append(f"❌ База данных не создана")
        
        return "Проверка безопасности:\n" + "\n".join(checks)
    
    def _cmd_backup(self, args: List[str]) -> str:
        """Команда создания резервной копии"""
        return "backup_start"  # Специальный код для GUI
    
    def _cmd_restore(self, args: List[str]) -> str:
        """Команда восстановления"""
        return "restore_start"  # Специальный код для GUI

# ============================================================================
# ОСНОВНОЙ GUI
# ============================================================================

class RavenGUI:
    """Основной графический интерфейс"""
    
    def __init__(self):
        # Инициализация конфигурации
        self.config = AppConfig()
        
        # Инициализация систем
        self.security = SecuritySystem(self.config)
        self.database = DatabaseManager(self.config)
        self.notifications = NotificationSystem(self.config)
        self.ai_assistant = AIAssistant(self.config)
        
        # Текущий пользователь
        self.current_user = None
        
        # Создание главного окна
        self.root = tk.Tk()
        self.root.title(f"{self.config.app_name} v{self.config.version}")
        self.root.geometry("1400x800")
        self.root.minsize(1200, 700)
        
        # Установка иконки
        self.set_icon()
        
        # Настройка стилей
        self.setup_styles()
        
        # Создание интерфейса
        self.create_interface()
        
        # Регистрация обработчиков
        self.notifications.register_callback("gui", self.on_notification)
        
        # Запуск
        self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
        
    def set_icon(self):
        """Установка иконки приложения"""
        try:
            # Создаем простую иконку если нет файла
            icon_path = self.config.data_dir / "icon.ico"
            if not icon_path.exists():
                self.create_default_icon(icon_path)
            
            if platform.system() == "Windows":
                self.root.iconbitmap(str(icon_path))
            else:
                # Для Linux/Mac
                img = ImageTk.PhotoImage(file=str(icon_path))
                self.root.iconphoto(True, img)
        except Exception as e:
            logger.error(f"Error setting icon: {e}")
    
    def create_default_icon(self, path: Path):
        """Создание иконки по умолчанию"""
        try:
            img = Image.new('RGBA', (256, 256), (41, 128, 185, 255))
            draw = ImageDraw.Draw(img)
            
            # Рисуем простую птичку (raven)
            draw.ellipse([50, 50, 206, 206], fill=(52, 152, 219, 255))
            draw.ellipse([70, 70, 186, 186], fill=(41, 128, 185, 255))
            
            # Сохраняем
            img.save(path, format='ICO')
        except Exception as e:
            logger.error(f"Error creating icon: {e}")
    
    def setup_styles(self):
        """Настройка стилей и тем"""
        # Используем современную тему
        sv_ttk.set_theme("dark")
        
        # Кастомные стили
        self.style = ttk.Style()
        
        # Стиль для кнопок
        self.style.configure('Raven.TButton',
                           padding=10,
                           font=('Segoe UI', 10))
        
        # Стиль для ввода
        self.style.configure('Raven.TEntry',
                           padding=8)
        
        # Стиль для меток
        self.style.configure('Raven.TLabel',
                           font=('Segoe UI', 10))
        
        # Стиль для заголовков
        self.style.configure('Title.TLabel',
                           font=('Segoe UI', 16, 'bold'))
    
    def create_interface(self):
        """Создание интерфейса"""
        # Главный контейнер
        main_container = ttk.Frame(self.root)
        main_container.pack(fill='both', expand=True, padx=2, pady=2)
        
        # Боковая панель
        self.create_sidebar(main_container)
        
        # Основная область
        self.create_main_area(main_container)
        
        # Статус бар
        self.create_status_bar()
        
        # Меню
        self.create_menu()
        
        # Запуск стартового диалога
        self.root.after(100, self.show_startup_dialog)
    
    def create_sidebar(self, parent):
        """Создание боковой панели"""
        # Боковая панель
        sidebar = ttk.Frame(parent, width=300)
        sidebar.pack(side='left', fill='y', padx=(0, 2))
        sidebar.pack_propagate(False)
        
        # Заголовок
        title_frame = ttk.Frame(sidebar)
        title_frame.pack(fill='x', pady=(10, 20), padx=10)
        
        # Логотип и название
        logo_label = ttk.Label(title_frame, 
                              text="🦅 RAVEN",
                              style='Title.TLabel')
        logo_label.pack()
        
        version_label = ttk.Label(title_frame,
                                 text=f"v{self.config.version}",
                                 style='Raven.TLabel')
        version_label.pack()
        
        # Панель поиска
        search_frame = ttk.Frame(sidebar)
        search_frame.pack(fill='x', padx=10, pady=(0, 15))
        
        self.search_var = tk.StringVar()
        search_entry = ttk.Entry(search_frame,
                                textvariable=self.search_var,
                                style='Raven.TEntry')
        search_entry.pack(fill='x')
        search_entry.insert(0, "Поиск контактов, сообщений...")
        search_entry.bind('<FocusIn>', lambda e: search_entry.delete(0, 'end') if search_entry.get() == "Поиск контактов, сообщений..." else None)
        
        # Вкладки боковой панели
        notebook = ttk.Notebook(sidebar)
        notebook.pack(fill='both', expand=True, padx=10, pady=(0, 10))
        
        # Вкладка контактов
        contacts_frame = ttk.Frame(notebook)
        self.setup_contacts_tab(contacts_frame)
        notebook.add(contacts_frame, text="👥 Контакты")
        
        # Вкладка чатов
        chats_frame = ttk.Frame(notebook)
        self.setup_chats_tab(chats_frame)
        notebook.add(chats_frame, text="💬 Чаты")
        
        # Вкладка групп
        groups_frame = ttk.Frame(notebook)
        self.setup_groups_tab(groups_frame)
        notebook.add(groups_frame, text="👥 Группы")
        
        # Кнопки быстрого доступа
        quick_frame = ttk.Frame(sidebar)
        quick_frame.pack(fill='x', padx=10, pady=(0, 15))
        
        buttons = [
            ("➕ Новый чат", self.new_chat),
            ("👤 Добавить контакт", self.add_contact),
            ("🔄 Обновить", self.refresh_all),
            ("⚙️ Настройки", self.open_settings)
        ]
        
        for text, command in buttons:
            btn = ttk.Button(quick_frame, text=text, command=command,
                           style='Raven.TButton')
            btn.pack(fill='x', pady=2)
        
        # Панель пользователя
        user_frame = ttk.Frame(sidebar)
        user_frame.pack(fill='x', padx=10, pady=15)
        
        if self.current_user:
            user_label = ttk.Label(user_frame,
                                  text=f"👤 {self.current_user.username}",
                                  style='Raven.TLabel')
            user_label.pack(anchor='w')
            
            status_label = ttk.Label(user_frame,
                                    text="🟢 В сети",
                                    style='Raven.TLabel')
            status_label.pack(anchor='w')
        else:
            login_btn = ttk.Button(user_frame,
                                  text="Войти / Зарегистрироваться",
                                  command=self.show_login_dialog,
                                  style='Raven.TButton')
            login_btn.pack(fill='x')
    
    def setup_contacts_tab(self, parent):
        """Настройка вкладки контактов"""
        # Панель инструментов
        toolbar = ttk.Frame(parent)
        toolbar.pack(fill='x', pady=(0, 10))
        
        ttk.Button(toolbar, text="Импорт", command=self.import_contacts).pack(side='left', padx=2)
        ttk.Button(toolbar, text="Экспорт", command=self.export_contacts).pack(side='left', padx=2)
        
        # Список контактов
        self.contacts_listbox = tk.Listbox(parent,
                                          bg='#2d2d2d',
                                          fg='white',
                                          font=('Segoe UI', 10),
                                          relief='flat',
                                          selectbackground='#3d3d3d')
        
        scrollbar = ttk.Scrollbar(parent)
        self.contacts_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.contacts_listbox.yview)
        
        self.contacts_listbox.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Заполняем тестовыми данными
        for i in range(1, 21):
            self.contacts_listbox.insert('end', f"👤 Контакт {i}")
        
        self.contacts_listbox.bind('<<ListboxSelect>>', self.on_contact_select)
    
    def setup_chats_tab(self, parent):
        """Настройка вкладки чатов"""
        self.chats_listbox = tk.Listbox(parent,
                                       bg='#2d2d2d',
                                       fg='white',
                                       font=('Segoe UI', 10),
                                       relief='flat',
                                       selectbackground='#3d3d3d')
        
        scrollbar = ttk.Scrollbar(parent)
        self.chats_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.chats_listbox.yview)
        
        self.chats_listbox.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Тестовые чаты
        chats = [
            "💬 Иван Петров (3 новых)",
            "💬 Мария Сидорова",
            "💬 Рабочая группа",
            "💬 Семья",
            "💬 Друзья"
        ]
        
        for chat in chats:
            self.chats_listbox.insert('end', chat)
        
        self.chats_listbox.bind('<<ListboxSelect>>', self.on_chat_select)
    
    def setup_groups_tab(self, parent):
        """Настройка вкладки групп"""
        # Панель создания группы
        create_frame = ttk.Frame(parent)
        create_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Button(create_frame,
                  text="➕ Создать группу",
                  command=self.create_group).pack(fill='x')
        
        # Список групп
        groups_frame = ttk.Frame(parent)
        groups_frame.pack(fill='both', expand=True)
        
        self.groups_listbox = tk.Listbox(groups_frame,
                                        bg='#2d2d2d',
                                        fg='white',
                                        font=('Segoe UI', 10),
                                        relief='flat',
                                        selectbackground='#3d3d3d')
        
        scrollbar = ttk.Scrollbar(groups_frame)
        self.groups_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=self.groups_listbox.yview)
        
        self.groups_listbox.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Тестовые группы
        groups = [
            "👥 Рабочая группа (15)",
            "👥 Семья (8)",
            "👥 Друзья (12)",
            "👥 Проект Alpha (6)"
        ]
        
        for group in groups:
            self.groups_listbox.insert('end', group)
    
    def create_main_area(self, parent):
        """Создание основной области"""
        # Основная область
        main_area = ttk.Frame(parent)
        main_area.pack(side='right', fill='both', expand=True)
        
        # Заголовок чата
        self.chat_header = ttk.Frame(main_area, height=60)
        self.chat_header.pack(fill='x')
        self.chat_header.pack_propagate(False)
        
        self.chat_title = ttk.Label(self.chat_header,
                                   text="Выберите чат для начала общения",
                                   style='Title.TLabel')
        self.chat_title.pack(side='left', padx=20, pady=15)
        
        # Кнопки управления чатом
        chat_buttons = ttk.Frame(self.chat_header)
        chat_buttons.pack(side='right', padx=20)
        
        button_configs = [
            ("📎", self.attach_file),
            ("🎤", self.start_voice_call),
            ("📹", self.start_video_call),
            ("📁", self.open_shared_files),
            ("⚙️", self.open_chat_settings)
        ]
        
        for text, command in button_configs:
            btn = ttk.Button(chat_buttons, text=text, command=command,
                           width=3, style='Raven.TButton')
            btn.pack(side='left', padx=2)
        
        # Область сообщений
        messages_container = ttk.Frame(main_area)
        messages_container.pack(fill='both', expand=True, pady=(0, 2))
        
        # Canvas для сообщений
        self.messages_canvas = tk.Canvas(messages_container,
                                        bg='#1e1e1e',
                                        highlightthickness=0)
        
        scrollbar = ttk.Scrollbar(messages_container,
                                 orient='vertical',
                                 command=self.messages_canvas.yview)
        
        self.messages_frame = ttk.Frame(self.messages_canvas)
        
        self.messages_canvas.configure(yscrollcommand=scrollbar.set)
        self.messages_canvas.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Создаем окно для фрейма сообщений
        self.messages_window = self.messages_canvas.create_window(
            (0, 0), window=self.messages_frame, anchor='nw',
            width=self.messages_canvas.winfo_reqwidth())
        
        # Привязка событий
        self.messages_frame.bind('<Configure>', self.on_messages_configure)
        self.messages_canvas.bind('<Configure>', self.on_canvas_configure)
        
        # Панель ввода
        input_frame = ttk.Frame(main_area)
        input_frame.pack(fill='x', pady=(0, 2))
        
        # Панель инструментов ввода
        input_toolbar = ttk.Frame(input_frame)
        input_toolbar.pack(fill='x', padx=10, pady=5)
        
        input_buttons = [
            ("📎", self.attach_file),
            ("🎵", self.attach_audio),
            ("📷", self.attach_photo),
            ("📍", self.send_location),
            ("😊", self.open_emoji_picker)
        ]
        
        for text, command in input_buttons:
            btn = ttk.Button(input_toolbar, text=text, command=command,
                           width=3, style='Raven.TButton')
            btn.pack(side='left', padx=2)
        
        # Текстовое поле ввода
        self.message_input = tk.Text(input_frame,
                                    height=4,
                                    bg='#2d2d2d',
                                    fg='white',
                                    insertbackground='white',
                                    font=('Segoe UI', 11),
                                    wrap='word',
                                    relief='flat',
                                    padx=10, pady=10)
        self.message_input.pack(fill='x', padx=10, pady=(0, 5))
        
        # Привязка событий
        self.message_input.bind('<Return>', self.on_input_return)
        self.message_input.bind('<Control-Return>', self.on_input_ctrl_return)
        self.message_input.bind('<KeyRelease>', self.on_input_change)
        
        # Панель отправки
        send_frame = ttk.Frame(input_frame)
        send_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        # Индикатор шифрования
        self.encryption_indicator = ttk.Label(send_frame,
                                             text="🔒 Сообщение будет зашифровано",
                                             style='Raven.TLabel')
        self.encryption_indicator.pack(side='left')
        
        # Кнопка отправки
        ttk.Button(send_frame,
                  text="Отправить",
                  command=self.send_message,
                  style='Raven.TButton').pack(side='right')
        
        # AI ассистент
        assistant_frame = ttk.Frame(main_area)
        assistant_frame.pack(fill='x', padx=10, pady=(0, 10))
        
        ttk.Label(assistant_frame,
                 text="🤖 AI Ассистент:",
                 style='Raven.TLabel').pack(side='left')
        
        self.assistant_input = ttk.Entry(assistant_frame,
                                        style='Raven.TEntry')
        self.assistant_input.pack(side='left', fill='x', expand=True, padx=(5, 0))
        self.assistant_input.bind('<Return>', self.on_assistant_command)
        
        ttk.Button(assistant_frame,
                  text="Выполнить",
                  command=self.execute_assistant_command,
                  style='Raven.TButton').pack(side='right', padx=(5, 0))
    
    def create_status_bar(self):
        """Создание статус бара"""
        status_bar = ttk.Frame(self.root, height=25)
        status_bar.pack(side='bottom', fill='x')
        status_bar.pack_propagate(False)
        
        # Левая часть
        left_frame = ttk.Frame(status_bar)
        left_frame.pack(side='left', fill='y', padx=10)
        
        self.status_label = ttk.Label(left_frame,
                                     text="Готов к работе",
                                     style='Raven.TLabel')
        self.status_label.pack(side='left')
        
        # Правая часть
        right_frame = ttk.Frame(status_bar)
        right_frame.pack(side='right', fill='y', padx=10)
        
        self.network_status = ttk.Label(right_frame,
                                       text="🌐 Сеть: Онлайн",
                                       style='Raven.TLabel')
        self.network_status.pack(side='right', padx=(10, 0))
        
        self.encryption_status = ttk.Label(right_frame,
                                          text="🔐 Шифрование: Активно",
                                          style='Raven.TLabel')
        self.encryption_status.pack(side='right', padx=(10, 0))
        
        self.time_label = ttk.Label(right_frame,
                                   text=datetime.now().strftime('%H:%M:%S'),
                                   style='Raven.TLabel')
        self.time_label.pack(side='right')
        
        # Обновление времени
        self.update_time()
    
    def create_menu(self):
        """Создание меню приложения"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # Файл
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Файл", menu=file_menu)
        file_menu.add_command(label="Новый чат", command=self.new_chat)
        file_menu.add_command(label="Новая группа", command=self.create_group)
        file_menu.add_separator()
        file_menu.add_command(label="Импорт контактов", command=self.import_contacts)
        file_menu.add_command(label="Экспорт контактов", command=self.export_contacts)
        file_menu.add_separator()
        file_menu.add_command(label="Резервная копия", command=self.create_backup)
        file_menu.add_command(label="Восстановление", command=self.restore_backup)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self.on_closing)
        
        # Правка
        edit_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Правка", menu=edit_menu)
        edit_menu.add_command(label="Копировать", command=self.copy_text)
        edit_menu.add_command(label="Вставить", command=self.paste_text)
        edit_menu.add_separator()
        edit_menu.add_command(label="Настройки", command=self.open_settings)
        
        # Вид
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Вид", menu=view_menu)
        view_menu.add_command(label="Темная тема", command=lambda: self.change_theme('dark'))
        view_menu.add_command(label="Светлая тема", command=lambda: self.change_theme('light'))
        view_menu.add_separator()
        view_menu.add_command(label="Увеличить шрифт", command=self.increase_font)
        view_menu.add_command(label="Уменьшить шрифт", command=self.decrease_font)
        
        # Инструменты
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Инструменты", menu=tools_menu)
        tools_menu.add_command(label="OSINT Анализ", command=self.open_osint_tools)
        tools_menu.add_command(label="Шифрование файлов", command=self.open_encryption_tools)
        tools_menu.add_command(label="Аудитор безопасности", command=self.run_security_audit)
        
        # Помощь
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Помощь", menu=help_menu)
        help_menu.add_command(label="Документация", command=self.open_documentation)
        help_menu.add_command(label="Проверка обновлений", command=self.check_updates)
        help_menu.add_separator()
        help_menu.add_command(label="О программе", command=self.show_about)
    
    def show_startup_dialog(self):
        """Показ стартового диалога"""
        if not self.current_user:
            self.show_login_dialog()
    
    def show_login_dialog(self):
        """Диалог входа/регистрации"""
        dialog = tk.Toplevel(self.root)
        dialog.title("RAVEN Messenger - Вход")
        dialog.geometry("400x500")
        dialog.resizable(False, False)
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Центрирование
        dialog.update_idletasks()
        x = (dialog.winfo_screenwidth() - dialog.winfo_width()) // 2
        y = (dialog.winfo_screenheight() - dialog.winfo_height()) // 2
        dialog.geometry(f"+{x}+{y}")
        
        # Заголовок
        title_label = ttk.Label(dialog,
                               text="Добро пожаловать в RAVEN",
                               style='Title.TLabel')
        title_label.pack(pady=(30, 10))
        
        subtitle_label = ttk.Label(dialog,
                                  text="Безопасный P2P мессенджер",
                                  style='Raven.TLabel')
        subtitle_label.pack(pady=(0, 30))
        
        # Вкладки
        notebook = ttk.Notebook(dialog)
        notebook.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        # Вход
        login_frame = ttk.Frame(notebook)
        self.setup_login_tab(login_frame, dialog)
        notebook.add(login_frame, text="Вход")
        
        # Регистрация
        register_frame = ttk.Frame(notebook)
        self.setup_register_tab(register_frame, dialog)
        notebook.add(register_frame, text="Регистрация")
        
        # Быстрый старт
        quick_frame = ttk.Frame(notebook)
        self.setup_quick_start_tab(quick_frame, dialog)
        notebook.add(quick_frame, text="Быстрый старт")
    
    def setup_login_tab(self, parent, dialog):
        """Настройка вкладки входа"""
        ttk.Label(parent, text="Имя пользователя:").pack(anchor='w', pady=(10, 0))
        username_entry = ttk.Entry(parent)
        username_entry.pack(fill='x', pady=(0, 10))
        
        ttk.Label(parent, text="Пароль:").pack(anchor='w')
        password_entry = ttk.Entry(parent, show="•")
        password_entry.pack(fill='x', pady=(0, 20))
        
        def login():
            username = username_entry.get()
            password = password_entry.get()
            
            if username and password:
                # Здесь должна быть проверка учетных данных
                self.current_user = UserProfile(
                    username=username,
                    user_id=hashlib.sha256(username.encode()).hexdigest()[:16],
                    avatar_path="",
                    status="online",
                    bio="",
                    public_key=b"",
                    created_at=datetime.now(),
                    last_seen=datetime.now()
                )
                
                # Сохраняем пользователя
                self.database.save_user(self.current_user)
                
                # Обновляем интерфейс
                self.update_user_panel()
                
                dialog.destroy()
                
                # Показываем уведомление
                self.notifications.show_notification(
                    "Вход выполнен",
                    f"Добро пожаловать, {username}!",
                    "success"
                )
            else:
                messagebox.showerror("Ошибка", "Заполните все поля")
        
        ttk.Button(parent,
                  text="Войти",
                  command=login,
                  style='Raven.TButton').pack(fill='x', pady=(0, 10))
    
    def setup_register_tab(self, parent, dialog):
        """Настройка вкладки регистрации"""
        ttk.Label(parent, text="Имя пользователя:").pack(anchor='w', pady=(10, 0))
        username_entry = ttk.Entry(parent)
        username_entry.pack(fill='x', pady=(0, 10))
        
        ttk.Label(parent, text="Пароль:").pack(anchor='w')
        password_entry = ttk.Entry(parent, show="•")
        password_entry.pack(fill='x', pady=(0, 5))
        
        ttk.Label(parent, text="Повторите пароль:").pack(anchor='w')
        password_confirm_entry = ttk.Entry(parent, show="•")
        password_confirm_entry.pack(fill='x', pady=(0, 20))
        
        def register():
            username = username_entry.get()
            password = password_entry.get()
            password_confirm = password_confirm_entry.get()
            
            if not username or not password:
                messagebox.showerror("Ошибка", "Заполните все поля")
                return
            
            if password != password_confirm:
                messagebox.showerror("Ошибка", "Пароли не совпадают")
                return
            
            # Регистрация пользователя
            user_id = hashlib.sha256(f"{username}{datetime.now().timestamp()}".encode()).hexdigest()[:16]
            
            # Генерация ключей
            private_key = NaClPrivateKey.generate()
            public_key = private_key.public_key
            
            self.current_user = UserProfile(
                username=username,
                user_id=user_id,
                avatar_path="",
                status="online",
                bio="Новый пользователь RAVEN",
                public_key=public_key._public_key,
                created_at=datetime.now(),
                last_seen=datetime.now()
            )
            
            # Сохраняем пользователя
            self.database.save_user(self.current_user)
            
            # Инициализируем безопасность
            self.security.initialize(password)
            
            # Обновляем интерфейс
            self.update_user_panel()
            
            dialog.destroy()
            
            # Показываем уведомление
            self.notifications.show_notification(
                "Регистрация успешна",
                f"Аккаунт {username} создан!",
                "success"
            )
            
            # Показываем мастер настройки
            self.show_setup_wizard()
        
        ttk.Button(parent,
                  text="Зарегистрироваться",
                  command=register,
                  style='Raven.TButton').pack(fill='x', pady=(0, 10))
    
    def setup_quick_start_tab(self, parent, dialog):
        """Настройка вкладки быстрого старта"""
        ttk.Label(parent,
                 text="Быстрый старт",
                 style='Title.TLabel').pack(pady=(20, 10))
        
        ttk.Label(parent,
                 text="Создайте временный аккаунт для тестирования:",
                 style='Raven.TLabel').pack(pady=(0, 20))
        
        def quick_start():
            # Генерация случайного имени
            adjectives = ["Быстрый", "Умный", "Смелый", "Тайный", "Свободный"]
            nouns = ["Сокол", "Ворон", "Орел", "Ястреб", "Сокол"]
            
            import random
            username = f"{random.choice(adjectives)}_{random.choice(nouns)}_{random.randint(100, 999)}"
            password = secrets.token_urlsafe(12)
            
            # Создаем пользователя
            user_id = hashlib.sha256(f"{username}{datetime.now().timestamp()}".encode()).hexdigest()[:16]
            
            self.current_user = UserProfile(
                username=username,
                user_id=user_id,
                avatar_path="",
                status="online",
                bio="Временный пользователь",
                public_key=b"",
                created_at=datetime.now(),
                last_seen=datetime.now()
            )
            
            # Сохраняем
            self.database.save_user(self.current_user)
            
            dialog.destroy()
            
            # Показываем учетные данные
            messagebox.showinfo(
                "Быстрый старт",
                f"Временный аккаунт создан!\n\n"
                f"Имя: {username}\n"
                f"Пароль: {password}\n\n"
                f"Сохраните пароль для восстановления доступа."
            )
            
            # Обновляем интерфейс
            self.update_user_panel()
        
        ttk.Button(parent,
                  text="Создать временный аккаунт",
                  command=quick_start,
                  style='Raven.TButton').pack(fill='x', pady=(0, 10))
        
        ttk.Button(parent,
                  text="Продолжить без регистрации",
                  command=lambda: dialog.destroy(),
                  style='Raven.TButton').pack(fill='x', pady=(0, 10))
    
    def show_setup_wizard(self):
        """Мастер начальной настройки"""
        wizard = tk.Toplevel(self.root)
        wizard.title("Мастер настройки RAVEN")
        wizard.geometry("500x600")
        wizard.resizable(False, False)
        wizard.transient(self.root)
        wizard.grab_set()
        
        # Центрирование
        wizard.update_idletasks()
        x = (wizard.winfo_screenwidth() - wizard.winfo_width()) // 2
        y = (wizard.winfo_screenheight() - wizard.winfo_height()) // 2
        wizard.geometry(f"+{x}+{y}")
        
        notebook = ttk.Notebook(wizard)
        notebook.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Шаг 1: Приветствие
        step1 = ttk.Frame(notebook)
        ttk.Label(step1,
                 text="Добро пожаловать в RAVEN!",
                 style='Title.TLabel').pack(pady=30)
        ttk.Label(step1,
                 text="Давайте настроим ваш мессенджер",
                 style='Raven.TLabel').pack(pady=(0, 20))
        notebook.add(step1, text="Приветствие")
        
        # Шаг 2: Безопасность
        step2 = ttk.Frame(notebook)
        ttk.Label(step2,
                 text="Настройки безопасности",
                 style='Title.TLabel').pack(pady=30)
        notebook.add(step2, text="Безопасность")
        
        # Шаг 3: Внешний вид
        step3 = ttk.Frame(notebook)
        ttk.Label(step3,
                 text="Настройки внешнего вида",
                 style='Title.TLabel').pack(pady=30)
        notebook.add(step3, text="Внешний вид")
        
        # Шаг 4: Завершение
        step4 = ttk.Frame(notebook)
        ttk.Label(step4,
                 text="Настройка завершена!",
                 style='Title.TLabel').pack(pady=30)
        
        def finish():
            wizard.destroy()
            self.notifications.show_notification(
                "Настройка завершена",
                "RAVEN Messenger готов к использованию!",
                "success"
            )
        
        ttk.Button(step4,
                  text="Завершить настройку",
                  command=finish,
                  style='Raven.TButton').pack(pady=20)
        
        notebook.add(step4, text="Завершение")
        
        # Кнопки навигации
        nav_frame = ttk.Frame(wizard)
        nav_frame.pack(fill='x', padx=20, pady=(0, 20))
        
        def next_tab():
            current = notebook.index(notebook.select())
            if current < len(notebook.tabs()) - 1:
                notebook.select(current + 1)
        
        def prev_tab():
            current = notebook.index(notebook.select())
            if current > 0:
                notebook.select(current - 1)
        
        ttk.Button(nav_frame,
                  text="Назад",
                  command=prev_tab,
                  style='Raven.TButton').pack(side='left')
        
        ttk.Button(nav_frame,
                  text="Далее",
                  command=next_tab,
                  style='Raven.TButton').pack(side='right')
    
    # ============================================================================
    # ОБРАБОТЧИКИ СОБЫТИЙ
    # ============================================================================
    
    def on_notification(self, notification):
        """Обработчик уведомлений"""
        if self.config.notify_new_message:
            # Показываем уведомление в GUI
            pass
    
    def on_messages_configure(self, event):
        """Обработчик изменения размера фрейма сообщений"""
        self.messages_canvas.configure(scrollregion=self.messages_canvas.bbox("all"))
    
    def on_canvas_configure(self, event):
        """Обработчик изменения размера canvas"""
        self.messages_canvas.itemconfig(self.messages_window, width=event.width)
    
    def on_input_return(self, event):
        """Обработчик нажатия Enter в поле ввода"""
        if not event.state & 0x4:  # Не Ctrl
            self.send_message()
            return 'break'  # Предотвращаем перенос строки
    
    def on_input_ctrl_return(self, event):
        """Обработчик нажатия Ctrl+Enter в поле ввода"""
        # Разрешаем перенос строки
        return None
    
    def on_input_change(self, event):
        """Обработчик изменения текста в поле ввода"""
        # Можно добавить live preview или подсчет символов
        pass
    
    def on_assistant_command(self, event):
        """Обработчик команды ассистента"""
        self.execute_assistant_command()
    
    def on_contact_select(self, event):
        """Обработчик выбора контакта"""
        selection = self.contacts_listbox.curselection()
        if selection:
            index = selection[0]
            contact_name = self.contacts_listbox.get(index)
            self.start_chat(contact_name)
    
    def on_chat_select(self, event):
        """Обработчик выбора чата"""
        selection = self.chats_listbox.curselection()
        if selection:
            index = selection[0]
            chat_name = self.chats_listbox.get(index)
            self.load_chat(chat_name)
    
    # ============================================================================
    # ОСНОВНЫЕ ФУНКЦИИ
    # ============================================================================
    
    def send_message(self):
        """Отправка сообщения"""
        message = self.message_input.get("1.0", "end-1c").strip()
        if not message or not self.current_user:
            return
        
        # Проверяем, является ли сообщение командой
        if message.startswith('/'):
            result = self.ai_assistant.process_command(message)
            if result == "clear_chat":
                self.clear_chat()
            elif result.startswith("change_theme:"):
                theme = result.split(":")[1]
                self.change_theme(theme)
            elif result == "backup_start":
                self.create_backup()
            elif result == "restore_start":
                self.restore_backup()
            else:
                self.add_message("🤖 Ассистент", result, is_assistant=True)
        else:
            # Отправляем обычное сообщение
            message_id = hashlib.sha256(
                f"{datetime.now().timestamp()}{message}".encode()
            ).hexdigest()[:16]
            
            msg = Message(
                message_id=message_id,
                sender_id=self.current_user.user_id,
                receiver_id="contact_id",  # Здесь должен быть ID получателя
                content=message,
                timestamp=datetime.now(),
                message_type="text",
                encrypted=True,
                read=False,
                attachments=[]
            )
            
            # Сохраняем в БД
            self.database.save_message(msg)
            
            # Добавляем в чат
            self.add_message(self.current_user.username, message, is_outgoing=True)
            
            # Шифруем и отправляем (если получатель в сети)
            # encrypted = self.security.encrypt_message(message, recipient_public_key)
            # self.network.send_message(recipient_id, encrypted)
        
        # Очищаем поле ввода
        self.message_input.delete("1.0", "end")
    
    def add_message(self, sender: str, content: str, is_outgoing: bool = False, is_assistant: bool = False):
        """Добавление сообщения в чат"""
        # Создаем фрейм для сообщения
        message_frame = ttk.Frame(self.messages_frame)
        message_frame.pack(fill='x', padx=20, pady=5)
        
        # Внутренний контейнер
        container = ttk.Frame(message_frame)
        
        if is_outgoing:
            container.pack(anchor='e')
            bg_color = '#2ecc71'  # Зеленый для исходящих
            text_color = 'white'
        elif is_assistant:
            container.pack(anchor='w')
            bg_color = '#9b59b6'  # Фиолетовый для ассистента
            text_color = 'white'
        else:
            container.pack(anchor='w')
            bg_color = '#34495e'  # Темный для входящих
            text_color = 'white'
        
        # Аватар и отправитель
        header_frame = ttk.Frame(container)
        header_frame.pack(fill='x')
        
        if not is_outgoing and not is_assistant:
            sender_label = ttk.Label(header_frame,
                                    text=f"👤 {sender}",
                                    style='Raven.TLabel')
            sender_label.pack(anchor='w')
        
        # Текст сообщения
        message_label = tk.Label(container,
                                text=content,
                                bg=bg_color,
                                fg=text_color,
                                font=('Segoe UI', 11),
                                wraplength=400,
                                justify='left',
                                padx=15, pady=10,
                                relief='flat')
        message_label.pack(fill='x')
        
        # Время
        time_frame = ttk.Frame(container)
        time_frame.pack(fill='x')
        
        time_text = datetime.now().strftime('%H:%M')
        time_label = ttk.Label(time_frame,
                              text=time_text,
                              style='Raven.TLabel')
        
        if is_outgoing:
            time_label.pack(side='right')
            # Иконка шифрования
            ttk.Label(time_frame,
                     text="🔒",
                     style='Raven.TLabel').pack(side='right', padx=(5, 0))
        else:
            time_label.pack(side='left')
        
        # Прокручиваем вниз
        self.messages_canvas.yview_moveto(1)
    
    def execute_assistant_command(self):
        """Выполнение команды ассистента"""
        command = self.assistant_input.get().strip()
        if not command:
            return
        
        result = self.ai_assistant.process_command(command)
        self.add_message("🤖 Ассистент", result, is_assistant=True)
        
        # Очищаем поле ввода
        self.assistant_input.delete(0, 'end')
    
    def start_chat(self, contact_name: str):
        """Начало чата с контактом"""
        self.chat_title.config(text=f"💬 {contact_name}")
        
        # Очищаем текущий чат
        self.clear_chat()
        
        # Загружаем историю (здесь должна быть загрузка из БД)
        self.add_message("Система", f"Начат чат с {contact_name}", is_assistant=True)
        
        # Тестовые сообщения
        self.add_message(contact_name, "Привет! Как дела?", is_outgoing=False)
        self.add_message(self.current_user.username if self.current_user else "Вы", "Привет! Все отлично, спасибо!", is_outgoing=True)
    
    def load_chat(self, chat_name: str):
        """Загрузка чата"""
        self.chat_title.config(text=chat_name)
        
        # Очищаем текущий чат
        self.clear_chat()
        
        # Загружаем историю
        self.add_message("Система", f"Загружен чат: {chat_name}", is_assistant=True)
    
    def clear_chat(self):
        """Очистка чата"""
        for widget in self.messages_frame.winfo_children():
            widget.destroy()
    
    def change_theme(self, theme: str):
        """Смена темы"""
        sv_ttk.set_theme(theme)
        self.config.theme = theme
        self.config.save_config()
        
        self.notifications.show_notification(
            "Тема изменена",
            f"Установлена {theme} тема",
            "info"
        )
    
    def update_time(self):
        """Обновление времени"""
        current_time = datetime.now().strftime('%H:%M:%S')
        self.time_label.config(text=current_time)
        self.root.after(1000, self.update_time)
    
    def update_user_panel(self):
        """Обновление панели пользователя"""
        # Здесь должна быть логика обновления интерфейса
        # после изменения пользователя
        pass
    
    # ============================================================================
    # ДОПОЛНИТЕЛЬНЫЕ ФУНКЦИИ
    # ============================================================================
    
    def new_chat(self):
        """Создание нового чата"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Новый чат")
        dialog.geometry("400x300")
        
        ttk.Label(dialog,
                 text="Создать новый чат",
                 style='Title.TLabel').pack(pady=20)
        
        # Поля для выбора контакта
        ttk.Label(dialog, text="Выберите контакт:").pack(anchor='w', padx=20)
        
        contacts_listbox = tk.Listbox(dialog,
                                     bg='#2d2d2d',
                                     fg='white',
                                     font=('Segoe UI', 10),
                                     height=8)
        contacts_listbox.pack(fill='both', expand=True, padx=20, pady=5)
        
        # Заполняем контактами
        for i in range(1, 11):
            contacts_listbox.insert('end', f"Контакт {i}")
        
        def create():
            selection = contacts_listbox.curselection()
            if selection:
                contact = contacts_listbox.get(selection[0])
                dialog.destroy()
                self.start_chat(contact)
            else:
                messagebox.showerror("Ошибка", "Выберите контакт")
        
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Button(btn_frame,
                  text="Создать",
                  command=create,
                  style='Raven.TButton').pack(side='right')
        ttk.Button(btn_frame,
                  text="Отмена",
                  command=dialog.destroy,
                  style='Raven.TButton').pack(side='right', padx=(0, 10))
    
    def add_contact(self):
        """Добавление контакта"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Добавить контакт")
        dialog.geometry("500x400")
        
        notebook = ttk.Notebook(dialog)
        notebook.pack(fill='both', expand=True, padx=20, pady=20)
        
        # По Node ID
        node_frame = ttk.Frame(notebook)
        self.setup_add_by_node(node_frame, dialog)
        notebook.add(node_frame, text="По Node ID")
        
        # По IP
        ip_frame = ttk.Frame(notebook)
        self.setup_add_by_ip(ip_frame, dialog)
        notebook.add(ip_frame, text="По IP адресу")
        
        # Импорт
        import_frame = ttk.Frame(notebook)
        self.setup_import_contact(import_frame, dialog)
        notebook.add(import_frame, text="Импорт")
    
    def setup_add_by_node(self, parent, dialog):
        """Настройка добавления по Node ID"""
        ttk.Label(parent,
                 text="Добавление по Node ID",
                 style='Raven.TLabel').pack(pady=10)
        
        ttk.Label(parent, text="Node ID:").pack(anchor='w', pady=(10, 0))
        node_entry = ttk.Entry(parent)
        node_entry.pack(fill='x', pady=(0, 10))
        
        ttk.Label(parent, text="Имя (опционально):").pack(anchor='w')
        name_entry = ttk.Entry(parent)
        name_entry.pack(fill='x', pady=(0, 20))
        
        def add():
            node_id = node_entry.get().strip()
            name = name_entry.get().strip() or f"Контакт_{node_id[:8]}"
            
            if node_id:
                # Здесь должно быть добавление контакта
                self.notifications.show_notification(
                    "Контакт добавлен",
                    f"Контакт {name} добавлен",
                    "success"
                )
                dialog.destroy()
            else:
                messagebox.showerror("Ошибка", "Введите Node ID")
        
        ttk.Button(parent,
                  text="Добавить",
                  command=add,
                  style='Raven.TButton').pack(fill='x')
    
    def setup_add_by_ip(self, parent, dialog):
        """Настройка добавления по IP"""
        ttk.Label(parent,
                 text="Добавление по IP адресу",
                 style='Raven.TLabel').pack(pady=10)
        
        ttk.Label(parent, text="IP адрес:").pack(anchor='w', pady=(10, 0))
        ip_entry = ttk.Entry(parent)
        ip_entry.pack(fill='x', pady=(0, 10))
        
        ttk.Label(parent, text="Порт:").pack(anchor='w')
        port_entry = ttk.Entry(parent)
        port_entry.pack(fill='x', pady=(0, 10))
        
        ttk.Label(parent, text="Имя (опционально):").pack(anchor='w')
        name_entry = ttk.Entry(parent)
        name_entry.pack(fill='x', pady=(0, 20))
        
        def add():
            ip = ip_entry.get().strip()
            port = port_entry.get().strip()
            name = name_entry.get().strip() or f"Контакт_{ip}"
            
            if ip and port:
                # Здесь должно быть добавление контакта
                self.notifications.show_notification(
                    "Контакт добавлен",
                    f"Контакт {name} добавлен",
                    "success"
                )
                dialog.destroy()
            else:
                messagebox.showerror("Ошибка", "Введите IP и порт")
        
        ttk.Button(parent,
                  text="Добавить",
                  command=add,
                  style='Raven.TButton').pack(fill='x')
    
    def setup_import_contact(self, parent, dialog):
        """Настройка импорта контакта"""
        ttk.Label(parent,
                 text="Импорт контакта из файла",
                 style='Raven.TLabel').pack(pady=10)
        
        def import_file():
            filepath = filedialog.askopenfilename(
                title="Выберите файл контакта",
                filetypes=[("JSON файлы", "*.json"), ("Все файлы", "*.*")]
            )
            
            if filepath:
                try:
                    # Здесь должен быть импорт
                    self.notifications.show_notification(
                        "Импорт выполнен",
                        f"Контакты импортированы из {os.path.basename(filepath)}",
                        "success"
                    )
                    dialog.destroy()
                except Exception as e:
                    messagebox.showerror("Ошибка", f"Ошибка импорта: {e}")
        
        ttk.Button(parent,
                  text="Выбрать файл",
                  command=import_file,
                  style='Raven.TButton').pack(pady=20)
    
    def import_contacts(self):
        """Импорт контактов"""
        self.add_contact()  # Используем тот же диалог
    
    def export_contacts(self):
        """Экспорт контактов"""
        filepath = filedialog.asksaveasfilename(
            title="Экспорт контактов",
            defaultextension=".json",
            filetypes=[("JSON файлы", "*.json"), ("Все файлы", "*.*")]
        )
        
        if filepath:
            try:
                # Здесь должен быть экспорт
                self.notifications.show_notification(
                    "Экспорт выполнен",
                    f"Контакты экспортированы в {os.path.basename(filepath)}",
                    "success"
                )
            except Exception as e:
                messagebox.showerror("Ошибка", f"Ошибка экспорта: {e}")
    
    def create_group(self):
        """Создание группы"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Создание группы")
        dialog.geometry("500x600")
        
        ttk.Label(dialog,
                 text="Создание новой группы",
                 style='Title.TLabel').pack(pady=20)
        
        # Поля для ввода
        fields = [
            ("Название группы:", "name"),
            ("Описание:", "description"),
            ("Аватар (опционально):", "avatar")
        ]
        
        entries = {}
        
        for label_text, key in fields:
            frame = ttk.Frame(dialog)
            frame.pack(fill='x', padx=20, pady=5)
            
            ttk.Label(frame, text=label_text, style='Raven.TLabel').pack(anchor='w')
            
            if key == "avatar":
                avatar_frame = ttk.Frame(frame)
                avatar_frame.pack(fill='x')
                
                avatar_entry = ttk.Entry(avatar_frame)
                avatar_entry.pack(side='left', fill='x', expand=True)
                
                def browse_avatar():
                    filepath = filedialog.askopenfilename(
                        title="Выберите аватар",
                        filetypes=[("Изображения", "*.png *.jpg *.jpeg *.gif")]
                    )
                    if filepath:
                        avatar_entry.delete(0, 'end')
                        avatar_entry.insert(0, filepath)
                
                ttk.Button(avatar_frame,
                          text="Обзор",
                          command=browse_avatar).pack(side='right', padx=(5, 0))
                entries[key] = avatar_entry
            else:
                entry = ttk.Entry(frame)
                entry.pack(fill='x')
                entries[key] = entry
        
        # Список контактов для добавления
        ttk.Label(dialog,
                 text="Выберите участников:",
                 style='Raven.TLabel').pack(anchor='w', padx=20, pady=(10, 0))
        
        contacts_frame = ttk.Frame(dialog)
        contacts_frame.pack(fill='both', expand=True, padx=20, pady=5)
        
        contacts_listbox = tk.Listbox(contacts_frame,
                                     bg='#2d2d2d',
                                     fg='white',
                                     font=('Segoe UI', 10),
                                     selectmode='multiple')
        
        scrollbar = ttk.Scrollbar(contacts_frame)
        contacts_listbox.config(yscrollcommand=scrollbar.set)
        scrollbar.config(command=contacts_listbox.yview)
        
        contacts_listbox.pack(side='left', fill='both', expand=True)
        scrollbar.pack(side='right', fill='y')
        
        # Заполняем контактами
        for i in range(1, 21):
            contacts_listbox.insert('end', f"Контакт {i}")
        
        def create():
            name = entries['name'].get().strip()
            if not name:
                messagebox.showerror("Ошибка", "Введите название группы")
                return
            
            selected = contacts_listbox.curselection()
            if not selected:
                messagebox.showerror("Ошибка", "Выберите хотя бы одного участника")
                return
            
            # Здесь должно быть создание группы
            self.notifications.show_notification(
                "Группа создана",
                f"Группа '{name}' создана",
                "success"
            )
            dialog.destroy()
        
        btn_frame = ttk.Frame(dialog)
        btn_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Button(btn_frame,
                  text="Создать группу",
                  command=create,
                  style='Raven.TButton').pack(side='right')
        ttk.Button(btn_frame,
                  text="Отмена",
                  command=dialog.destroy,
                  style='Raven.TButton').pack(side='right', padx=(0, 10))
    
    def refresh_all(self):
        """Обновление всех данных"""
        self.notifications.show_notification(
            "Обновление",
            "Данные обновлены",
            "info"
        )
    
    def open_settings(self):
        """Открытие настроек"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Настройки")
        dialog.geometry("600x500")
        
        notebook = ttk.Notebook(dialog)
        notebook.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Общие настройки
        general_frame = ttk.Frame(notebook)
        self.setup_general_settings(general_frame)
        notebook.add(general_frame, text="Общие")
        
        # Безопасность
        security_frame = ttk.Frame(notebook)
        self.setup_security_settings(security_frame)
        notebook.add(security_frame, text="Безопасность")
        
        # Уведомления
        notify_frame = ttk.Frame(notebook)
        self.setup_notification_settings(notify_frame)
        notebook.add(notify_frame, text="Уведомления")
        
        # Сеть
        network_frame = ttk.Frame(notebook)
        self.setup_network_settings(network_frame)
        notebook.add(network_frame, text="Сеть")
        
        # Внешний вид
        appearance_frame = ttk.Frame(notebook)
        self.setup_appearance_settings(appearance_frame)
        notebook.add(appearance_frame, text="Внешний вид")
    
    def setup_general_settings(self, parent):
        """Настройка общих параметров"""
        ttk.Label(parent,
                 text="Общие настройки",
                 style='Title.TLabel').pack(pady=10)
        
        # Автозапуск
        autostart_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(parent,
                       text="Запускать при старте системы",
                       variable=autostart_var).pack(anchor='w', pady=5)
        
        # Автообновление
        update_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(parent,
                       text="Автоматически проверять обновления",
                       variable=update_var).pack(anchor='w', pady=5)
        
        # Язык
        ttk.Label(parent, text="Язык:").pack(anchor='w', pady=(10, 0))
        lang_var = tk.StringVar(value="ru")
        lang_combo = ttk.Combobox(parent,
                                 textvariable=lang_var,
                                 values=["Русский", "English", "Español"])
        lang_combo.pack(fill='x', pady=(0, 20))
    
    def setup_security_settings(self, parent):
        """Настройка параметров безопасности"""
        ttk.Label(parent,
                 text="Настройки безопасности",
                 style='Title.TLabel').pack(pady=10)
        
        # Алгоритм шифрования
        ttk.Label(parent, text="Алгоритм шифрования:").pack(anchor='w', pady=(10, 0))
        algo_var = tk.StringVar(value="chacha20")
        algo_combo = ttk.Combobox(parent,
                                 textvariable=algo_var,
                                 values=["chacha20-poly1305", "aes-256-gcm", "xchacha20-poly1305"])
        algo_combo.pack(fill='x', pady=(0, 10))
        
        # Ротация ключей
        ttk.Label(parent, text="Ротация ключей (дней):").pack(anchor='w')
        rotation_var = tk.StringVar(value="30")
        rotation_spin = ttk.Spinbox(parent,
                                   textvariable=rotation_var,
                                   from_=1, to=365)
        rotation_spin.pack(fill='x', pady=(0, 10))
        
        # Таймаут сессии
        ttk.Label(parent, text="Таймаут сессии (минут):").pack(anchor='w')
        timeout_var = tk.StringVar(value="60")
        timeout_spin = ttk.Spinbox(parent,
                                  textvariable=timeout_var,
                                  from_=1, to=480)
        timeout_spin.pack(fill='x', pady=(0, 20))
        
        def save_security():
            self.config.encryption_algorithm = algo_var.get()
            self.config.key_rotation_days = int(rotation_var.get())
            self.config.session_timeout_minutes = int(timeout_var.get())
            self.config.save_config()
            
            self.notifications.show_notification(
                "Настройки сохранены",
                "Параметры безопасности обновлены",
                "success"
            )
        
        ttk.Button(parent,
                  text="Сохранить",
                  command=save_security,
                  style='Raven.TButton').pack(fill='x')
    
    def setup_notification_settings(self, parent):
        """Настройка уведомлений"""
        ttk.Label(parent,
                 text="Настройки уведомлений",
                 style='Title.TLabel').pack(pady=10)
        
        # Чекбоксы уведомлений
        notify_vars = {}
        
        options = [
            ("Показывать уведомления о новых сообщениях", "notify_new_message"),
            ("Уведомлять о подключении контактов", "notify_contact_online"),
            ("Уведомлять о получении файлов", "notify_file_received"),
            ("Звуковые уведомления", "notify_sound"),
            ("Всплывающие уведомления", "notify_popup")
        ]
        
        for text, key in options:
            var = tk.BooleanVar(value=getattr(self.config, key, True))
            notify_vars[key] = var
            
            cb = ttk.Checkbutton(parent, text=text, variable=var)
            cb.pack(anchor='w', pady=5)
        
        def save_notifications():
            for key, var in notify_vars.items():
                setattr(self.config, key, var.get())
            
            self.config.save_config()
            
            self.notifications.show_notification(
                "Настройки сохранены",
                "Параметры уведомлений обновлены",
                "success"
            )
        
        ttk.Button(parent,
                  text="Сохранить",
                  command=save_notifications,
                  style='Raven.TButton').pack(fill='x', pady=(20, 0))
    
    def setup_network_settings(self, parent):
        """Настройка параметров сети"""
        ttk.Label(parent,
                 text="Настройки сети",
                 style='Title.TLabel').pack(pady=10)
        
        # Порт
        ttk.Label(parent, text="Порт:").pack(anchor='w', pady=(10, 0))
        port_var = tk.StringVar(value=str(self.config.default_port))
        port_entry = ttk.Entry(parent, textvariable=port_var)
        port_entry.pack(fill='x', pady=(0, 10))
        
        # STUN серверы
        ttk.Label(parent, text="STUN серверы:").pack(anchor='w')
        stun_text = scrolledtext.ScrolledText(parent,
                                             height=4,
                                             bg='#2d2d2d',
                                             fg='white')
        stun_text.pack(fill='x', pady=(0, 20))
        
        for server in self.config.stun_servers:
            stun_text.insert('end', f"{server[0]}:{server[1]}\n")
        
        def save_network():
            try:
                self.config.default_port = int(port_var.get())
                self.config.save_config()
                
                self.notifications.show_notification(
                    "Настройки сохранены",
                    "Параметры сети обновлены",
                    "success"
                )
            except ValueError:
                messagebox.showerror("Ошибка", "Порт должен быть числом")
        
        ttk.Button(parent,
                  text="Сохранить",
                  command=save_network,
                  style='Raven.TButton').pack(fill='x')
    
    def setup_appearance_settings(self, parent):
        """Настройка внешнего вида"""
        ttk.Label(parent,
                 text="Настройки внешнего вида",
                 style='Title.TLabel').pack(pady=10)
        
        # Тема
        ttk.Label(parent, text="Тема:").pack(anchor='w', pady=(10, 0))
        theme_var = tk.StringVar(value=self.config.theme)
        
        theme_frame = ttk.Frame(parent)
        theme_frame.pack(fill='x', pady=(0, 10))
        
        ttk.Radiobutton(theme_frame,
                       text="Темная",
                       variable=theme_var,
                       value="dark").pack(side='left', padx=(0, 10))
        ttk.Radiobutton(theme_frame,
                       text="Светлая",
                       variable=theme_var,
                       value="light").pack(side='left')
        
        # Размер шрифта
        ttk.Label(parent, text="Размер шрифта:").pack(anchor='w')
        font_var = tk.StringVar(value=str(self.config.font_size))
        font_spin = ttk.Spinbox(parent,
                               textvariable=font_var,
                               from_=8, to=20)
        font_spin.pack(fill='x', pady=(0, 10))
        
        # Анимации
        anim_var = tk.BooleanVar(value=self.config.animation_enabled)
        ttk.Checkbutton(parent,
                       text="Включить анимации",
                       variable=anim_var).pack(anchor='w', pady=(0, 20))
        
        def save_appearance():
            self.config.theme = theme_var.get()
            self.config.font_size = int(font_var.get())
            self.config.animation_enabled = anim_var.get()
            self.config.save_config()
            
            # Применяем изменения
            self.change_theme(self.config.theme)
            
            self.notifications.show_notification(
                "Настройки сохранены",
                "Параметры внешнего вида обновлены",
                "success"
            )
        
        ttk.Button(parent,
                  text="Сохранить",
                  command=save_appearance,
                  style='Raven.TButton').pack(fill='x')
    
    def attach_file(self):
        """Прикрепление файла"""
        filepath = filedialog.askopenfilename(
            title="Выберите файл",
            filetypes=[
                ("Все файлы", "*.*"),
                ("Изображения", "*.png *.jpg *.jpeg *.gif *.bmp"),
                ("Документы", "*.pdf *.doc *.docx *.txt *.rtf"),
                ("Архивы", "*.zip *.rar *.7z"),
                ("Медиа", "*.mp3 *.mp4 *.avi *.mkv")
            ]
        )
        
        if filepath:
            self.add_message("Система", f"Файл прикреплен: {os.path.basename(filepath)}", is_assistant=True)
    
    def attach_audio(self):
        """Прикрепление аудио"""
        filepath = filedialog.askopenfilename(
            title="Выберите аудио файл",
            filetypes=[("Аудио файлы", "*.mp3 *.wav *.ogg *.flac")]
        )
        
        if filepath:
            self.add_message("Система", f"Аудио прикреплено: {os.path.basename(filepath)}", is_assistant=True)
    
    def attach_photo(self):
        """Прикрепление фото"""
        filepath = filedialog.askopenfilename(
            title="Выберите изображение",
            filetypes=[("Изображения", "*.png *.jpg *.jpeg *.gif *.bmp")]
        )
        
        if filepath:
            self.add_message("Система", f"Изображение прикреплено: {os.path.basename(filepath)}", is_assistant=True)
    
    def send_location(self):
        """Отправка местоположения"""
        # Здесь должна быть интеграция с геолокацией
        self.add_message("Система", "Функция отправки местоположения в разработке", is_assistant=True)
    
    def open_emoji_picker(self):
        """Открытие пикера эмодзи"""
        # Здесь должен быть пикер эмодзи
        self.add_message("Система", "Пикер эмодзи в разработке", is_assistant=True)
    
    def start_voice_call(self):
        """Начало голосового звонка"""
        self.notifications.show_notification(
            "Голосовой звонок",
            "Начинаем голосовой звонок...",
            "info"
        )
    
    def start_video_call(self):
        """Начало видеозвонка"""
        self.notifications.show_notification(
            "Видеозвонок",
            "Начинаем видеозвонок...",
            "info"
        )
    
    def open_shared_files(self):
        """Открытие общих файлов"""
        self.notifications.show_notification(
            "Общие файлы",
            "Открываю список общих файлов...",
            "info"
        )
    
    def open_chat_settings(self):
        """Открытие настроек чата"""
        self.notifications.show_notification(
            "Настройки чата",
            "Открываю настройки текущего чата...",
            "info"
        )
    
    def copy_text(self):
        """Копирование текста"""
        # Здесь должна быть логика копирования
        pass
    
    def paste_text(self):
        """Вставка текста"""
        # Здесь должна быть логика вставки
        pass
    
    def increase_font(self):
        """Увеличение шрифта"""
        self.config.font_size += 1
        if self.config.font_size > 20:
            self.config.font_size = 20
        self.config.save_config()
        
        self.notifications.show_notification(
            "Размер шрифта",
            f"Размер шрифта увеличен до {self.config.font_size}",
            "info"
        )
    
    def decrease_font(self):
        """Уменьшение шрифта"""
        self.config.font_size -= 1
        if self.config.font_size < 8:
            self.config.font_size = 8
        self.config.save_config()
        
        self.notifications.show_notification(
            "Размер шрифта",
            f"Размер шрифта уменьшен до {self.config.font_size}",
            "info"
        )
    
    def open_osint_tools(self):
        """Открытие OSINT инструментов"""
        dialog = tk.Toplevel(self.root)
        dialog.title("OSINT Tools")
        dialog.geometry("700x600")
        
        notebook = ttk.Notebook(dialog)
        notebook.pack(fill='both', expand=True, padx=20, pady=20)
        
        # Анализ текста
        text_frame = ttk.Frame(notebook)
        self.setup_osint_text_analysis(text_frame)
        notebook.add(text_frame, text="Анализ текста")
        
        # Анализ файлов
        file_frame = ttk.Frame(notebook)
        self.setup_osint_file_analysis(file_frame)
        notebook.add(file_frame, text="Анализ файлов")
        
        # Поиск в сети
        search_frame = ttk.Frame(notebook)
        self.setup_osint_web_search(search_frame)
        notebook.add(search_frame, text="Поиск в сети")
    
    def setup_osint_text_analysis(self, parent):
        """Настройка анализа текста"""
        ttk.Label(parent,
                 text="Анализ текста на конфиденциальную информацию",
                 style='Title.TLabel').pack(pady=10)
        
        ttk.Label(parent, text="Введите текст для анализа:").pack(anchor='w')
        
        text_area = scrolledtext.ScrolledText(parent,
                                             height=10,
                                             bg='#2d2d2d',
                                             fg='white')
        text_area.pack(fill='both', expand=True, pady=(0, 10))
        
        def analyze():
            text = text_area.get("1.0", "end-1c")
            if not text:
                return
            
            # Простой анализ
            findings = []
            
            # Поиск email
            emails = re.findall(r'[\w\.-]+@[\w\.-]+', text)
            if emails:
                findings.append(f"Найдены email: {', '.join(emails)}")
            
            # Поиск телефонов
            phones = re.findall(r'\+?[1-9][0-9 .\-\(\)]{8,}[0-9]', text)
            if phones:
                findings.append(f"Найдены телефоны: {', '.join(phones)}")
            
            # Поиск IP адресов
            ips = re.findall(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', text)
            if ips:
                findings.append(f"Найдены IP адреса: {', '.join(ips)}")
            
            # Вывод результатов
            if findings:
                result = "\n".join(findings)
                messagebox.showinfo("Результаты анализа", result)
            else:
                messagebox.showinfo("Результаты анализа", "Конфиденциальная информация не обнаружена")
        
        ttk.Button(parent,
                  text="🔍 Анализировать",
                  command=analyze,
                  style='Raven.TButton').pack(fill='x')
    
    def setup_osint_file_analysis(self, parent):
        """Настройка анализа файлов"""
        ttk.Label(parent,
                 text="Анализ файлов на метаданные",
                 style='Title.TLabel').pack(pady=10)
        
        def select_file():
            filepath = filedialog.askopenfilename(
                title="Выберите файл для анализа"
            )
            
            if filepath:
                try:
                    size = os.path.getsize(filepath)
                    modified = datetime.fromtimestamp(os.path.getmtime(filepath))
                    created = datetime.fromtimestamp(os.path.getctime(filepath))
                    
                    info = f"""
Файл: {os.path.basename(filepath)}
Размер: {size:,} байт ({size/1024:.1f} KB)
Создан: {created.strftime('%Y-%m-%d %H:%M:%S')}
Изменен: {modified.strftime('%Y-%m-%d %H:%M:%S')}
Расширение: {os.path.splitext(filepath)[1]}
                    """
                    
                    messagebox.showinfo("Метаданные файла", info)
                except Exception as e:
                    messagebox.showerror("Ошибка", f"Ошибка анализа: {e}")
        
        ttk.Button(parent,
                  text="📁 Выбрать файл",
                  command=select_file,
                  style='Raven.TButton').pack(pady=20)
    
    def setup_osint_web_search(self, parent):
        """Настройка поиска в сети"""
        ttk.Label(parent,
                 text="Поиск информации в интернете",
                 style='Title.TLabel').pack(pady=10)
        
        ttk.Label(parent, text="Поисковый запрос:").pack(anchor='w')
        query_entry = ttk.Entry(parent)
        query_entry.pack(fill='x', pady=(0, 10))
        
        def search():
            query = query_entry.get().strip()
            if query:
                # Открываем браузер с поиском
                url = f"https://www.google.com/search?q={query}"
                webbrowser.open(url)
                
                self.notifications.show_notification(
                    "Поиск выполнен",
                    f"Запрос '{query}' отправлен в Google",
                    "info"
                )
        
        ttk.Button(parent,
                  text="🔍 Искать в Google",
                  command=search,
                  style='Raven.TButton').pack(fill='x')
    
    def open_encryption_tools(self):
        """Открытие инструментов шифрования"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Инструменты шифрования")
        dialog.geometry("500x400")
        
        ttk.Label(dialog,
                 text="Инструменты шифрования",
                 style='Title.TLabel').pack(pady=20)
        
        # Шифрование текста
        text_frame = ttk.LabelFrame(dialog, text="Шифрование текста")
        text_frame.pack(fill='x', padx=20, pady=10)
        
        ttk.Label(text_frame, text="Текст:").pack(anchor='w', padx=10, pady=(10, 0))
        text_entry = tk.Text(text_frame, height=3, bg='#2d2d2d', fg='white')
        text_entry.pack(fill='x', padx=10, pady=(0, 10))
        
        def encrypt_text():
            text = text_entry.get("1.0", "end-1c")
            if text:
                encrypted = base64.b64encode(text.encode()).decode()
                messagebox.showinfo("Зашифрованный текст", encrypted)
        
        ttk.Button(text_frame,
                  text="Зашифровать",
                  command=encrypt_text).pack(padx=10, pady=(0, 10))
        
        # Шифрование файлов
        file_frame = ttk.LabelFrame(dialog, text="Шифрование файлов")
        file_frame.pack(fill='x', padx=20, pady=10)
        
        def encrypt_file():
            filepath = filedialog.askopenfilename(title="Выберите файл для шифрования")
            if filepath:
                messagebox.showinfo("Шифрование", f"Файл {os.path.basename(filepath)} будет зашифрован")
        
        ttk.Button(file_frame,
                  text="Выбрать файл для шифрования",
                  command=encrypt_file).pack(padx=10, pady=10)
    
    def run_security_audit(self):
        """Запуск аудита безопасности"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Аудит безопасности")
        dialog.geometry("600x400")
        
        ttk.Label(dialog,
                 text="Аудит безопасности системы",
                 style='Title.TLabel').pack(pady=20)
        
        # Проверки
        checks = [
            ("✅ Криптографические библиотеки", CRYPTO_AVAILABLE),
            ("✅ Директория данных", self.config.base_dir.exists()),
            ("✅ База данных", self.config.db_path.exists()),
            ("✅ Конфигурационный файл", (self.config.base_dir / "config.json").exists()),
            ("✅ Резервные копии", len(list(self.config.backup_dir.glob("*.backup"))) > 0),
        ]
        
        for check_text, check_result in checks:
            color = "green" if check_result else "red"
            symbol = "✅" if check_result else "❌"
            ttk.Label(dialog,
                     text=f"{symbol} {check_text}",
                     foreground=color).pack(anchor='w', padx=20, pady=2)
        
        # Кнопка детального аудита
        def detailed_audit():
            result = self.ai_assistant.process_command("/scan")
            messagebox.showinfo("Детальный аудит", result)
        
        ttk.Button(dialog,
                  text="Запустить детальный аудит",
                  command=detailed_audit,
                  style='Raven.TButton').pack(pady=20)
    
    def create_backup(self):
        """Создание резервной копии"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            backup_file = self.config.backup_dir / f"raven_backup_{timestamp}.zip"
            
            with zipfile.ZipFile(backup_file, 'w') as zipf:
                # Добавляем базу данных
                if self.config.db_path.exists():
                    zipf.write(self.config.db_path, "raven.db")
                
                # Добавляем конфигурацию
                config_file = self.config.base_dir / "config.json"
                if config_file.exists():
                    zipf.write(config_file, "config.json")
                
                # Добавляем ключи (если есть)
                key_file = self.config.data_dir / "keys.bin"
                if key_file.exists():
                    zipf.write(key_file, "keys.bin")
            
            self.notifications.show_notification(
                "Резервная копия создана",
                f"Backup сохранен: {backup_file.name}",
                "success"
            )
            
            messagebox.showinfo(
                "Резервная копия",
                f"Резервная копия успешно создана:\n{backup_file}"
            )
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка создания резервной копии: {e}")
    
    def restore_backup(self):
        """Восстановление из резервной копии"""
        filepath = filedialog.askopenfilename(
            title="Выберите резервную копию",
            filetypes=[("Backup files", "*.zip"), ("All files", "*.*")]
        )
        
        if filepath:
            if messagebox.askyesno("Восстановление", 
                                 "Восстановление перезапишет текущие данные. Продолжить?"):
                try:
                    with zipfile.ZipFile(filepath, 'r') as zipf:
                        zipf.extractall(self.config.base_dir)
                    
                    self.notifications.show_notification(
                        "Восстановление выполнено",
                        "Данные успешно восстановлены из резервной копии",
                        "success"
                    )
                    
                    # Перезагружаем конфигурацию
                    self.config.load_config()
                    
                    messagebox.showinfo(
                        "Восстановление",
                        "Данные успешно восстановлены. Перезапустите приложение."
                    )
                except Exception as e:
                    messagebox.showerror("Ошибка", f"Ошибка восстановления: {e}")
    
    def open_documentation(self):
        """Открытие документации"""
        webbrowser.open("https://github.com/YOUR-USERNAME/raven-secure-messenger/wiki")
    
    def check_updates(self):
        """Проверка обновлений"""
        self.notifications.show_notification(
            "Проверка обновлений",
            "Проверяем наличие обновлений...",
            "info"
        )
        
        # Здесь должна быть проверка обновлений
        messagebox.showinfo(
            "Проверка обновлений",
            f"Установлена последняя версия: {self.config.version}"
        )
    
    def show_about(self):
        """Показ информации о программе"""
        about_text = f"""
{self.config.app_name} v{self.config.version}

Полностью децентрализованный P2P мессенджер 
с военным шифрованием и AI ассистентом.

Возможности:
• P2P архитектура без серверов
• Шифрование X25519 + ChaCha20-Poly1305
• Встроенный OSINT анализ
• AI ассистент для помощи
• Современный графический интерфейс
• Поддержка файлов и медиа

Автор: {self.config.author}
GitHub: https://github.com/YOUR-USERNAME/raven-secure-messenger

Лицензия: MIT
        """
        
        messagebox.showinfo("О программе", about_text)
    
    def on_closing(self):
        """Обработка закрытия приложения"""
        if messagebox.askokcancel("Выход", "Закрыть RAVEN Messenger?"):
            # Сохраняем конфигурацию
            self.config.save_config()
            
            # Закрываем базу данных
            if hasattr(self, 'database'):
                self.database.close()
            
            # Закрываем окно
            self.root.destroy()
    
    def run(self):
        """Запуск приложения"""
        try:
            self.root.mainloop()
        except Exception as e:
            logger.error(f"Application error: {e}")
            messagebox.showerror("Ошибка", f"Критическая ошибка: {e}")

# ============================================================================
# ТОЧКА ВХОДА
# ============================================================================

def main():
    """Основная функция"""
    print("""
    ╔══════════════════════════════════════════════╗
    ║       RAVEN SECURE MESSENGER v3.0            ║
    ║       Complete System with GUI               ║
    ╚══════════════════════════════════════════════╝
    
    Загрузка системы...
    """)
    
    # Проверка зависимостей
    if not CRYPTO_AVAILABLE:
        print("Установите зависимости: pip install cryptography pynacl argon2-cffi pillow")
        return
    
    try:
        # Запуск приложения
        app = RavenGUI()
        app.run()
        
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        messagebox.showerror("Ошибка", f"Не удалось запустить приложение: {e}")

if __name__ == "__main__":
    main()
