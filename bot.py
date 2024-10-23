import logging  
import os  
import base64  
import hashlib  
import secrets  # Імпорт модуля для генерації криптографічно стійких випадкових чисел
import sqlite3  
from telegram import Update, ReplyKeyboardMarkup, KeyboardButton  
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters 
from web3 import Web3  # Імпорт Web3 для роботи з блокчейном Ethereum
from cryptography.fernet import Fernet, InvalidToken  # Імпорт Fernet для симетричного шифрування
from dotenv import load_dotenv  # Імпорт функції для завантаження змінних середовища з файлу .env

# Налаштування логування з більш детальним форматом
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',  # Формат повідомлень логування
    level=logging.INFO,  # Рівень логування: INFO
    handlers=[  # Список обробників
        logging.StreamHandler()  # Логування в консоль
    ]
)
logger = logging.getLogger(__name__)  # Ініціалізація логера

# Константи для кнопок
ENCRYPT_BUTTON = "Отримати зашифрований ключ"  # Текст кнопки для шифрування
DECRYPT_BUTTON = "Отримати розшифрований ключ"  # Текст кнопки для розшифрування

# Завантаження конфігурації з файлу .env
dotenv_path = os.path.join(os.path.dirname(__file__), 'password.env')  # Шлях до файлу .env
if not os.path.exists(dotenv_path):  # Перевірка існування файлу
    raise FileNotFoundError("Не знайдено файл password.env")  # Виведення помилки, якщо файл не знайдено

load_dotenv(dotenv_path)  # Завантаження змінних середовища з файлу .env

# Перевірка наявності необхідних змінних середовища
ENCRYPTION_PASSWORD = os.getenv('ENCRYPTION_PASSWORD')  # Отримання пароля для шифрування з середовища
TELEGRAM_TOKEN = os.getenv('TELEGRAM_TOKEN')  # Отримання токену Telegram бота з середовища

if not ENCRYPTION_PASSWORD or not TELEGRAM_TOKEN:  # Перевірка, чи всі змінні отримані
    raise ValueError("ENCRYPTION_PASSWORD або TELEGRAM_TOKEN не знайдено в файлі конфігурації")  # Виведення помилки

# Ініціалізація Web3 та Fernet
w3 = Web3(Web3.HTTPProvider('https://rpc.ankr.com/eth'))  # Ініціалізація Web3 для підключення до Ethereum через RPC

#Генерує ключ Fernet з паролю
def generate_fernet_key(password: str) -> bytes:
    hashed = hashlib.sha256(password.encode()).digest()  # Хешування паролю через SHA-256 для отримання 32 байтів
    return base64.urlsafe_b64encode(hashed)  # Кодування в base64 для використання з Fernet

try:
    fernet_key = generate_fernet_key(ENCRYPTION_PASSWORD)  # Генерація ключа Fernet з паролю
    fernet = Fernet(fernet_key)  # Ініціалізація об'єкта Fernet з ключем
    logger.info("Fernet успішно ініціалізовано")  # Логування успішної ініціалізації Fernet
except Exception as e:
    logger.critical(f"Помилка при ініціалізації Fernet: {e}")  # Логування критичної помилки при ініціалізації
    raise  # Виведення помилки

#Створює з'єднання з базою даних
def get_db_connection():
    try:
        conn = sqlite3.connect('user_wallets.db')  # Підключення до бази даних SQLite
        conn.execute("PRAGMA foreign_keys = ON")  # Включення підтримки зовнішніх ключів
        return conn  # Повернення об'єкта з'єднання
    except sqlite3.Error as e:
        logger.error(f"Помилка підключення до бази даних: {e}")  # Логування помилки
        raise  # Виведення помилки

# Ініціалізація бази даних
try:
    with get_db_connection() as conn:  # Відкриття з'єднання з базою даних
        c = conn.cursor()  # Створення курсору для взаємодії з базою даних
        c.execute('''CREATE TABLE IF NOT EXISTS wallets
                     (user_id INTEGER PRIMARY KEY, private_key TEXT, public_key TEXT)''')  # Створення таблиці для збереження гаманців
        conn.commit()  # Збереження змін у базі даних
        logger.info("База даних успішно ініціалізована")  # Логування успішної ініціалізації бази
except sqlite3.Error as e:
    logger.critical(f"Помилка при ініціалізації бази даних: {e}")  # Логування критичної помилки
    raise  # Виведення помилки

#Генерує новий Ethereum гаманець
def generate_wallet():
    try:
        private_key = secrets.token_hex(32)  # Генерація випадкового приватного ключа
        account = w3.eth.account.from_key(private_key)  # Створення об'єкта гаманця на основі приватного ключа
        return private_key, account.address  # Повернення приватного ключа та публічної адреси
    except Exception as e:
        logger.error(f"Помилка при генерації гаманця: {e}")  # Логування помилки
        raise  # Виведення помилки

#Шифрує приватний ключ
def encrypt_private_key(private_key: str) -> str:
    if not private_key:
        return private_key  # Повернення без змін, якщо ключ пустий
        
    try:
        try:
            encrypted_bytes = private_key.encode()  # Конвертація приватного ключа в байти
            fernet.decrypt(encrypted_bytes)  # Перевірка, чи не зашифрований ключ уже
            return private_key  # Якщо ключ уже зашифрований, повертаємо його
        except:
            encrypted_key = fernet.encrypt(private_key.encode())  # Шифрування ключа за допомогою Fernet
            return encrypted_key.decode()  # Повернення зашифрованого ключа
    except Exception:
        return private_key  # Повернення оригінального ключа у випадку помилки

#Розшифровує приватний ключ
def decrypt_private_key(encrypted_key: str) -> str:
    if not encrypted_key:
        return encrypted_key  # Повернення без змін, якщо ключ пустий
        
    try:
        encrypted_bytes = encrypted_key.encode()  # Конвертація зашифрованого ключа в байти
        decrypted_key = fernet.decrypt(encrypted_bytes)  # Розшифрування ключа
        return decrypted_key.decode()  # Повернення розшифрованого ключа
    except:
        return encrypted_key  # Якщо не вдалося розшифрувати, повертаємо як є
    
#Форматує повідомлення з балансом гаманця
async def format_balance_message(address):
    try:
        balance_wei = w3.eth.get_balance(address)  # Отримання балансу гаманця в Wei
        balance_eth = w3.from_wei(balance_wei, 'ether')  # Конвертація балансу в ETH
        return f"Баланс вашого гаманця: {balance_eth} ETH"  # Формування повідомлення з балансом
    except Exception as e:
        logger.error(f"Помилка при отриманні балансу для адреси {address}: {e}")  # Логування помилки
        return "Не вдалося отримати баланс. Спробуйте ще раз пізніше."  # Повернення повідомлення про помилку

#Створює клавіатуру з кнопками
def get_keyboard():
    
    keyboard = [
        [KeyboardButton(ENCRYPT_BUTTON)],  # Кнопка для шифрування
        [KeyboardButton(DECRYPT_BUTTON)]  # Кнопка для розшифрування
    ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True)  # Створення клавіатури

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Обробник команди /start"""
    user_id = update.effective_user.id  # Отримання ідентифікатора користувача
    logger.info(f"Команда /start від користувача {user_id}")  # Логування отримання команди
    
    try:
        with get_db_connection() as conn:  # Підключення до бази даних
            c = conn.cursor()  # Створення курсора
            c.execute("SELECT * FROM wallets WHERE user_id=?", (user_id,))  # Пошук гаманця за ідентифікатором користувача
            existing_wallet = c.fetchone()  # Отримання результату запиту
        
            if existing_wallet:  # Якщо гаманець уже існує
                logger.info(f"Знайдено існуючий гаманець для користувача {user_id}")  # Логування
                await update.message.reply_text(
                    "У вас вже є гаманець. Використовуйте /balance для перевірки балансу.",  # Повідомлення користувачу
                    reply_markup=get_keyboard()  # Додавання клавіатури
                )
            else:
                try:
                    logger.info(f"Створення нового гаманця для користувача {user_id}")  # Логування створення гаманця
                    private_key, public_key = generate_wallet()  # Генерація нового гаманця
                    encrypted_private_key = encrypt_private_key(private_key)  # Шифрування приватного ключа
                    
                    c.execute("INSERT INTO wallets (user_id, private_key, public_key) VALUES (?, ?, ?)",
                             (user_id, encrypted_private_key, public_key))  # Вставка нового гаманця в базу даних
                    conn.commit()  # Збереження змін
                    logger.info(f"Новий гаманець успішно створено для користувача {user_id}")  # Логування успішного створення
                    
                    await update.message.reply_text(
                        f"Ваш новий гаманець створено!\nПублічна адреса: {public_key}\n"
                        "Не забудьте зберегти свій приватний ключ у безпечному місці!",  # Повідомлення про успішне створення
                        reply_markup=get_keyboard()  # Додавання клавіатури
                    )
                    
                    balance_message = await format_balance_message(public_key)  # Формування повідомлення про баланс
                    await update.message.reply_text(balance_message)  # Відправка повідомлення про баланс
                except Exception as e:
                    error_msg = str(e)  # Отримання повідомлення про помилку
                    logger.error(f"Помилка при створенні гаманця для користувача {user_id}: {error_msg}")  # Логування помилки
                    await update.message.reply_text(
                        f"Виникла помилка при створенні гаманця: {error_msg}"  # Відправка повідомлення про помилку
                    )
    except Exception as e:
        error_msg = str(e)  # Отримання повідомлення про помилку
        logger.error(f"Критична помилка у функції start для користувача {user_id}: {error_msg}")  # Логування критичної помилки
        await update.message.reply_text(
            "Виникла критична помилка. Будь ласка, спробуйте пізніше або зверніться до адміністратора."  # Повідомлення користувачу
        )

#Обробник натискань кнопок
async def handle_button_press(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id  # Отримання ідентифікатора користувача
    button_text = update.message.text  # Отримання тексту кнопки
    logger.info(f"Отримано натискання кнопки від користувача {user_id}: {button_text}")  # Логування отриманого натискання
    
    try:
        with get_db_connection() as conn:  # Підключення до бази даних
            c = conn.cursor()  # Створення курсору
            c.execute("SELECT private_key, public_key FROM wallets WHERE user_id=?", (user_id,))  # Пошук гаманця за ідентифікатором користувача
            result = c.fetchone()  # Отримання результату запиту

            if result:  # Якщо гаманець знайдено
                encrypted_private_key, public_key = result  # Отримання зашифрованого приватного ключа та публічного ключа
                logger.info(f"Знайдено дані гаманця для користувача {user_id}")  # Логування
                
                if button_text == ENCRYPT_BUTTON:  # Якщо натиснуто кнопку шифрування
                    message = f"Ваш зашифрований ключ: {encrypted_private_key}"  # Формування повідомлення
                    logger.info(f"Відправляємо зашифрований ключ користувачу {user_id}")  # Логування
                    
                elif button_text == DECRYPT_BUTTON:  # Якщо натиснуто кнопку розшифрування
                    try:
                        logger.info(f"Спроба розшифрування ключа для користувача {user_id}")  # Логування спроби розшифрування
                        decrypted_key = decrypt_private_key(encrypted_private_key)  # Розшифрування ключа
                        message = f"Ваш розшифрований ключ: {decrypted_key}"  # Формування повідомлення з розшифрованим ключем
                        logger.info(f"Ключ успішно розшифровано для користувача {user_id}")  # Логування успішного розшифрування
                    except ValueError as e:
                        error_msg = str(e)  # Отримання повідомлення про помилку
                        logger.error(f"Помилка при розшифруванні для користувача {user_id}: {error_msg}")  # Логування помилки
                        message = (
                            "Виникла помилка при розшифруванні ключа. "
                            "Можливо, ключ шифрування був змінений або дані пошкоджені. "
                            "Будь ласка, зверніться до адміністратора."  # Повідомлення про помилку
                        )
                else:
                    logger.warning(f"Невідома команда від користувача {user_id}: {button_text}")  # Логування невідомої команди
                    return  # Вихід з функції
                
                await update.message.reply_text(message, reply_markup=get_keyboard())  # Відправка повідомлення з клавіатурою
                logger.info(f"Відповідь успішно надіслано користувачу {user_id}")  # Логування успішного відправлення
            else:
                logger.warning(f"Гаманець не знайдено для користувача {user_id}")  # Логування відсутності гаманця
                await update.message.reply_text(
                    "У вас ще немає гаманця. Використовуйте /start для створення."  # Повідомлення про відсутність гаманця
                )
    except Exception as e:
        error_msg = str(e)  # Отримання повідомлення про помилку
        logger.error(f"Загальна помилка для користувача {user_id}: {error_msg}")  # Логування загальної помилки
        
#Обробник команди /balance
async def balance(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id  # Отримання ідентифікатора користувача
    
    try:
        with get_db_connection() as conn:  # Підключення до бази даних
            c = conn.cursor()  # Створення курсору
            c.execute("SELECT private_key, public_key FROM wallets WHERE user_id=?", (user_id,))  # Пошук гаманця за ідентифікатором користувача
            result = c.fetchone()  # Отримання результату запиту

            if result:  # Якщо гаманець знайдено
                encrypted_private_key, public_key = result  # Отримання зашифрованого приватного ключа та публічного ключа
                balance_message = await format_balance_message(public_key)  # Формування повідомлення про баланс
                await update.message.reply_text(balance_message, reply_markup=get_keyboard())  # Відправка повідомлення з клавіатурою
            else:
                await update.message.reply_text("У вас ще немає гаманця. Використовуйте /start для створення.")  # Повідомлення про відсутність гаманця
    except Exception as e:
        error_msg = str(e)  # Отримання повідомлення про помилку
        logger.error(f"Помилка при отриманні балансу для користувача {user_id}: {error_msg}")  # Логування помилки
        await update.message.reply_text(
            "Виникла помилка при отриманні балансу. Спробуйте пізніше."  # Повідомлення про помилку при отриманні балансу
        )

#Головна функція запуску бота
def main():
    try:
        logger.info("Starting the bot")  # Логування запуску бота
        application = Application.builder().token(TELEGRAM_TOKEN).build()  # Створення об'єкта бота з токеном

        # Додавання обробників команд і повідомлень
        application.add_handler(CommandHandler("start", start))  # Обробник для команди /start
        application.add_handler(CommandHandler("balance", balance))  # Обробник для команди /balance
        application.add_handler(MessageHandler(
            filters.Regex(f"^({ENCRYPT_BUTTON}|{DECRYPT_BUTTON})$"),  # Фільтрація натискань кнопок
            handle_button_press  # Обробка натискань кнопок
        ))

        logger.info("Handlers added, starting polling")  # Логування успішного додавання обробників
        application.run_polling()  # Запуск бота у режимі довготривалого опитування
    except Exception as e:
        logger.critical(f"Критична помилка при запуску бота: {e}")  # Логування критичної помилки
        raise  # Повторне викидання винятку для зупинки програми

if __name__ == '__main__':
    main()  # Виклик основної функції
