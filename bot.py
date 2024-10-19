import logging
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes
import sqlite3
from web3 import Web3
import secrets
import json

# Налаштування логування
logging.basicConfig(format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', level=logging.INFO)
logger = logging.getLogger(__name__)

# Підключення до Ethereum мережі
w3 = Web3(Web3.HTTPProvider('https://rpc.ankr.com/eth'))

# Підключення до бази даних
conn = sqlite3.connect('user_wallets.db')
c = conn.cursor()

# Створення таблиці, якщо вона не існує
c.execute('''CREATE TABLE IF NOT EXISTS wallets
             (user_id INTEGER PRIMARY KEY, keys TEXT)''')
conn.commit()

# Функція для генерації нового гаманця
def generate_wallet():
    private_key = secrets.token_hex(32)
    account = w3.eth.account.from_key(private_key)
    return private_key, account.address

# Функція для форматування повідомлення з балансом
async def format_balance_message(address):
    try:
        balance_wei = w3.eth.get_balance(address)
        balance_eth = w3.from_wei(balance_wei, 'ether')
        return f"Баланс вашого гаманця: {balance_eth} ETH"
    except Exception as e:
        logger.error(f"Error fetching balance for address {address}: {e}")
        return "Не вдалося отримати баланс. Спробуйте ще раз пізніше."

# Обробник команди /start
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    c.execute("SELECT * FROM wallets WHERE user_id=?", (user_id,))
    existing_wallet = c.fetchone()
    
    if existing_wallet:
        await update.message.reply_text("У вас вже є гаманець. Використовуйте /balance для перевірки балансу.")
    else:
        private_key, public_key = generate_wallet()
        keys = json.dumps({"private": private_key, "public": public_key})
        c.execute("INSERT INTO wallets VALUES (?, ?)", (user_id, keys))
        conn.commit()
        await update.message.reply_text(f"Ваш новий гаманець створено!\nПублічна адреса: {public_key}\nПриватний ключ: {private_key}\nЗбережіть приватний ключ у надійному місці!")
        
        # Відразу перевіряємо баланс
        balance_message = await format_balance_message(public_key)
        await update.message.reply_text(balance_message)

# Обробник команди /balance
async def balance(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    c.execute("SELECT keys FROM wallets WHERE user_id=?", (user_id,))
    result = c.fetchone()

    if result:
        keys = json.loads(result[0])
        public_key = keys["public"]
        balance_message = await format_balance_message(public_key)
        await update.message.reply_text(balance_message)
    else:
        await update.message.reply_text("У вас ще немає гаманця. Використовуйте /start для створення.")

# Головна функція
def main():
    application = Application.builder().token("7388192040:AAE6ySUHROsj21UOZkSxs4uOmdVnRrKTmC4").build()

    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("balance", balance))

    # Запуск бота
    application.run_polling()

if __name__ == '__main__':
    main()