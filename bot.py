import logging
from telegram import Update, ReplyKeyboardMarkup
from telegram.ext import Application, CommandHandler, MessageHandler, filters, ContextTypes
import sqlite3
from web3 import Web3
import secrets

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
             (user_id INTEGER PRIMARY KEY, address TEXT)''')
conn.commit()

# Функція для генерації нового гаманця
def generate_wallet():
    private_key = secrets.token_hex(32)
    account = w3.eth.account.from_key(private_key)
    return account.address, private_key

# Обробник команди /start
async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    c.execute("SELECT * FROM wallets WHERE user_id=?", (user_id,))
    existing_wallet = c.fetchone()
    
    if existing_wallet:
        await update.message.reply_text("У вас вже є гаманець. Використовуйте /balance для перевірки балансу.")
    else:
        address, private_key = generate_wallet()
        c.execute("INSERT INTO wallets VALUES (?, ?)", (user_id, address))
        conn.commit()
        await update.message.reply_text(f"Ваш новий гаманець створено!\nАдреса: {address}\nПриватний ключ: {private_key}\nЗбережіть приватний ключ у надійному місці!")

# Обробник команди /balance
async def balance(update: Update, context: ContextTypes.DEFAULT_TYPE):
    user_id = update.effective_user.id
    c.execute("SELECT address FROM wallets WHERE user_id=?", (user_id,))
    result = c.fetchone()
    
    if result:
        address = result[0]
        balance_wei = w3.eth.get_balance(address)
        balance_eth = w3.from_wei(balance_wei, 'ether')
        await update.message.reply_text(f"Баланс вашого гаманця: {balance_eth} ETH")
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