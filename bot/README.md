# Scam Shield Telegram Bot

The bot runs locally and calls Scam Shield's existing text, URL, and image detection functions directly. It does not require the web server to be running.

## Setup

1. Install the project's existing dependencies and the Telegram bot dependency from the repository root:

   ```powershell
   python -m pip install -r requirements.txt
   python -m pip install -r bot/requirements.txt
   ```

2. Create a Telegram bot with [@BotFather](https://t.me/BotFather), then set its token in your environment. In PowerShell:

   ```powershell
   $env:TELEGRAM_BOT_TOKEN = "your-token-from-BotFather"
   ```

   On macOS or Linux:

   ```sh
   export TELEGRAM_BOT_TOKEN="your-token-from-BotFather"
   ```

3. From the repository root, start polling:

   ```powershell
   python -m bot.telegram_bot
   ```

4. To add a direct shortcut in the web frontend, copy `frontend/.env.example` to `frontend/.env.local` and replace the example username:

   ```env
   VITE_TELEGRAM_BOT_URL=https://t.me/YourBotUsername
   ```

   Restart the frontend after changing the value. This is a public bot link, not a secret. Never put `TELEGRAM_BOT_TOKEN` in a `VITE_` variable; Vite exposes those values to browsers.

Send or forward a text message or URL, or send a photo/image screenshot. The reply includes the verdict, confidence, red flags, explanation, and safety advice. High-risk results advise users in India to call **1930** if money has been lost.

The bot uses the same local models, data files, and optional provider settings as the existing Scam Shield application. Keep the token private and do not commit it to source control.
