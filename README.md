# 👁️‍🗨️ Rinnegan — Bounty Programs Watcher  

> _"The eye that sees everything."_  

Rinnegan is a **bounty program watcher** built for hackers & bug hunters.  
It monitors top bug bounty platforms and alerts you when **new programs** appear — so you can be the first to strike ⚡  

---

## 🔥 Features  
- Monitors **multiple platforms**:
  - HackerOne  
  - Bugcrowd  
  - Intigriti  
  - YesWeHack  
  - Federacy  
- Detects **newly added programs** in real-time  
- Sends alerts to **Telegram** (Discord optional)  
- Hacker-style HTML alerts with program names, bounty ranges, types (VDP/RDP), and scopes  
- Snapshot system to avoid duplicate notifications  
- Fully configurable via environment variables (no secrets hardcoded)  

---

## ⚙️ Installation  

```git clone https://github.com/indra-031/rinnegan.git```
```cd rinnegan```
```pip install -r requirements.txt```

## 🚀 Usage
Set environment variables (Linux/macOS):
```
export TELEGRAM_TOKEN="123456:ABC-DEF..."
export TELEGRAM_CHAT_ID="-1001234567890"
# Optional: if your Telegram group has topics
export TELEGRAM_MESSAGE_THREAD_ID="42"

# Optional Discord integration
export DISCORD_WEBHOOK_URL="https://discord.com/api/webhooks/..."
```
Run the watcher:
```
python rinnegan.py --dry-run     # just print results
python rinnegan.py               # send Telegram/Discord alerts
```
## 🛰️ Example Alert
🚨 3 new programs discovered — Rinnegan

🛰️ HackerOne — 2 new
• Tesla Motors [WEB,IP]
• Stripe VDP [VDP,WEB]

🛰️ Bugcrowd — 1 new
• Atlassian RDP [RDP,WEB]

🔎 Run your recon on these quickly — good luck! — Rinnegan

## 🧠 Automation (Cron Job)
You can automate Rinnegan to run every hour using cron on Linux:
crontab -e
Add the following line:

0 * * * * /usr/bin/python3 /path/to/rinnegan.py >> /path/to/rinnegan.log 2>&1
This will execute the watcher every hour and log its output to rinnegan.log.

## 🕶️ Hacker Notes
First blood matters. Speed + accuracy = impact.

Use --dry-run while tuning templates to avoid spamming your Telegram or Discord groups.

If Telegram refuses messages, check:

Token validity

Chat ID correctness

Bot permissions (make the bot admin or disable privacy mode via BotFather)

Keep tokens secure:

Use a .env file (ignored by git)

Or store secrets in CI/CD environment variables

Never commit tokens publicly

## 🛡️ Security & Etiquette
Respect platforms' Terms of Service.

Prefer official APIs when available.

Don’t abuse frequency — keep requests polite, rate-limited, and cached.

-Use responsibly and follow each program’s disclosure policy.

-This tool helps discover programs — what you do next is your responsibility.

## 🧑‍💻 Author
Built with ⚡ by Indra
