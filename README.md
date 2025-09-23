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
  - HackenProof (if available)  
- Detects **newly added programs** in real-time  
- Sends alerts to **Telegram** (Discord & Email coming soon)  
- Hacker-style HTML alerts with program names, types (VDP/RDP/WEB/IP), tags & scopes  
- Snapshot system to avoid duplicate notifications  
- Fully configurable via environment variables (no secrets hardcoded)  

---

## ⚙️ Installation  

```bash
git clone https://github.com/yourname/rinnegan.git
cd rinnegan
pip install -r requirements.txt
```

🚀 Usage

Set environment variables (Linux/macOS):

export TELEGRAM_TOKEN="123456:ABC-DEF..."
export TELEGRAM_CHAT_ID="-1001234567890"
# Optional: if your Telegram group has topics
export TELEGRAM_MESSAGE_THREAD_ID="42"

Run the watcher:

python rinnegan.py --dry-run     # just print results
python rinnegan.py               # send Telegram alerts

🛰️ Example Alert:

🚨 3 new programs discovered — Rinnegan

🛰️ HackerOne — 2 new
• Tesla Motors [WEB,IP]
• Stripe VDP [VDP,WEB]

🛰️ Bugcrowd — 1 new
• Atlassian RDP [RDP,WEB]

🔎 Run your recon on these quickly — good luck! — Rinnegan


🕶️ Hacker Notes

First blood matters. Speed + accuracy = impact.

Use --dry-run while tuning templates to avoid spamming your group.

If Telegram refuses messages, check token, chat ID, bot permissions (make the bot admin or disable privacy mode with BotFather).

Keep tokens secure: use .env (ignored by git) or CI secrets—never commit tokens.

🛡️ Security & Etiquette

Respect platforms' terms of service. Prefer official APIs when available.

Don’t abuse frequency or scrape aggressively — keep requests polite, rate-limited and cached.

Notify program owners responsibly; follow each program's disclosure policy. This tool helps find programs — how you act after discovery is your responsibility.

☠️ License & Disclaimer

This tool is for education and reconnaissance only. Use responsibly. The author is not responsible for misuse or illegal activity. You are responsible for complying with applicable laws and platform policies.
