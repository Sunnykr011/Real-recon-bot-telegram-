#!/usr/bin/env python3
import os
import logging
import asyncio
import threading
import requests
from bs4 import BeautifulSoup

# PTB v20 imports
from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes

# Local modules
from vulnerability_scanner import VulnerabilityScanner
from report_generator import ReportGenerator
from utils import split_text, validate_domain

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class ReconBot:
    def __init__(self, token: str):
        self.token = token
        self.scanner = VulnerabilityScanner()
        self.report_generator = ReportGenerator()
        self.active_scans = {}

    # ---------- legacy helpers (sync) ----------
    def crtsh_scan(self, domain):
        try:
            url = f"https://crt.sh/?q=%25.{domain}"
            res = requests.get(url, timeout=10)
            res.raise_for_status()
        except requests.RequestException:
            return []
        from bs4 import BeautifulSoup as BS
        soup = BS(res.text, 'html.parser')
        subdomains = set()
        for td in soup.find_all('td'):
            text = td.get_text(strip=True)
            if text.endswith(domain):
                subdomains.add(text.lower())
        return list(subdomains)

    def wayback_scan(self, domain):
        try:
            url = f"http://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json"
            res = requests.get(url, timeout=10)
            res.raise_for_status()
        except requests.RequestException:
            return []
        try:
            data = res.json()
        except ValueError:
            return []
        urls = [entry[2] for entry in data[1:]]
        return list(set(urls))

    def sitemap_scan(self, domain):
        urls = []
        for scheme in ['http://', 'https://']:
            url = f"{scheme}{domain}/sitemap.xml"
            try:
                res = requests.get(url, timeout=10)
                res.raise_for_status()
            except requests.RequestException:
                continue
            from bs4 import BeautifulSoup as BS
            soup = BS(res.text, 'xml')
            for loc in soup.find_all('loc'):
                text = loc.text.strip()
                if text:
                    urls.append(text)
            if urls:
                break
        return list(set(urls))

    def pastebin_scan(self, domain):
        try:
            res = requests.get(f"https://pastebin.com/search?q={domain}", timeout=10)
            res.raise_for_status()
        except requests.RequestException:
            return []
        from bs4 import BeautifulSoup as BS
        soup = BS(res.text, 'html.parser')
        results = []
        for a in soup.find_all('a'):
            href = getattr(a, 'get', lambda *_: None)('href')
            if not href:
                continue
            href = str(href)
            if href.startswith('/paste/') or href.startswith('/raw/'):
                paste_id = href.split('/')[-1]
                raw_url = f"https://pastebin.com/raw/{paste_id}"
                try:
                    raw = requests.get(raw_url, timeout=5)
                    raw.raise_for_status()
                    text = raw.text
                    if domain in text:
                        results.append(text)
                except requests.RequestException:
                    continue
        return results

    def run_legacy_scan(self, domain):
        results = {}
        try:
            results['subdomains'] = self.crtsh_scan(domain)
        except Exception as e:
            logger.error(f"CRT.sh scan error: {e}")
            results['subdomains'] = []
        try:
            results['wayback'] = self.wayback_scan(domain)
        except Exception as e:
            logger.error(f"Wayback scan error: {e}")
            results['wayback'] = []
        try:
            results['sitemap'] = self.sitemap_scan(domain)
        except Exception as e:
            logger.error(f"Sitemap scan error: {e}")
            results['sitemap'] = []
        try:
            results['pastebin'] = self.pastebin_scan(domain)
        except Exception as e:
            logger.error(f"Pastebin scan error: {e}")
            results['pastebin'] = []
        return results

    async def _send_report(self, ctx: ContextTypes.DEFAULT_TYPE, chat_id: int, report: str):
        for chunk in split_text(report, 4000):
            await ctx.bot.send_message(chat_id=chat_id, text=chunk, parse_mode='Markdown')

    # ---------- command handlers (async) ----------
    async def start(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        welcome_text = (
            "🤖 *Advanced Recon Bot* - Bug Hunting Edition\n\n"
            "🎯 *Available Commands:*\n"
            "• `/scan <domain>` - Full reconnaissance scan\n"
            "• `/dorks <domain>` - Google dork vulnerability scan\n"
            "• `/quick <domain>` - Quick vulnerability check\n"
            "• `/status` - Show active scans\n"
            "• `/help` - Show detailed help\n\n"
            "🔍 *Features:*\n"
            "• 200+ Google dorks for vulnerability discovery\n"
            "• SQL injection, XSS, and LFI detection\n"
            "• Exposed files and admin panels discovery\n"
            "• Smart false positive filtering\n"
            "• Detailed vulnerability reports with severity scoring\n"
            "• Multi-threaded scanning for efficiency\n\n"
            "⚠️ *Usage:* `/scan example.com` or `/dorks target.com`\n\n"
            "*Note:* This bot is for educational and authorized security testing only."
        )
        await update.message.reply_text(welcome_text, parse_mode='Markdown')

    async def help_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        help_text = (
            "📚 *Detailed Help - Advanced Recon Bot*\n\n"
            "🔍 **SCAN COMMANDS:**\n\n"
            "**`/scan <domain>`**\n- Complete reconnaissance scan\n- Includes: subdomains, wayback URLs, sitemaps, pastebins\n- Google dork vulnerability scanning\n- Comprehensive security assessment\n\n"
            "**`/dorks <domain>`**  \n- Focused Google dork scanning\n- 200+ vulnerability-specific dorks\n- Categories: SQLi, XSS, LFI, exposed files\n- Smart result validation and filtering\n\n"
            "**`/quick <domain>`**\n- Fast vulnerability check\n- Essential dorks only\n- Quick response for time-sensitive assessments\n\n"
            "📊 **SCAN TYPES COVERED:**\n• SQL Injection vulnerabilities\n• Cross-Site Scripting (XSS)\n• Local File Inclusion (LFI)\n• Directory traversal\n• Exposed configuration files\n• Database backups and dumps\n• Admin panels and login pages\n• API endpoints and documentation\n• Sensitive file exposure\n\n"
            "🎯 **REPORT FEATURES:**\n• CVSS-like severity scoring\n• Detailed vulnerability descriptions\n• Proof-of-concept URLs\n• Remediation recommendations\n• False positive filtering\n\n"
            "⚠️ **IMPORTANT DISCLAIMERS:**\n• Use only on domains you own or have permission to test\n• Bot includes rate limiting to avoid IP blocks\n• Results are for security assessment purposes only\n• Always verify findings manually before reporting\n\n"
            "Type `/scan example.com` to get started!"
        )
        await update.message.reply_text(help_text, parse_mode='Markdown')

    async def status_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not self.active_scans:
            await update.message.reply_text("✅ No active scans running")
        else:
            active_list = "\n".join([f"• `{d}`" for d in self.active_scans.keys()])
            await update.message.reply_text(f"⏳ *Active Scans:*\n{active_list}", parse_mode='Markdown')

    # ---- scan wrappers: run blocking scans in thread, then send report ----
    async def scan_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        args = context.args or []
        if not args:
            await update.message.reply_text(
                "❌ Usage: `/scan <domain>`\nExample: `/scan example.com`",
                parse_mode='Markdown'
            )
            return
        domain = args[0].strip()
        if not validate_domain(domain):
            await update.message.reply_text("❌ Invalid domain format.", parse_mode='Markdown')
            return
        chat_id = update.message.chat_id
        if domain in self.active_scans:
            await update.message.reply_text(f"⏳ Scan already in progress for `{domain}`", parse_mode='Markdown')
            return
        self.active_scans[domain] = True
        await update.message.reply_text(
            f"🚀 Starting comprehensive scan for `{domain}`\n⏱️ This may take 5-10 minutes...",
            parse_mode='Markdown'
        )

        async def work():
            try:
                legacy_results = await asyncio.to_thread(self.run_legacy_scan, domain)
                vuln_results = await asyncio.to_thread(self.scanner.comprehensive_scan, domain)
                report = await asyncio.to_thread(self.report_generator.generate_full_report, domain, legacy_results, vuln_results)
                await self._send_report(context, chat_id, report)
            except Exception as e:
                logger.exception("Scan error")
                await context.bot.send_message(chat_id=chat_id, text=f"❌ Scan failed for `{domain}`\nError: {e}", parse_mode='Markdown')
            finally:
                self.active_scans.pop(domain, None)
        asyncio.create_task(work())

    async def dorks_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        args = context.args or []
        if not args:
            await update.message.reply_text("❌ Usage: `/dorks <domain>`", parse_mode='Markdown')
            return
        domain = args[0].strip()
        if not validate_domain(domain):
            await update.message.reply_text("❌ Invalid domain format.", parse_mode='Markdown')
            return
        chat_id = update.message.chat_id
        await update.message.reply_text(f"🎯 Starting Google dork scan for `{domain}`", parse_mode='Markdown')
        async def work():
            try:
                vuln = await asyncio.to_thread(self.scanner.dork_scan_only, domain)
                report = await asyncio.to_thread(self.report_generator.generate_dork_report, domain, vuln)
                await self._send_report(context, chat_id, report)
            except Exception as e:
                logger.exception("Dork scan error")
                await context.bot.send_message(chat_id=chat_id, text=f"❌ Dork scan failed for `{domain}`\nError: {e}", parse_mode='Markdown')
        asyncio.create_task(work())

    async def quick_command(self, update: Update, context: ContextTypes.DEFAULT_TYPE):
        args = context.args or []
        if not args:
            await update.message.reply_text("❌ Usage: `/quick <domain>`", parse_mode='Markdown')
            return
        domain = args[0].strip()
        if not validate_domain(domain):
            await update.message.reply_text("❌ Invalid domain format.", parse_mode='Markdown')
            return
        chat_id = update.message.chat_id
        await update.message.reply_text(f"⚡ Quick scan for `{domain}`", parse_mode='Markdown')
        async def work():
            try:
                vuln = await asyncio.to_thread(self.scanner.quick_scan, domain)
                report = await asyncio.to_thread(self.report_generator.generate_quick_report, domain, vuln)
                await self._send_report(context, chat_id, report)
            except Exception as e:
                logger.exception("Quick scan error")
                await context.bot.send_message(chat_id=chat_id, text=f"❌ Quick scan failed for `{domain}`\nError: {e}", parse_mode='Markdown')
        asyncio.create_task(work())


async def main():
    token = os.getenv("TELEGRAM_BOT_TOKEN")
    if not token:
        raise RuntimeError("TELEGRAM_BOT_TOKEN not set")

    bot = ReconBot(token)
    app = ApplicationBuilder().token(token).build()

    app.add_handler(CommandHandler("start", bot.start))
    app.add_handler(CommandHandler("help", bot.help_command))
    app.add_handler(CommandHandler("scan", bot.scan_command))
    app.add_handler(CommandHandler("dorks", bot.dorks_command))
    app.add_handler(CommandHandler("quick", bot.quick_command))
    app.add_handler(CommandHandler("status", bot.status_command))

    logger.info("🔗 Starting bot polling (PTB v20)...")
    await app.initialize()
    await app.start()
    await app.updater.start_polling()
    logger.info("🎯 Bot is now active and listening for commands!")

    # Run until Ctrl+C / container stop
    await app.updater.idle()
    await app.stop()
    await app.shutdown()

if __name__ == '__main__':
    asyncio.run(main())