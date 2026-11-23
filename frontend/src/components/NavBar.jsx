import { Github, Send, Shield } from "lucide-react";
import { Link } from "react-router-dom";

export default function NavBar() {
  const telegramBotUrl = import.meta.env.VITE_TELEGRAM_BOT_URL?.trim();
  const hasTelegramBotUrl = /^https:\/\/t\.me\/[a-z0-9_]{5,32}\/?$/i.test(
    telegramBotUrl || "",
  );

  return (
    <header className="sticky top-0 z-30 border-b border-slate-200/70 bg-white/80 backdrop-blur">
      <div className="mx-auto flex w-full max-w-3xl items-center justify-between px-4 py-3 md:py-4">
        <div className="flex items-center gap-3">
          <Link to="/" className="flex items-center gap-2.5">
            <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-orange-500 to-red-600 shadow-lg shadow-orange-200">
              <Shield className="h-5 w-5 text-white" />
            </div>
            <div className="leading-tight">
              <div className="text-lg font-black text-slate-900 tracking-tight">Scam Shield</div>
              <div className="text-[10px] font-semibold text-orange-600 uppercase tracking-wider">AI Fraud Detection</div>
            </div>
          </Link>
        </div>

        <nav className="flex items-center gap-1.5 text-xs text-slate-500 md:gap-4 md:text-sm">
          <Link to="/batch-scan" className="rounded-full px-2 py-1 hover:bg-slate-100 md:px-3">
            Batch Scan
          </Link>
          {hasTelegramBotUrl ? (
            <a
              href={telegramBotUrl}
              target="_blank"
              rel="noopener noreferrer"
              aria-label="Open Scam Shield on Telegram"
              title="Open Scam Shield on Telegram"
              className="inline-flex items-center gap-2 rounded-full border border-sky-200 bg-sky-50 px-2.5 py-1.5 font-medium text-sky-800 hover:bg-sky-100 md:px-3"
            >
              <Send className="h-4 w-4" />
              <span className="hidden sm:inline">Telegram Bot</span>
            </a>
          ) : (
            <Link
              to="/docs#telegram"
              aria-label="Set up the Telegram bot link"
              title="Set up the Telegram bot link"
              className="inline-flex items-center gap-2 rounded-full border border-sky-200 bg-sky-50 px-2.5 py-1.5 font-medium text-sky-800 hover:bg-sky-100 md:px-3"
            >
              <Send className="h-4 w-4" />
              <span className="hidden sm:inline">Telegram Bot</span>
            </Link>
          )}
          <Link to="/docs" className="hidden rounded-full px-3 py-1 hover:bg-slate-100 md:inline-block">
            Docs
          </Link>
          <a
            href="https://github.com/Varad-kotkar/AI_Powered_Scam_Shield"
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-2 rounded-full border border-slate-200 bg-white px-3 py-1.5 text-xs font-medium text-slate-800 shadow-sm hover:border-slate-300 hover:bg-slate-50"
          >
            <Github className="h-4 w-4" />
            <span className="hidden md:inline">View on GitHub</span>
          </a>
        </nav>
      </div>
    </header>
  );
}
