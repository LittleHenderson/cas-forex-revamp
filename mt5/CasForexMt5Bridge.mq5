//+------------------------------------------------------------------+
//|                                           CasForexMt5Bridge.mq5  |
//|            CAS Forex Revamp - Phase 6 MetaTrader 5 spool bridge   |
//|                                                                  |
//|  DUAL-MODE (DEMO DEFAULT + TWO-KEY LIVE). Protocol:              |
//|  "cas-forex-mt5-spool/1" between Python and this terminal:       |
//|    order_request_<id>.json  (Python -> EA, flat, string values)  |
//|    order_receipt_<id>.json  (EA -> Python, flat, string values)  |
//|    market_ticks.json        (EA -> Python, account/ticks/pos)    |
//|                                                                  |
//|  DEMO (default): requires ACCOUNT_TRADE_MODE_DEMO + "demo" srv.  |
//|  LIVE (opt-in): requires InpLiveExecutionMode=true AND exact     |
//|  InpLiveArmPhrase="I_AUTHORIZE_LIVE_REAL_MONEY_TRADING" plus     |
//|  ACCOUNT_TRADE_MODE_REAL on pinned live server (Hugo PRO5 /      |
//|  LHFXSA-Live). Mode mismatches are always refused.               |
//+------------------------------------------------------------------+
#property copyright   "CAS Forex Revamp"
#property version     "1.10"
#property description "Dual-mode file-spool bridge for CAS Forex Revamp (Demo default + Two-Key Live)."
#define LIVE_ARM_PHRASE "I_AUTHORIZE_LIVE_REAL_MONEY_TRADING"

#include <Trade\Trade.mqh>

//--- inputs
input string InpSpoolFolder        = "cas_forex_spool";  // Spool root under MQL5\Files (or Common\Files)
input string InpBrokerChannel      = "hugosway_mt5";     // hugosway_mt5 or lhfx_mt5 (matches Python broker id)
input bool   InpUseCommonFolder    = true;               // true: Terminal\Common\Files; false: portable MQL5\Files junction
input int    InpTimerMs            = 50;                 // Spool polling interval in ms (50ms fast-tick for NAS100/US30)
input string InpSymbols            = "NAS100,US30,EURUSD,GBPUSD,USDJPY,USDCHF,AUDUSD,USDCAD,NZDUSD,EURGBP,EURJPY,GBPJPY,EURCHF,EURAUD,EURCAD,AUDJPY,CHFJPY,CADJPY";
input string InpNas100Symbol       = "NAS100";           // Broker Nasdaq-100 symbol name (e.g. NAS100, USTEC, US100)
input string InpUs30Symbol         = "US30";             // Broker Dow Jones 30 symbol name (e.g. US30, DJ30, WS30)
input string InpSymbolSuffix       = "";                 // Broker symbol suffix, e.g. ".ecn" (empty when none)
input int    InpMaxDeviationPoints = 30;                 // Maximum slippage in points
input double InpMaxVolumeLots      = 50.0;               // Hard per-order volume cap in lots
input bool   InpLiveExecutionMode  = false;              // false=DEMO only, true=LIVE real-money
input string InpLiveArmPhrase      = "";                 // Must be I_AUTHORIZE_LIVE_REAL_MONEY_TRADING when LIVE=true

#define SPOOL_PROTOCOL "cas-forex-mt5-spool/1"

CTrade   g_trade;
string   g_symbols[];
bool     g_mode_ok = false;
datetime g_last_publish = 0;

//+------------------------------------------------------------------+
//| Helpers                                                          |
//+------------------------------------------------------------------+
int CommonFlag()
  {
   return(InpUseCommonFolder ? FILE_COMMON : 0);
  }

string SpoolDir()
  {
   return(InpSpoolFolder + "\\" + InpBrokerChannel);
  }

string SpoolPath(const string name)
  {
   return(SpoolDir() + "\\" + name);
  }

string IsoNowUtc()
  {
   string t = TimeToString(TimeGMT(), TIME_DATE | TIME_SECONDS);   // yyyy.mm.dd hh:mi:ss
   StringReplace(t, ".", "-");
   StringReplace(t, " ", "T");
   return(t + "Z");
  }

string SafeText(string text)
  {
   StringReplace(text, "\\", "/");
   StringReplace(text, "\"", "'");
   StringReplace(text, "\r", " ");
   StringReplace(text, "\n", " ");
   if(StringLen(text) > 60)
      text = StringSubstr(text, 0, 60);
   return(text);
  }

string AccountTradeModeLabel()
  {
   ENUM_ACCOUNT_TRADE_MODE m = (ENUM_ACCOUNT_TRADE_MODE)AccountInfoInteger(ACCOUNT_TRADE_MODE);
   if(m == ACCOUNT_TRADE_MODE_REAL)
      return("REAL");
   if(m == ACCOUNT_TRADE_MODE_CONTEST)
      return("CONTEST");
   return("DEMO");
  }

bool IsPinnedLiveServer(string server)
  {
   StringToLower(server);
   StringTrimLeft(server);
   StringTrimRight(server);
   if(StringFind(server, "demo") >= 0 || StringFind(server, "practice") >= 0)
      return(false);
   return(server == "hugo pro5" || server == "hugopro5" || server == "hugo-real" || server == "hugosway-live" ||
          server == "lhfxsa-live" || server == "lhfx-live" || server == "lhfxsa-real" || server == "lhfxsa-trade");
  }

//--- Strict mode guard: DEMO by default; two-key REAL when explicitly armed.
bool ModeGuard()
  {
   ENUM_ACCOUNT_TRADE_MODE m = (ENUM_ACCOUNT_TRADE_MODE)AccountInfoInteger(ACCOUNT_TRADE_MODE);
   string server = AccountInfoString(ACCOUNT_SERVER);
   StringToLower(server);
   StringTrimLeft(server);
   StringTrimRight(server);
   if(!InpLiveExecutionMode)
     {
      if(m != ACCOUNT_TRADE_MODE_DEMO)
         return(false);
      if(StringFind(server, "live") >= 0 || StringFind(server, "real") >= 0)
         return(false);
      if(StringFind(server, "demo") < 0 && !(InpBrokerChannel == "lhfx_mt5" && server == "lhfxsa-trade"))
         return(false);
      return(true);
     }
   if(InpLiveArmPhrase != LIVE_ARM_PHRASE)
      return(false);
   if(m != ACCOUNT_TRADE_MODE_REAL)
      return(false);
   return(IsPinnedLiveServer(server));
  }

//--- Extract a string value from a FLAT JSON object whose values are all plain strings.
string JsonGet(const string json, const string key)
  {
   string needle = "\"" + key + "\":\"";
   int start = StringFind(json, needle);
   if(start < 0)
      return("");
   start += StringLen(needle);
   int stop = StringFind(json, "\"", start);
   if(stop < 0)
      return("");
   return(StringSubstr(json, start, stop - start));
  }

string Sha256Hex(const string text)
  {
   uchar data[];
   uchar key[];
   uchar digest[];
   int n = StringToCharArray(text, data, 0, StringLen(text), CP_UTF8);
   if(n <= 0)
      return("");
   ArrayResize(data, n);
   if(CryptEncode(CRYPT_HASH_SHA256, data, key, digest) <= 0)
      return("");
   string hex = "";
   for(int i = 0; i < ArraySize(digest); i++)
      hex += StringFormat("%02x", digest[i]);
   return(hex);
  }

string ReadText(const string path)
  {
   int h = FileOpen(path, FILE_READ | FILE_TXT | FILE_ANSI | CommonFlag());
   if(h == INVALID_HANDLE)
      return("");
   string text = "";
   while(!FileIsEnding(h))
      text += FileReadString(h);
   FileClose(h);
   return(text);
  }

//--- Atomic write: write a dot-prefixed temp file, then move it over the final name.
bool WriteAtomic(const string name, const string text)
  {
   string tmp = SpoolPath("." + name + ".tmp");
   int h = FileOpen(tmp, FILE_WRITE | FILE_TXT | FILE_ANSI | CommonFlag());
   if(h == INVALID_HANDLE)
     {
      PrintFormat("CasForexMt5Bridge: cannot open %s (error %d)", tmp, GetLastError());
      return(false);
     }
   FileWriteString(h, text + "\n");
   FileFlush(h);
   FileClose(h);
   if(!FileMove(tmp, CommonFlag(), SpoolPath(name), FILE_REWRITE | CommonFlag()))
     {
      PrintFormat("CasForexMt5Bridge: cannot publish %s (error %d)", name, GetLastError());
      return(false);
     }
   return(true);
  }

string BrokerSymbol(const string cas_symbol)
  {
   if(cas_symbol == "NAS100")
      return(InpNas100Symbol + InpSymbolSuffix);
   if(cas_symbol == "US30")
      return(InpUs30Symbol + InpSymbolSuffix);
   return(cas_symbol + InpSymbolSuffix);
  }

string CasSymbol(string broker_symbol)
  {
   if(StringLen(InpSymbolSuffix) > 0)
      StringReplace(broker_symbol, InpSymbolSuffix, "");
   if(broker_symbol == InpNas100Symbol || broker_symbol == "USTEC" || broker_symbol == "US100" || broker_symbol == "NAS100USD")
      return("NAS100");
   if(broker_symbol == InpUs30Symbol || broker_symbol == "DJ30" || broker_symbol == "WS30" || broker_symbol == "US30USD")
      return("US30");
   return(broker_symbol);
  }

string Price(const string broker_symbol, const double value)
  {
   int digits = (int)SymbolInfoInteger(broker_symbol, SYMBOL_DIGITS);
   return(DoubleToString(value, digits));
  }

//+------------------------------------------------------------------+
//| Receipts                                                         |
//+------------------------------------------------------------------+
string ReceiptJson(const string request_id, const string request_sha, const string status, const uint retcode,
                   const string position_ticket, const string deal_ticket, const string volume,
                   const string price, const string sl, const string tp, const string message)
  {
   string server = AccountInfoString(ACCOUNT_SERVER);
   return(StringFormat(
      "{\"protocol\":\"%s\",\"request_id\":\"%s\",\"request_sha256\":\"%s\",\"status\":\"%s\",\"retcode\":\"%u\","
      "\"position_ticket\":\"%s\",\"deal_ticket\":\"%s\",\"volume\":\"%s\",\"price\":\"%s\",\"sl\":\"%s\",\"tp\":\"%s\","
      "\"server\":\"%s\",\"account_trade_mode\":\"%s\",\"observed_at\":\"%s\",\"message\":\"%s\"}",
      SPOOL_PROTOCOL, request_id, request_sha, status, retcode, position_ticket, deal_ticket, volume, price, sl, tp,
      SafeText(server), AccountTradeModeLabel(), IsoNowUtc(), SafeText(message)));
  }

void WriteReceipt(const string request_id, const string json)
  {
   WriteAtomic("order_receipt_" + request_id + ".json", json);
  }

string StatusFor(const uint retcode, const string action)
  {
   if(retcode == TRADE_RETCODE_DONE || retcode == TRADE_RETCODE_PLACED)
      return(action == "AMEND_STOP" ? "MODIFIED" : "FILLED");
   if(retcode == TRADE_RETCODE_DONE_PARTIAL)
      return("PARTIAL");
   return("REJECTED");
  }

//+------------------------------------------------------------------+
//| Request execution                                                |
//+------------------------------------------------------------------+
void ExecuteRequest(const string request_id, const string text)
  {
   string request_sha = JsonGet(text, "request_sha256");
   string core = text;
   StringReplace(core, ",\"request_sha256\":\"" + request_sha + "\"", "");
   StringTrimRight(core);
   if(JsonGet(text, "protocol") != SPOOL_PROTOCOL || StringLen(request_sha) != 64 || Sha256Hex(core) != request_sha)
     {
      WriteReceipt(request_id, ReceiptJson(request_id, request_sha, "REJECTED", 10013, "0", "0", "0", "0", "0", "0", "request hash mismatch"));
      return;
     }
   if(!ModeGuard())
     {
      WriteReceipt(request_id, ReceiptJson(request_id, request_sha, "REJECTED", 10017, "0", "0", "0", "0", "0", "0", "mode guard failed"));
      return;
     }

   string action  = JsonGet(text, "action");
   string symbol  = BrokerSymbol(JsonGet(text, "symbol"));
   string side    = JsonGet(text, "side");
   double volume  = StringToDouble(JsonGet(text, "volume"));
   double sl      = StringToDouble(JsonGet(text, "sl"));
   double tp      = StringToDouble(JsonGet(text, "tp"));
   ulong  ticket  = (ulong)StringToInteger(JsonGet(text, "position_ticket"));
   ulong  magic   = (ulong)StringToInteger(JsonGet(text, "magic"));
   int    dev     = (int)StringToInteger(JsonGet(text, "deviation_points"));
   string comment = JsonGet(text, "comment");

   if(!SymbolSelect(symbol, true))
     {
      WriteReceipt(request_id, ReceiptJson(request_id, request_sha, "REJECTED", 10013, "0", "0", "0", "0", "0", "0", "unknown symbol"));
      return;
     }
   if(dev <= 0 || dev > InpMaxDeviationPoints)
      dev = InpMaxDeviationPoints;
   g_trade.SetExpertMagicNumber(magic);
   g_trade.SetDeviationInPoints(dev);
   g_trade.SetTypeFillingBySymbol(symbol);

   bool ok = false;
   string pos_text = "0";
   if(action == "OPEN")
     {
      double step = SymbolInfoDouble(symbol, SYMBOL_VOLUME_STEP);
      if(step > 0.0)
         volume = MathRound(volume / step) * step;
      if(volume <= 0.0 || volume > InpMaxVolumeLots || sl <= 0.0)
        {
         WriteReceipt(request_id, ReceiptJson(request_id, request_sha, "REJECTED", 10014, "0", "0", "0", "0", "0", "0", "volume cap or missing protective stop"));
         return;
        }
      ENUM_ORDER_TYPE type = (side == "BUY") ? ORDER_TYPE_BUY : ORDER_TYPE_SELL;
      double price = (side == "BUY") ? SymbolInfoDouble(symbol, SYMBOL_ASK) : SymbolInfoDouble(symbol, SYMBOL_BID);
      if((side == "BUY" && (sl >= price || (tp > 0.0 && tp <= price))) ||
         (side == "SELL" && (sl <= price || (tp > 0.0 && tp >= price))))
        {
         WriteReceipt(request_id, ReceiptJson(request_id, request_sha, "REJECTED", 10016, "0", "0", "0", "0", "0", "0", "inverted stop or take-profit"));
         return;
        }
      ok = g_trade.PositionOpen(symbol, type, volume, price, sl, (tp > 0.0) ? tp : 0.0, comment);
      ulong deal = g_trade.ResultDeal();
      ulong position_id = g_trade.ResultOrder();
      if(deal > 0 && HistoryDealSelect(deal))
         position_id = (ulong)HistoryDealGetInteger(deal, DEAL_POSITION_ID);
      if(ok && position_id > 0)
         pos_text = IntegerToString((long)position_id);
     }
   else
     {
      if(!PositionSelectByTicket(ticket) || PositionGetString(POSITION_SYMBOL) != symbol)
        {
         WriteReceipt(request_id, ReceiptJson(request_id, request_sha, "REJECTED", 10036, "0", "0", "0", "0", "0", "0", "position not found"));
         return;
        }
      pos_text = IntegerToString((long)ticket);
      if(action == "AMEND_STOP")
        {
         double eff_sl = (sl > 0.0) ? sl : PositionGetDouble(POSITION_SL);
         double eff_tp = (tp > 0.0) ? tp : PositionGetDouble(POSITION_TP);
         ok = g_trade.PositionModify(ticket, eff_sl, eff_tp);
        }
      else
         if(action == "REDUCE")
            ok = g_trade.PositionClosePartial(ticket, volume, dev);
         else
            if(action == "CLOSE")
               ok = g_trade.PositionClose(ticket, dev);
            else
              {
               WriteReceipt(request_id, ReceiptJson(request_id, request_sha, "REJECTED", 10013, "0", "0", "0", "0", "0", "0", "unsupported action"));
               return;
              }
     }

   uint   retcode = g_trade.ResultRetcode();
   string status  = StatusFor(retcode, action);
   string deal_text = (g_trade.ResultDeal() > 0) ? IntegerToString((long)g_trade.ResultDeal()) : "0";
   string vol_text  = (g_trade.ResultVolume() > 0.0) ? DoubleToString(g_trade.ResultVolume(), 2) : "0";
   string px_text   = (g_trade.ResultPrice() > 0.0) ? Price(symbol, g_trade.ResultPrice()) : "0";
   string sl_text   = (sl > 0.0) ? Price(symbol, sl) : "0";
   string tp_text   = (tp > 0.0) ? Price(symbol, tp) : "0";
   if(!ok && status != "REJECTED")
      status = "REJECTED";
   WriteReceipt(request_id, ReceiptJson(request_id, request_sha, status, retcode, (status == "REJECTED") ? "0" : pos_text,
                                        deal_text, vol_text, px_text, sl_text, tp_text, g_trade.ResultRetcodeDescription()));
  }

//--- Claim each request by renaming it to processing_<id>.json BEFORE executing, so a restart
//--- can never execute the same request twice.
void ProcessRequests()
  {
   string found;
   long search = FileFindFirst(SpoolDir() + "\\order_request_*.json", found, CommonFlag());
   if(search == INVALID_HANDLE)
      return;
   string names[];
   do
     {
      int n = ArraySize(names);
      ArrayResize(names, n + 1);
      names[n] = found;
     }
   while(FileFindNext(search, found));
   FileFindClose(search);

   for(int i = 0; i < ArraySize(names); i++)
     {
      string name = names[i];
      string request_id = StringSubstr(name, StringLen("order_request_"), StringLen(name) - StringLen("order_request_") - StringLen(".json"));
      string claimed = "processing_" + request_id + ".json";
      if(FileIsExist(SpoolPath("order_receipt_" + request_id + ".json"), CommonFlag()))
        {
         FileDelete(SpoolPath(name), CommonFlag());
         continue;
        }
      if(!FileMove(SpoolPath(name), CommonFlag(), SpoolPath(claimed), FILE_REWRITE | CommonFlag()))
         continue;
      string text = ReadText(SpoolPath(claimed));
      ExecuteRequest(request_id, text);
      FileDelete(SpoolPath(claimed), CommonFlag());
     }
  }

//--- After a restart, any processing_<id>.json means the outcome is UNKNOWN: report, never re-execute.
void ReportInterruptedRequests()
  {
   string found;
   long search = FileFindFirst(SpoolDir() + "\\processing_*.json", found, CommonFlag());
   if(search == INVALID_HANDLE)
      return;
   do
     {
      string request_id = StringSubstr(found, StringLen("processing_"), StringLen(found) - StringLen("processing_") - StringLen(".json"));
      string text = ReadText(SpoolPath(found));
      WriteReceipt(request_id, ReceiptJson(request_id, JsonGet(text, "request_sha256"), "UNKNOWN", (uint)0, "0", "0", "0", "0", "0", "0",
                                           "EA restarted mid-order; check terminal history"));
      FileDelete(SpoolPath(found), CommonFlag());
     }
   while(FileFindNext(search, found));
   FileFindClose(search);
  }

//+------------------------------------------------------------------+
//| Market snapshot publication                                      |
//+------------------------------------------------------------------+
void PublishMarket()
  {
   string json = StringFormat(
      "{\"protocol\":\"%s\",\"server\":\"%s\",\"account_trade_mode\":\"%s\",\"observed_at\":\"%s\",\"account\":{"
      "\"login\":\"%s\",\"currency\":\"%s\",\"balance\":\"%s\",\"equity\":\"%s\",\"margin\":\"%s\",\"margin_free\":\"%s\",\"leverage\":\"%s\"},\"ticks\":[",
      SPOOL_PROTOCOL, SafeText(AccountInfoString(ACCOUNT_SERVER)), AccountTradeModeLabel(), IsoNowUtc(),
      IntegerToString(AccountInfoInteger(ACCOUNT_LOGIN)), AccountInfoString(ACCOUNT_CURRENCY),
      DoubleToString(AccountInfoDouble(ACCOUNT_BALANCE), 2), DoubleToString(AccountInfoDouble(ACCOUNT_EQUITY), 2),
      DoubleToString(AccountInfoDouble(ACCOUNT_MARGIN), 2), DoubleToString(AccountInfoDouble(ACCOUNT_MARGIN_FREE), 2),
      IntegerToString(AccountInfoInteger(ACCOUNT_LEVERAGE)));

   bool first = true;
   for(int i = 0; i < ArraySize(g_symbols); i++)
     {
      string bsym = BrokerSymbol(g_symbols[i]);
      MqlTick tick;
      if(!SymbolInfoTick(bsym, tick) || tick.bid <= 0.0 || tick.ask < tick.bid)
         continue;
      json += StringFormat("%s{\"symbol\":\"%s\",\"bid\":\"%s\",\"ask\":\"%s\",\"time_msc\":\"%s\"}",
                           first ? "" : ",", g_symbols[i], Price(bsym, tick.bid), Price(bsym, tick.ask),
                           IntegerToString((long)tick.time_msc));
      first = false;
     }
   json += "],\"positions\":[";

   first = true;
   for(int p = 0; p < PositionsTotal(); p++)
     {
      ulong ticket = PositionGetTicket(p);
      if(ticket == 0 || !PositionSelectByTicket(ticket))
         continue;
      string bsym = PositionGetString(POSITION_SYMBOL);
      string side = ((ENUM_POSITION_TYPE)PositionGetInteger(POSITION_TYPE) == POSITION_TYPE_BUY) ? "BUY" : "SELL";
      double psl = PositionGetDouble(POSITION_SL);
      double ptp = PositionGetDouble(POSITION_TP);
      json += StringFormat("%s{\"ticket\":\"%s\",\"symbol\":\"%s\",\"side\":\"%s\",\"volume\":\"%s\",\"price_open\":\"%s\",\"sl\":\"%s\",\"tp\":\"%s\",\"profit\":\"%s\"}",
                           first ? "" : ",", IntegerToString((long)ticket), CasSymbol(bsym), side,
                           DoubleToString(PositionGetDouble(POSITION_VOLUME), 2), Price(bsym, PositionGetDouble(POSITION_PRICE_OPEN)),
                           (psl > 0.0) ? Price(bsym, psl) : "0", (ptp > 0.0) ? Price(bsym, ptp) : "0", DoubleToString(PositionGetDouble(POSITION_PROFIT), 2));
      first = false;
     }
   json += "]}";
   WriteAtomic("market_ticks.json", json);
   g_last_publish = TimeCurrent();
  }

//+------------------------------------------------------------------+
//| Expert lifecycle                                                 |
//+------------------------------------------------------------------+
int OnInit()
  {
   if(!ModeGuard())
     {
      Print("CasForexMt5Bridge: REFUSED - account trade mode / server / two-key arm phrase mismatch.");
      return(INIT_FAILED);
     }
   if(InpBrokerChannel != "hugosway_mt5" && InpBrokerChannel != "lhfx_mt5")
     {
      Print("CasForexMt5Bridge: InpBrokerChannel must be hugosway_mt5 or lhfx_mt5.");
      return(INIT_PARAMETERS_INCORRECT);
     }
   if(StringSplit(InpSymbols, ',', g_symbols) <= 0)
     {
      Print("CasForexMt5Bridge: InpSymbols is empty.");
      return(INIT_PARAMETERS_INCORRECT);
     }
   for(int i = 0; i < ArraySize(g_symbols); i++)
     {
      StringTrimLeft(g_symbols[i]);
      StringTrimRight(g_symbols[i]);
      SymbolSelect(BrokerSymbol(g_symbols[i]), true);
     }
   FolderCreate(InpSpoolFolder, CommonFlag());
   FolderCreate(SpoolDir(), CommonFlag());
   g_mode_ok = true;
   ReportInterruptedRequests();
   PublishMarket();
   EventSetMillisecondTimer(MathMax(50, InpTimerMs));
   PrintFormat("CasForexMt5Bridge: running [%s] on server %s, spool %s", AccountTradeModeLabel(), AccountInfoString(ACCOUNT_SERVER), SpoolDir());
   return(INIT_SUCCEEDED);
  }

void OnDeinit(const int reason)
  {
   EventKillTimer();
  }

void OnTimer()
  {
   g_mode_ok = ModeGuard();
   if(!g_mode_ok)
     {
      Print("CasForexMt5Bridge: mode guard failed - spool processing halted.");
      ExpertRemove();
      return;
     }
   ProcessRequests();
   PublishMarket();
  }

void OnTick()
  {
   // Ticks only refresh the market snapshot (at most once per second); orders run on the timer.
   if(g_mode_ok && TimeCurrent() != g_last_publish)
      PublishMarket();
  }
//+------------------------------------------------------------------+
