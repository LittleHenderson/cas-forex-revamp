//+------------------------------------------------------------------+
//|                                           CasForexMt5Bridge.mq5  |
//|         CAS Forex Revamp - Phase 6 MetaTrader 5 Spool v2 Bridge  |
//|                                                                  |
//|  DUAL-MODE (DEMO DEFAULT + CRYPTO-TICKET LIVE). Protocol v2:     |
//|  "cas-forex-mt5-spool/2" with RFC 2104 HMAC-SHA256 signatures,   |
//|  strict TTL expiry, and persistent monotonic nonce replay check. |
//|                                                                  |
//|  DEMO (default): requires ACCOUNT_TRADE_MODE_DEMO + "demo" srv.  |
//|  LIVE (opt-in): requires InpLiveExecutionMode=true AND exact     |
//|  InpLiveArmPhrase + signed live_auth_ticket.json verified by     |
//|  .live_auth.key + ACCOUNT_TRADE_MODE_REAL on pinned live server. |
//+------------------------------------------------------------------+
#property copyright   "CAS Forex Revamp"
#property version     "2.00"
#property description "Authenticated HMAC-SHA256 v2 file-spool bridge (Demo default + Crypto-Ticket Live)."
#define LIVE_ARM_PHRASE "I_AUTHORIZE_LIVE_REAL_MONEY_TRADING"

#include <Trade\Trade.mqh>

//--- inputs
input string InpSpoolFolder        = "cas_forex_spool";
input string InpBrokerChannel      = "hugosway_mt5";
input bool   InpUseCommonFolder    = true;
input int    InpTimerMs            = 50;
input string InpSymbols            = "NAS100,US30,SPX500,XAUUSD,EURUSD,GBPUSD,USDJPY,USDCHF,AUDUSD,USDCAD,NZDUSD,EURGBP,EURJPY,GBPJPY,EURCHF,EURAUD,EURCAD,AUDJPY,CHFJPY,CADJPY";
input string InpNas100Symbol       = "NAS100";
input string InpUs30Symbol         = "US30";
input string InpSpx500Symbol       = "SPX500";
input string InpXauusdSymbol       = "XAUUSD";
input string InpSymbolSuffix       = "";
input int    InpMaxDeviationPoints = 30;
input double InpMaxVolumeLots      = 50.0;
input bool   InpLiveExecutionMode  = false;
input string InpLiveArmPhrase      = "";

#define SPOOL_PROTOCOL "cas-forex-mt5-spool/2"

CTrade   g_trade;
string   g_symbols[];
bool     g_mode_ok = false;
datetime g_last_publish = 0;
datetime g_last_candles = 0;
datetime g_last_history = 0;
bool     g_history_dirty = false;
string   g_active_nonce = "0";
ulong    g_last_monotonic_nonce = 0;
uchar    g_master_hmac_key[];
uchar    g_hmac_key[];
string   g_channel_key_id = "";
bool     g_hmac_key_loaded = false;
uchar    g_valve_key[];
bool     g_valve_key_loaded = false;
string   g_global_seen_ids[];
bool     g_replay_ledger_healthy      = false;
ulong    g_snapshot_seq               = 0;
bool     g_snapshot_seq_loaded        = false;
double   g_last_connected_balance     = 0.0;
double   g_last_connected_equity      = 0.0;
double   g_last_connected_margin      = 0.0;
double   g_last_connected_margin_free = 0.0;
bool     g_has_connected_account      = false;

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

string RootSpoolPath(const string name)
  {
   return(InpSpoolFolder + "\\" + name);
  }

string IsoNowUtc()
  {
   string t = TimeToString(TimeGMT(), TIME_DATE | TIME_SECONDS);
   StringReplace(t, ".", "-");
   StringReplace(t, " ", "T");
   return(t + "Z");
  }

long ServerUtcOffsetSeconds()
  {
   long srv_now = (long)TimeTradeServer();
   long gmt_now = (long)TimeGMT();
   if(srv_now <= 0 || gmt_now <= 0)
      return(0);
   long raw_off = srv_now - gmt_now;
   if(raw_off < -43200 || raw_off > 50400)
      return(0);
   if(raw_off >= 0)
      return(((raw_off + 450) / 900) * 900);
   return(-((((-raw_off) + 450) / 900) * 900));
  }

datetime ParseIsoUtc(const string iso)
  {
   if(StringLen(iso) < 19)
      return(0);
   string head = StringSubstr(iso, 0, 19);
   StringReplace(head, "T", " ");
   StringReplace(head, "-", ".");
   return(StringToTime(head));
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

string SafeHistText(string text)
  {
   text = SafeText(text);
   StringReplace(text, "|", "_");
   StringReplace(text, ";", "_");
   StringReplace(text, ":", "_");
   return(text);
  }

string IsoFromUtcSeconds(const long utc_s)
  {
   if(utc_s <= 0)
      return("");
   MqlDateTime dt;
   TimeToStruct((datetime)utc_s, dt);
   return(StringFormat("%04d-%02d-%02dT%02d:%02d:%02dZ", dt.year, dt.mon, dt.day, dt.hour, dt.min, dt.sec));
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
   if(StringFind(server, "demo") >= 0 || StringFind(server, "practice") >= 0 || StringFind(server, "trial") >= 0)
      return(false);
   if(InpBrokerChannel == "hugosway_mt5")
      return(server == "hugo pro5" || server == "hugopro5" || server == "hugo-real" || server == "hugosway-real" || server == "hugosway-live" || server == "hugosway live");
   if(InpBrokerChannel == "lhfx_mt5")
      return(server == "lhfxsa-trade" || server == "lhfxsa trade" || server == "lhfxsa-live" || server == "lhfx-live" || server == "lhfxsa-real" || server == "lhfxsa live");
   return(false);
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

string BytesToHex(const uchar &buf[])
  {
   string hex = "";
   int sz = ArraySize(buf);
   for(int i = 0; i < sz; i++)
      hex += StringFormat("%02x", buf[i]);
   return(hex);
  }

int HexNibble(const ushort ch)
  {
   if(ch >= '0' && ch <= '9')
      return((int)(ch - '0'));
   if(ch >= 'a' && ch <= 'f')
      return((int)(ch - 'a' + 10));
   if(ch >= 'A' && ch <= 'F')
      return((int)(ch - 'A' + 10));
   return(-1);
  }

bool DecodeHexKey(string hex_text, uchar &out_bytes[])
  {
   StringTrimLeft(hex_text);
   StringTrimRight(hex_text);
   StringReplace(hex_text, "\r", "");
   StringReplace(hex_text, "\n", "");
   int len = StringLen(hex_text);
   if(len == 64)
     {
      ArrayResize(out_bytes, 32);
      for(int i = 0; i < 32; i++)
        {
         int hi = HexNibble(StringGetCharacter(hex_text, i * 2));
         int lo = HexNibble(StringGetCharacter(hex_text, i * 2 + 1));
         if(hi < 0 || lo < 0)
            return(false);
         out_bytes[i] = (uchar)((hi << 4) | lo);
        }
      return(true);
     }
   if(len >= 32)
     {
      int n = StringToCharArray(hex_text, out_bytes, 0, len, CP_UTF8);
      if(n < 32)
         return(false);
      ArrayResize(out_bytes, n);
      return(true);
     }
   return(false);
  }

bool ConstTimeHexEquals(string a, string b)
  {
   StringToLower(a);
   StringToLower(b);
   int la = StringLen(a);
   int lb = StringLen(b);
   if(la != lb || la != 64)
      return(false);
   int diff = 0;
   for(int i = 0; i < la; i++)
      diff |= (StringGetCharacter(a, i) ^ StringGetCharacter(b, i));
   return(diff == 0);
  }

string Sha256Hex(const string text)
  {
   if(StringLen(text) == 0)
      return("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
   uchar data[];
   uchar key[];
   uchar digest[];
   int n = StringToCharArray(text, data, 0, StringLen(text), CP_UTF8);
   if(n <= 0)
      return("");
   ArrayResize(data, n);
   if(CryptEncode(CRYPT_HASH_SHA256, data, key, digest) <= 0)
      return("");
   return(BytesToHex(digest));
  }

string TrimAll(string value)
  {
   StringReplace(value, "\r", "");
   StringReplace(value, "\n", "");
   StringTrimLeft(value);
   StringTrimRight(value);
   return(value);
  }

bool IsDigitsOnly(string value)
  {
   value = TrimAll(value);
   int len = StringLen(value);
   if(len == 0)
      return(false);
   for(int i = 0; i < len; i++)
     {
      ushort ch = StringGetCharacter(value, i);
      if(ch < '0' || ch > '9')
         return(false);
     }
   return(true);
  }

string NormalizeLowerTrim(string value)
  {
   StringToLower(value);
   StringTrimLeft(value);
   StringTrimRight(value);
   return(value);
  }

bool IsHex64(string text)
  {
   if(StringLen(text) != 64)
      return(false);
   for(int i = 0; i < 64; i++)
     {
      if(HexNibble(StringGetCharacter(text, i)) < 0)
         return(false);
     }
   return(true);
  }

bool BytesEqualConstTime(const uchar &a[], const uchar &b[])
  {
   int la = ArraySize(a);
   int lb = ArraySize(b);
   if(la != lb || la == 0)
      return(false);
   int diff = 0;
   for(int i = 0; i < la; i++)
      diff |= (a[i] ^ b[i]);
   return(diff == 0);
  }

bool HmacSha256Raw(const uchar &key_bytes[], const string message, uchar &out_hash[])
  {
   int klen = ArraySize(key_bytes);
   if(klen < 32)
      return(false);
   uchar k_pad[64];
   ArrayInitialize(k_pad, 0);
   if(klen > 64)
     {
      uchar khash[];
      uchar empty_k[];
      if(CryptEncode(CRYPT_HASH_SHA256, key_bytes, empty_k, khash) <= 0)
         return(false);
      for(int i = 0; i < ArraySize(khash) && i < 64; i++)
         k_pad[i] = khash[i];
     }
   else
     {
      for(int i = 0; i < klen; i++)
         k_pad[i] = key_bytes[i];
     }

   uchar msg[];
   int mlen = StringToCharArray(message, msg, 0, StringLen(message), CP_UTF8);
   if(mlen < 0)
      mlen = 0;
   ArrayResize(msg, mlen);

   uchar inner_in[];
   ArrayResize(inner_in, 64 + mlen);
   for(int i = 0; i < 64; i++)
      inner_in[i] = (uchar)(k_pad[i] ^ 0x36);
   for(int i = 0; i < mlen; i++)
      inner_in[64 + i] = msg[i];

   uchar empty_key[];
   uchar inner_hash[];
   if(CryptEncode(CRYPT_HASH_SHA256, inner_in, empty_key, inner_hash) <= 0)
      return(false);

   uchar outer_in[];
   ArrayResize(outer_in, 64 + ArraySize(inner_hash));
   for(int i = 0; i < 64; i++)
      outer_in[i] = (uchar)(k_pad[i] ^ 0x5c);
   for(int i = 0; i < ArraySize(inner_hash); i++)
      outer_in[64 + i] = inner_hash[i];

   if(CryptEncode(CRYPT_HASH_SHA256, outer_in, empty_key, out_hash) <= 0)
      return(false);
   return(ArraySize(out_hash) == 32);
  }

string HmacSha256Hex(const uchar &key_bytes[], const string message)
  {
   uchar digest[];
   if(!HmacSha256Raw(key_bytes, message, digest))
      return("");
   return(BytesToHex(digest));
  }

bool DeriveChannelKey(const uchar &master_key[], const string broker_channel, uchar &out_channel_key[])
  {
   return(HmacSha256Raw(master_key, "channel:" + NormalizeLowerTrim(broker_channel), out_channel_key));
  }

string ComputeChannelKeyId(const string broker_channel, const uchar &channel_key[])
  {
   string prefix = "key-id:" + NormalizeLowerTrim(broker_channel) + ":";
   uchar pbytes[];
   int plen = StringToCharArray(prefix, pbytes, 0, StringLen(prefix), CP_UTF8);
   if(plen <= 0)
      return("");
   int klen = ArraySize(channel_key);
   uchar buf[];
   ArrayResize(buf, plen + klen);
   for(int i = 0; i < plen; i++)
      buf[i] = pbytes[i];
   for(int i = 0; i < klen; i++)
      buf[plen + i] = channel_key[i];
   uchar empty_key[];
   uchar digest[];
   if(CryptEncode(CRYPT_HASH_SHA256, buf, empty_key, digest) <= 0)
      return("");
   return(StringSubstr(BytesToHex(digest), 0, 16));
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

bool LoadSpoolHmacKey()
  {
   string raw = ReadText(RootSpoolPath(".spool_hmac.key"));
   if(StringLen(raw) == 0)
      raw = ReadText(SpoolPath(".spool_hmac.key"));
   if(StringLen(raw) == 0)
      return(false);
   if(!DecodeHexKey(raw, g_master_hmac_key))
      return(false);
   if(!DeriveChannelKey(g_master_hmac_key, InpBrokerChannel, g_hmac_key))
      return(false);
   g_channel_key_id = ComputeChannelKeyId(InpBrokerChannel, g_hmac_key);
   return(StringLen(g_channel_key_id) == 16);
  }

bool LoadValveAdmissionKey()
  {
   string raw = ReadText(RootSpoolPath(".valve_admission.key"));
   if(StringLen(raw) == 0)
      raw = ReadText(SpoolPath(".valve_admission.key"));
   if(StringLen(raw) == 0)
      return(false);
   if(!DecodeHexKey(raw, g_valve_key))
      return(false);
   if(g_hmac_key_loaded && (BytesEqualConstTime(g_valve_key, g_master_hmac_key) || BytesEqualConstTime(g_valve_key, g_hmac_key)))
     {
      ArrayResize(g_valve_key, 0);
      return(false);
     }
   return(true);
  }

bool VerifyValveAdmission(const string text)
  {
   if(!g_valve_key_loaded)
      g_valve_key_loaded = LoadValveAdmissionKey();
   if(!g_valve_key_loaded)
      return(false);
   if(g_hmac_key_loaded && (BytesEqualConstTime(g_valve_key, g_master_hmac_key) || BytesEqualConstTime(g_valve_key, g_hmac_key)))
      return(false);
   string dec_sha = JsonGet(text, "valve_decision_sha256");
   string adm_exp = JsonGet(text, "valve_admission_expires_at");
   string adm_sig = JsonGet(text, "valve_admission_sig");
   if(!IsHex64(dec_sha) || !IsHex64(adm_sig))
      return(false);
   datetime exp_dt = ParseIsoUtc(adm_exp);
   datetime iss_dt = ParseIsoUtc(JsonGet(text, "issued_at"));
   if(exp_dt == 0 || iss_dt == 0 || TimeGMT() > exp_dt)
      return(false);
   long ttl_sec = (long)(exp_dt - iss_dt);
   if(ttl_sec <= 0 || ttl_sec > 60)
      return(false);
   string valve_msg = "cas-forex-valve-admission/1|" +
                      JsonGet(text, "broker_channel") + "|" + JsonGet(text, "account_login") + "|" +
                      JsonGet(text, "server") + "|" + JsonGet(text, "execution_mode") + "|" +
                      JsonGet(text, "action") + "|" + JsonGet(text, "symbol") + "|" +
                      JsonGet(text, "side") + "|" + JsonGet(text, "volume") + "|" +
                      JsonGet(text, "sl") + "|" + JsonGet(text, "tp") + "|" +
                      JsonGet(text, "position_ticket") + "|" + dec_sha + "|" + adm_exp;
   string expected_sig = HmacSha256Hex(g_valve_key, valve_msg);
   return(ConstTimeHexEquals(expected_sig, adm_sig));
  }

bool LoadGlobalReplayDomain()
  {
   ArrayResize(g_global_seen_ids, 0);
   string fname = RootSpoolPath(".global_ea_seen.txt");
   if(!FileIsExist(fname, CommonFlag()))
      return(true);
   int h = FileOpen(fname, FILE_READ | FILE_TXT | FILE_ANSI | CommonFlag());
   if(h == INVALID_HANDLE)
     {
      g_replay_ledger_healthy = false;
      return(false);
     }
   ulong fsz = FileSize(h);
   while(!FileIsEnding(h))
     {
      string line = TrimAll(FileReadString(h));
      if(StringLen(line) > 0)
        {
         int n = ArraySize(g_global_seen_ids);
         ArrayResize(g_global_seen_ids, n + 1);
         g_global_seen_ids[n] = line;
        }
     }
   FileClose(h);
   if(fsz > 0 && ArraySize(g_global_seen_ids) == 0)
     {
      g_replay_ledger_healthy = false;
      return(false);
     }
   return(true);
  }

bool IsGlobalReplayIdSeen(const string req_id)
  {
   if(!LoadGlobalReplayDomain())
     {
      g_replay_ledger_healthy = false;
      return(true);
     }
   int n = ArraySize(g_global_seen_ids);
   for(int i = 0; i < n; i++)
     {
      if(g_global_seen_ids[i] == req_id)
         return(true);
     }
   return(false);
  }

bool RecordGlobalReplayId(const string req_id)
  {
   if(StringLen(req_id) == 0)
     {
      g_replay_ledger_healthy = false;
      return(false);
     }
   if(!LoadGlobalReplayDomain())
     {
      g_replay_ledger_healthy = false;
      return(false);
     }
   int existing_n = ArraySize(g_global_seen_ids);
   for(int i = 0; i < existing_n; i++)
     {
      if(g_global_seen_ids[i] == req_id)
         return(false);
     }
   ArrayResize(g_global_seen_ids, existing_n + 1);
   g_global_seen_ids[existing_n] = req_id;
   int start = (ArraySize(g_global_seen_ids) > 2048) ? (ArraySize(g_global_seen_ids) - 2048) : 0;
   string fname = RootSpoolPath(".global_ea_seen.txt");
   string tmp = RootSpoolPath(".global_ea_seen.txt.tmp");
   int h = FileOpen(tmp, FILE_WRITE | FILE_TXT | FILE_ANSI | CommonFlag());
   if(h == INVALID_HANDLE)
     {
      ArrayResize(g_global_seen_ids, existing_n);
      g_replay_ledger_healthy = false;
      return(false);
     }
   bool write_ok = true;
   for(int i = start; i < ArraySize(g_global_seen_ids); i++)
     {
      if(FileWriteString(h, g_global_seen_ids[i] + "\n") == 0)
        {
         write_ok = false;
         break;
        }
     }
   FileFlush(h);
   FileClose(h);
   if(!write_ok)
     {
      FileDelete(tmp, CommonFlag());
      ArrayResize(g_global_seen_ids, existing_n);
      g_replay_ledger_healthy = false;
      return(false);
     }
   bool moved = false;
   for(int attempt = 0; attempt < 6; attempt++)
     {
      if(FileMove(tmp, CommonFlag(), fname, CommonFlag() | FILE_REWRITE))
        {
         moved = true;
         break;
        }
      Sleep(8);
     }
   if(!moved)
     {
      FileDelete(tmp, CommonFlag());
      ArrayResize(g_global_seen_ids, existing_n);
      g_replay_ledger_healthy = false;
      return(false);
     }
   int rh = FileOpen(fname, FILE_READ | FILE_TXT | FILE_ANSI | CommonFlag());
   if(rh == INVALID_HANDLE)
     {
      g_replay_ledger_healthy = false;
      return(false);
     }
   bool verified = false;
   while(!FileIsEnding(rh))
     {
      string line = TrimAll(FileReadString(rh));
      if(line == req_id)
         verified = true;
     }
   FileClose(rh);
   if(!verified)
     {
      g_replay_ledger_healthy = false;
      return(false);
     }
   return(true);
  }

bool LoadReplayNonceLedger()
  {
   string fname = RootSpoolPath("." + InpBrokerChannel + ".ea_nonce.txt");
   if(!FileIsExist(fname, CommonFlag()))
      return(true);
   int h = FileOpen(fname, FILE_READ | FILE_TXT | FILE_ANSI | CommonFlag());
   if(h == INVALID_HANDLE)
     {
      g_replay_ledger_healthy = false;
      return(false);
     }
   string raw = "";
   while(!FileIsEnding(h))
      raw += FileReadString(h);
   FileClose(h);
   raw = TrimAll(raw);
   if(!IsDigitsOnly(raw))
     {
      g_replay_ledger_healthy = false;
      return(false);
     }
   ulong saved = (ulong)StringToInteger(raw);
   if(saved == 0 || IntegerToString((long)saved) != raw)
     {
      g_replay_ledger_healthy = false;
      return(false);
     }
   if(saved > g_last_monotonic_nonce)
      g_last_monotonic_nonce = saved;
   return(true);
  }

bool SaveReplayNonceLedger(const ulong nonce_val)
  {
   if(nonce_val == 0)
     {
      g_replay_ledger_healthy = false;
      return(false);
     }
   string payload = IntegerToString((long)nonce_val);
   string fname = RootSpoolPath("." + InpBrokerChannel + ".ea_nonce.txt");
   string tmp = RootSpoolPath("." + InpBrokerChannel + ".ea_nonce.txt.tmp");
   int h = FileOpen(tmp, FILE_WRITE | FILE_TXT | FILE_ANSI | CommonFlag());
   if(h == INVALID_HANDLE)
     {
      g_replay_ledger_healthy = false;
      return(false);
     }
   uint written = FileWriteString(h, payload);
   FileFlush(h);
   FileClose(h);
   if(written == 0)
     {
      FileDelete(tmp, CommonFlag());
      g_replay_ledger_healthy = false;
      return(false);
     }
   bool moved = false;
   for(int attempt = 0; attempt < 6; attempt++)
     {
      if(FileMove(tmp, CommonFlag(), fname, CommonFlag() | FILE_REWRITE))
        {
         moved = true;
         break;
        }
      Sleep(8);
     }
   if(!moved)
     {
      FileDelete(tmp, CommonFlag());
      g_replay_ledger_healthy = false;
      return(false);
     }
   int rh = FileOpen(fname, FILE_READ | FILE_TXT | FILE_ANSI | CommonFlag());
   if(rh == INVALID_HANDLE)
     {
      g_replay_ledger_healthy = false;
      return(false);
     }
   string reread = "";
   while(!FileIsEnding(rh))
      reread += FileReadString(rh);
   FileClose(rh);
   reread = TrimAll(reread);
   if(!IsDigitsOnly(reread) || (ulong)StringToInteger(reread) != nonce_val || IntegerToString((long)nonce_val) != reread)
     {
      g_replay_ledger_healthy = false;
      return(false);
     }
   return(true);
  }

bool LoadSnapshotSeq()
  {
   string fname = RootSpoolPath("." + InpBrokerChannel + ".ea_snapshot_seq.txt");
   if(!FileIsExist(fname, CommonFlag()))
     {
      g_snapshot_seq_loaded = true;
      return(true);
     }
   int h = FileOpen(fname, FILE_READ | FILE_TXT | FILE_ANSI | CommonFlag());
   if(h == INVALID_HANDLE)
      return(false);
   string raw = "";
   while(!FileIsEnding(h))
      raw += FileReadString(h);
   FileClose(h);
   raw = TrimAll(raw);
   if(!IsDigitsOnly(raw))
      return(false);
   ulong saved = (ulong)StringToInteger(raw);
   if(saved == 0 || IntegerToString((long)saved) != raw)
      return(false);
   if(saved > g_snapshot_seq)
      g_snapshot_seq = saved;
   g_snapshot_seq_loaded = true;
   return(true);
  }

bool AdvanceAndPersistSnapshotSeq()
  {
   if(!g_snapshot_seq_loaded && !LoadSnapshotSeq())
      return(false);
   ulong next_seq = g_snapshot_seq + 1;
   string payload = IntegerToString((long)next_seq);
   string fname = RootSpoolPath("." + InpBrokerChannel + ".ea_snapshot_seq.txt");
   string tmp = RootSpoolPath("." + InpBrokerChannel + ".ea_snapshot_seq.txt.tmp");
   int h = FileOpen(tmp, FILE_WRITE | FILE_TXT | FILE_ANSI | CommonFlag());
   if(h == INVALID_HANDLE)
      return(false);
   uint written = FileWriteString(h, payload);
   FileFlush(h);
   FileClose(h);
   if(written == 0)
     {
      FileDelete(tmp, CommonFlag());
      return(false);
     }
   bool moved = false;
   for(int attempt = 0; attempt < 6; attempt++)
     {
      if(FileMove(tmp, CommonFlag(), fname, CommonFlag() | FILE_REWRITE))
        {
         moved = true;
         break;
        }
      Sleep(8);
     }
   if(!moved)
     {
      FileDelete(tmp, CommonFlag());
      return(false);
     }
   int rh = FileOpen(fname, FILE_READ | FILE_TXT | FILE_ANSI | CommonFlag());
   if(rh == INVALID_HANDLE)
      return(false);
   string reread = "";
   while(!FileIsEnding(rh))
      reread += FileReadString(rh);
   FileClose(rh);
   reread = TrimAll(reread);
   if(!IsDigitsOnly(reread) || (ulong)StringToInteger(reread) != next_seq || IntegerToString((long)next_seq) != reread)
      return(false);
   g_snapshot_seq = next_seq;
   return(true);
  }

bool VerifyLiveTicketGuard(const string server)
  {
   string key_txt = ReadText(RootSpoolPath(".live_auth.key"));
   if(StringLen(key_txt) == 0)
      key_txt = ReadText(SpoolPath(".live_auth.key"));
   uchar live_key[];
   if(!DecodeHexKey(key_txt, live_key))
      return(false);
   string ticket_json = ReadText(SpoolPath("live_auth_ticket.json"));
   if(StringLen(ticket_json) == 0)
      return(false);
   if(JsonGet(ticket_json, "protocol") != "cas-forex-live-auth/1" || JsonGet(ticket_json, "execution_mode") != "LIVE")
      return(false);
   if(JsonGet(ticket_json, "broker_id") != (InpBrokerChannel == "hugosway_mt5" ? "HUGOSWAY_MT5" : "LHFX_MT5"))
      return(false);
   if(JsonGet(ticket_json, "account_login") != IntegerToString(AccountInfoInteger(ACCOUNT_LOGIN)))
      return(false);
   string t_srv = JsonGet(ticket_json, "server");
   StringToLower(t_srv);
   StringTrimLeft(t_srv);
   StringTrimRight(t_srv);
   if(t_srv != server)
      return(false);
   datetime exp_dt = ParseIsoUtc(JsonGet(ticket_json, "expires_at_utc"));
   if(exp_dt == 0 || TimeGMT() > exp_dt)
      return(false);
   string canonical = JsonGet(ticket_json, "protocol") + "|" + JsonGet(ticket_json, "execution_mode") + "|" +
                      JsonGet(ticket_json, "broker_id") + "|" + JsonGet(ticket_json, "account_login") + "|" +
                      JsonGet(ticket_json, "server") + "|" + JsonGet(ticket_json, "issued_at_utc") + "|" +
                      JsonGet(ticket_json, "expires_at_utc") + "|" + JsonGet(ticket_json, "nonce");
   string expected_mac = HmacSha256Hex(live_key, canonical);
   return(ConstTimeHexEquals(expected_mac, JsonGet(ticket_json, "hmac_sha256")));
  }

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
   if(!IsPinnedLiveServer(server))
      return(false);
   return(VerifyLiveTicketGuard(server));
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
   for(int attempt = 0; attempt < 6; attempt++)
     {
      if(FileMove(tmp, CommonFlag(), SpoolPath(name), FILE_REWRITE | CommonFlag()))
         return(true);
      Sleep(8);
     }
   PrintFormat("CasForexMt5Bridge: cannot publish %s (error %d)", name, GetLastError());
   return(false);
  }

string BrokerSymbol(const string cas_symbol)
  {
   if(cas_symbol == "NAS100")
      return(InpNas100Symbol + InpSymbolSuffix);
   if(cas_symbol == "US30")
      return(InpUs30Symbol + InpSymbolSuffix);
   if(cas_symbol == "SPX500")
      return(InpSpx500Symbol + InpSymbolSuffix);
   if(cas_symbol == "XAUUSD")
      return(InpXauusdSymbol + InpSymbolSuffix);
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
   if(broker_symbol == InpSpx500Symbol || broker_symbol == "US500" || broker_symbol == "SP500" || broker_symbol == "SPX500USD" || broker_symbol == "US500.247")
      return("SPX500");
   if(broker_symbol == InpXauusdSymbol || broker_symbol == "GOLD" || broker_symbol == "XAU_USD" || broker_symbol == "GOLD.247")
      return("XAUUSD");
   return(broker_symbol);
  }

string Price(const string broker_symbol, const double value)
  {
   int digits = (int)SymbolInfoInteger(broker_symbol, SYMBOL_DIGITS);
   return(DoubleToString(value, digits));
  }

//+------------------------------------------------------------------+
//| Receipts (exact 11 typed parameters preserved for v2 contracts)  |
//+------------------------------------------------------------------+
string ReceiptJson(const string request_id, const string request_sha, const string status, const uint retcode,
                   const string position_ticket, const string deal_ticket, const string volume,
                   const string price, const string sl, const string tp, const string message)
  {
   string server = SafeText(AccountInfoString(ACCOUNT_SERVER));
   string trade_mode = AccountTradeModeLabel();
   string obs_at = IsoNowUtc();
   string safe_msg = SafeText(message);
   string ret_str = StringFormat("%u", retcode);
   string nonce_str = g_active_nonce;
   string canonical = SPOOL_PROTOCOL + "|" + request_id + "|" + request_sha + "|" + nonce_str + "|" +
                      status + "|" + ret_str + "|" + position_ticket + "|" + deal_ticket + "|" +
                      volume + "|" + price + "|" + sl + "|" + tp + "|" +
                      trade_mode + "|" + server + "|" + obs_at + "|" + safe_msg;
   string mac_hex = g_hmac_key_loaded ? HmacSha256Hex(g_hmac_key, canonical) : "";
   return(StringFormat(
      "{\"protocol\":\"%s\",\"request_id\":\"%s\",\"request_sha256\":\"%s\",\"monotonic_nonce\":\"%s\","
      "\"status\":\"%s\",\"retcode\":\"%s\",\"position_ticket\":\"%s\",\"deal_ticket\":\"%s\","
      "\"volume\":\"%s\",\"price\":\"%s\",\"sl\":\"%s\",\"tp\":\"%s\","
      "\"server\":\"%s\",\"account_trade_mode\":\"%s\",\"observed_at\":\"%s\",\"message\":\"%s\","
      "\"receipt_hmac_sha256\":\"%s\"}",
      SPOOL_PROTOCOL, request_id, request_sha, nonce_str, status, ret_str, position_ticket, deal_ticket,
      volume, price, sl, tp, server, trade_mode, obs_at, safe_msg, mac_hex));
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
   string request_mac = JsonGet(text, "request_hmac_sha256");
   string nonce_s = JsonGet(text, "monotonic_nonce");
   g_active_nonce = (StringLen(nonce_s) > 0) ? nonce_s : "0";

   string json_req_id = JsonGet(text, "request_id");
   if(StringLen(request_id) == 0 || json_req_id != request_id)
     {
      WriteReceipt(request_id, ReceiptJson(request_id, request_sha, "REJECTED", 10013, "0", "0", "0", "0", "0", "0", "request_id filename mismatch"));
      return;
     }

   string core = text;
   StringReplace(core, ",\"request_sha256\":\"" + request_sha + "\"", "");
   StringReplace(core, ",\"request_hmac_sha256\":\"" + request_mac + "\"", "");
   StringTrimRight(core);

   if(JsonGet(text, "protocol") != SPOOL_PROTOCOL || StringLen(request_sha) != 64 || Sha256Hex(core) != request_sha)
     {
      WriteReceipt(request_id, ReceiptJson(request_id, request_sha, "REJECTED", 10013, "0", "0", "0", "0", "0", "0", "request hash mismatch"));
      return;
     }

   if(!g_hmac_key_loaded)
      g_hmac_key_loaded = LoadSpoolHmacKey();
   if(!g_hmac_key_loaded || JsonGet(text, "channel_key_id") != g_channel_key_id)
     {
      WriteReceipt(request_id, ReceiptJson(request_id, request_sha, "REJECTED", 10017, "0", "0", "0", "0", "0", "0", "channel_key_id mismatch"));
      return;
     }
   string hmac_msg = JsonGet(text, "protocol") + "|" + JsonGet(text, "request_id") + "|" + nonce_s + "|" +
                     JsonGet(text, "issued_at") + "|" + JsonGet(text, "expires_at") + "|" +
                     JsonGet(text, "broker_channel") + "|" + JsonGet(text, "channel_key_id") + "|" +
                     JsonGet(text, "account_login") + "|" + JsonGet(text, "server") + "|" +
                     JsonGet(text, "execution_mode") + "|" + JsonGet(text, "valve_decision_sha256") + "|" +
                     JsonGet(text, "valve_admission_expires_at") + "|" + JsonGet(text, "valve_admission_sig") + "|" +
                     JsonGet(text, "action") + "|" + JsonGet(text, "symbol") + "|" + JsonGet(text, "side") + "|" +
                     JsonGet(text, "volume") + "|" + JsonGet(text, "price") + "|" + JsonGet(text, "sl") + "|" +
                     JsonGet(text, "tp") + "|" + JsonGet(text, "position_ticket") + "|" +
                     JsonGet(text, "deviation_points") + "|" + JsonGet(text, "magic") + "|" + JsonGet(text, "comment");
   string expected_mac = g_hmac_key_loaded ? HmacSha256Hex(g_hmac_key, hmac_msg) : "";
   if(!g_hmac_key_loaded || !ConstTimeHexEquals(expected_mac, request_mac))
     {
      WriteReceipt(request_id, ReceiptJson(request_id, request_sha, "REJECTED", 10013, "0", "0", "0", "0", "0", "0", "request hmac mismatch"));
      return;
     }

   string expected_mode = InpLiveExecutionMode ? "LIVE" : "DEMO";
   if(!ModeGuard() ||
      NormalizeLowerTrim(JsonGet(text, "broker_channel")) != NormalizeLowerTrim(InpBrokerChannel) ||
      JsonGet(text, "account_login") != IntegerToString(AccountInfoInteger(ACCOUNT_LOGIN)) ||
      NormalizeLowerTrim(JsonGet(text, "server")) != NormalizeLowerTrim(AccountInfoString(ACCOUNT_SERVER)) ||
      JsonGet(text, "execution_mode") != expected_mode)
     {
      WriteReceipt(request_id, ReceiptJson(request_id, request_sha, "REJECTED", 10017, "0", "0", "0", "0", "0", "0", "mode guard or sink context binding failed"));
      return;
     }

   datetime exp_dt = ParseIsoUtc(JsonGet(text, "expires_at"));
   if(exp_dt == 0 || TimeGMT() > exp_dt)
     {
      WriteReceipt(request_id, ReceiptJson(request_id, request_sha, "REJECTED", 10013, "0", "0", "0", "0", "0", "0", "request expired"));
      return;
     }

   if(!VerifyValveAdmission(text))
     {
      WriteReceipt(request_id, ReceiptJson(request_id, request_sha, "REJECTED", 10017, "0", "0", "0", "0", "0", "0", "valve admission verification failed"));
      return;
     }

   if(!g_replay_ledger_healthy || !LoadReplayNonceLedger() || !LoadGlobalReplayDomain())
     {
      g_replay_ledger_healthy = false;
      WriteReceipt(request_id, ReceiptJson(request_id, request_sha, "REJECTED", 10013, "0", "0", "0", "0", "0", "0", "replay ledger persistence failed"));
      return;
     }
   ulong req_nonce = (ulong)StringToInteger(nonce_s);
   if(req_nonce == 0 || req_nonce <= g_last_monotonic_nonce || IsGlobalReplayIdSeen(request_id))
     {
      WriteReceipt(request_id, ReceiptJson(request_id, request_sha, "REJECTED", 10013, "0", "0", "0", "0", "0", "0", "replayed nonce or request_id"));
      return;
     }
   if(!SaveReplayNonceLedger(req_nonce) || !RecordGlobalReplayId(request_id))
     {
      g_replay_ledger_healthy = false;
      WriteReceipt(request_id, ReceiptJson(request_id, request_sha, "REJECTED", 10013, "0", "0", "0", "0", "0", "0", "replay ledger persistence failed"));
      return;
     }
   g_last_monotonic_nonce = req_nonce;

   if(TerminalInfoInteger(TERMINAL_CONNECTED) == 0)
     {
      WriteReceipt(request_id, ReceiptJson(request_id, request_sha, "REJECTED", 10031, "0", "0", "0", "0", "0", "0", "BROKER_OFFLINE"));
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
      g_history_dirty = true;
     }
  }

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
      g_active_nonce = JsonGet(text, "monotonic_nonce");
      if(StringLen(g_active_nonce) == 0)
         g_active_nonce = "0";
      WriteReceipt(request_id, ReceiptJson(request_id, JsonGet(text, "request_sha256"), "UNKNOWN", (uint)0, "0", "0", "0", "0", "0", "0",
                                           "EA restarted mid-order; check terminal history"));
      FileDelete(SpoolPath(found), CommonFlag());
     }
   while(FileFindNext(search, found));
   FileFindClose(search);
  }


string CandleSeriesJson(const string bsym, const ENUM_TIMEFRAMES tf, const int count)
  {
   MqlRates rates[];
   ArraySetAsSeries(rates, false);
   int got = CopyRates(bsym, tf, 0, count, rates);
   long srv_offset_s = ServerUtcOffsetSeconds();
   string out = "[";
   bool first = true;
   for(int i = 0; i < got; i++)
     {
      double hi = MathMax(rates[i].high, MathMax(rates[i].open, rates[i].close));
      double lo = MathMin(rates[i].low, MathMin(rates[i].open, rates[i].close));
      if(lo <= 0.0)
         continue;
      long bar_utc_s = (long)rates[i].time - srv_offset_s;
      if(bar_utc_s <= 0)
         continue;
      MqlDateTime dt;
      TimeToStruct((datetime)bar_utc_s, dt);
      string t_iso = StringFormat("%04d-%02d-%02dT%02d:%02d:00Z", dt.year, dt.mon, dt.day, dt.hour, dt.min);
      out += StringFormat("%s{\"t\":\"%s\",\"o\":\"%s\",\"h\":\"%s\",\"l\":\"%s\",\"c\":\"%s\",\"v\":\"%s\",\"n\":1}",
                          first ? "" : ",", t_iso, Price(bsym, rates[i].open), Price(bsym, hi),
                          Price(bsym, lo), Price(bsym, rates[i].close),
                          IntegerToString((long)MathMax((long)1, rates[i].tick_volume)));
      first = false;
     }
   out += "]";
   return(out);
  }

void PublishCandles()
  {
   string idx_syms[4] = {"NAS100", "US30", "SPX500", "XAUUSD"};
   string json = StringFormat("{\"protocol\":\"%s\",\"observed_at\":\"%s\",\"markets\":{", SPOOL_PROTOCOL, IsoNowUtc());
   bool first = true;
   for(int i = 0; i < 4; i++)
     {
      string sym = idx_syms[i];
      string bsym = BrokerSymbol(sym);
      string m1 = CandleSeriesJson(bsym, PERIOD_M1, 36);
      string m5 = CandleSeriesJson(bsym, PERIOD_M5, 36);
      string h1 = CandleSeriesJson(bsym, PERIOD_H1, 24);
      json += StringFormat("%s\"%s\":{\"candles_m1\":%s,\"candles_m5\":%s,\"candles_h1\":%s}",
                           first ? "" : ",", sym, m1, m5, h1);
      first = false;
     }
   json += "}}";
   WriteAtomic("market_candles.json", json);
   g_last_candles = TimeCurrent();
  }

void PublishMarket()
  {
   if(!g_hmac_key_loaded)
      g_hmac_key_loaded = LoadSpoolHmacKey();
   if(!g_hmac_key_loaded || StringLen(g_channel_key_id) != 16)
     {
      Print("CasForexMt5Bridge: refusing unsigned PublishMarket (spool HMAC key unavailable).");
      return;
     }
   bool   connected        = (TerminalInfoInteger(TERMINAL_CONNECTED) != 0);
   double live_balance     = AccountInfoDouble(ACCOUNT_BALANCE);
   double live_equity      = AccountInfoDouble(ACCOUNT_EQUITY);
   double live_margin      = AccountInfoDouble(ACCOUNT_MARGIN);
   double live_margin_free = AccountInfoDouble(ACCOUNT_MARGIN_FREE);
   if(connected)
     {
      if(live_balance > 0.0 || live_equity > 0.0 || g_has_connected_account)
        {
         g_last_connected_balance     = live_balance;
         g_last_connected_equity      = live_equity;
         g_last_connected_margin      = live_margin;
         g_last_connected_margin_free = live_margin_free;
         if(live_balance > 0.0 || live_equity > 0.0)
            g_has_connected_account = true;
        }
     }
   double out_balance     = connected ? live_balance     : (g_has_connected_account ? g_last_connected_balance     : 0.0);
   double out_equity      = connected ? live_equity      : (g_has_connected_account ? g_last_connected_equity      : 0.0);
   double out_margin      = connected ? live_margin      : (g_has_connected_account ? g_last_connected_margin      : 0.0);
   double out_margin_free = connected ? live_margin_free : (g_has_connected_account ? g_last_connected_margin_free : 0.0);

   string ticks_json  = "";
   string ticks_canon = "";
   bool first = true;
   if(connected)
     {
      long srv_offset_ms = ServerUtcOffsetSeconds() * 1000;
      for(int i = 0; i < ArraySize(g_symbols); i++)
        {
         string bsym = BrokerSymbol(g_symbols[i]);
         MqlTick tick;
         if(!SymbolInfoTick(bsym, tick) || tick.bid <= 0.0 || tick.ask < tick.bid)
            continue;
         long tick_utc_msc = (long)tick.time_msc - srv_offset_ms;
         if(tick_utc_msc <= 0)
            continue;
         string bid_s = Price(bsym, tick.bid);
         string ask_s = Price(bsym, tick.ask);
         string msc_s = IntegerToString(tick_utc_msc);
         ticks_json += StringFormat("%s{\"symbol\":\"%s\",\"bid\":\"%s\",\"ask\":\"%s\",\"time_msc\":\"%s\"}",
                                    first ? "" : ",", g_symbols[i], bid_s, ask_s, msc_s);
         ticks_canon += (first ? "" : ";") + g_symbols[i] + ":" + bid_s + ":" + ask_s + ":" + msc_s;
         first = false;
        }
     }

   string positions_json  = "";
   string positions_canon = "";
   first = true;
   if(connected)
     {
      for(int p = 0; p < PositionsTotal(); p++)
        {
         ulong ticket = PositionGetTicket(p);
         if(ticket == 0 || !PositionSelectByTicket(ticket))
            continue;
         string bsym = PositionGetString(POSITION_SYMBOL);
         string side = ((ENUM_POSITION_TYPE)PositionGetInteger(POSITION_TYPE) == POSITION_TYPE_BUY) ? "BUY" : "SELL";
         double psl = PositionGetDouble(POSITION_SL);
         double ptp = PositionGetDouble(POSITION_TP);
         string tkt_s  = IntegerToString((long)ticket);
         string csym_s = CasSymbol(bsym);
         string vol_s  = DoubleToString(PositionGetDouble(POSITION_VOLUME), 2);
         string open_s = Price(bsym, PositionGetDouble(POSITION_PRICE_OPEN));
         string sl_s   = (psl > 0.0) ? Price(bsym, psl) : "0";
         string tp_s   = (ptp > 0.0) ? Price(bsym, ptp) : "0";
         string prof_s = DoubleToString(PositionGetDouble(POSITION_PROFIT), 2);
         positions_json += StringFormat("%s{\"ticket\":\"%s\",\"symbol\":\"%s\",\"side\":\"%s\",\"volume\":\"%s\",\"price_open\":\"%s\",\"sl\":\"%s\",\"tp\":\"%s\",\"profit\":\"%s\"}",
                                        first ? "" : ",", tkt_s, csym_s, side, vol_s, open_s, sl_s, tp_s, prof_s);
         positions_canon += (first ? "" : ";") + tkt_s + ":" + csym_s + ":" + side + ":" + vol_s + ":" + open_s + ":" + sl_s + ":" + tp_s + ":" + prof_s;
         first = false;
        }
     }

   if(!AdvanceAndPersistSnapshotSeq())
     {
      Print("CasForexMt5Bridge: refusing PublishMarket (snapshot_seq persistence failed).");
      return;
     }

   string execution_mode  = InpLiveExecutionMode ? "LIVE" : "DEMO";
   string server          = SafeText(AccountInfoString(ACCOUNT_SERVER));
   string trade_mode      = AccountTradeModeLabel();
   string connected_str   = connected ? "true" : "false";
   string observed_at     = IsoNowUtc();
   string snapshot_seq_str = IntegerToString((long)g_snapshot_seq);
   string login           = IntegerToString(AccountInfoInteger(ACCOUNT_LOGIN));
   string currency        = AccountInfoString(ACCOUNT_CURRENCY);
   string balance         = DoubleToString(out_balance, 2);
   string equity          = DoubleToString(out_equity, 2);
   string margin          = DoubleToString(out_margin, 2);
   string margin_free     = DoubleToString(out_margin_free, 2);
   string leverage        = IntegerToString(AccountInfoInteger(ACCOUNT_LEVERAGE));

   string ticks_sha     = Sha256Hex(ticks_canon);
   string positions_sha = Sha256Hex(positions_canon);
   if(StringLen(ticks_sha) != 64 || StringLen(positions_sha) != 64)
      return;
   string snapshot_msg = SPOOL_PROTOCOL + "|" + InpBrokerChannel + "|" + g_channel_key_id + "|" + execution_mode + "|" +
                         server + "|" + trade_mode + "|" + connected_str + "|" + observed_at + "|" + snapshot_seq_str + "|" +
                         login + "|" + currency + "|" + balance + "|" + equity + "|" + margin + "|" + margin_free + "|" +
                         leverage + "|" + ticks_sha + "|" + positions_sha;
   string snapshot_mac = HmacSha256Hex(g_hmac_key, snapshot_msg);
   if(StringLen(snapshot_mac) != 64)
      return;

   string json = StringFormat(
      "{\"protocol\":\"%s\",\"broker_channel\":\"%s\",\"channel_key_id\":\"%s\",\"execution_mode\":\"%s\",\"snapshot_seq\":\"%s\","
      "\"connected\":%s,\"server\":\"%s\",\"account_trade_mode\":\"%s\",\"observed_at\":\"%s\",\"account\":{"
      "\"login\":\"%s\",\"currency\":\"%s\",\"balance\":\"%s\",\"equity\":\"%s\",\"margin\":\"%s\",\"margin_free\":\"%s\",\"leverage\":\"%s\"},\"ticks\":[",
      SPOOL_PROTOCOL, InpBrokerChannel, g_channel_key_id, execution_mode, snapshot_seq_str,
      connected_str, server, trade_mode, observed_at,
      login, currency, balance, equity, margin, margin_free, leverage);
   json += ticks_json;
   json += "],\"positions\":[";
   json += positions_json;
   json += StringFormat("],\"snapshot_hmac_sha256\":\"%s\"}", snapshot_mac);
   WriteAtomic("market_ticks.json", json);
   g_last_publish = TimeCurrent();
  }

void PublishOrderHistory()
  {
   if(!g_hmac_key_loaded)
      g_hmac_key_loaded = LoadSpoolHmacKey();
   if(!g_hmac_key_loaded || StringLen(g_channel_key_id) != 16)
     {
      Print("CasForexMt5Bridge: refusing unsigned PublishOrderHistory (spool HMAC key unavailable).");
      return;
     }
   bool   connected     = (TerminalInfoInteger(TERMINAL_CONNECTED) != 0);
   string connected_str = connected ? "true" : "false";
   string execution_mode = InpLiveExecutionMode ? "LIVE" : "DEMO";
   string server        = SafeHistText(AccountInfoString(ACCOUNT_SERVER));
   string trade_mode    = AccountTradeModeLabel();
   string login         = IntegerToString(AccountInfoInteger(ACCOUNT_LOGIN));
   string observed_at   = IsoNowUtc();
   long   srv_offset_s  = ServerUtcOffsetSeconds();

   string open_json  = "";
   string open_canon = "";
   bool first = true;
   if(connected)
     {
      for(int p = 0; p < PositionsTotal(); p++)
        {
         ulong ticket = PositionGetTicket(p);
         if(ticket == 0)
            continue;
         string tkt_s = IntegerToString((long)ticket);
         open_json  += StringFormat("%s\"%s\"", first ? "" : ",", tkt_s);
         open_canon += (first ? "" : ";") + tkt_s;
         first = false;
        }
     }

   const int MAX_HIST_ROWS = 600;
   string orders_json  = "";
   string orders_canon = "";
   string deals_json   = "";
   string deals_canon  = "";
   bool complete = false;
   if(connected)
     {
      long end_srv_s = MathMax((long)TimeCurrent(), (long)TimeTradeServer()) + 86400;
      bool hist_ok = HistorySelect(0, (datetime)end_srv_s);
      int o_total = hist_ok ? HistoryOrdersTotal() : 0;
      int d_total = hist_ok ? HistoryDealsTotal() : 0;
      bool truncated = (o_total > MAX_HIST_ROWS || d_total > MAX_HIST_ROWS);
      complete = (hist_ok && !truncated);

      int o_start = MathMax(0, o_total - MAX_HIST_ROWS);
      first = true;
      for(int i = o_start; i < o_total; i++)
        {
         ulong ot = HistoryOrderGetTicket(i);
         if(ot == 0)
            continue;
         string ot_s  = IntegerToString((long)ot);
         string req_s = SafeHistText(HistoryOrderGetString(ot, ORDER_COMMENT));
         string raw_sym = HistoryOrderGetString(ot, ORDER_SYMBOL);
         string sym_s = SafeHistText(StringLen(raw_sym) > 0 ? CasSymbol(raw_sym) : "");
         long ot_utc  = HistoryOrderGetInteger(ot, ORDER_TIME_SETUP) - srv_offset_s;
         string t_iso = IsoFromUtcSeconds(ot_utc);
         orders_json += StringFormat(
            "%s{\"order_ticket\":\"%s\",\"request_id\":\"%s\",\"symbol\":\"%s\",\"time_utc\":\"%s\"}",
            first ? "" : ",", ot_s, req_s, sym_s, t_iso);
         orders_canon += (first ? "" : ";") + ot_s + ":" + req_s + ":" + sym_s + ":" + t_iso;
         first = false;
        }

      int d_start = MathMax(0, d_total - MAX_HIST_ROWS);
      first = true;
      for(int i = d_start; i < d_total; i++)
        {
         ulong dtkt = HistoryDealGetTicket(i);
         if(dtkt == 0)
            continue;
         string dt_s  = IntegerToString((long)dtkt);
         string do_s  = IntegerToString(HistoryDealGetInteger(dtkt, DEAL_ORDER));
         string req_s = SafeHistText(HistoryDealGetString(dtkt, DEAL_COMMENT));
         string raw_sym = HistoryDealGetString(dtkt, DEAL_SYMBOL);
         string sym_s = SafeHistText(StringLen(raw_sym) > 0 ? CasSymbol(raw_sym) : "");
         long dt_utc  = HistoryDealGetInteger(dtkt, DEAL_TIME) - srv_offset_s;
         string t_iso = IsoFromUtcSeconds(dt_utc);
         deals_json += StringFormat(
            "%s{\"deal_ticket\":\"%s\",\"order_ticket\":\"%s\",\"request_id\":\"%s\",\"symbol\":\"%s\",\"time_utc\":\"%s\"}",
            first ? "" : ",", dt_s, do_s, req_s, sym_s, t_iso);
         deals_canon += (first ? "" : ";") + dt_s + ":" + do_s + ":" + req_s + ":" + sym_s + ":" + t_iso;
         first = false;
        }
     }

   string complete_str = complete ? "true" : "false";
   string open_sha   = Sha256Hex(open_canon);
   string orders_sha = Sha256Hex(orders_canon);
   string deals_sha  = Sha256Hex(deals_canon);
   if(StringLen(open_sha) != 64 || StringLen(orders_sha) != 64 || StringLen(deals_sha) != 64)
      return;

   string hist_msg = SPOOL_PROTOCOL + "|" + InpBrokerChannel + "|" + g_channel_key_id + "|" + execution_mode + "|" +
                     login + "|" + server + "|" + trade_mode + "|" + connected_str + "|" + complete_str + "|" +
                     observed_at + "|" + open_sha + "|" + orders_sha + "|" + deals_sha;
   string hist_mac = HmacSha256Hex(g_hmac_key, hist_msg);
   if(StringLen(hist_mac) != 64)
      return;

   string json = StringFormat(
      "{\"protocol\":\"%s\",\"broker_channel\":\"%s\",\"channel_key_id\":\"%s\",\"execution_mode\":\"%s\","
      "\"account_login\":\"%s\",\"server\":\"%s\",\"account_trade_mode\":\"%s\","
      "\"connected\":%s,\"complete\":%s,\"observed_at\":\"%s\",\"open_position_tickets\":[",
      SPOOL_PROTOCOL, InpBrokerChannel, g_channel_key_id, execution_mode,
      login, server, trade_mode, connected_str, complete_str, observed_at);
   json += open_json;
   json += "],\"orders\":[";
   json += orders_json;
   json += "],\"deals\":[";
   json += deals_json;
   json += StringFormat("],\"history_hmac_sha256\":\"%s\"}", hist_mac);
   WriteAtomic("order_history.json", json);
   g_last_history = TimeGMT();
   g_history_dirty = false;
  }

int OnInit()
  {
   if(!ModeGuard())
     {
      Print("CasForexMt5Bridge: REFUSED - account trade mode / server / live ticket mismatch.");
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
   g_hmac_key_loaded = LoadSpoolHmacKey();
   g_valve_key_loaded = LoadValveAdmissionKey();
   bool nonce_ok = LoadReplayNonceLedger();
   bool domain_ok = LoadGlobalReplayDomain();
   g_replay_ledger_healthy = (nonce_ok && domain_ok);
   LoadSnapshotSeq();
   g_mode_ok = true;
   ReportInterruptedRequests();
   PublishMarket();
   PublishCandles();
   PublishOrderHistory();
   EventSetMillisecondTimer(MathMax(50, InpTimerMs));
   PrintFormat("CasForexMt5Bridge v2: running [%s] on server %s, spool %s (hmac_loaded=%s)",
               AccountTradeModeLabel(), AccountInfoString(ACCOUNT_SERVER), SpoolDir(), g_hmac_key_loaded ? "true" : "false");
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
   if(TimeCurrent() - g_last_candles >= 5)
      PublishCandles();
   if(g_history_dirty || (TimeGMT() - g_last_history >= 15))
      PublishOrderHistory();
  }

void OnTick()
  {
   if(g_mode_ok && TimeCurrent() != g_last_publish)
      PublishMarket();
  }
