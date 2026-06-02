import { tool } from "@opencode-ai/plugin";
import { readFileSync, existsSync, readdirSync, writeFileSync, mkdirSync, chmodSync, unlinkSync } from "fs";
import { join, dirname } from "path";
import { hostname, homedir, networkInterfaces } from "os";
import { createSign, createHash } from "crypto";
import { Database } from "bun:sqlite";


const PORT = 3456;
function findConfigDir(start) {
  var dir = start;
  for (var i = 0; i < 5; i++) {
    if (existsSync(join(dir, "opencode.json"))) return dir;
    if (existsSync(join(dir, "config", "plugins.json"))) return dir;
    if (existsSync(join(dir, "plugins.json"))) return dir;
    var parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return dirname(start);
}
const CONFIG_DIR = findConfigDir(import.meta.dir);
const LOGS_DIR = join(CONFIG_DIR, "logs");
const CONFIG_FOLDER = join(CONFIG_DIR, "config");
const DB_PATH = join(homedir(), ".local", "share", "opencode", "opencode.db");
const SYNC_INTERVAL_MS = 60_000;
const SA_PATH = join(CONFIG_FOLDER, "firebase-service-account.json");
const FIREBASE_SCOPE = "https://www.googleapis.com/auth/firebase.database https://www.googleapis.com/auth/userinfo.email";

function getMacAddress() {
  var nets = networkInterfaces();
  for (var addrs of Object.values(nets)) {
    for (var a of addrs) {
      if (a.mac && a.mac !== "00:00:00:00:00:00" && !a.internal) return a.mac;
    }
  }
  return null;
}

function buildDeviceId() {
  var cacheDir = join(CONFIG_DIR, "cache");
  var idFile = join(cacheDir, "device-id");
  var legacyIdFile = join(CONFIG_DIR, "device-id");
  try {
    if (existsSync(idFile)) {
      var saved = readFileSync(idFile, "utf-8").trim();
      if (saved) return saved;
    }
    if (existsSync(legacyIdFile)) {
      var legacySaved = readFileSync(legacyIdFile, "utf-8").trim();
      if (legacySaved) {
        try {
          if (!existsSync(cacheDir)) mkdirSync(cacheDir, { recursive: true });
          writeFileSync(idFile, legacySaved, "utf-8");
        } catch {}
        return legacySaved;
      }
    }
  } catch {}
  var host = hostname().toLowerCase();
  var mac = getMacAddress();
  var id;
  if (mac) {
    var hash = createHash("sha256").update(mac).digest("hex").substring(0, 8);
    id = (host + "-" + hash).replace(/[^a-z0-9_-]/g, "-");
  } else {
    id = host.replace(/[^a-z0-9_-]/g, "-");
  }
  try {
    if (!existsSync(cacheDir)) mkdirSync(cacheDir, { recursive: true });
    writeFileSync(idFile, id, "utf-8");
  } catch {}
  return id;
}

const DEVICE_ID = buildDeviceId();
var fbConnected = false;
var ownsServer = false;

function loadServiceAccount() {
  if (!existsSync(SA_PATH)) return null;
  try { return JSON.parse(readFileSync(SA_PATH, "utf-8")); } catch { return null; }
}

function base64url(input) {
  var b64 = typeof input === "string"
    ? Buffer.from(input).toString("base64")
    : input.toString("base64");
  return b64.replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

function createSignedJWT(sa) {
  var now = Math.floor(Date.now() / 1000);
  var header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  var claims = base64url(JSON.stringify({
    iss: sa.client_email, scope: FIREBASE_SCOPE,
    aud: sa.token_uri, iat: now, exp: now + 3600,
  }));
  var unsigned = header + "." + claims;
  var signer = createSign("RSA-SHA256");
  signer.update(unsigned);
  return unsigned + "." + base64url(signer.sign(sa.private_key));
}

var tokenCache = { token: null, expiresAt: 0 };

async function getAccessToken() {
  var now = Date.now();
  if (tokenCache.token && now < tokenCache.expiresAt - 60_000) return tokenCache.token;
  var sa = loadServiceAccount();
  if (!sa) return null;
  try {
    var res = await fetch(sa.token_uri, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "grant_type=" + encodeURIComponent("urn:ietf:params:oauth:grant-type:jwt-bearer") + "&assertion=" + encodeURIComponent(createSignedJWT(sa)),
    });
    if (!res.ok) { return null; }
    var data = await res.json();
    tokenCache.token = data.access_token;
    tokenCache.expiresAt = now + (data.expires_in || 3600) * 1000;
    return tokenCache.token;
  } catch (err) { return null; }
}

function getFirebaseUrl() {
  var sa = loadServiceAccount();
  return sa?.project_id ? "https://" + sa.project_id + "-default-rtdb.europe-west1.firebasedatabase.app" : null;
}

function sanitizeKeys(obj) {
  if (obj === null || obj === undefined || typeof obj !== "object") return obj;
  if (Array.isArray(obj)) return obj.map(sanitizeKeys);
  var out = {};
  for (var [k, v] of Object.entries(obj)) {
    var safe = k.replace(/[.$/\[\]#]/g, "~");
    out[safe] = sanitizeKeys(v);
  }
  return out;
}

async function pushToFirebase(snapshot) {
  var fbUrl = getFirebaseUrl();
  var token = await getAccessToken();
  if (!fbUrl || !token) {
    return;
  }
  try {
    var res = await fetch(fbUrl + "/devices/" + DEVICE_ID + ".json", {
      method: "PUT",
      headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
      body: JSON.stringify(sanitizeKeys(snapshot)),
    });
    if (!res.ok) {
    }
  } catch (err) {
  }
}

async function pullAllDevices() {
  var fbUrl = getFirebaseUrl();
  var token = await getAccessToken();
  if (!fbUrl || !token) return null;
  try {
    var res = await fetch(fbUrl + "/devices.json", { headers: { "Authorization": "Bearer " + token } });
    if (!res.ok) return null;
    return await res.json();
  } catch { return null; }
}

var remoteCache = { data: null, fetchedAt: 0 };
const CACHE_TTL = 15_000;

async function getRemoteSnapshots() {
  var now = Date.now();
  if (!remoteCache.data || (now - remoteCache.fetchedAt) > CACHE_TTL) {
    var remote = await pullAllDevices();
    if (remote) { remoteCache.data = remote; remoteCache.fetchedAt = now; }
  }
  return remoteCache.data;
}

var nicknameCache = { data: {}, fetchedAt: 0 };

async function pullNicknames() {
  var fbUrl = getFirebaseUrl();
  var token = await getAccessToken();
  if (!fbUrl || !token) return {};
  try {
    var res = await fetch(fbUrl + "/nicknames.json", { headers: { "Authorization": "Bearer " + token } });
    if (!res.ok) return {};
    return (await res.json()) || {};
  } catch { return {}; }
}

async function getNicknames() {
  var now = Date.now();
  if (now - nicknameCache.fetchedAt > CACHE_TTL) {
    var nicks = await pullNicknames();
    nicknameCache.data = nicks || {};
    nicknameCache.fetchedAt = now;
  }
  return nicknameCache.data;
}

async function setNicknameOnFirebase(deviceId, nickname) {
  var fbUrl = getFirebaseUrl();
  var token = await getAccessToken();
  if (!fbUrl || !token) return false;
  try {
    var safeId = deviceId.replace(/[.$/\[\]#]/g, "~");
    var res = await fetch(fbUrl + "/nicknames/" + safeId + ".json", {
      method: "PUT",
      headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
      body: JSON.stringify(nickname || null),
    });
    if (res.ok) { nicknameCache.fetchedAt = 0; }
    return res.ok;
  } catch { return false; }
}

async function removeDeviceFromFirebase(deviceId) {
  var fbUrl = getFirebaseUrl();
  var token = await getAccessToken();
  if (!fbUrl || !token) return false;
  try {
    var safeId = deviceId.replace(/[.$/\[\]#]/g, "~");
    await fetch(fbUrl + "/devices/" + safeId + ".json", {
      method: "DELETE", headers: { "Authorization": "Bearer " + token },
    });
    await fetch(fbUrl + "/nicknames/" + safeId + ".json", {
      method: "DELETE", headers: { "Authorization": "Bearer " + token },
    });
    remoteCache.data = null;
    nicknameCache.fetchedAt = 0;
    return true;
  } catch { return false; }
}

function openDB() {
  var paths = [];
  if (process.env.OPENCODE_DIR) paths.push(join(process.env.OPENCODE_DIR, "opencode.db"));
  if (process.env.LOCALAPPDATA) paths.push(join(process.env.LOCALAPPDATA, "opencode", "opencode.db"));
  paths.push(DB_PATH);
  for (var p of paths) {
    if (existsSync(p)) {
      try { return new Database(p, { readonly: true }); } catch {}
    }
  }
  return null;
}

function readJSON(p) {
  try { return JSON.parse(readFileSync(p, "utf-8")); } catch { return null; }
}

function getAccountsData() {
  var allAccounts = [];
  var files = ["antigravity-accounts.json", "cursor-accounts.json", "zen-accounts.json"];
  
  for (var file of files) {
    var raw = readJSON(join(CONFIG_FOLDER, file)) || readJSON(join(CONFIG_DIR, file));
    if (!raw?.accounts) continue;
    var now = Date.now();
    var mapped = raw.accounts.map(a => {
      var rateLimits = {};
      for (var [key, resetTs] of Object.entries(a.rateLimitResetTimes || {})) {
        rateLimits[key] = { resetTime: resetTs, isLimited: resetTs > now };
      }
      var quotas = {};
      for (var [model, q] of Object.entries(a.cachedQuota || {})) {
        quotas[model] = {
          remaining: q.remainingFraction,
          resetTime: q.resetTime ? new Date(q.resetTime).getTime() : null,
          modelCount: q.modelCount,
        };
      }
      return {
        email: a.email || a.username || a.id || file.split('-')[0],
        enabled: a.enabled !== false,
        lastUsed: a.lastUsed || a.updatedAt || 0,
        rateLimits,
        quotas,
        quotaUpdatedAt: a.cachedQuotaUpdatedAt || 0,
        provider: file.split('-')[0]
      };
    });
    allAccounts = allAccounts.concat(mapped);
  }
  return allAccounts;
}

function buildSessionsWithCosts() {
  var db = openDB();
  var dbSessions = [];
  
  if (db) {
    try {
      var sessions = db.query(
        "SELECT id, title, time_created, time_updated FROM session WHERE parent_id IS NULL ORDER BY time_updated DESC"
      ).all();

      var msgRows = db.query(
        `SELECT m.session_id,
                m.time_created as msg_time,
                json_extract(m.data, '$.role') as role,
                json_extract(m.data, '$.modelID') as modelID,
                json_extract(m.data, '$.providerID') as providerID,
                json_extract(m.data, '$.cost') as cost,
                json_extract(m.data, '$.tokens.input') as tok_in,
                json_extract(m.data, '$.tokens.output') as tok_out,
                json_extract(m.data, '$.tokens.reasoning') as tok_reason,
                json_extract(m.data, '$.tokens.cache.read') as tok_cr,
                json_extract(m.data, '$.tokens.cache.write') as tok_cw
         FROM message m
         INNER JOIN session s ON m.session_id = s.id
         WHERE s.parent_id IS NULL AND json_extract(m.data, '$.role') = 'assistant'
               AND (COALESCE(json_extract(m.data, '$.tokens.input'), 0) + COALESCE(json_extract(m.data, '$.tokens.output'), 0)) > 0`
      ).all();

      db.close();

      var msgBySession = {};
      for (var row of msgRows) {
        var sid = row.session_id;
        if (!msgBySession[sid]) msgBySession[sid] = [];
        msgBySession[sid].push(row);
      }

      dbSessions = sessions.map(s => {
        var msgs = msgBySession[s.id] || [];
        var totalCost = 0;
        var tokens = { input: 0, output: 0, reasoning: 0, cacheRead: 0, cacheWrite: 0 };
        var modelUsage = {};
        var costByDay = {};

        for (var msg of msgs) {
          var cost = msg.cost || 0;
          totalCost += cost;
          tokens.input += msg.tok_in || 0;
          tokens.output += msg.tok_out || 0;
          tokens.reasoning += msg.tok_reason || 0;
          tokens.cacheRead += msg.tok_cr || 0;
          tokens.cacheWrite += msg.tok_cw || 0;

          var mid = msg.modelID || "unknown";
          if (!modelUsage[mid]) modelUsage[mid] = { cost: 0, tokens: { input: 0, output: 0, reasoning: 0 }, provider: msg.providerID || "", count: 0 };
          modelUsage[mid].cost += cost;
          modelUsage[mid].count += 1;
          modelUsage[mid].tokens.input += msg.tok_in || 0;
          modelUsage[mid].tokens.output += msg.tok_out || 0;
          modelUsage[mid].tokens.reasoning += msg.tok_reason || 0;

          var mTs = msg.msg_time || s.time_updated || 0;
          if (mTs) {
            var md = new Date(mTs);
            var dayKey = md.getFullYear() + "-" + (md.getMonth() + 1 < 10 ? "0" : "") + (md.getMonth() + 1) + "-" + (md.getDate() < 10 ? "0" : "") + md.getDate();
            if (!costByDay[dayKey]) costByDay[dayKey] = { cost: 0, tokens: 0, tokens_in: 0, tokens_out: 0, tokens_reason: 0, msgs: 0 };
            costByDay[dayKey].cost += cost;
            costByDay[dayKey].tokens += (msg.tok_in || 0) + (msg.tok_out || 0) + (msg.tok_reason || 0);
            costByDay[dayKey].tokens_in += msg.tok_in || 0;
            costByDay[dayKey].tokens_out += msg.tok_out || 0;
            costByDay[dayKey].tokens_reason += msg.tok_reason || 0;
            costByDay[dayKey].msgs += 1;
          }
        }

        return {
          id: s.id,
          title: s.title || "Untitled",
          created: s.time_created || 0,
          updated: s.time_updated || 0,
          cost: totalCost,
          tokens,
          modelUsage,
          costByDay,
          messageCount: msgs.length || s.messageCount || 0,
        };
      });
    } catch (err) {
      try { db.close(); } catch {}
    }
  }
  
  var legacySessions = [];
  var sessionDir = join(CONFIG_DIR, "data", "storage", "session");
  var msgDirBase = join(CONFIG_DIR, "data", "storage", "message");
  
  if (existsSync(sessionDir)) {
    try {
      for (var projectDir of readdirSync(sessionDir)) {
        var fullDir = join(sessionDir, projectDir);
        try {
          for (var file of readdirSync(fullDir)) {
            if (!file.endsWith(".json")) continue;
            var s = readJSON(join(fullDir, file));
            if (!s?.id || s.parentID) continue;
            
            if (dbSessions.some(ds => ds.id === s.id)) continue;
            if (legacySessions.some(ls => ls.id === s.id)) continue;
            
            var msgs = [];
            var msgDir = join(msgDirBase, s.id);
            if (existsSync(msgDir)) {
              try {
                for (var mFile of readdirSync(msgDir)) {
                  if (!mFile.endsWith(".json")) continue;
                  var m = readJSON(join(msgDir, mFile));
                  if (m?.id && m.role === "assistant" && ((m.tokens?.input || 0) + (m.tokens?.output || 0)) > 0) msgs.push(m);
                }
              } catch {}
            }
            
            var totalCost = 0;
            var tokens = { input: 0, output: 0, reasoning: 0, cacheRead: 0, cacheWrite: 0 };
            var modelUsage = {};
            var costByDay = {};

            for (var msg of msgs) {
              var cost = msg.cost || 0;
              totalCost += cost;
              var msgTokIn = 0, msgTokOut = 0, msgTokR = 0;
              if (msg.tokens) {
                msgTokIn = msg.tokens.input || 0;
                msgTokOut = msg.tokens.output || 0;
                msgTokR = msg.tokens.reasoning || 0;
                tokens.input += msgTokIn;
                tokens.output += msgTokOut;
                tokens.reasoning += msgTokR;
                tokens.cacheRead += msg.tokens.cache?.read || 0;
                tokens.cacheWrite += msg.tokens.cache?.write || 0;
              }

              var mid = (msg.modelID || "unknown").replace(/[.#$[]]/g, "_");
              if (!modelUsage[mid]) modelUsage[mid] = { cost: 0, tokens: { input: 0, output: 0, reasoning: 0 }, provider: msg.providerID || "", count: 0 };
              modelUsage[mid].cost += cost;
              modelUsage[mid].count += 1;
              if (msg.tokens) {
                modelUsage[mid].tokens.input += msgTokIn;
                modelUsage[mid].tokens.output += msgTokOut;
                modelUsage[mid].tokens.reasoning += msgTokR;
              }

              var mTs = msg.time?.created || s.time?.updated || 0;
              if (mTs) {
                var md = new Date(mTs);
                var dayKey = md.getFullYear() + "-" + (md.getMonth() + 1 < 10 ? "0" : "") + (md.getMonth() + 1) + "-" + (md.getDate() < 10 ? "0" : "") + md.getDate();
                if (!costByDay[dayKey]) costByDay[dayKey] = { cost: 0, tokens: 0, tokens_in: 0, tokens_out: 0, tokens_reason: 0, msgs: 0 };
                costByDay[dayKey].cost += cost;
                costByDay[dayKey].tokens += msgTokIn + msgTokOut + msgTokR;
                costByDay[dayKey].tokens_in += msgTokIn;
                costByDay[dayKey].tokens_out += msgTokOut;
                costByDay[dayKey].tokens_reason += msgTokR;
                costByDay[dayKey].msgs += 1;
              }
            }

            legacySessions.push({
              id: s.id,
              title: s.title || "Untitled",
              created: s.time?.created || 0,
              updated: s.time?.updated || 0,
              cost: totalCost,
              tokens,
              modelUsage,
              costByDay,
              messageCount: msgs.length || s.messageCount || 0,
            });
          }
        } catch {}
      }
    } catch {}
  }
  
  var allSessions = [...dbSessions, ...legacySessions];
  allSessions.sort((a, b) => b.updated - a.updated);
  return allSessions;
}

function buildModelSummary(sessions) {
  var models = {};
  for (var s of sessions) {
    for (var [mid, u] of Object.entries(s.modelUsage || {})) {
      if (!models[mid]) models[mid] = { cost: 0, tokens: { input: 0, output: 0, reasoning: 0 }, provider: u.provider, sessionCount: 0, msgCount: 0 };
      models[mid].cost += u.cost;
      models[mid].tokens.input += u.tokens.input;
      models[mid].tokens.output += u.tokens.output;
      models[mid].tokens.reasoning += u.tokens.reasoning;
      models[mid].sessionCount += 1;
      models[mid].msgCount += u.count;
    }
  }
  return models;
}

function buildSnapshot() {
  var accounts = getAccountsData();
  var sessions = buildSessionsWithCosts();
  var models = buildModelSummary(sessions);
  var costByDay = {};
  for (var i = 0; i < sessions.length; i++) {
    var cbd = sessions[i].costByDay;
    if (cbd) {
      for (var dk of Object.keys(cbd)) {
        if (!costByDay[dk]) costByDay[dk] = { cost: 0, tokens: 0, tokens_in: 0, tokens_out: 0, tokens_reason: 0, msgs: 0 };
        costByDay[dk].cost += cbd[dk].cost || 0;
        costByDay[dk].tokens += cbd[dk].tokens || 0;
        costByDay[dk].tokens_in += cbd[dk].tokens_in || 0;
        costByDay[dk].tokens_out += cbd[dk].tokens_out || 0;
        costByDay[dk].tokens_reason += cbd[dk].tokens_reason || 0;
        costByDay[dk].msgs += cbd[dk].msgs || 0;
      }
    }
  }
  return { device: DEVICE_ID, updatedAt: Date.now(), accounts, sessions: sessions.slice(0, 50), models, costByDay };
}

var snapshotCache = { data: null, builtAt: 0 };
const SNAPSHOT_TTL = 5_000;

function getCachedSnapshot() {
  var now = Date.now();
  if (!snapshotCache.data || (now - snapshotCache.builtAt) > SNAPSHOT_TTL) {
    snapshotCache.data = buildSnapshot();
    snapshotCache.builtAt = now;
  }
  return snapshotCache.data;
}

function mergeSnapshots(local, remotes) {
  var allDevices = [{ ...local, isLocal: true }];
  if (remotes) {
    for (var [id, snap] of Object.entries(remotes)) {
      if (id !== DEVICE_ID) allDevices.push({ ...snap, isLocal: false });
    }
  }
  allDevices.sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0));
  var accounts = allDevices[0].accounts || [];

  var byId = {};
  for (var dev of allDevices) {
    for (var s of (dev.sessions || [])) {
      if (!byId[s.id]) {
        byId[s.id] = { ...s, device: dev.device, isLocal: dev.isLocal, onDevices: [dev.device] };
      } else {
        if (byId[s.id].onDevices.indexOf(dev.device) === -1) byId[s.id].onDevices.push(dev.device);
        if ((s.updated || 0) > (byId[s.id].updated || 0)) {
          var prevDevices = byId[s.id].onDevices;
          byId[s.id] = { ...s, device: dev.device, isLocal: dev.isLocal, onDevices: prevDevices };
        }
      }
    }
  }
  var sessions = Object.values(byId).sort((a, b) => (b.updated || 0) - (a.updated || 0));

  var models = {};
  for (var dev of allDevices) {
    for (var [mid, u] of Object.entries(dev.models || {})) {
      if (!models[mid]) models[mid] = { cost: 0, tokens: { input: 0, output: 0, reasoning: 0 }, provider: u.provider, sessionCount: 0, msgCount: 0 };
      models[mid].cost += u.cost;
      models[mid].tokens.input += u.tokens.input;
      models[mid].tokens.output += u.tokens.output;
      models[mid].tokens.reasoning += u.tokens.reasoning;
      models[mid].sessionCount += u.sessionCount;
      models[mid].msgCount += u.msgCount;
    }
  }

  var devices = allDevices.map(function(d) {
    var tCost = 0, tTok = 0, tMsg = 0;
    for (var s of (d.sessions || [])) {
      tCost += s.cost || 0;
      tTok += (s.tokens?.input || 0) + (s.tokens?.output || 0) + (s.tokens?.reasoning || 0);
      tMsg += s.messageCount || 0;
    }
    return {
      device: d.device, updatedAt: d.updatedAt, isLocal: d.isLocal,
      sessionCount: (d.sessions || []).length, totalCost: tCost, totalTokens: tTok, totalMessages: tMsg,
      costByDay: d.costByDay || {},
    };
  });

  var costByDay = {};
  for (var dev of allDevices) {
    var dcbd = dev.costByDay || {};
    for (var dk of Object.keys(dcbd)) {
      if (!costByDay[dk]) costByDay[dk] = { cost: 0, tokens: 0, tokens_in: 0, tokens_out: 0, tokens_reason: 0, msgs: 0 };
      costByDay[dk].cost += dcbd[dk].cost || 0;
      costByDay[dk].tokens += dcbd[dk].tokens || 0;
      costByDay[dk].tokens_in += dcbd[dk].tokens_in || 0;
      costByDay[dk].tokens_out += dcbd[dk].tokens_out || 0;
      costByDay[dk].tokens_reason += dcbd[dk].tokens_reason || 0;
      costByDay[dk].msgs += dcbd[dk].msgs || 0;
    }
  }

  return { accounts, sessions, models, devices, costByDay };
}

var HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OpenCode Analytics</title>
<link rel="icon" href="data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 100 100%22><text y=%22.9em%22 font-size=%2290%22>ðŸ“Š</text></svg>">
<style>
:root{--bg:#0a0f16;--bg2:#0d1117;--card:#151b23;--card2:#1a2230;--hover:#1e2a38;--border:#1e2a38;--border2:#30363d;--text:#e6edf3;--text2:#b1bac4;--dim:#8b949e;--muted:#484f58;--green:#3fb950;--green2:#238636;--yellow:#d29922;--red:#f85149;--blue:#58a6ff;--purple:#bc8cff;--cyan:#56d4dd;--r:12px;--r-sm:8px;--shadow:0 1px 3px rgba(0,0,0,.4);--shadow-lg:0 4px 12px rgba(0,0,0,.5)}
*{margin:0;padding:0;box-sizing:border-box}
body{background:var(--bg);color:var(--text);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif;font-size:14px;line-height:1.6;-webkit-font-smoothing:antialiased}
#app{max-width:1320px;margin:0 auto;padding:32px 24px}
header{display:flex;align-items:center;justify-content:space-between;margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid var(--border)}
h1{font-size:22px;font-weight:700;letter-spacing:-.5px;display:flex;align-items:baseline;gap:10px}
h1 small{color:var(--dim);font-weight:400;font-size:12px;font-variant-numeric:tabular-nums}
.hdr-r{display:flex;align-items:center;gap:10px}
.sync-badge{font-size:11px;padding:3px 10px;border-radius:12px;border:1px solid var(--border);font-weight:500}
.sync-badge.y{border-color:var(--green2);color:var(--green);background:rgba(63,185,80,.06)}
.sync-badge.n{color:var(--muted)}
.dot{width:7px;height:7px;border-radius:50%;display:inline-block;margin-right:5px;background:var(--green);animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.35}}
.meta{color:var(--dim);font-size:12px}
.btn{background:var(--card);border:1px solid var(--border2);color:var(--text2);padding:6px 14px;border-radius:var(--r-sm);cursor:pointer;font-size:12px;font-weight:500;transition:all .15s ease}
.btn:hover{background:var(--hover);border-color:var(--muted);color:var(--text)}
.btn.on{border-color:var(--green2);color:var(--green);background:rgba(63,185,80,.08)}
.devices{display:flex;gap:6px;flex-wrap:wrap;margin-bottom:20px}
.chip{display:inline-flex;align-items:center;gap:5px;padding:5px 12px;border-radius:16px;font-size:11px;border:1px solid var(--border);background:var(--card);font-weight:500;transition:border-color .15s}
.chip:hover{border-color:var(--border2)}
.chip.local{border-color:var(--green2);background:rgba(63,185,80,.04)}
.ddot{width:6px;height:6px;border-radius:50%;display:inline-block}
.ddot.on{background:var(--green)}.ddot.stale{background:var(--yellow)}.ddot.off{background:var(--red)}
.summary-row{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:24px}
.sum-card{background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:20px 22px;position:relative;overflow:hidden;box-shadow:var(--shadow);transition:border-color .2s,box-shadow .2s}
.sum-card:hover{border-color:var(--border2);box-shadow:var(--shadow-lg)}
.sum-card::before{content:"";position:absolute;top:0;left:0;right:0;height:3px}
.sum-card.c1::before{background:linear-gradient(90deg,var(--green),var(--cyan))}
.sum-card.c2::before{background:linear-gradient(90deg,var(--blue),var(--purple))}
.sum-card.c3::before{background:linear-gradient(90deg,var(--yellow),var(--red))}
.sum-card h3{font-size:11px;text-transform:uppercase;letter-spacing:.8px;color:var(--dim);margin-bottom:6px;font-weight:600}
.sum-card .val{font-size:28px;font-weight:700;font-variant-numeric:tabular-nums;letter-spacing:-.5px}
.sum-card .sub{font-size:11px;color:var(--dim);margin-top:6px;font-variant-numeric:tabular-nums}
.sum-card .sub span{margin-right:12px}
.graph-section{background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:20px;margin-bottom:24px;box-shadow:var(--shadow)}
.graph-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:16px}
.graph-hdr h2{font-size:13px;font-weight:600;color:var(--dim);text-transform:uppercase;letter-spacing:.6px}
.graph-outer{position:relative}
.graph-area{width:100%;height:240px}
.graph-tip{display:none;position:absolute;pointer-events:none;background:var(--card2);border:1px solid var(--border2);border-radius:6px;padding:5px 12px;font-size:11px;color:var(--text);white-space:nowrap;z-index:20;box-shadow:var(--shadow-lg);font-variant-numeric:tabular-nums}
.graph-legend{display:flex;flex-wrap:wrap;gap:14px;padding:12px 0 0;justify-content:center}
.legend-item{display:inline-flex;align-items:center;gap:6px;font-size:11px;color:var(--dim);font-weight:500}
.legend-dot{width:10px;height:10px;border-radius:3px;display:inline-block}
.empty-graph{width:100%;height:100%;display:flex;align-items:center;justify-content:center;color:var(--dim);font-size:13px}
.tabs{display:flex;gap:4px;margin-bottom:20px;background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:4px;width:fit-content}
.tab{background:0;border:0;color:var(--dim);padding:7px 20px;border-radius:var(--r-sm);cursor:pointer;font-size:13px;font-weight:500;transition:all .15s ease}
.tab:hover{color:var(--text)}
.tab.on{color:var(--text);background:var(--hover);box-shadow:0 1px 2px rgba(0,0,0,.3)}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(290px,1fr));gap:14px;margin-bottom:24px}
.card{background:var(--card);border:1px solid var(--border);border-radius:var(--r);padding:18px;transition:all .2s ease;box-shadow:var(--shadow)}
.card:hover{border-color:var(--border2);box-shadow:var(--shadow-lg);transform:translateY(-1px)}
.card h3{font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--dim);margin-bottom:6px;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.card .val{font-size:24px;font-weight:700;margin-bottom:6px;font-variant-numeric:tabular-nums;letter-spacing:-.3px}
.card .bar-t{width:100%;height:4px;background:var(--border);border-radius:4px;overflow:hidden;margin-bottom:8px}
.card .bar-f{height:100%;border-radius:4px;transition:width .5s ease}
.card .sub{font-size:11px;color:var(--dim);font-variant-numeric:tabular-nums}
.card .sub span{margin-right:10px}
.section-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px}
.section-hdr h2{font-size:16px;font-weight:600;letter-spacing:-.2px}
.section-hdr .controls{display:flex;gap:8px;align-items:center}
.filter{background:var(--bg2);border:1px solid var(--border);color:var(--text);padding:6px 12px;border-radius:var(--r-sm);font-size:12px;outline:0;transition:border-color .15s ease;-webkit-appearance:none;appearance:none}
.filter:focus{border-color:var(--blue)}
select.filter{padding-right:28px;background-image:url("data:image/svg+xml,%3csvg xmlns='http://www.w3.org/2000/svg' fill='none' viewBox='0 0 20 20'%3e%3cpath stroke='%238b949e' stroke-linecap='round' stroke-linejoin='round' stroke-width='1.5' d='M6 8l4 4 4-4'/%3e%3c/svg%3e");background-position:right 6px center;background-repeat:no-repeat;background-size:16px}
.tw{background:var(--card);border:1px solid var(--border);border-radius:var(--r);overflow:hidden;box-shadow:var(--shadow)}
table{width:100%;border-collapse:collapse}
th{text-align:left;padding:10px 16px;font-size:11px;text-transform:uppercase;letter-spacing:.5px;color:var(--dim);border-bottom:1px solid var(--border);cursor:pointer;user-select:none;white-space:nowrap;font-weight:600;background:var(--bg2);transition:color .15s}
th:hover{color:var(--text)}
td{padding:10px 16px;border-bottom:1px solid var(--border);font-size:13px;vertical-align:middle}
tr:last-child td{border-bottom:0}
tr:hover{background:var(--hover)}
tr.dis{opacity:.35}
tr.totals td{font-weight:600;border-top:2px solid var(--border2);color:var(--dim);background:transparent}
.pill{display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;background:var(--border);margin-right:4px;font-variant-numeric:tabular-nums;font-weight:500}
.badge{display:inline-block;padding:2px 8px;border-radius:10px;font-size:10px;border:1px solid var(--border);color:var(--dim);font-weight:500}
.badge.local{border-color:var(--green2);color:var(--green)}
.badge.prov{border-color:var(--purple);color:var(--purple);margin-left:4px}
.lim-y{color:var(--red);font-weight:600}
.lim-n{color:var(--green)}
.qbar{flex:1;height:4px;background:var(--border);border-radius:4px;overflow:hidden;min-width:40px}
.qbar-f{height:100%;border-radius:4px}
.qpct{font-size:11px;min-width:32px;text-align:right;font-variant-numeric:tabular-nums}
.cost{font-variant-numeric:tabular-nums}
.empty{text-align:center;padding:48px;color:var(--dim);font-size:13px}
.nick-input{background:var(--bg2);border:1px solid var(--blue);color:var(--text);padding:4px 10px;border-radius:6px;font-size:12px;outline:0;width:140px}
.btn-sm{background:var(--card);border:1px solid var(--border2);color:var(--text2);padding:4px 10px;border-radius:6px;cursor:pointer;font-size:11px;font-weight:500;transition:all .15s}
.btn-sm:hover{background:var(--hover);border-color:var(--muted)}
.btn-sm.danger{color:var(--red);border-color:var(--red)}
.btn-sm.danger:hover{background:rgba(248,81,73,.1)}
.btn-sm.success{color:var(--green);border-color:var(--green)}
.btn-sm.success:hover{background:rgba(63,185,80,.1)}
.dev-nick{color:var(--cyan);font-size:12px;cursor:pointer;border-bottom:1px dashed var(--muted);transition:border-color .15s}
.dev-nick:hover{border-color:var(--cyan)}
footer{text-align:center;padding:24px 0 8px;color:var(--muted);font-size:11px;border-top:1px solid var(--border);margin-top:32px}
@media(max-width:768px){.summary-row{grid-template-columns:1fr}.grid{grid-template-columns:1fr}.tw{overflow-x:auto}header{flex-direction:column;align-items:flex-start;gap:10px}.tabs{width:100%}.tab{flex:1;text-align:center}}
.quota-status{display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px}
.q-avail{font-size:24px;font-weight:700;margin-bottom:8px;font-variant-numeric:tabular-nums;letter-spacing:-.5px}
</style>
</head>
<body>
<div id="app">
<header>
  <h1>OpenCode Analytics<small id="info"></small></h1>
  <div class="hdr-r">
    <span class="sync-badge n" id="sync"></span>
    <span class="meta"><span class="dot" id="dot"></span><span id="when">Loading...</span></span>
    <button class="btn on" id="ar" onclick="toggleAR()">Auto-refresh</button>
    <button class="btn" onclick="load()">Refresh</button>
  </div>
</header>
<div class="devices" id="devs"></div>
<div class="summary-row" id="summary"></div>
<div class="graph-section">
  <div class="graph-hdr">
    <h2>Usage Over Time</h2>
    <div style="display:flex;gap:8px">
      <select id="gd" class="filter" onchange="rG();rSummary()"><option value="all">All devices</option></select>
      <select id="gf" class="filter" onchange="rG();rSummary()">
        <option value="7">7 Days</option>
        <option value="30">30 Days</option>
        <option value="365" selected>Year</option>
        <option value="all">All Time</option>
      </select>
      <select id="gm" class="filter" onchange="rG()">
        <option value="tokens">Tokens</option>
        <option value="cost">Cost</option>
        <option value="msgs">Messages</option>
      </select>
    </div>
  </div>
  <div class="graph-outer">
    <div class="graph-area" id="graph-container"></div>
    <div class="graph-tip" id="graph-tip"></div>
  </div>
  <div class="graph-legend" id="graph-legend"></div>
</div>
<div class="tabs" id="tabs">
  <button class="tab on" onclick="go('models')">Models</button>
  <button class="tab" onclick="go('accounts')">Accounts</button>
  <button class="tab" onclick="go('sessions')">Sessions</button>
  <button class="tab" onclick="go('devices')">Devices</button>
</div>
<div id="p-models">
  <div class="section-hdr"><h2>Models <small id="msub" style="color:var(--dim)"></small> <small style="color:var(--muted);font-weight:400;font-size:11px">(All-Time)</small></h2>
    <div class="controls">
      <select class="filter" id="md" onchange="rM()"><option value="all">All devices</option></select>
      <select class="filter" id="mf" onchange="rM()" style="width:140px">
        <option value="tokens">Sort by Tokens</option>
        <option value="cost">Sort by Cost</option>
        <option value="msgs">Sort by Messages</option>
        <option value="name">Sort by Name</option>
      </select>
    </div>
  </div>
  <div class="grid" id="mcards"></div>
</div>
<div id="p-accounts" style="display:none">
  <div class="section-hdr">
    <h2>Accounts <small id="asub" style="color:var(--dim)"></small></h2>
    <div class="controls">
      <button class="btn-sm success" onclick="toggleAllAccounts(true)">Enable All</button>
      <button class="btn-sm danger" onclick="toggleAllAccounts(false)">Disable All</button>
      <input class="filter" placeholder="Filter accounts..." id="af" oninput="rA()" style="width:200px">
    </div>
  </div>
  <div class="summary-row" id="quotas"></div>
  <div class="tw"><table><thead><tr>
    <th onclick="sA('email')">Account</th>
    <th onclick="sA('enabled')">Status</th>
    <th onclick="sA('credits')">Quota Remaining</th>
    <th onclick="sA('rateLimited')">Rate Limited</th>
    <th onclick="sA('lastUsed')">Last Used</th>
    <th>Actions</th>
  </tr></thead><tbody id="atb"></tbody></table></div>
</div>
<div id="p-sessions" style="display:none">
  <div class="section-hdr"><h2>Sessions <small id="ssub" style="color:var(--dim)"></small></h2>
    <select class="filter" id="df" onchange="rS()" style="width:160px"><option value="all">All devices</option></select>
  </div>
  <div class="tw"><table><thead><tr>
    <th onclick="sS('title')">Title</th>
    <th onclick="sS('device')">Device</th>
    <th onclick="sS('cost')">Cost</th>
    <th onclick="sS('tokens')">Tokens</th>
    <th onclick="sS('updated')">Updated</th>
  </tr></thead><tbody id="stb"></tbody></table></div>
</div>
<div id="p-devices" style="display:none">
  <div class="section-hdr"><h2>Devices <small id="dsub" style="color:var(--dim)"></small></h2></div>
  <div class="tw"><table><thead><tr>
    <th>Status</th>
    <th>Device ID</th>
    <th>Nickname</th>
    <th>Sessions</th>
    <th>Tokens</th>
    <th>Cost</th>
    <th>Last Seen</th>
    <th>Actions</th>
  </tr></thead><tbody id="dtb"></tbody></table></div>
</div>
<footer>OpenCode Analytics Dashboard</footer>
</div>
<script>
var D={},cur="models",ari=true,ri=null,aK={k:"email",d:1},sK={k:"updated",d:-1},_di=false;
var DCOLORS=["#58a6ff","#3fb950","#d29922","#f85149","#bc8cff","#56d4dd","#f0883e","#db61a2"];
function bc(p){return p>=60?"var(--green)":p>=20?"var(--yellow)":"var(--red)"}
function fp(f){return f==null?"--":(f*100).toFixed(0)+"%"}
function ft(n){return!n?"0":n>=1e6?(n/1e6).toFixed(1)+"M":n>=1e3?(n/1e3).toFixed(1)+"K":""+n}
function fc(c){return!c?"$0.00":c<.01?"$"+c.toFixed(4):"$"+c.toFixed(2)}
function ta(t){if(!t)return"--";var d=Date.now()-t;return d<6e4?"now":d<36e5?Math.floor(d/6e4)+"m ago":d<864e5?Math.floor(d/36e5)+"h ago":Math.floor(d/864e5)+"d ago"}
function tu(t){if(!t)return"--";var d=t-Date.now();return d<=0?"now":d<36e5?Math.ceil(d/6e4)+"m":d<864e5?Math.ceil(d/36e5)+"h":Math.ceil(d/864e5)+"d"}
function x(s){return s?s.replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;"):""}
function ds(t){if(!t)return"off";var a=Date.now()-t;return a<12e4?"on":a<6e5?"stale":"off"}
function sk(s){return s?s.split(".").join("~").split("$").join("~").split("/").join("~").split("[").join("~").split("]").join("~").split("#").join("~"):""}
function dn(id){var n=D.nicknames||{};var k=sk(id);return(n[k]||n[id]||"")}
function dd(id,loc){var nick=dn(id);if(nick)return x(nick)+(loc?" (this)":"");return x(id)+(loc?" (this)":"")}

function go(t){cur=t;
  var tabs=["models","accounts","sessions","devices"];
  document.querySelectorAll(".tab").forEach(function(el,i){el.classList.toggle("on",tabs[i]===t)});
  tabs.forEach(function(p){
    var el=document.getElementById("p-"+p);
    if(el) el.style.display=p===t?"":"none";
  });
}

function rD(){
  var h="";var devs=D.devices||[];
  for(var i=0;i<devs.length;i++){var d=devs[i];var s=ds(d.updatedAt);var c=d.isLocal?" local":"";
    h+='<div class="chip'+c+'"><span class="ddot '+s+'"></span>'+dd(d.device,d.isLocal)
    +' <span style="color:var(--muted)">'+d.sessionCount+' sess &middot; '+ta(d.updatedAt)+'</span></div>'}
  document.getElementById("devs").innerHTML=h;
  var sb=document.getElementById("sync");
  if(devs.length>1){sb.className="sync-badge y";sb.textContent=devs.length+" devices synced"}
  else{sb.className="sync-badge n";sb.textContent=D.firebaseConnected?"syncing":"local only"}
  var sels=["df","gd","md"];
  for(var si=0;si<sels.length;si++){var selId=sels[si];var sel=document.getElementById(selId);if(!sel)continue;var pv=sel.value;
    sel.innerHTML='<option value="all">All devices</option>';
    for(var i=0;i<devs.length;i++){var d=devs[i];sel.innerHTML+='<option value="'+x(d.device)+'">'+dd(d.device,d.isLocal)+'</option>'}
    if(!_di&&D.localDevice){sel.value=D.localDevice}else{sel.value=pv||"all"}}
_di=true;}


function rQ(){
  var accs=D.accounts||[];
  var total=accs.length;
  var qStats={};
  var qNames=["gemini-pro","gemini-flash","claude"];
  for(var qi=0;qi<qNames.length;qi++){qStats[qNames[qi]]={total:total,avail:total,exhausted:0,nextReset:null,modelCount:0}}
  for(var i=0;i<accs.length;i++){
    var a=accs[i];
    var rl=a.rateLimits||{};
    var limited={};
    var rlKeys=Object.keys(rl);
    for(var ri=0;ri<rlKeys.length;ri++){
      var rk=rlKeys[ri];var r=rl[rk];
      if(r.isLimited){
        if(rk==="claude")limited["claude"]=r.resetTime;
        else if(rk.indexOf("flash")!==-1)limited["gemini-flash"]=r.resetTime;
        else if(rk.indexOf("gemini")!==-1)limited["gemini-pro"]=r.resetTime;
      }
    }
    for(var qi=0;qi<qNames.length;qi++){
      var k=qNames[qi];
      if(limited[k]){
        qStats[k].avail--;
        qStats[k].exhausted++;
        var rt=limited[k];
        if(rt&&(!qStats[k].nextReset||rt<qStats[k].nextReset)){
          qStats[k].nextReset=rt;
        }
      }
    }
    var qs=a.quotas||{};
    for(var qi=0;qi<qNames.length;qi++){
      var q=qs[qNames[qi]];
      if(q&&q.modelCount&&!qStats[qNames[qi]].modelCount)qStats[qNames[qi]].modelCount=q.modelCount;
    }
  }
  var h="";
  for(var i=0;i<qNames.length;i++){
    var k=qNames[i];
    var st=qStats[k];
    if(!st)continue;
    var pct=st.total>0?(st.avail/st.total)*100:0;
    var c=bc(pct);
    var sc=st.avail>0?"var(--green)":"var(--red)";
    var ns="";
    if(st.avail===st.total)ns="All available";
    else if(st.nextReset)ns="Next in "+tu(st.nextReset);
    else ns="None available";
    h+='<div class="sum-card">';
    h+='<h3><span class="quota-status" style="background:'+sc+'"></span>'+x(k)+'</h3>';
    h+='<div class="q-avail">'+st.avail+' / '+st.total+' available</div>';
    h+='<div class="qbar" style="margin-bottom:8px"><div class="qbar-f" style="width:'+Math.max(pct,1)+'%;background:'+c+'"></div></div>';
    h+='<div class="sub"><span>'+ns+'</span><span>'+st.modelCount+' models</span></div>';
    h+='</div>';
  }
  var el=document.getElementById("quotas");
  if(el)el.innerHTML=h;
}

function rSummary(){
  var gd=document.getElementById("gd").value;
  var days=parseInt(document.getElementById("gf").value)||9999;
  var now=Date.now();
  var cutoff=days===9999?0:now-(days*86400000);
  var src={};
  if(gd==="all"){src=D.costByDay||{}}else{
    var devs=D.devices||[];
    for(var di=0;di<devs.length;di++){if(devs[di].device===gd&&devs[di].costByDay){src=devs[di].costByDay;break;}}
  }
  var tC=0,tTok=0,tIn=0,tOut=0,tReason=0,tMsg=0;
  var dkeys=Object.keys(src);
  for(var di=0;di<dkeys.length;di++){
    var dk=dkeys[di];
    var parts=dk.split("-");
    var dTs=new Date(parseInt(parts[0]),parseInt(parts[1])-1,parseInt(parts[2])).getTime();
    if(cutoff&&dTs<cutoff)continue;
    tC+=src[dk].cost||0;
    tTok+=src[dk].tokens||0;
    tIn+=src[dk].tokens_in||0;
    tOut+=src[dk].tokens_out||0;
    tReason+=src[dk].tokens_reason||0;
    tMsg+=src[dk].msgs||0;
  }
  var ss=D.sessions||[];
  var sCount=0;var modelSet={};
  for(var i=0;i<ss.length;i++){
    var s=ss[i];
    if(gd!=="all"&&(s.onDevices||[]).indexOf(gd)===-1&&s.device!==gd)continue;
    if(cutoff&&s.updated&&s.updated<cutoff)continue;
    sCount++;
    var mu=s.modelUsage||{};
    for(var mid in mu){if(mu[mid].count>0)modelSet[mid]=true;}
  }
  var mc=Object.keys(modelSet).length;
  var h='<div class="sum-card c1"><h3>Total Cost</h3><div class="val cost">'+fc(tC)+'</div><div class="sub"><span>'+tMsg+' messages</span><span>'+mc+' models</span></div></div>';
  var tokSub='<span>'+tMsg+' messages</span>';
  if(tIn>0||tOut>0){tokSub='<span>In: '+ft(tIn)+'</span><span>Out: '+ft(tOut)+'</span>'+(tReason?'<span>Think: '+ft(tReason)+'</span>':'')+'<span>'+tMsg+' msgs</span>';}
  h+='<div class="sum-card c2"><h3>Total Tokens</h3><div class="val">'+ft(tTok)+'</div><div class="sub">'+tokSub+'</div></div>';
  h+='<div class="sum-card c3"><h3>Total Sessions</h3><div class="val">'+sCount+'</div><div class="sub"><span>'+mc+' models used</span></div></div>';
  document.getElementById("summary").innerHTML=h;
  document.getElementById("info").textContent=mc+" models, "+fc(tC)+" total, "+ft(tTok)+" tokens"}

function rM(){
  var mdVal=document.getElementById("md").value;
  var m;
  if(mdVal==="all"){
    m=D.models||{};
  }else{
    m={};
    var ss=D.sessions||[];
    for(var i=0;i<ss.length;i++){
      var s=ss[i];
      if((s.onDevices||[]).indexOf(mdVal)===-1&&s.device!==mdVal)continue;
      var mu=s.modelUsage||{};
      var muKeys=Object.keys(mu);
      for(var j=0;j<muKeys.length;j++){
        var mid=muKeys[j];var u=mu[mid];
        if(!m[mid])m[mid]={cost:0,tokens:{input:0,output:0,reasoning:0},provider:u.provider||"",sessionCount:0,msgCount:0};
        m[mid].cost+=u.cost||0;
        m[mid].tokens.input+=(u.tokens&&u.tokens.input)||0;
        m[mid].tokens.output+=(u.tokens&&u.tokens.output)||0;
        m[mid].tokens.reasoning+=(u.tokens&&u.tokens.reasoning)||0;
        m[mid].sessionCount+=1;
        m[mid].msgCount+=u.count||0;
      }
    }
  }
  var keys=Object.keys(m).filter(function(k){return m[k].msgCount>0});
  var ms=document.getElementById("mf").value;
  keys.sort(function(a,b){
    if(ms==="tokens"){var ta=(m[a].tokens.input||0)+(m[a].tokens.output||0)+(m[a].tokens.reasoning||0),tb=(m[b].tokens.input||0)+(m[b].tokens.output||0)+(m[b].tokens.reasoning||0);return tb-ta||m[b].cost-m[a].cost}
    if(ms==="msgs")return(m[b].msgCount-m[a].msgCount)||(m[b].cost-m[a].cost);
    if(ms==="name")return a<b?-1:a>b?1:0;
    return(m[b].cost-m[a].cost)||(m[b].msgCount-m[a].msgCount)});
  var tC=0,tI=0,tO=0,tR=0,tMsg=0;
  for(var i=0;i<keys.length;i++){var u=m[keys[i]];tC+=u.cost;tI+=u.tokens.input;tO+=u.tokens.output;tR+=u.tokens.reasoning;tMsg+=u.msgCount}
  var totalTok=tI+tO+tR;
  var h="";
  for(var i=0;i<keys.length;i++){var k=keys[i],u=m[k];
    var pct=0;
    if(ms==="tokens")pct=totalTok>0?(((u.tokens.input||0)+(u.tokens.output||0)+(u.tokens.reasoning||0))/totalTok*100):0;
    else if(ms==="msgs")pct=tMsg>0?((u.msgCount/tMsg)*100):0;
    else pct=tC>0?((u.cost/tC)*100):0;
    var uTok=(u.tokens.input||0)+(u.tokens.output||0)+(u.tokens.reasoning||0);
    var bigVal,bigCls,subLine;
    if(ms==="tokens"){bigVal=ft(uTok);bigCls="";subLine='<span>'+fc(u.cost)+'</span><span>'+u.msgCount+' msgs</span><span>'+u.sessionCount+' sess</span>';}
    else if(ms==="msgs"){bigVal=u.msgCount+' msgs';bigCls="";subLine='<span>'+fc(u.cost)+'</span><span>'+ft(uTok)+' tokens</span><span>'+u.sessionCount+' sess</span>';}
    else{bigVal=fc(u.cost);bigCls=" cost";subLine='<span>'+ft(uTok)+' tokens</span><span>'+u.msgCount+' msgs</span><span>'+u.sessionCount+' sess</span>';}
    h+='<div class="card"><h3>'+x(k)+'</h3><div class="val'+bigCls+'">'+bigVal+'</div>';
    h+='<div class="bar-t"><div class="bar-f" style="width:'+Math.max(pct,1)+'%;background:var(--blue)"></div></div>';
    h+='<div class="sub">'+subLine+'<span>'+x(u.provider)+'</span></div>';
    h+='<div class="sub" style="margin-top:4px"><span>In: '+ft(u.tokens.input)+'</span><span>Out: '+ft(u.tokens.output)+'</span>'+(u.tokens.reasoning?'<span>Think: '+ft(u.tokens.reasoning)+'</span>':'')+'</div></div>'}
  document.getElementById("mcards").innerHTML=h||'<div class="empty">No model usage found</div>';
  document.getElementById("msub").textContent="("+keys.length+" models)"}

function minQuota(a){
  var qs=a.quotas||{},keys=Object.keys(qs),min=null;
  for(var i=0;i<keys.length;i++){var r=qs[keys[i]].remaining;if(min===null||r<min)min=r}
  return min}

function creditsCell(a){
  var qs=a.quotas||{},keys=Object.keys(qs);
  if(!keys.length)return'<td><span style="color:var(--muted)">--</span></td>';
  var parts=[];
  for(var i=0;i<keys.length;i++){var k=keys[i],q=qs[k],p=(q.remaining*100).toFixed(0),c=bc(q.remaining*100);
    parts.push('<div style="display:flex;align-items:center;gap:5px;margin-bottom:2px"><span style="font-size:10px;color:var(--dim);min-width:72px">'+x(k)+'</span><div class="qbar"><div class="qbar-f" style="width:'+p+'%;background:'+c+'"></div></div><span class="qpct" style="color:'+c+'">'+p+'%</span></div>')}
  return'<td style="min-width:200px">'+parts.join("")+'</td>'}

function isRL(a){var now=Date.now();var rl=a.rateLimits||{};
  for(var k in rl){if(rl[k].isLimited&&rl[k].resetTime>now)return true}return false}

function rlInfo(a){var now=Date.now(),parts=[];var rl=a.rateLimits||{};
  for(var k in rl){var r=rl[k];if(r.isLimited&&r.resetTime>now){var nm=k.replace(/^.*:/,"");parts.push(x(nm)+" ("+tu(r.resetTime)+")")}}
  if(!parts.length)return'<td><span class="lim-n">No</span></td>';
  return'<td><span class="lim-y">Yes</span><br><span style="font-size:10px;color:var(--dim)">'+parts.join(", ")+'</span></td>'}

function rA(){
  var accs=D.accounts||[],f=(document.getElementById("af").value||"").toLowerCase();
  if(f)accs=accs.filter(function(a){return a.email.toLowerCase().indexOf(f)!==-1});
  var sk=aK.k,sd=aK.d;
  accs=accs.slice().sort(function(a,b){
    if(sk==="email")return a.email<b.email?-sd:a.email>b.email?sd:0;
    if(sk==="enabled")return((a.enabled?1:0)-(b.enabled?1:0))*sd;
    if(sk==="lastUsed")return((a.lastUsed||0)-(b.lastUsed||0))*sd;
    if(sk==="rateLimited"){return((isRL(a)?1:0)-(isRL(b)?1:0))*sd}
    if(sk==="credits"){var av=minQuota(a),bv=minQuota(b);return((av===null?-2:av)-(bv===null?-2:bv))*sd}
    return 0});
  var h="";
  for(var i=0;i<accs.length;i++){var a=accs[i];
    h+='<tr class="'+(a.enabled?"":"dis")+'">';
    var provTag=a.provider&&a.provider!=="antigravity"?'<span class="badge prov">'+x(a.provider)+'</span>':"";
    h+='<td>'+x(a.email)+provTag+'</td>';
    h+='<td>'+(a.enabled?'<span style="color:var(--green)">Active</span>':'<span style="color:var(--muted)">Disabled</span>')+'</td>';
    h+=creditsCell(a);
    h+=rlInfo(a);
    h+='<td style="color:var(--dim)">'+ta(a.lastUsed)+'</td>';
    h+='<td><button class="btn-sm '+(a.enabled?'danger':'success')+'" onclick="toggleAccount(\\''+x(a.email)+'\\', \\''+x(a.provider)+'\\')">'+(a.enabled?'Disable':'Enable')+'</button></td></tr>'}
  document.getElementById("atb").innerHTML=h||'<tr><td colspan="6" class="empty">No accounts</td></tr>';
  document.getElementById("asub").textContent="("+accs.length+" accounts)"}

async function toggleAccount(email, provider) {
  try {
    var res = await fetch("/api/account/toggle", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email: email, provider: provider })
    });
    if (res.ok) load();
  } catch (e) {}
}

async function toggleAllAccounts(enabled) {
  try {
    var res = await fetch("/api/account/toggle-all", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ enabled: enabled })
    });
    if (res.ok) load();
  } catch (e) {}
}

function rS(){
  var ss=D.sessions||[],df=document.getElementById("df").value;
  if(df!=="all")ss=ss.filter(function(s){return(s.onDevices||[]).indexOf(df)!==-1||s.device===df});
  var sk=sK.k,sd=sK.d;
  ss=ss.slice().sort(function(a,b){
    if(sk==="title")return(a.title||"")<(b.title||"")?-sd:(a.title||"")>(b.title||"")?sd:0;
    if(sk==="device")return(a.device||"")<(b.device||"")?-sd:(a.device||"")>(b.device||"")?sd:0;
    if(sk==="cost")return((a.cost||0)-(b.cost||0))*sd;
    if(sk==="tokens")return(((a.tokens?.input||0)+(a.tokens?.output||0))-((b.tokens?.input||0)+(b.tokens?.output||0)))*sd;
    return((a.updated||0)-(b.updated||0))*sd});
  var tC=0,tI=0,tO=0,tR2=0;
  for(var i=0;i<ss.length;i++){var z=ss[i];tC+=z.cost||0;tI+=(z.tokens&&z.tokens.input)||0;tO+=(z.tokens&&z.tokens.output)||0;tR2+=(z.tokens&&z.tokens.reasoning)||0}
  var h="";
  for(var i=0;i<ss.length;i++){var s=ss[i];
    var tt=(s.tokens?.input||0)+(s.tokens?.output||0)+(s.tokens?.reasoning||0);
    var mods=Object.keys(s.modelUsage||{}).filter(function(k){return(s.modelUsage[k].count||0)>0});
    h+='<tr><td style="max-width:280px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">'+x(s.title);
    if(mods.length)h+='<br>'+mods.map(function(m){return'<span class="badge">'+x(m)+'</span>'}).join(" ");
    h+='</td>';
    h+='<td>';var devs=s.onDevices||[s.device||D.localDevice||""];for(var di=0;di<devs.length;di++){var isLoc=devs[di]===D.localDevice;h+='<span class="badge'+(isLoc?" local":"")+'">'+dd(devs[di],false)+(isLoc?" âœ¦":"")+'</span> '}h+='</td>';
    h+='<td class="cost">'+fc(s.cost)+'</td><td>';
    if(tt>0){h+='<span class="pill">In:'+ft(s.tokens.input)+'</span><span class="pill">Out:'+ft(s.tokens.output)+'</span>';
      if(s.tokens.reasoning>0)h+='<span class="pill">Think:'+ft(s.tokens.reasoning)+'</span>'}
    else h+='<span style="color:var(--muted)">--</span>';
    h+='</td><td style="color:var(--dim)">'+ta(s.updated)+'</td></tr>'}
  if(ss.length){
    h+='<tr class="totals"><td>Total ('+ss.length+')</td><td></td>';
    h+='<td class="cost">'+fc(tC)+'</td><td>';
    h+='<span class="pill">In:'+ft(tI)+'</span><span class="pill">Out:'+ft(tO)+'</span>';
    if(tR2)h+='<span class="pill">Think:'+ft(tR2)+'</span>';
    h+='</td><td></td></tr>'}
  document.getElementById("stb").innerHTML=h||'<tr><td colspan="5" class="empty">No sessions</td></tr>';
  document.getElementById("ssub").textContent="("+ss.length+" sessions)"}

function sA(k){if(aK.k===k)aK.d*=-1;else{aK.k=k;aK.d=k==="email"?1:-1}rA()}
function sS(k){if(sK.k===k)sK.d*=-1;else{sK.k=k;sK.d=k==="title"||k==="device"?1:-1}rS()}

function toggleAR(){ari=!ari;document.getElementById("ar").classList.toggle("on",ari);
  var d=document.getElementById("dot");d.style.background=ari?"var(--green)":"var(--muted)";d.style.animation=ari?"pulse 2s infinite":"none";
  ari?startAR():stopAR()}
function startAR(){stopAR();ri=setInterval(load,30000)}
function stopAR(){if(ri){clearInterval(ri);ri=null}}

function rG(){
  var gd=document.getElementById("gd").value;
  var days=parseInt(document.getElementById("gf").value)||9999;
  var metric=document.getElementById("gm").value;
  var now=Date.now();
  var cutoff=days===9999?0:now-(days*86400000);
  var container=document.getElementById("graph-container");
  var tip=document.getElementById("graph-tip");
  var legendEl=document.getElementById("graph-legend");

  var allDatesMap={};
  var aggSrc=D.costByDay||{};
  var aggKeys=Object.keys(aggSrc);
  for(var i=0;i<aggKeys.length;i++){
    var dk=aggKeys[i];var pts=dk.split("-");
    var dTs=new Date(parseInt(pts[0]),parseInt(pts[1])-1,parseInt(pts[2])).getTime();
    if(cutoff&&dTs<cutoff)continue;
    allDatesMap[dk]=true;
  }
  var devs=D.devices||[];
  for(var di=0;di<devs.length;di++){
    var dcbd=devs[di].costByDay||{};
    var dcKeys=Object.keys(dcbd);
    for(var ci=0;ci<dcKeys.length;ci++){
      var dk=dcKeys[ci];var pts=dk.split("-");
      var dTs=new Date(parseInt(pts[0]),parseInt(pts[1])-1,parseInt(pts[2])).getTime();
      if(cutoff&&dTs<cutoff)continue;
      allDatesMap[dk]=true;
    }
  }
  var sortedDates=Object.keys(allDatesMap).sort();

  if(!sortedDates.length){
    container.innerHTML='<div class="empty-graph">No data for this period</div>';
    if(legendEl)legendEl.innerHTML="";
    return;
  }

  var series=[];
  if(gd==="all"){
    var aggData=[];
    for(var i=0;i<sortedDates.length;i++){
      var dk=sortedDates[i];var e=aggSrc[dk]||{};
      aggData.push({d:dk,v:e[metric]||0});
    }
    series.push({name:"All Devices",data:aggData,color:"#e6edf3",thick:true});
    for(var di=0;di<devs.length;di++){
      var dev=devs[di];var dcbd=dev.costByDay||{};
      var devData=[];var hasData=false;
      for(var i=0;i<sortedDates.length;i++){
        var dk=sortedDates[i];var e=dcbd[dk]||{};var val=e[metric]||0;
        if(val>0)hasData=true;
        devData.push({d:dk,v:val});
      }
      if(hasData){
        var rawName=dn(dev.device)||dev.device;
        var dName=rawName+(dev.isLocal?" (this)":"");
        series.push({name:dName,data:devData,color:DCOLORS[di%DCOLORS.length],thick:false});
      }
    }
  }else{
    var devCbd={};
    for(var di=0;di<devs.length;di++){
      if(devs[di].device===gd){devCbd=devs[di].costByDay||{};break;}
    }
    var devData=[];
    for(var i=0;i<sortedDates.length;i++){
      var dk=sortedDates[i];var e=devCbd[dk]||{};
      devData.push({d:dk,v:e[metric]||0});
    }
    var rawName=dn(gd)||gd;
    series.push({name:rawName,data:devData,color:DCOLORS[0],thick:true});
  }

  var max=0;
  for(var si=0;si<series.length;si++){
    for(var i=0;i<series[si].data.length;i++){
      if(series[si].data[i].v>max)max=series[si].data[i].v;
    }
  }
  if(max===0)max=1;

  var w=container.offsetWidth||800;
  var h=240;
  var padL=58,padR=16,padT=16,padB=28;
  var plotW=w-padL-padR;
  var plotH=h-padT-padB;

  var svg='<svg width="'+w+'" height="'+h+'" xmlns="http://www.w3.org/2000/svg" style="font-family:-apple-system,BlinkMacSystemFont,sans-serif;display:block">';

  var ySteps=[0,0.25,0.5,0.75,1.0];
  for(var yi=0;yi<ySteps.length;yi++){
    var yPx=padT+plotH-(ySteps[yi]*plotH);
    var yVal=max*ySteps[yi];
    var yLabel=metric==="tokens"?ft(yVal):metric==="cost"?fc(yVal):Math.round(yVal);
    svg+='<line x1="'+padL+'" y1="'+yPx+'" x2="'+(w-padR)+'" y2="'+yPx+'" stroke="#30363d" stroke-dasharray="'+(ySteps[yi]===0?"0":"3,3")+'"/>';
    svg+='<text x="'+(padL-10)+'" y="'+(yPx+4)+'" text-anchor="end" fill="#8b949e" font-size="10">'+yLabel+'</text>';
  }

  var maxLabels=12;
  var labelStep=Math.max(1,Math.ceil(sortedDates.length/maxLabels));
  for(var i=0;i<sortedDates.length;i+=labelStep){
    var xPx=padL+(sortedDates.length>1?(i/(sortedDates.length-1))*plotW:plotW/2);
    var shortDate=sortedDates[i].substring(5);
    svg+='<text x="'+xPx+'" y="'+(h-4)+'" text-anchor="middle" fill="#8b949e" font-size="10">'+shortDate+'</text>';
  }

  var drawOrder=[];
  for(var si=0;si<series.length;si++){drawOrder.push(series[si])}
  drawOrder.sort(function(a,b){return(a.thick?1:0)-(b.thick?1:0)});

  for(var si=0;si<drawOrder.length;si++){
    var s=drawOrder[si];
    var points=[];
    for(var i=0;i<s.data.length;i++){
      var xPx=padL+(s.data.length>1?(i/(s.data.length-1))*plotW:plotW/2);
      var yPx=padT+plotH-((s.data[i].v/max)*plotH);
      points.push({x:xPx,y:yPx});
    }

    if(s.thick&&points.length>1){
      var polyPts="";
      for(var pi=0;pi<points.length;pi++){polyPts+=(pi>0?" ":"")+points[pi].x.toFixed(1)+","+points[pi].y.toFixed(1)}
      var bY=padT+plotH;
      svg+='<polygon points="'+points[0].x.toFixed(1)+','+bY+' '+polyPts+' '+points[points.length-1].x.toFixed(1)+','+bY+'" fill="'+s.color+'" fill-opacity="0.05"/>';
    }

    if(points.length>1){
      var linePts="";
      for(var pi=0;pi<points.length;pi++){linePts+=(pi>0?" ":"")+points[pi].x.toFixed(1)+","+points[pi].y.toFixed(1)}
      var sw=s.thick?"2.5":"1.5";
      var op=s.thick?"0.9":"0.5";
      svg+='<polyline points="'+linePts+'" fill="none" stroke="'+s.color+'" stroke-width="'+sw+'" stroke-opacity="'+op+'" stroke-linejoin="round" stroke-linecap="round"/>';
    }

    if(s.data.length<=90){
      for(var i=0;i<s.data.length;i++){
        var px=points[i].x.toFixed(1);
        var py=points[i].y.toFixed(1);
        var r=s.thick?"2.5":"1.5";
        var dop=s.thick?"0.9":"0.5";
        svg+='<circle cx="'+px+'" cy="'+py+'" r="'+r+'" fill="'+s.color+'" fill-opacity="'+dop+'" style="pointer-events:none" data-si="'+si+'" data-di="'+i+'"/>';
      }
    }
  }

  svg+='<line id="gcross" x1="0" y1="'+padT+'" x2="0" y2="'+(padT+plotH)+'" stroke="#e6edf3" stroke-opacity="0.2" stroke-width="1" style="display:none;pointer-events:none"/>';
  svg+='<rect x="'+padL+'" y="'+padT+'" width="'+plotW+'" height="'+plotH+'" fill="transparent" id="ghover" style="cursor:crosshair"/>';
  svg+='</svg>';
  container.innerHTML=svg;

  var _gXs=[];
  if(sortedDates.length>0){
    for(var gi=0;gi<sortedDates.length;gi++){
      _gXs.push(padL+(sortedDates.length>1?(gi/(sortedDates.length-1))*plotW:plotW/2));
    }
  }
  window._gSeries=series;
  window._gDates=sortedDates;
  window._gXs=_gXs;
  window._gMetric=metric;
  window._gPadT=padT;
  window._gPlotH=plotH;

  var hoverRect=document.getElementById("ghover");
  var crossLine=document.getElementById("gcross");

  if(hoverRect){
    hoverRect.onmousemove=function(e){
      var rect=container.getBoundingClientRect();
      var mx=e.clientX-rect.left;
      var bestIdx=0;var bestDist=9999;
      for(var gi=0;gi<_gXs.length;gi++){
        var dist=Math.abs(_gXs[gi]-mx);
        if(dist<bestDist){bestDist=dist;bestIdx=gi;}
      }
      if(crossLine){crossLine.setAttribute("x1",_gXs[bestIdx]);crossLine.setAttribute("x2",_gXs[bestIdx]);crossLine.style.display="";}
      var allCircles=container.querySelectorAll("circle[data-si]");
      for(var ci=0;ci<allCircles.length;ci++){
        var cdi=parseInt(allCircles[ci].getAttribute("data-di"));
        if(cdi===bestIdx){allCircles[ci].setAttribute("r","5");}
        else{var csi=parseInt(allCircles[ci].getAttribute("data-si"));var origR=(window._gSeries[csi]&&window._gSeries[csi].thick)?"2.5":"1.5";allCircles[ci].setAttribute("r",origR);}
      }
      if(tip){
        var date=window._gDates[bestIdx]||"";
        var lines='<div style="font-weight:600;margin-bottom:4px;color:var(--text)">'+date+'</div>';
        for(var si=0;si<window._gSeries.length;si++){
          var sv=window._gSeries[si];
          var val=sv.data[bestIdx]?sv.data[bestIdx].v:0;
          var fmtVal=window._gMetric==="tokens"?ft(val):window._gMetric==="cost"?fc(val):val;
          var weight=sv.thick?"600":"400";
          var op=sv.thick?"1":"0.8";
          lines+='<div style="display:flex;align-items:center;gap:6px;padding:1px 0;font-weight:'+weight+';opacity:'+op+'"><span style="width:8px;height:8px;border-radius:2px;background:'+sv.color+';display:inline-block;flex-shrink:0"></span><span style="flex:1">'+x(sv.name)+'</span><span style="font-variant-numeric:tabular-nums;margin-left:12px">'+fmtVal+'</span></div>';
        }
        tip.innerHTML=lines;
        tip.style.display="block";
        var tx=_gXs[bestIdx]-rect.left+rect.left-container.getBoundingClientRect().left+14;
        var ty=e.clientY-container.getBoundingClientRect().top-20;
        var tipW=tip.offsetWidth||180;
        if(tx+tipW>container.offsetWidth)tx=_gXs[bestIdx]-container.getBoundingClientRect().left-tipW-14;
        if(ty<0)ty=10;
        tip.style.left=tx+"px";
        tip.style.top=ty+"px";
      }
    };
    hoverRect.onmouseleave=function(){
      if(crossLine)crossLine.style.display="none";
      if(tip)tip.style.display="none";
      var allCircles=container.querySelectorAll("circle[data-si]");
      for(var ci=0;ci<allCircles.length;ci++){var csi=parseInt(allCircles[ci].getAttribute("data-si"));var origR=(window._gSeries[csi]&&window._gSeries[csi].thick)?"2.5":"1.5";allCircles[ci].setAttribute("r",origR);}
    };
  }
  container.onmouseleave=function(){if(tip)tip.style.display="none";if(crossLine)crossLine.style.display="none"};

  if(legendEl){
    if(series.length>1){
      var lh="";
      for(var si=0;si<series.length;si++){
        var s=series[si];
        var lop=s.thick?"1":"0.7";
        lh+='<span class="legend-item" style="opacity:'+lop+'"><span class="legend-dot" style="background:'+s.color+'"></span>'+x(s.name)+'</span>';
      }
      legendEl.innerHTML=lh;
    }else{
      legendEl.innerHTML="";
    }
  }
}

function rDevTab(){
  var devs=D.devices||[];var nicks=D.nicknames||{};var h="";
  window._devIds=[];
  for(var i=0;i<devs.length;i++){var d=devs[i];var s=ds(d.updatedAt);
    window._devIds.push(d.device);
    var safeId=sk(d.device);
    var nick=nicks[safeId]||nicks[d.device]||"";
    h+='<tr><td><span class="ddot '+s+'" style="margin-right:6px"></span>'+(s==="on"?'<span style="color:var(--green)">Online</span>':s==="stale"?'<span style="color:var(--yellow)">Stale</span>':'<span style="color:var(--muted)">Offline</span>')+'</td>';
    h+='<td style="font-family:monospace;font-size:12px">'+x(d.device)+(d.isLocal?' <span class="badge local">this</span>':'')+'</td>';
    h+='<td id="nick-cell-'+i+'">';
    if(nick){h+='<span class="dev-nick" onclick="editNick('+i+')">'+x(nick)+'</span>';}
    else{h+='<button class="btn-sm" onclick="editNick('+i+')">Set nickname</button>';}
    h+='</td>';
    h+='<td>'+d.sessionCount+'</td>';
    h+='<td>'+ft(d.totalTokens||0)+'</td>';
    h+='<td class="cost">'+fc(d.totalCost||0)+'</td>';
    h+='<td style="color:var(--dim)">'+ta(d.updatedAt)+'</td>';
    h+='<td>';
    if(!d.isLocal){h+='<button class="btn-sm danger" onclick="removeDev('+i+')">Remove</button>';}
    else{h+='<span style="color:var(--muted);font-size:11px">--</span>';}
    h+='</td></tr>';}
  document.getElementById("dtb").innerHTML=h||'<tr><td colspan="8" class="empty">No devices</td></tr>';
  document.getElementById("dsub").textContent="("+devs.length+" devices)";
}

var editingNickIdx=-1;
function editNick(idx){
  editingNickIdx=idx;
  var deviceId=window._devIds[idx];if(!deviceId)return;
  var cell=document.getElementById("nick-cell-"+idx);if(!cell)return;
  var safeId=sk(deviceId);
  var nicks=D.nicknames||{};var cur=nicks[safeId]||nicks[deviceId]||"";
  cell.innerHTML='<input class="nick-input" id="nick-inp-'+idx+'" value="'+x(cur)+'" onkeydown="nickKey(event)" placeholder="Enter nickname...">'
    +' <button class="btn-sm" onclick="saveNick()">Save</button>'
    +' <button class="btn-sm" onclick="rDevTab()">Cancel</button>';
  var inp=document.getElementById("nick-inp-"+idx);if(inp)inp.focus();
}

function nickKey(e){if(e.key==="Enter"){e.preventDefault();saveNick();}if(e.key==="Escape"){rDevTab();}}

function saveNick(){
  var deviceId=window._devIds[editingNickIdx];if(!deviceId)return;
  var inp=document.getElementById("nick-inp-"+editingNickIdx);if(!inp)return;
  var val=inp.value.trim();
  fetch("/api/nickname",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({device:deviceId,nickname:val})})
    .then(function(r){return r.json()}).then(function(res){if(res.ok){load();}else{rDevTab();}}).catch(function(){rDevTab();});
}

function removeDev(idx){
  var deviceId=window._devIds[idx];if(!deviceId)return;
  if(!confirm("Remove device "+deviceId+"? This deletes its synced data from Firebase."))return;
  fetch("/api/device/remove",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({device:deviceId})})
    .then(function(r){return r.json()}).then(function(res){if(res.ok){load();}}).catch(function(){});
}

function load(){
  fetch("/api/data").then(function(r){return r.json()}).then(function(d){
    D=d;rD();rSummary();rQ();rM();rA();rS();rG();rDevTab();
    document.getElementById("when").textContent="Updated "+new Date().toLocaleTimeString();
  }).catch(function(err){})}

var _resizeTimer;
window.onresize=function(){clearTimeout(_resizeTimer);_resizeTimer=setTimeout(function(){rG()},200)};

load();startAR();
</script>
</body>
</html>`;

var OC_BASH = [
  '#!/usr/bin/env bash',
  '# oc - OpenCode project launcher (auto-installed by credit-dashboard plugin)',
  'set -e',
  'if [ "$1" = "remove" ]; then',
  '  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"',
  '  rm -f "$SCRIPT_DIR/oc" "$SCRIPT_DIR/oc-tui.js" "$SCRIPT_DIR/oc.cmd"',
  '  echo "oc launcher removed. Will be reinstalled on next opencode start if plugin is still active."',
  '  exit 0',
  'fi',
  'if [ $# -gt 0 ]; then exec opencode "$@"; fi',
  'SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"',
  'export OC_OUTPUT="${TEMP:-${TMPDIR:-/tmp}}/oc-dir-$$.txt"',
  'bun run "$SCRIPT_DIR/oc-tui.js"',
  'EXIT=$?',
  'if [ $EXIT -eq 0 ] && [ -f "$OC_OUTPUT" ]; then',
  '  DIR=$(cat "$OC_OUTPUT")',
  '  rm -f "$OC_OUTPUT"',
  '  if [ -n "$DIR" ]; then cd "$DIR" && exec opencode; fi',
  'fi',
  'rm -f "$OC_OUTPUT"',
  'exit $EXIT',
  ''
].join('\n');

var OC_CMD = [
  '@echo off',
  'if /i "%~1"=="remove" (',
  '  del "%~dp0oc-tui.js" 2>nul',
  '  del "%~dp0oc" 2>nul',
  '  echo oc launcher removed. Will be reinstalled on next opencode start if plugin is still active.',
  '  del "%~dp0oc.cmd" 2>nul & exit /b 0',
  ')',
  'if not "%~1"=="" (opencode %* & exit /b)',
  'setlocal',
  'set "SCRIPT_DIR=%~dp0"',
  'set "OC_OUTPUT=%TEMP%\\oc-dir-%RANDOM%.txt"',
  'call bun run "%SCRIPT_DIR%oc-tui.js" %*',
  'if errorlevel 1 (',
  '  del "%OC_OUTPUT%" 2>nul',
  '  exit /b 1',
  ')',
  'if not exist "%OC_OUTPUT%" exit /b 1',
  'set /p OCDIR=<"%OC_OUTPUT%"',
  'del "%OC_OUTPUT%" 2>nul',
  'if not defined OCDIR exit /b 1',
  'endlocal & cd /d "%OCDIR%" & opencode',
  ''
].join('\r\n');

var PATH_LINE = 'export PATH="$HOME/.local/bin:$PATH"';
var PATH_MARKER = "# oc-launcher PATH";

async function installOcLauncher() {
  var home = homedir();
  var binDir = join(home, ".local", "bin");
  var tuiSrc = join(import.meta.dir, "..", "oc-tui.js");
  var tuiDst = join(binDir, "oc-tui.js");
  var bashPath = join(binDir, "oc");
  var isWin = process.platform === "win32";

  if (!existsSync(binDir)) mkdirSync(binDir, { recursive: true });

  if (existsSync(tuiSrc)) {
    writeFileSync(tuiDst, readFileSync(tuiSrc));
  }

  writeFileSync(bashPath, OC_BASH, { mode: 0o755 });
  try { chmodSync(bashPath, 0o755); } catch {}

  if (isWin) {
    var cmdPath = join(binDir, "oc.cmd");
    writeFileSync(cmdPath, OC_CMD);
  }

  var oldQuery = join(binDir, "oc-query.js");
  try { if (existsSync(oldQuery)) { var fs = require("fs"); fs.unlinkSync(oldQuery); } } catch {}

  if (!isWin) {
    var rcCandidates = [
      join(home, ".bashrc"),
      join(home, ".bash_profile"),
      join(home, ".profile"),
    ];
    var zshrc = join(home, ".zshrc");
    var zprofile = join(home, ".zprofile");
    if (process.platform === "darwin") {
      rcCandidates.push(zprofile);
      rcCandidates.push(zshrc);
    } else {
      if (existsSync(zshrc)) rcCandidates.push(zshrc);
      if (existsSync(zprofile)) rcCandidates.push(zprofile);
    }
    for (var rcFile of rcCandidates) {
      var content = "";
      if (existsSync(rcFile)) {
        content = readFileSync(rcFile, "utf-8");
        if (content.includes(".local/bin")) continue;
      } else {
        if (rcFile === zshrc || rcFile === zprofile) {
          if (process.platform !== "darwin") continue;
        } else {
          continue;
        }
      }
      var addition = "\n" + PATH_MARKER + "\n" + PATH_LINE + "\n";
      writeFileSync(rcFile, content + addition, "utf-8");
    }
  }

  if (isWin) {
    var winBinDir = join(home, ".local", "bin");
    var runtimePath = process.env.PATH || process.env.Path || "";
    if (!runtimePath.includes(winBinDir)) {
      try {
        var getProc = Bun.spawn(["powershell", "-NoProfile", "-Command", "[Environment]::GetEnvironmentVariable('Path', 'User')"], { stdin: "ignore", stdout: "pipe", stderr: "ignore" });
        var currentPath = (await new Response(getProc.stdout).text()).trim();
        await getProc.exited;
        if (currentPath && !currentPath.includes(winBinDir)) {
          var newPath = winBinDir + ";" + currentPath;
          var setProc = Bun.spawn(["powershell", "-NoProfile", "-Command", "[Environment]::SetEnvironmentVariable('Path', '" + newPath.replace(/'/g, "''") + "', 'User')"], { stdin: "ignore", stdout: "ignore", stderr: "ignore" });
          await setProc.exited;
        }
      } catch {}
    }
  }
}

async function uninstallOcLauncher() {
  var home = homedir();
  var binDir = join(home, ".local", "bin");
  var isWin = process.platform === "win32";
  var removed = [];

  var files = ["oc", "oc-tui.js"];
  if (isWin) files.push("oc.cmd");
  for (var f of files) {
    var p = join(binDir, f);
    try { if (existsSync(p)) { unlinkSync(p); removed.push(p); } } catch {}
  }

  var rcFiles = [
    join(home, ".bashrc"),
    join(home, ".bash_profile"),
    join(home, ".profile"),
    join(home, ".zshrc"),
    join(home, ".zprofile"),
  ];
  for (var rcFile of rcFiles) {
    if (!existsSync(rcFile)) continue;
    try {
      var content = readFileSync(rcFile, "utf-8");
      if (!content.includes(PATH_MARKER)) continue;
      var lines = content.split("\n");
      var out = [];
      var skip = false;
      for (var i = 0; i < lines.length; i++) {
        if (lines[i].trim() === PATH_MARKER) { skip = true; continue; }
        if (skip && lines[i].trim() === PATH_LINE) { skip = false; continue; }
        skip = false;
        out.push(lines[i]);
      }
      var cleaned = out.join("\n").replace(/\n{3,}$/g, "\n\n");
      writeFileSync(rcFile, cleaned, "utf-8");
      removed.push(rcFile + " (PATH entry)");
    } catch {}
  }

  if (isWin) {
    try {
      var winBinDir = join(home, ".local", "bin");
      var getProc = Bun.spawn(["powershell", "-NoProfile", "-Command", "[Environment]::GetEnvironmentVariable('Path', 'User')"], { stdin: "ignore", stdout: "pipe", stderr: "ignore" });
      var currentPath = (await new Response(getProc.stdout).text()).trim();
      await getProc.exited;
      if (currentPath && currentPath.includes(winBinDir)) {
        var parts = currentPath.split(";").filter(function(p) { return p !== winBinDir; });
        var newPath = parts.join(";");
        var setProc = Bun.spawn(["powershell", "-NoProfile", "-Command", "[Environment]::SetEnvironmentVariable('Path', '" + newPath.replace(/'/g, "''") + "', 'User')"], { stdin: "ignore", stdout: "ignore", stderr: "ignore" });
        await setProc.exited;
        removed.push("Windows PATH entry");
      }
    } catch {}
  }

  return removed;
}

async function isPortTaken() {
  try {
    var res = await fetch("http://127.0.0.1:" + PORT + "/", { signal: AbortSignal.timeout(500) });
    return res.ok;
  } catch { return false; }
}

async function startBackground() {
  fbConnected = !!loadServiceAccount();

  installOcLauncher().catch(function() {});

  await tryClaimServer();

  try { await pushToFirebase(getCachedSnapshot()); } catch {}

  setInterval(async () => {
    try { await pushToFirebase(getCachedSnapshot()); } catch {}
    if (!ownsServer) { await tryClaimServer(); }
  }, SYNC_INTERVAL_MS);

  setInterval(async () => {
    if (!ownsServer) { await tryClaimServer(); }
  }, 5000);
}

async function tryClaimServer() {
  var taken = await isPortTaken();
  if (!taken) {
    try {
      Bun.serve({
        port: PORT,
        hostname: "127.0.0.1",
        async fetch(req) {
          var url = new URL(req.url);
          if (url.pathname === "/" || url.pathname === "") {
            return new Response(HTML, { headers: { "Content-Type": "text/html; charset=utf-8" } });
          }
          if (url.pathname === "/api/data") {
            var localSnapshot = getCachedSnapshot();
            var remotes = await getRemoteSnapshots();
            var merged = mergeSnapshots(localSnapshot, remotes);
            merged.localDevice = DEVICE_ID;
            merged.firebaseConnected = fbConnected;
            merged.nicknames = await getNicknames();
            return Response.json(merged);
          }
          if (url.pathname === "/api/nickname" && req.method === "POST") {
            try {
              var body = await req.json();
              var ok = await setNicknameOnFirebase(body.device, body.nickname || "");
              return Response.json({ ok: ok });
            } catch { return Response.json({ ok: false }, { status: 400 }); }
          }
          if (url.pathname === "/api/device/remove" && req.method === "POST") {
            try {
              var body = await req.json();
              if (body.device === DEVICE_ID) return Response.json({ ok: false, error: "Cannot remove self" }, { status: 400 });
              var ok = await removeDeviceFromFirebase(body.device);
              return Response.json({ ok: ok });
            } catch { return Response.json({ ok: false }, { status: 400 }); }
          }
          if (url.pathname === "/api/account/toggle" && req.method === "POST") {
            try {
              var body = await req.json();
              var file = join(CONFIG_FOLDER, body.provider + "-accounts.json");
              if (!existsSync(file)) file = join(CONFIG_DIR, body.provider + "-accounts.json");
              if (existsSync(file)) {
                var raw = readJSON(file);
                if (raw && raw.accounts) {
                  var changed = false;
                  for (var i = 0; i < raw.accounts.length; i++) {
                    if ((raw.accounts[i].email || raw.accounts[i].username || raw.accounts[i].id || body.provider) === body.email) {
                      var currentEnabled = raw.accounts[i].enabled !== false;
                      raw.accounts[i].enabled = !currentEnabled;
                      if (raw.accounts[i].enabled === true) delete raw.accounts[i].enabled;
                      changed = true;
                      break;
                    }
                  }
                  if (changed) {
                    writeFileSync(file, JSON.stringify(raw, null, 2), "utf-8");
                    snapshotCache.data = null;
                    return Response.json({ ok: true });
                  }
                }
              }
              return Response.json({ ok: false, error: "Account not found" }, { status: 404 });
            } catch { return Response.json({ ok: false }, { status: 400 }); }
          }
          if (url.pathname === "/api/account/toggle-all" && req.method === "POST") {
            try {
              var body = await req.json();
              var files = ["antigravity-accounts.json", "cursor-accounts.json", "zen-accounts.json"];
              var changedAny = false;
              for (var file of files) {
                var p = join(CONFIG_FOLDER, file);
                if (!existsSync(p)) p = join(CONFIG_DIR, file);
                if (existsSync(p)) {
                  var raw = readJSON(p);
                  if (raw && raw.accounts) {
                    var changed = false;
                    for (var i = 0; i < raw.accounts.length; i++) {
                      var currentEnabled = raw.accounts[i].enabled !== false;
                      if (currentEnabled !== body.enabled) {
                        raw.accounts[i].enabled = body.enabled;
                        if (raw.accounts[i].enabled === true) delete raw.accounts[i].enabled;
                        changed = true;
                      }
                    }
                    if (changed) {
                      writeFileSync(p, JSON.stringify(raw, null, 2), "utf-8");
                      changedAny = true;
                    }
                  }
                }
              }
              if (changedAny) snapshotCache.data = null;
              return Response.json({ ok: true });
            } catch { return Response.json({ ok: false }, { status: 400 }); }
          }
          return new Response("Not found", { status: 404 });
        },
      });
      ownsServer = true;
    } catch (err) {
      var msg = String(err?.message || err?.code || err);
      if (!msg.includes("EADDRINUSE") && !msg.includes("address already in use")) {
      }
    }
  }
}

const creditDashboardPlugin = async (ctx) => {
  setTimeout(startBackground, 0);

  return {
    tool: {
      credit_dashboard: tool({
        description: "Get the URL of the credit usage dashboard. Shows account quotas and session costs across all synced devices.",
        args: {},
        async execute() {
          return "Credit usage dashboard: http://127.0.0.1:" + PORT;
        },
      }),
      oc_remove: tool({
        description: "Remove the oc launcher command. Deletes oc, oc.cmd, oc-tui.js from ~/.local/bin and removes PATH entries from shell rc files. The launcher will be reinstalled on next opencode start if the plugin is still active.",
        args: {},
        async execute() {
          var removed = await uninstallOcLauncher();
          if (!removed.length) return "Nothing to remove â€” oc launcher was not installed.";
          return "Removed oc launcher:\\n" + removed.join("\\n") + "\\n\\nNote: will be reinstalled on next opencode start if credit-dashboard plugin is still active.";
        },
      }),
    },
  };
};

export const server = creditDashboardPlugin;
export default creditDashboardPlugin;
