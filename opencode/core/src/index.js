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
const CONFIG_DIR = findConfigDir(__dirname);
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

