"use strict";
/**
 * 🗄️ لوحة قاعدة البيانات — ملف واحد
 *   زرّين: الأمن السيبراني / فلاش  →  أقسام (الحسابات، المخالفات، ...) → عرض البيانات + الصور + حذف
 *   المتغيرات المطلوبة (Environment):  MONGO_URI  و  ADMIN_PASSWORD
 *   اختياري: PORT ، SESSION_SECRET ، DB_LIMIT_MB (الافتراضي 512)
 *   التشغيل: node db_admin.js      (يحتاج: express + mongoose بس)
 */
const express = require("express");
const crypto = require("crypto");
const mongoose = require("mongoose");

const MONGO_URI = process.env.MONGO_URI;
const PASS = process.env.ADMIN_PASSWORD;
if (!MONGO_URI || !PASS) { console.error("❌ لازم تحط MONGO_URI و ADMIN_PASSWORD في المتغيرات"); process.exit(1); }
const SECRET = process.env.SESSION_SECRET || ("dbadmin|" + PASS);
const TOKEN = crypto.createHmac("sha256", SECRET).update("admin-session").digest("hex");
const LIMIT_MB = Number(process.env.DB_LIMIT_MB || 512);
const PORT = process.env.PORT || 3000;

// ───────── مساعدات ─────────
const sha = s => crypto.createHash("sha256").update(String(s)).digest();
const same = (a, b) => crypto.timingSafeEqual(sha(a), sha(b));
const getCookie = (req, n) => { const m = (req.headers.cookie || "").split(/;\s*/).find(x => x.startsWith(n + "=")); return m ? decodeURIComponent(m.slice(n.length + 1)) : ""; };
const authed = req => same(getCookie(req, "dba"), TOKEN);
const guard = (req, res, next) => authed(req) ? next() : res.status(401).json({ error: "سجّل دخولك أول" });
const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(e => { console.error(e); res.status(e.status || 500).json({ error: e.message || "خطأ" }); });
const bad = (m, s) => { const e = new Error(m); e.status = s || 400; return e; };
const db = () => mongoose.connection.db;
const OID = v => !!v && (v._bsontype === "ObjectId" || v._bsontype === "ObjectID");
const idKey = id => OID(id) ? "o:" + id.toString() : typeof id === "number" ? "n:" + id : "s:" + String(id);
const fromKey = k => {
    k = String(k || ""); const t = k[0], v = k.slice(2);
    if (t === "o") { if (!/^[a-f0-9]{24}$/i.test(v)) throw bad("معرّف غير صحيح"); return new mongoose.Types.ObjectId(v); }
    if (t === "n") return Number(v);
    return v;
};
const oidFromTime = ms => new mongoose.Types.ObjectId(Math.floor(ms / 1000).toString(16).padStart(8, "0") + "0000000000000000");

async function collNames() {
    const l = await db().listCollections({}, { nameOnly: true }).toArray();
    return l.filter(c => c.type !== "view" && !c.name.startsWith("system.")).map(c => c.name);
}
async function mustColl(name) {
    name = String(name || "");
    if (!(await collNames()).includes(name)) throw bad("القسم غير موجود", 404);
    return name;
}

// ───────── تصنيف الأقسام (سيبراني / فلاش) + أسماء عربية ─────────
const CYBER_LABELS = {
    cyberaccess: ["👤 حسابات الصلاحيات", "accounts", "الحسابات اللي لها صلاحية دخول لوحة الأمن السيبراني."],
    cyberpanelmember: ["👥 أعضاء اللوحة", "accounts", "الأعضاء المسجلين في لوحة الأمن السيبراني."],
    cybermemberactivity: ["📈 نشاط الأعضاء", "accounts", "سجل نشاط أعضاء اللوحة (وش سوّوا ومتى)."],
    cybercase: ["⚠️ القضايا والمخالفات", "violations", "القضايا المسجلة على الأعضاء — كل سجل = قضية / مخالفة وحدة."],
    cyberevent: ["🛡️ الأحداث المشبوهة", "violations", "الأحداث والعمليات المشبوهة اللي رصدها البوت — كل سجل = حدث / مخالفة."],
    cybereventimage: ["🖼️ صور الأحداث", "violations", "الصور المرفقة مع الأحداث المشبوهة (دليل المخالفة)."],
    cybervoicesess: ["🎙️ جلسات التسجيل الصوتي", "other", "كل سجل = جلسة تسجيل صوتي بدأها البوت في روم صوتي."],
    cybervoicechunk: ["🎙️ مقاطع الصوت", "other", "قطع صغيرة من التسجيل الصوتي — كل سجل = مقطع. (رقم الجلسة = الجلسة اللي ينتمي لها، رقم المقطع = ترتيبه، معرّف العضو = صاحب الصوت). تاخذ مساحة كبيرة، نظّفها إذا القاعدة قربت تمتلي."],
    cybermsglog: ["💬 الرسائل المحذوفة", "other", "سجل الرسائل اللي انحذفت في السيرفر."],
    cyberban: ["🔨 الباندات", "other", "سجل الأعضاء المحظورين (باند)."],
    cyberinquiry: ["📨 الاستفسارات", "other", "الاستفسارات والطلبات المرسلة من الأعضاء."],
    cyberdailystat: ["📊 إحصائيات يومية", "other", "أرقام وإحصائيات كل يوم."],
    cyberstatmeta: ["📊 بيانات الإحصائيات", "other", "بيانات مساعدة للإحصائيات."],
    cyberweekarchive: ["🗓️ أرشيف الأسابيع", "other", "أرشيف الإحصائيات الأسبوعية القديمة."],
    cyberjob: ["⚙️ طلبات الموقع للبوت", "other", "أوامر ترسلها لوحة الموقع للبوت لينفذها."],
    cyberrecjob: ["⚙️ طلبات صفحة التسجيل", "other", "أوامر ترسلها صفحة التسجيل للبوت لينفذها."],
    cyberrecbot: ["🤖 بوتات التسجيل", "other", "بوتات التسجيل الصوتي المتصلة."],
};
// mongoose يحط اسم القسم بصيغة الجمع (cybercases / cybermemberactivities ...) فنجرب كل الصيغ
function cyberInfo(low) {
    const cands = [low, low.replace(/ies$/, "y"), low.replace(/es$/, ""), low.replace(/s$/, "")];
    for (const x of cands) if (CYBER_LABELS[x]) return CYBER_LABELS[x];
    return null;
}
const RX_ACC = /(user|account|member|access|officer|soldier|staff|person|profile|military|حساب)/i;
const RX_VIO = /(violation|vio|fine|penalt|infraction|mokhalf|offence|offense|report|case|مخالف)/i;
function classify(name) {
    const low = name.toLowerCase();
    if (low.startsWith("cyber")) {
        const k = cyberInfo(low);
        return { proj: "cyber", label: k ? k[0] : "📁 " + name, kind: k ? k[1] : "other", desc: k ? k[2] : "قسم ما له شرح مسجّل (اسمه في القاعدة: " + name + ")." };
    }
    if (RX_VIO.test(name)) return { proj: "flash", label: "⚠️ المخالفات — " + name, kind: "violations", desc: "سجلات المخالفات في موقع فلاش — كل سجل = مخالفة." };
    if (RX_ACC.test(name)) return { proj: "flash", label: "👤 الحسابات — " + name, kind: "accounts", desc: "حسابات المستخدمين في موقع فلاش." };
    return { proj: "flash", label: "📁 " + name, kind: "other", desc: "قسم ما له شرح مسجّل (اسمه في القاعدة: " + name + ")." };
}

// ───────── كشف الصور وتجهيز العرض ─────────
const binOf = v => {
    if (Buffer.isBuffer(v)) return v;
    if (v && v._bsontype === "Binary" && v.buffer) return Buffer.from(v.buffer).subarray(0, typeof v.length === "function" ? v.length() : v.buffer.length);
    return null;
};
function imgMime(b) {
    if (!b || b.length < 12) return null;
    if (b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47) return "image/png";
    if (b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "image/jpeg";
    if (b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46) return "image/gif";
    if (b.toString("ascii", 0, 4) === "RIFF" && b.toString("ascii", 8, 12) === "WEBP") return "image/webp";
    return null;
}
function imgOfString(s) {
    if (s.length < 20) return null;
    if (/^data:image\/(png|jpe?g|gif|webp|bmp);base64,/i.test(s)) return {};
    if (s.length > 200 && /^(iVBORw0KGgo|\/9j\/|R0lGOD|UklGR)/.test(s) && /^[A-Za-z0-9+\/=\s]+$/.test(s.slice(0, 500))) return {};
    if (/^https?:\/\/\S+$/.test(s) && (/\.(png|jpe?g|gif|webp|bmp)(\?.*)?$/i.test(s) || /(cdn\.discordapp\.com|media\.discordapp\.net|i\.imgur\.com)/i.test(s))) return { url: s };
    return null;
}
function view(coll, doc) {
    const images = [], key = idKey(doc._id);
    const blobUrl = p => "/api/blob?c=" + encodeURIComponent(coll) + "&k=" + encodeURIComponent(key) + "&p=" + encodeURIComponent(p);
    const walk = (v, path, d) => {
        if (v === null || v === undefined) return v;
        if (typeof v === "string") {
            const im = imgOfString(v);
            if (im) { if (images.length < 12) images.push({ label: path, src: im.url || blobUrl(path) }); return "🖼️ صورة"; }
            return v.length > 400 ? v.slice(0, 400) + "… (" + v.length + " حرف)" : v;
        }
        if (typeof v === "number" || typeof v === "boolean") return v;
        if (v instanceof Date) return v.toISOString();
        if (OID(v)) return v.toString();
        const buf = binOf(v);
        if (buf) {
            if (imgMime(buf)) { if (images.length < 12) images.push({ label: path, src: blobUrl(path) }); return "🖼️ صورة (" + buf.length + " بايت)"; }
            return "[بيانات ثنائية " + buf.length + " بايت]";
        }
        if (Array.isArray(v)) {
            if (d >= 4) return "[قائمة " + v.length + "]";
            const out = v.slice(0, 30).map((x, i) => walk(x, path + "." + i, d + 1));
            if (v.length > 30) out.push("… +" + (v.length - 30));
            return out;
        }
        if (typeof v === "object") {
            if (d >= 4) return "{…}";
            const o = {}; for (const k of Object.keys(v)) o[k] = walk(v[k], path + "." + k, d + 1); return o;
        }
        return String(v);
    };
    const fields = {};
    for (const k of Object.keys(doc)) if (k !== "_id") fields[k] = walk(doc[k], k, 0);
    return { k: key, fields, images, ts: OID(doc._id) ? parseInt(doc._id.toString().slice(0, 8), 16) * 1000 : null };
}

// ───────── السيرفر ─────────
const app = express();
app.set("trust proxy", 1);
app.disable("x-powered-by");
app.use(express.json({ limit: "1mb" }));

const fails = new Map();
app.post("/api/login", wrap(async (req, res) => {
    const ip = req.ip, f = fails.get(ip) || { n: 0, t: Date.now() };
    if (Date.now() - f.t > 60000) { f.n = 0; f.t = Date.now(); }
    if (f.n >= 5) throw bad("محاولات كثيرة — انتظر دقيقة", 429);
    if (!same(req.body.password || "", PASS)) { f.n++; fails.set(ip, f); throw bad("كلمة المرور غلط", 401); }
    fails.delete(ip);
    const secure = req.secure || req.headers["x-forwarded-proto"] === "https";
    res.setHeader("Set-Cookie", "dba=" + TOKEN + "; HttpOnly; SameSite=Strict; Path=/; Max-Age=" + 60 * 60 * 12 + (secure ? "; Secure" : ""));
    res.json({ ok: true });
}));
app.post("/api/logout", (req, res) => { res.setHeader("Set-Cookie", "dba=; HttpOnly; Path=/; Max-Age=0"); res.json({ ok: true }); });
app.get("/api/auth", (req, res) => res.json({ ok: authed(req) }));

app.get("/api/overview", guard, wrap(async (req, res) => {
    const names = await collNames();
    const st = await db().command({ dbStats: 1 }).catch(() => null);
    const list = await Promise.all(names.map(async n => {
        let s = {}; try { s = await db().command({ collStats: n }); } catch {}
        const count = s.count != null ? s.count : await db().collection(n).estimatedDocumentCount().catch(() => 0);
        return { name: n, count, size: s.size || 0, storage: (s.storageSize || 0) + (s.totalIndexSize || 0), ...classify(n) };
    }));
    const used = st ? (st.dataSize || 0) + (st.indexSize || 0) : list.reduce((a, c) => a + c.size, 0);
    res.json({ used, limit: LIMIT_MB * 1048576, colls: list });
}));

app.get("/api/docs", guard, wrap(async (req, res) => {
    const c = await mustColl(req.query.c), col = db().collection(c);
    const page = Math.max(0, parseInt(req.query.page) || 0), per = 20;
    const q = String(req.query.q || "").trim();
    let filter = {};
    if (q) {
        if (/^[a-f0-9]{24}$/i.test(q)) filter = { $or: [{ _id: new mongoose.Types.ObjectId(q) }, { _id: q }] };
        else {
            const sample = await col.findOne({}, { sort: { _id: -1 } });
            const keys = Object.keys(sample || {}).filter(k => k !== "_id" && typeof sample[k] === "string").slice(0, 20);
            const rx = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
            filter = keys.length ? { $or: keys.map(k => ({ [k]: rx })) } : { _id: null };
        }
    }
    const [total, docs] = await Promise.all([col.countDocuments(filter), col.find(filter).sort({ _id: -1 }).skip(page * per).limit(per).toArray()]);
    res.json({ total, per, page, docs: docs.map(d => view(c, d)) });
}));

app.get("/api/blob", guard, wrap(async (req, res) => {
    const c = await mustColl(req.query.c);
    const doc = await db().collection(c).findOne({ _id: fromKey(req.query.k) });
    if (!doc) throw bad("غير موجود", 404);
    let v = doc; for (const p of String(req.query.p || "").split(".")) { if (v == null) break; v = v[p]; }
    let buf = null, mime = null;
    if (typeof v === "string") {
        const m = v.match(/^data:(image\/[\w+.-]+);base64,(.*)$/is);
        if (m) { mime = m[1]; buf = Buffer.from(m[2], "base64"); }
        else if (imgOfString(v)) { buf = Buffer.from(v.replace(/\s/g, ""), "base64"); mime = imgMime(buf); }
    } else buf = binOf(v);
    if (buf && !mime) mime = imgMime(buf);
    if (!buf || !mime) throw bad("مو صورة", 404);
    res.setHeader("Content-Type", mime);
    res.setHeader("Cache-Control", "private, max-age=300");
    res.send(buf);
}));

app.post("/api/delete", guard, wrap(async (req, res) => {
    const c = await mustColl(req.body.c);
    const keys = Array.isArray(req.body.keys) ? req.body.keys.slice(0, 500) : [];
    if (!keys.length) throw bad("ما اخترت شي");
    const r = await db().collection(c).deleteMany({ _id: { $in: keys.map(fromKey) } });
    res.json({ deleted: r.deletedCount });
}));

// حذف جماعي: أقدم من X يوم، أو الكل (drop + إعادة إنشاء الفهارس عشان المساحة تتحرر فعلاً)
app.post("/api/purge", guard, wrap(async (req, res) => {
    const c = await mustColl(req.body.c), col = db().collection(c), days = Number(req.body.days);
    if (days === 0) {
        if (req.body.confirm !== c) throw bad("اكتب اسم القسم بالضبط للتأكيد");
        let idx = []; try { idx = (await col.indexes()).filter(i => i.name !== "_id_").map(({ v, ns, ...r }) => r); } catch {}
        const before = await col.estimatedDocumentCount().catch(() => 0);
        await col.drop();
        try { await db().createCollection(c); } catch {}
        if (idx.length) { try { await db().collection(c).createIndexes(idx); } catch (e) { console.error("index restore:", e.message); } }
        return res.json({ deleted: before });
    }
    if (!(days > 0)) throw bad("عدد الأيام غير صحيح");
    const cutoff = Date.now() - days * 864e5;
    const sample = await col.findOne({}, { projection: { _id: 1 } });
    const filter = sample && OID(sample._id) ? { _id: { $lt: oidFromTime(cutoff) } } : { createdAt: { $lt: new Date(cutoff) } };
    const r = await col.deleteMany(filter);
    res.json({ deleted: r.deletedCount });
}));

// ───────── الواجهة ─────────
const CSS = String.raw`
*{box-sizing:border-box}body{margin:0;font-family:system-ui,-apple-system,"Segoe UI",Tahoma,sans-serif;background:linear-gradient(160deg,#07101f,#0d2040);color:#e6edf7;min-height:100vh;direction:rtl}
button{font:inherit;cursor:pointer}input{font:inherit}
.wrap{max-width:1100px;margin:0 auto;padding:16px}
.top{display:flex;justify-content:space-between;align-items:center;gap:8px;margin-bottom:14px}
h1,h2,h3{margin:0}.muted{color:#8aa0bf;font-size:13px}
.card{background:#12213b;border:1px solid #223a63;border-radius:14px;padding:14px;margin-bottom:12px}
.btn{background:linear-gradient(135deg,#1d4ed8,#3b82f6);color:#fff;border:0;border-radius:10px;padding:9px 14px}
.btn.gray{background:#25364f}.btn.red{background:linear-gradient(135deg,#b91c1c,#ef4444)}.btn.sm{padding:5px 10px;font-size:13px}.btn:disabled{opacity:.5}
.big{display:flex;gap:14px;flex-wrap:wrap}.big button{flex:1;min-width:240px;padding:34px 16px;font-size:22px;border-radius:18px;border:1px solid #2c4a7c;color:#fff}
.b-cyber{background:linear-gradient(135deg,#1e3a8a,#2563eb)}.b-flash{background:linear-gradient(135deg,#6d28d9,#a855f7)}.big small{display:block;font-size:13px;opacity:.85;margin-top:8px}
.bar{height:12px;background:#1a2c4a;border-radius:8px;overflow:hidden;margin:8px 0}.bar i{display:block;height:100%;background:linear-gradient(90deg,#22c55e,#eab308,#ef4444)}
.tabs{display:flex;gap:8px;overflow-x:auto;padding-bottom:8px;margin-bottom:10px}.tab{white-space:nowrap;background:#16294a;color:#bcd0ee;border:1px solid #27406b;border-radius:10px;padding:8px 12px}
.tab.on{background:#2563eb;color:#fff;border-color:#60a5fa}.tab small{opacity:.75;margin-right:6px}
.tool{display:flex;gap:8px;flex-wrap:wrap;align-items:center;margin-bottom:10px}.tool input[type=text],.in{background:#0e1b33;border:1px solid #29467a;color:#fff;border-radius:10px;padding:9px 12px;flex:1;min-width:160px}
.row{display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.k{color:#60a5fa;font-size:12px}.kv{display:flex;gap:8px;padding:3px 0;border-bottom:1px dashed #1c3052;font-size:13px}.kv b{color:#7fb0ff;min-width:150px;font-weight:600}.en{display:block;color:#5b7399;font-size:10px;direction:ltr;text-align:right;font-weight:400}.sum{background:#0e1b33;border:1px solid #29467a;border-radius:10px;padding:8px 10px;margin:6px 0;font-size:13px;line-height:1.7}.desc{background:#0f2a4a;border:1px solid #2c4a7c;border-radius:12px;padding:10px 12px;margin-bottom:10px;font-size:13px;line-height:1.8;color:#cfe0ff}.kv span{flex:1;word-break:break-word;white-space:pre-wrap}
pre{margin:0;font-size:12px;white-space:pre-wrap;word-break:break-word;color:#cfe0ff}
.imgs{display:flex;gap:8px;flex-wrap:wrap;margin:8px 0}.imgs img{height:120px;border-radius:10px;border:1px solid #2c4a7c;cursor:zoom-in;background:#0b1730;max-width:100%}
.ov{position:fixed;inset:0;background:rgba(3,8,18,.82);display:flex;align-items:center;justify-content:center;padding:14px;z-index:50}
.md{background:#12213b;border:1px solid #2c4a7c;border-radius:16px;padding:18px;max-width:440px;width:100%}.ov img{max-width:100%;max-height:92vh;border-radius:12px}
.toast{position:fixed;bottom:18px;left:50%;transform:translateX(-50%);background:#0e1b33;border:1px solid #3b82f6;border-radius:12px;padding:10px 16px;z-index:60;max-width:92vw}
.center{text-align:center}
`;

const CLIENT = String.raw`
var $=function(i){return document.getElementById(i);};
var S={ov:null,proj:null,coll:null,page:0,q:'',sel:{},docs:[]};
var PN={cyber:['🛡️ الأمن السيبراني','b-cyber'],flash:['⚡ فلاش','b-flash']};
function esc(s){return String(s==null?'':s).replace(/[&<>"']/g,function(c){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c];});}
function mb(b){b=b||0;return b<1048576?(b/1024).toFixed(0)+' ك.ب':(b/1048576).toFixed(b<10485760?2:1)+' م.ب';}
async function api(p,o){o=o||{};o.headers={'Content-Type':'application/json'};var r=await fetch(p,o);var j=await r.json().catch(function(){return {};});
  if(r.status===401&&p!=='/api/login'){showLogin();throw new Error('سجّل دخولك');}
  if(!r.ok)throw new Error(j.error||'خطأ');return j;}
function toast(m){var t=document.createElement('div');t.className='toast';t.textContent=m;document.body.appendChild(t);setTimeout(function(){t.remove();},3500);}
function closeM(){var o=$('ovl');if(o)o.remove();}
function modal(h){closeM();var o=document.createElement('div');o.className='ov';o.id='ovl';o.innerHTML='<div class="md">'+h+'</div>';o.addEventListener('click',function(e){if(e.target===o)closeM();});document.body.appendChild(o);}
function ask(msg,okTxt){return new Promise(function(res){modal('<h3>تأكيد</h3><p style="line-height:1.7">'+esc(msg)+'</p><div class="row"><button class="btn red" id="aY">'+(okTxt||'نعم، احذف')+'</button><button class="btn gray" id="aN">إلغاء</button></div>');
  $('aY').onclick=function(){closeM();res(true);};$('aN').onclick=function(){closeM();res(false);};});}

function showLogin(){
  $('app').innerHTML='<div class="wrap" style="max-width:380px;padding-top:12vh"><div class="card center"><h2>🗄️ لوحة قاعدة البيانات</h2><p class="muted">أدخل كلمة المرور</p>'
   +'<input class="in" id="pw" type="password" placeholder="كلمة المرور" style="width:100%;margin:10px 0"><button class="btn" id="go" style="width:100%">دخول</button></div></div>';
  var go=async function(){try{await api('/api/login',{method:'POST',body:JSON.stringify({password:$('pw').value})});home();}catch(e){toast(e.message);}};
  $('go').onclick=go;$('pw').onkeydown=function(e){if(e.key==='Enter')go();};
}

async function home(){
  S.proj=null;S.coll=null;
  $('app').innerHTML='<div class="wrap"><div class="card center muted">جاري التحميل...</div></div>';
  try{S.ov=await api('/api/overview');}catch(e){if(e.message!=='سجّل دخولك')toast(e.message);return;}
  var ov=S.ov,pct=Math.min(100,ov.used/ov.limit*100);
  var tot={cyber:{n:0,s:0},flash:{n:0,s:0}};
  ov.colls.forEach(function(c){tot[c.proj].n+=c.count;tot[c.proj].s+=c.size;});
  $('app').innerHTML='<div class="wrap"><div class="top"><h2>🗄️ لوحة قاعدة البيانات</h2><button class="btn gray sm" id="lo">خروج</button></div>'
   +'<div class="card"><div class="row" style="justify-content:space-between"><b>المساحة المستخدمة</b><span>'+mb(ov.used)+' من '+mb(ov.limit)+'</span></div><div class="bar"><i style="width:'+pct.toFixed(1)+'%"></i></div>'
   +(pct>=95?'<div class="muted" style="color:#f87171">القاعدة مليانة — الكتابة موقوفة، احذف بيانات قديمة عشان ترجع تشتغل المواقع.</div>':'')+'</div>'
   +'<div class="big">'+['cyber','flash'].map(function(p){return '<button class="'+PN[p][1]+'" data-p="'+p+'">'+PN[p][0]+'<small>'+tot[p].n+' سجل — '+mb(tot[p].s)+'</small></button>';}).join('')+'</div></div>';
  $('lo').onclick=async function(){await api('/api/logout',{method:'POST'});showLogin();};
  document.querySelectorAll('.big button').forEach(function(b){b.onclick=function(){openProj(b.getAttribute('data-p'));};});
}

function projColls(){
  var o={accounts:0,violations:1,other:2};
  return S.ov.colls.filter(function(c){return c.proj===S.proj;}).sort(function(a,b){return o[a.kind]-o[b.kind]||b.size-a.size;});
}
function openProj(p){S.proj=p;var l=projColls();S.coll=l.length?l[0].name:null;S.page=0;S.q='';S.sel={};drawProj();if(S.coll)loadDocs();}
function drawProj(){
  var l=projColls();
  $('app').innerHTML='<div class="wrap"><div class="top"><div class="row"><button class="btn gray sm" id="bk">← رجوع</button><h2>'+PN[S.proj][0]+'</h2></div><span class="muted">'+mb(S.ov.used)+' من '+mb(S.ov.limit)+'</span></div>'
   +(l.length?'<div class="tabs">'+l.map(function(c){return '<button class="tab'+(c.name===S.coll?' on':'')+'" data-c="'+esc(c.name)+'">'+esc(c.label)+'<small>'+c.count+' سجل • '+mb(c.size)+'</small></button>';}).join('')+'</div>'
   +'<div class="desc">ℹ️ <b>'+esc((l.filter(function(c){return c.name===S.coll;})[0]||{}).label||'')+'</b><br>'+esc((l.filter(function(c){return c.name===S.coll;})[0]||{}).desc||'')+'</div>'
   +'<div class="tool"><input type="text" id="q" placeholder="بحث (نص أو معرّف)" value="'+esc(S.q)+'"><button class="btn sm" id="sq">بحث</button><button class="btn sm gray" id="rf">تحديث</button>'
   +'<button class="btn sm red" id="dsel" style="display:none"></button><button class="btn sm red" id="pg">🧹 تنظيف القسم</button></div><div id="list"></div><div id="pager" class="row" style="justify-content:center;margin:12px 0"></div>'
   :'<div class="card center muted">ما لقيت أقسام لهذا الموقع في القاعدة</div>')+'</div>';
  $('bk').onclick=home;
  if(!l.length)return;
  document.querySelectorAll('.tab').forEach(function(t){t.onclick=function(){S.coll=t.getAttribute('data-c');S.page=0;S.q='';S.sel={};drawProj();loadDocs();};});
  var sq=function(){S.q=$('q').value.trim();S.page=0;loadDocs();};
  $('sq').onclick=sq;$('q').onkeydown=function(e){if(e.key==='Enter')sq();};$('rf').onclick=function(){refresh();};
  $('dsel').onclick=delSel;$('pg').onclick=purgeDlg;
}
async function refresh(){try{S.ov=await api('/api/overview');}catch(e){}drawProj();loadDocs();}
var FAR={seq:'رقم المقطع',sid:'رقم الجلسة',uid:'معرّف العضو (ID)',__v:'نسخة السجل',createdAt:'تاريخ الإنشاء',updatedAt:'تاريخ آخر تعديل',data:'البيانات',
  userId:'معرّف العضو',user:'العضو',guildId:'معرّف السيرفر',guild:'السيرفر',channelId:'معرّف الروم',channel:'الروم',messageId:'معرّف الرسالة',type:'النوع',kind:'النوع',
  reason:'السبب',content:'المحتوى',text:'النص',status:'الحالة',name:'الاسم',username:'اسم المستخدم',title:'العنوان',description:'الوصف',moderator:'المشرف',
  by:'بواسطة',action:'الإجراء',count:'العدد',date:'التاريخ',day:'اليوم',role:'الرتبة',roles:'الرتب',image:'صورة',images:'صور',url:'الرابط',duration:'المدة',
  expiresAt:'ينتهي في',startedAt:'بدأ في',endedAt:'انتهى في',caseId:'رقم القضية',targetId:'معرّف المستهدف',target:'المستهدف',severity:'الخطورة',
  note:'ملاحظة',notes:'ملاحظات',permissions:'الصلاحيات',level:'المستوى',code:'الرمز',id:'المعرّف',week:'الأسبوع',total:'الإجمالي',result:'النتيجة',evidence:'الدليل'};
function fname(k){return FAR[k]?esc(FAR[k])+'<span class="en">'+esc(k)+'</span>':esc(k);}
function fdate(s){return new Date(s).toLocaleString('ar-SA-u-ca-gregory');}
function val(v){
  if(v!==null&&typeof v==='object')return '<pre>'+esc(JSON.stringify(v,null,1))+'</pre>';
  if(typeof v==='string'&&/^\d{4}-\d\d-\d\dT[\d:.]+Z$/.test(v))return esc(fdate(v));
  if(v===true)return 'نعم';if(v===false)return 'لا';
  return esc(v);}
function summ(d){
  var c=(S.ov.colls.filter(function(x){return x.name===S.coll;})[0]||{}),f=d.fields,n=String(c.name||'').toLowerCase();
  if(/voicechunk/.test(n))return 'مقطع صوتي رقم '+esc(f.seq)+' من الجلسة '+esc(f.sid)+' — صاحب الصوت: '+esc(f.uid);
  return '';}
function card(d){
  var keys=Object.keys(d.fields),ts=d.ts?new Date(d.ts).toLocaleString('ar-SA-u-ca-gregory'):'';
  var rows=keys.slice(0,10).map(function(k){return '<div class="kv"><b>'+fname(k)+'</b><span>'+val(d.fields[k])+'</span></div>';}).join('');
  var more=keys.length>10?'<div id="m_'+esc(d.k)+'" style="display:none">'+keys.slice(10).map(function(k){return '<div class="kv"><b>'+fname(k)+'</b><span>'+val(d.fields[k])+'</span></div>';}).join('')+'</div><button class="btn gray sm" data-more="'+esc(d.k)+'" style="margin-top:6px">عرض كل الحقول ('+keys.length+')</button>':'';
  var imgs=d.images.length?'<div class="imgs">'+d.images.map(function(i){return '<img loading="lazy" src="'+esc(i.src)+'" data-big="'+esc(i.src)+'" alt="">';}).join('')+'</div>':'';
  return '<div class="card"><div class="row" style="justify-content:space-between;margin-bottom:6px"><label class="row"><input type="checkbox" data-sel="'+esc(d.k)+'"'+(S.sel[d.k]?' checked':'')+'><span class="k">'+esc(d.k.slice(2))+(ts?' • '+ts:'')+'</span></label>'
    +'<button class="btn red sm" data-del="'+esc(d.k)+'">🗑️ حذف</button></div>'+(summ(d)?'<div class="sum">📌 '+summ(d)+'</div>':'')+imgs+rows+more+'</div>';
}
async function loadDocs(){
  var L=$('list');if(!L)return;L.innerHTML='<div class="card center muted">جاري التحميل...</div>';
  try{
    var j=await api('/api/docs?c='+encodeURIComponent(S.coll)+'&page='+S.page+'&q='+encodeURIComponent(S.q));
    S.docs=j.docs;
    L.innerHTML=j.docs.length?j.docs.map(card).join(''):'<div class="card center muted">ما فيه بيانات</div>';
    var pages=Math.max(1,Math.ceil(j.total/j.per));
    $('pager').innerHTML='<button class="btn gray sm" id="pp"'+(S.page<=0?' disabled':'')+'>السابق</button><span class="muted">صفحة '+(S.page+1)+' من '+pages+' — الإجمالي '+j.total+'</span><button class="btn gray sm" id="pn"'+(S.page+1>=pages?' disabled':'')+'>التالي</button>';
    $('pp').onclick=function(){S.page--;loadDocs();window.scrollTo(0,0);};$('pn').onclick=function(){S.page++;loadDocs();window.scrollTo(0,0);};
    selUi();
  }catch(e){L.innerHTML='<div class="card center muted">'+esc(e.message)+'</div>';}
}
function selUi(){var n=Object.keys(S.sel).length,b=$('dsel');if(!b)return;b.style.display=n?'':'none';b.textContent='🗑️ حذف المحدد ('+n+')';}
async function doDelete(keys){
  try{var r=await api('/api/delete',{method:'POST',body:JSON.stringify({c:S.coll,keys:keys})});toast('انحذف '+r.deleted);keys.forEach(function(k){delete S.sel[k];});refresh();}catch(e){toast(e.message);}
}
async function delSel(){var k=Object.keys(S.sel);if(!k.length)return;if(await ask('تحذف '+k.length+' عنصر نهائياً؟ ما يرجعون.'))doDelete(k);}
function purgeDlg(){
  modal('<h3>🧹 تنظيف القسم</h3><p class="muted">حذف الأقدم من عدد أيام تحدده:</p><div class="row"><input class="in" id="pd" type="number" min="1" value="7" style="max-width:110px"><span>يوم</span><button class="btn red" id="pdo">حذف الأقدم</button></div>'
   +'<hr style="border-color:#223a63;margin:16px 0"><p class="muted">أو حذف كل القسم (يتحرر المكان فوراً). اكتب اسم القسم للتأكيد:</p><div class="muted" style="direction:ltr;text-align:left;color:#fbbf24">'+esc(S.coll)+'</div>'
   +'<input class="in" id="pc" type="text" style="width:100%;margin:8px 0" placeholder="اكتب الاسم أعلاه"><button class="btn red" id="pall" style="width:100%">حذف كل القسم</button><button class="btn gray" onclick="closeM()" style="width:100%;margin-top:8px">إلغاء</button>');
  $('pdo').onclick=async function(){var d=Number($('pd').value);if(!(d>0)){toast('عدد الأيام غير صحيح');return;}if(!(await ask('تحذف كل شي أقدم من '+d+' يوم في هذا القسم؟')))return;purge({days:d});};
  $('pall').onclick=function(){purge({days:0,confirm:$('pc').value.trim()});};
}
async function purge(b){
  b.c=S.coll;
  try{var r=await api('/api/purge',{method:'POST',body:JSON.stringify(b)});closeM();toast('انحذف '+r.deleted+' سجل');S.page=0;refresh();}catch(e){toast(e.message);}
}
document.addEventListener('click',function(e){
  var t=e.target;
  var del=t.closest&&t.closest('[data-del]');if(del){var k=del.getAttribute('data-del');ask('تحذف هذا السجل نهائياً؟').then(function(ok){if(ok)doDelete([k]);});return;}
  var mo=t.closest&&t.closest('[data-more]');if(mo){var id='m_'+mo.getAttribute('data-more'),el=$(id);if(el){el.style.display='block';mo.remove();}return;}
  var im=t.closest&&t.closest('[data-big]');if(im){modal('<div class="center"><img src="'+esc(im.getAttribute('data-big'))+'" alt=""></div>');return;}
});
document.addEventListener('change',function(e){var s=e.target.getAttribute&&e.target.getAttribute('data-sel');if(s){if(e.target.checked)S.sel[s]=1;else delete S.sel[s];selUi();}});
(async function(){try{var a=await (await fetch('/api/auth')).json();if(a.ok)home();else showLogin();}catch(e){showLogin();}})();
`;

const PAGE = '<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>لوحة قاعدة البيانات</title><style>'
    + CSS + '</style></head><body><div id="app"></div><script>' + CLIENT + '</script></body></html>';
app.get("/", (req, res) => { res.setHeader("Cache-Control", "no-store"); res.type("html").send(PAGE); });

mongoose.set("strictQuery", false);
mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 20000 })
    .then(() => { console.log("✅ متصل بقاعدة البيانات"); app.listen(PORT, () => console.log("🗄️ لوحة قاعدة البيانات شغّالة على المنفذ " + PORT)); })
    .catch(e => { console.error("❌ فشل الاتصال بالقاعدة:", e.message); process.exit(1); });
