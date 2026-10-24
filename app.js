"use strict";
/**
 * 🗄️ لوحة قاعدة البيانات — ملف واحد
 *   زرّين: الأمن السيبراني / فلاش  →  أقسام (الحسابات، المخالفات، ...) → عرض البيانات + الصور + حذف
 *   + زر «نقل من إلى» (نسخ أقسام من قاعدة لقاعدة) + زر «سجل القاعدة» (عرض محتوى أي قاعدة)
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

// ───────── نقل البيانات بين قواعد + سجل القاعدة ─────────
// أسماء الأقسام تتحول للعربي حسب الكلمات اللي فيها (ما يطلع أي اسم إنجليزي للمستخدم)
const AR_WORDS = [
    ["civilregistr", "السجل المدني"], ["transaction", "المعاملات"], ["notification", "الإشعارات"], ["application", "طلبات التقديم"],
    ["attendance", "الحضور"], ["permission", "الصلاحيات"], ["punishment", "العقوبات"], ["interview", "المقابلات"],
    ["complaint", "الشكاوى"], ["inquir", "الاستفسارات"], ["violation", "المخالفات"], ["frequenc", "الترددات"],
    ["registr", "السجل"], ["securit", "الأمن"], ["propert", "الممتلكات"], ["vehicle", "المركبات"], ["citizen", "المواطنين"],
    ["profile", "الملفات الشخصية"], ["session", "الجلسات"], ["message", "الرسائل"], ["setting", "الإعدادات"],
    ["archive", "الأرشيف"], ["balance", "الأرصدة"], ["payment", "المدفوعات"], ["transfer", "التحويلات"],
    ["license", "الرخص"], ["warning", "الإنذارات"], ["request", "الطلبات"], ["officer", "الضباط"], ["soldier", "الجنود"],
    ["account", "الحسابات"], ["member", "الأعضاء"], ["person", "الأشخاص"], ["report", "البلاغات"], ["ticket", "التذاكر"],
    ["arrest", "الاعتقالات"], ["warrant", "أوامر القبض"], ["weapon", "الأسلحة"], ["status", "الحالات"], ["config", "الإعدادات"],
    ["sector", "القطاعات"], ["police", "الشرطة"], ["civil", "المدني"], ["voice", "الصوت"], ["image", "الصور"],
    ["event", "الأحداث"], ["staff", "الموظفين"], ["admin", "الإداريين"], ["audit", "التدقيق"], ["leave", "الإجازات"],
    ["shift", "المناوبات"], ["point", "النقاط"], ["stat", "الإحصائيات"], ["user", "المستخدمين"], ["case", "القضايا"],
    ["card", "البطاقات"], ["loan", "القروض"], ["bank", "البنك"], ["plate", "اللوحات"], ["role", "الرتب"], ["rank", "الرتب"],
    ["file", "الملفات"], ["test", "الاختبارات"], ["fine", "الغرامات"], ["job", "المهام"], ["bot", "البوتات"],
    ["ban", "الباندات"], ["log", "السجلات"], ["flash", "فلاش"],
].sort((a, b) => b[0].length - a[0].length);

function arInfo(name) {
    const low = String(name).toLowerCase();
    if (low.startsWith("cyber")) { const k = cyberInfo(low); if (k) return { label: k[0], desc: k[2] }; }
    let work = low; const hit = [];
    for (const [stem, ar] of AR_WORDS) {
        const i = work.indexOf(stem);
        if (i !== -1) { hit.push([i, ar]); work = work.slice(0, i) + " ".repeat(stem.length) + work.slice(i + stem.length); }
    }
    hit.sort((a, b) => a[0] - b[0]);
    const words = hit.map(h => h[1]).filter((w, i, a) => a.indexOf(w) === i);
    if (words.length) return { label: "📁 " + words.join(" "), desc: "بيانات: " + words.join(" ") + "." };
    return { label: "📁 قسم آخر", desc: "قسم بيانات ما له شرح مسجّل." };
}

async function openConn(uri) {
    uri = String(uri || "").trim();
    if (!/^mongodb(\+srv)?:\/\/\S+$/i.test(uri)) throw bad("الرابط غير صحيح — لازم يكون رابط اتصال القاعدة (يبدأ بـ mongodb)");
    try {
        const c = mongoose.createConnection(uri, { serverSelectionTimeoutMS: 15000 });
        return typeof c.asPromise === "function" ? await c.asPromise() : await c;
    } catch (e) {
        console.error("xfer connect:", e && e.name);
        throw bad("ما قدرت أتصل بالقاعدة — تأكد من الرابط وكلمة المرور والصلاحيات");
    }
}
const listNames = async d => (await d.listCollections({}, { nameOnly: true }).toArray())
    .filter(c => c.type !== "view" && !c.name.startsWith("system.")).map(c => c.name);

async function inspectDb(conn, uri) {
    const d = conn.db;
    let names;
    try { names = await listNames(d); }
    catch (e) { console.error("xfer list:", e.message); throw bad("ما قدرت أقرأ القاعدة — تأكد من صلاحيات القراءة"); }
    const colls = await Promise.all(names.map(async n => {
        let s = {}; try { s = await d.command({ collStats: n }); } catch {}
        const count = s.count != null ? s.count : await d.collection(n).estimatedDocumentCount().catch(() => 0);
        let last = null;
        try {
            const one = await d.collection(n).findOne({}, { sort: { _id: -1 }, projection: { _id: 1 } });
            if (one && OID(one._id)) last = parseInt(one._id.toString().slice(0, 8), 16) * 1000;
        } catch {}
        return { name: n, count, size: s.size || 0, last };
    }));
    colls.sort((a, b) => b.size - a.size || a.name.localeCompare(b.name));
    const seen = {};
    for (const c of colls) {
        const i = arInfo(c.name); c.label = i.label; c.desc = i.desc;
        seen[c.label] = (seen[c.label] || 0) + 1;
        if (seen[c.label] > 1) c.label += " " + seen[c.label];
    }
    return {
        name: conn.name,
        hasDb: /^mongodb(\+srv)?:\/\/[^/?]+\/[^?\s]+/i.test(uri),
        colls,
        total: colls.reduce((a, c) => a + c.count, 0),
        size: colls.reduce((a, c) => a + c.size, 0),
    };
}

app.post("/api/xfer/inspect", guard, wrap(async (req, res) => {
    const uri = String(req.body.uri || "").trim();
    const conn = await openConn(uri);
    try { res.json(await inspectDb(conn, uri)); }
    finally { conn.close().catch(() => {}); }
}));

// ── عملية النقل (تشتغل بالخلفية، والواجهة تسأل عن تقدمها) ──
const jobs = new Map();
const pubJob = j => ({
    id: j.id, status: j.status, error: j.error,
    items: j.items.map(i => ({ label: i.label, total: i.total, done: i.done, skipped: i.skipped, status: i.status, note: i.note })),
});

async function runXfer(job, src, dst) {
    try {
        for (const it of job.items) {
            it.status = "running";
            try {
                const sc = src.db.collection(it.name), dc = dst.db.collection(it.name);
                it.total = await sc.countDocuments({});
                try { await dst.db.createCollection(it.name); } catch {}
                const sizeOf = (mongoose.mongo.BSON && mongoose.mongo.BSON.calculateObjectSize) || null;
                let batch = [], bytes = 0;
                const flush = async () => {
                    if (!batch.length) return;
                    const b = batch, n = b.length; batch = []; bytes = 0;
                    try { await dc.insertMany(b, { ordered: false }); it.done += n; }
                    catch (e) {
                        const we = [].concat(e.writeErrors || []);
                        const dup = w => (w.code != null ? w.code : w.err && w.err.code) === 11000;
                        if (!we.length || !we.every(dup)) throw e;
                        it.skipped += we.length; it.done += n - we.length;
                    }
                };
                const cur = sc.find({}).batchSize(200);
                while (await cur.hasNext()) {
                    const doc = await cur.next();
                    batch.push(doc);
                    try { bytes += sizeOf ? sizeOf(doc) : 20000; } catch { bytes += 20000; }
                    if (batch.length >= 500 || bytes >= 8 * 1048576) await flush();
                }
                await flush();
                try {
                    const idx = (await sc.indexes()).filter(i => i.name !== "_id_").map(({ v, ns, ...r }) => r);
                    if (idx.length) await dc.createIndexes(idx);
                } catch (e) { it.note = "انتقلت البيانات لكن تعذّر نسخ الفهارس"; console.error("xfer index:", e.message); }
                it.status = "done";
            } catch (e) {
                console.error("xfer fail:", it.name, e.message);
                it.status = "failed";
                it.note = "فشل النقل — غالباً القاعدة الهدف مليانة أو ما عندك صلاحية كتابة عليها";
            }
        }
    } catch (e) {
        console.error("xfer job:", e.message);
        job.error = "صار خطأ غير متوقع أثناء النقل";
    } finally {
        job.status = "done";
        src.close().catch(() => {}); dst.close().catch(() => {});
        setTimeout(() => jobs.delete(job.id), 3600e3).unref();
    }
}

app.post("/api/xfer/start", guard, wrap(async (req, res) => {
    if ([...jobs.values()].some(j => j.status === "running")) throw bad("فيه عملية نقل شغّالة الحين، انتظر لين تخلص", 409);
    const fromUri = String(req.body.fromUri || "").trim(), toUri = String(req.body.toUri || "").trim();
    if (!fromUri || !toUri) throw bad("حدد قاعدة «من» وقاعدة «إلى»");
    const wanted = Array.isArray(req.body.colls) ? [...new Set(req.body.colls.map(String))].slice(0, 300) : [];
    if (!wanted.length) throw bad("ما اخترت أي قسم");
    const labels = req.body.labels && typeof req.body.labels === "object" ? req.body.labels : {};
    const src = await openConn(fromUri);
    let dst;
    try { dst = await openConn(toUri); } catch (e) { src.close().catch(() => {}); throw e; }
    let names;
    try {
        if (fromUri === toUri || (src.host === dst.host && src.port === dst.port && src.name === dst.name))
            throw bad("قاعدة «من» و«إلى» هي نفس القاعدة — اختر قاعدتين مختلفتين");
        const have = new Set(await listNames(src.db).catch(() => { throw bad("ما قدرت أقرأ القاعدة المصدر — تأكد من صلاحيات القراءة"); }));
        names = wanted.filter(n => have.has(n));
        if (!names.length) throw bad("الأقسام المختارة مو موجودة في قاعدة «من»");
    } catch (e) { src.close().catch(() => {}); dst.close().catch(() => {}); throw e; }
    const job = {
        id: crypto.randomBytes(8).toString("hex"), status: "running", error: "",
        items: names.map(n => ({ name: n, label: String(labels[n] || "📁 قسم").slice(0, 80), total: 0, done: 0, skipped: 0, status: "waiting", note: "" })),
    };
    jobs.set(job.id, job);
    runXfer(job, src, dst);
    res.json({ id: job.id });
}));

app.get("/api/xfer/status", guard, wrap(async (req, res) => {
    const j = jobs.get(String(req.query.id || ""));
    if (!j) throw bad("عملية النقل غير موجودة (يمكن السيرفر انعاد تشغيله)", 404);
    res.json(pubJob(j));
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
.big.wide button{flex:1 1 100%;min-width:0;padding:24px 16px;font-size:20px}.b-xfer{background:linear-gradient(135deg,#0f766e,#14b8a6)}.b-log{background:linear-gradient(135deg,#b45309,#f59e0b)}
.xf{display:grid;grid-template-columns:1fr auto 1fr;gap:12px;align-items:start}.xmid{display:flex;align-items:center;justify-content:center;padding-top:70px}
.xgo{background:linear-gradient(135deg,#1d4ed8,#3b82f6);color:#fff;border:0;border-radius:14px;padding:16px 22px;font-size:18px;font-weight:700}.xgo:disabled{opacity:.5}
@media(max-width:760px){.xf{grid-template-columns:1fr}.xmid{padding:0}.xgo{width:100%}}
.xi{display:flex;gap:8px;align-items:center;padding:9px 8px;border-bottom:1px dashed #1c3052;cursor:pointer;font-size:14px}.xi input{width:18px;height:18px;flex:none}.xi .l{flex:1}.xi small{color:#8aa0bf}
.xall{background:#0f2a4a;border:1px solid #2c4a7c;border-radius:10px;font-weight:700;margin:8px 0 4px}
.ok{color:#4ade80}.warn{color:#fbbf24}.errt{color:#f87171}
.pb{height:8px;background:#1a2c4a;border-radius:6px;overflow:hidden;margin:6px 0}.pb i{display:block;height:100%;background:linear-gradient(90deg,#22c55e,#3b82f6);transition:width .4s}
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
function ask(msg,okTxt,cls){return new Promise(function(res){modal('<h3>تأكيد</h3><p style="line-height:1.7">'+esc(msg)+'</p><div class="row"><button class="btn '+(cls===undefined?'red':cls)+'" id="aY">'+(okTxt||'نعم، احذف')+'</button><button class="btn gray" id="aN">إلغاء</button></div>');
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
   +'<div class="big">'+['cyber','flash'].map(function(p){return '<button class="'+PN[p][1]+'" data-p="'+p+'">'+PN[p][0]+'<small>'+tot[p].n+' سجل — '+mb(tot[p].s)+'</small></button>';}).join('')+'</div>'
   +'<div class="big wide" style="margin-top:14px"><button class="b-xfer" id="bx">🔄 نقل من إلى<small>انسخ البيانات من قاعدة بيانات لقاعدة ثانية</small></button></div>'
   +'<div class="big wide" style="margin-top:14px"><button class="b-log" id="bl">📋 سجل القاعدة<small>شوف وش موجود داخل أي قاعدة بيانات</small></button></div></div>';
  $('bx').onclick=openXfer;$('bl').onclick=openLog;
  $('lo').onclick=async function(){await api('/api/logout',{method:'POST'});showLogin();};
  document.querySelectorAll('.big button[data-p]').forEach(function(b){b.onclick=function(){openProj(b.getAttribute('data-p'));};});
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

/* ───────── نقل من إلى ───────── */
var X={fromUri:'',toUri:'',from:null,to:null,sel:{},err:{},busy:{},timer:null,running:false,jobId:null};
function xBack(){if(X.timer){clearInterval(X.timer);X.timer=null;}home();}
function xPanel(s){
  var f=s==='from';
  return '<div class="card"><h3>'+(f?'📤 من':'📥 إلى')+'</h3><div class="muted" style="margin:4px 0 8px">'+(f?'ضع القاعدة اللي تنقل منها':'ضع القاعدة اللي تنقل لها')+'</div>'
   +'<div class="tool"><input type="text" class="in" id="u_'+s+'" placeholder="ضع قاعدة بيانات" value="'+esc(X[s+'Uri'])+'" autocomplete="off" spellcheck="false" style="direction:ltr;text-align:left"><button class="btn sm" id="s_'+s+'">بحث</button></div><div id="r_'+s+'"></div></div>';
}
function openXfer(){
  S.proj=null;
  $('app').innerHTML='<div class="wrap"><div class="top"><div class="row"><button class="btn gray sm" id="bk">← رجوع</button><h2>🔄 نقل من إلى</h2></div></div>'
   +'<div class="xf">'+xPanel('from')+'<div class="xmid"><button class="xgo" id="xgo">🔄 نقل</button></div>'+xPanel('to')+'</div><div id="xprog"></div></div>';
  $('bk').onclick=xBack;
  ['from','to'].forEach(function(s){
    var u=$('u_'+s);
    u.oninput=function(){X[s+'Uri']=u.value.trim();if(X[s]||X.err[s]){X[s]=null;X.err[s]='';if(s==='from')X.sel={};xRes(s);}};
    u.onkeydown=function(e){if(e.key==='Enter')xSearch(s);};
    $('s_'+s).onclick=function(){xSearch(s);};
    xRes(s);
  });
  $('xgo').onclick=xRun;
  if(X.jobId)xPoll();
}
async function xSearch(s){
  var el=$('u_'+s);if(!el)return;
  var uri=(el.value||'').trim();X[s+'Uri']=uri;
  if(!uri){toast('ضع رابط القاعدة أول');return;}
  X.busy[s]=true;X.err[s]='';X[s]=null;if(s==='from')X.sel={};xRes(s);
  var j=null,er='';
  try{j=await api('/api/xfer/inspect',{method:'POST',body:JSON.stringify({uri:uri})});}catch(e){er=e.message;}
  X.busy[s]=false;
  var el2=$('u_'+s);if(!el2)return;
  if((el2.value||'').trim()!==uri){xRes(s);return;}
  if(er){X.err[s]=er;}
  else{j.uri=uri;X[s]=j;if(s==='from')j.colls.forEach(function(c){X.sel[c.name]=1;});}
  xRes(s);
}
function xRes(s){
  var el=$('r_'+s);if(!el)return;
  if(X.busy[s]){el.innerHTML='<div class="muted center" style="padding:14px">⏳ جاري الاتصال بالقاعدة...</div>';return;}
  if(X.err[s]){el.innerHTML='<div class="sum errt">❌ '+esc(X.err[s])+'</div>';return;}
  var d=X[s];
  if(!d){el.innerHTML='<div class="muted" style="padding:6px">ما بحثت بعد</div>';return;}
  var head='<div class="sum"><span class="ok">✅ تم الاتصال</span> — اسم القاعدة: <b style="direction:ltr;unicode-bidi:embed">'+esc(d.name)+'</b><br>'+d.colls.length+' قسم • '+d.total+' سجل • '+mb(d.size)
   +(d.hasDb?'':'<br><span class="warn">⚠️ الرابط ما فيه اسم قاعدة، فبتستخدم القاعدة الافتراضية.</span>')+'</div>';
  if(!d.colls.length){el.innerHTML=head+'<div class="muted">القاعدة فاضية ما فيها بيانات</div>';return;}
  if(s==='to'){
    el.innerHTML=head+'<div class="muted" style="margin:6px 0">الموجود فيها حالياً:</div>'+d.colls.map(function(c){return '<div class="xi" style="cursor:default"><span class="l">'+esc(c.label)+'</span><small>'+c.count+' سجل</small></div>';}).join('');
    return;
  }
  var n=0;d.colls.forEach(function(c){if(X.sel[c.name])n++;});
  var allOn=n===d.colls.length;
  el.innerHTML=head+'<label class="xi xall"><input type="checkbox" id="xall"'+(allOn?' checked':'')+'><span class="l">✅ الجميع</span><small>'+n+' من '+d.colls.length+'</small></label>'
   +d.colls.map(function(c){return '<label class="xi"><input type="checkbox" data-xi="'+esc(c.name)+'"'+(X.sel[c.name]?' checked':'')+'><span class="l">'+esc(c.label)+'</span><small>'+c.count+' سجل</small></label>';}).join('');
  var a=$('xall');if(a)a.indeterminate=(n>0&&!allOn);
}
async function xRun(){
  if(X.running)return;
  if(!X.from||!X.to){toast('ابحث عن القاعدتين أول: «من» و«إلى»');return;}
  var names=[],labels={},rec=0;
  X.from.colls.forEach(function(c){if(X.sel[c.name]){names.push(c.name);labels[c.name]=c.label;rec+=c.count;}});
  if(!names.length){toast('ما اخترت أي قسم تنقله');return;}
  if(!(await ask('تنقل '+names.length+' قسم ('+rec+' سجل) من القاعدة «من» إلى القاعدة «إلى»؟ اللي موجود مسبقاً في القاعدة الجديدة يتخطاه وما ينكرر، والقاعدة القديمة ما ينحذف منها شي.','نعم، انقل','')))return;
  X.running=true;var g=$('xgo');if(g)g.disabled=true;
  try{
    var j=await api('/api/xfer/start',{method:'POST',body:JSON.stringify({fromUri:X.from.uri,toUri:X.to.uri,colls:names,labels:labels})});
    X.jobId=j.id;xPoll();
  }catch(e){X.running=false;var g2=$('xgo');if(g2)g2.disabled=false;toast(e.message);}
}
function xPoll(){
  if(X.timer)clearInterval(X.timer);
  var stop=function(){if(X.timer){clearInterval(X.timer);X.timer=null;}X.running=false;var g=$('xgo');if(g)g.disabled=false;};
  var tick=async function(){
    try{
      var j=await api('/api/xfer/status?id='+encodeURIComponent(X.jobId));
      xProg(j);
      if(j.status!=='running'){stop();if(X.to&&$('u_to'))xSearch('to');}
      else{X.running=true;var g=$('xgo');if(g)g.disabled=true;}
    }catch(e){stop();X.jobId=null;toast(e.message);}
  };
  tick();X.timer=setInterval(tick,1000);
}
function xProg(j){
  var el=$('xprog');if(!el)return;
  var dn=0,sk=0,fl=0;
  var ST={waiting:'⏳ بانتظار الدور',running:'🔄 جاري النقل',done:'✅ تم',failed:'❌ فشل'};
  var rows=j.items.map(function(i){
    dn+=i.done;sk+=i.skipped;if(i.status==='failed')fl++;
    var p=i.total?Math.min(100,(i.done+i.skipped)/i.total*100):(i.status==='done'?100:0);
    return '<div class="card"><div class="row" style="justify-content:space-between"><b>'+esc(i.label)+'</b><span class="muted">'+(ST[i.status]||'')+'</span></div><div class="pb"><i style="width:'+p.toFixed(0)+'%"></i></div>'
     +'<div class="muted">'+(i.done+i.skipped)+' من '+i.total+' سجل'+(i.skipped?' • '+i.skipped+' موجود مسبقاً (تخطّيته)':'')+'</div>'
     +(i.note?'<div class="warn" style="font-size:13px;margin-top:4px">⚠️ '+esc(i.note)+'</div>':'')+'</div>';
  }).join('');
  var head;
  if(j.status==='running')head='<div class="sum">⏳ جاري النقل... العملية تكمل بالخلفية حتى لو قفلت الصفحة</div>';
  else head='<div class="sum"><span class="'+((fl||j.error)?'warn':'ok')+'">'+((fl||j.error)?'⚠️ خلص النقل مع مشاكل':'✅ خلص النقل بنجاح')+'</span><br>انتقل '+dn+' سجل'+(sk?' • تخطّى '+sk+' موجود مسبقاً':'')+(j.error?'<br><span class="errt">'+esc(j.error)+'</span>':'')+'</div>';
  el.innerHTML='<h3 style="margin:14px 0 8px">📦 تقدّم النقل</h3>'+head+rows;
}
document.addEventListener('change',function(e){
  var t=e.target;if(!t||!t.getAttribute)return;
  if(t.id==='xall'&&X.from){X.sel={};if(t.checked)X.from.colls.forEach(function(c){X.sel[c.name]=1;});xRes('from');return;}
  var xi=t.getAttribute('data-xi');
  if(xi!==null){if(t.checked)X.sel[xi]=1;else delete X.sel[xi];xRes('from');}
});

/* ───────── سجل القاعدة ───────── */
var LG={uri:'',data:null,err:'',busy:false};
function openLog(){
  S.proj=null;
  $('app').innerHTML='<div class="wrap"><div class="top"><div class="row"><button class="btn gray sm" id="bk">← رجوع</button><h2>📋 سجل القاعدة</h2></div></div>'
   +'<div class="card"><div class="muted" style="margin-bottom:8px">ضع القاعدة اللي تبي تشوف وش موجود فيها</div><div class="tool"><input type="text" class="in" id="lu" placeholder="ضع قاعدة بيانات" value="'+esc(LG.uri)+'" autocomplete="off" spellcheck="false" style="direction:ltr;text-align:left"><button class="btn sm" id="ls">بحث</button></div></div><div id="lr"></div></div>';
  $('bk').onclick=home;
  $('ls').onclick=logSearch;
  $('lu').onkeydown=function(e){if(e.key==='Enter')logSearch();};
  $('lu').oninput=function(){LG.uri=$('lu').value.trim();};
  logRes();
}
async function logSearch(){
  var el=$('lu');if(!el)return;
  var uri=(el.value||'').trim();LG.uri=uri;
  if(!uri){toast('ضع رابط القاعدة أول');return;}
  LG.busy=true;LG.err='';LG.data=null;logRes();
  try{LG.data=await api('/api/xfer/inspect',{method:'POST',body:JSON.stringify({uri:uri})});}catch(e){LG.err=e.message;}
  LG.busy=false;logRes();
}
function logRes(){
  var el=$('lr');if(!el)return;
  if(LG.busy){el.innerHTML='<div class="card center muted">⏳ جاري الاتصال بالقاعدة...</div>';return;}
  if(LG.err){el.innerHTML='<div class="card errt">❌ '+esc(LG.err)+'</div>';return;}
  var d=LG.data;if(!d){el.innerHTML='';return;}
  var head='<div class="card"><span class="ok">✅ تم الاتصال</span> — اسم القاعدة: <b style="direction:ltr;unicode-bidi:embed">'+esc(d.name)+'</b>'
   +'<div class="muted" style="margin-top:6px">'+d.colls.length+' قسم • '+d.total+' سجل • '+mb(d.size)+'</div>'
   +(d.hasDb?'':'<div class="warn" style="margin-top:6px;font-size:13px">⚠️ الرابط ما فيه اسم قاعدة، فهذي القاعدة الافتراضية.</div>')+'</div>';
  if(!d.colls.length){el.innerHTML=head+'<div class="card center muted">القاعدة فاضية ما فيها بيانات</div>';return;}
  el.innerHTML=head+d.colls.map(function(c){
    return '<div class="card"><div class="row" style="justify-content:space-between"><b>'+esc(c.label)+'</b><span class="muted">'+c.count+' سجل • '+mb(c.size)+'</span></div>'
     +'<div class="muted" style="margin-top:6px;line-height:1.7">'+esc(c.desc)+'</div>'
     +(c.last?'<div class="muted" style="margin-top:4px">آخر إضافة: '+esc(new Date(c.last).toLocaleString('ar-SA-u-ca-gregory'))+'</div>':'')+'</div>';
  }).join('');
}

(async function(){try{var a=await (await fetch('/api/auth')).json();if(a.ok)home();else showLogin();}catch(e){showLogin();}})();
`;

const PAGE = '<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>لوحة قاعدة البيانات</title><style>'
    + CSS + '</style></head><body><div id="app"></div><script>' + CLIENT + '</script></body></html>';
app.get("/", (req, res) => { res.setHeader("Cache-Control", "no-store"); res.type("html").send(PAGE); });

mongoose.set("strictQuery", false);
mongoose.connect(MONGO_URI, { serverSelectionTimeoutMS: 20000 })
    .then(() => { console.log("✅ متصل بقاعدة البيانات"); app.listen(PORT, () => console.log("🗄️ لوحة قاعدة البيانات شغّالة على المنفذ " + PORT)); })
    .catch(e => { console.error("❌ فشل الاتصال بالقاعدة:", e.message); process.exit(1); });
