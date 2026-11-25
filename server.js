// ResearchHub server — Express + MongoDB (Atlas or self-hosted)
// Roles: admin (everything), supervisor (assigned students), reviewer (read + feedback on assigned students),
// student (own record only). Uploaded files are stored in MongoDB GridFS.
require('dotenv').config();
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const cookieParser = require('cookie-parser');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const rateLimit = require('express-rate-limit');
const { MongoClient, GridFSBucket, ObjectId } = require('mongodb');

const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.DB_NAME || 'researchhub';
const JWT_SECRET = process.env.JWT_SECRET;
const MAX_UPLOAD_MB = Number(process.env.MAX_UPLOAD_MB || 25);
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';
const ANTHROPIC_MODEL = process.env.ANTHROPIC_MODEL || 'claude-sonnet-5-5';
const COOKIE_SECURE = process.env.COOKIE_SECURE ? process.env.COOKIE_SECURE === 'true' : process.env.NODE_ENV === 'production';

if (!MONGODB_URI) { console.error('Missing MONGODB_URI in environment (.env).'); process.exit(1); }
if (!JWT_SECRET || JWT_SECRET.length < 24) { console.error('JWT_SECRET must be set to a long random string (24+ characters).'); process.exit(1); }

// ---------- Data model ----------
const ROLES = ['admin', 'supervisor', 'reviewer', 'student'];
const FIELDS = {
  students: ['name', 'track', 'degree', 'topic', 'coSupervisor', 'cadence', 'startDate', 'targetGraduation', 'nextMeetingDate'],
  milestones: ['phase', 'title', 'startDate', 'endDate', 'status', 'progress', 'deliverableUrl'],
  logs: ['date', 'author', 'completed', 'nextPlan', 'hasBlocker', 'blockerResolved', 'blockers', 'codeUrl', 'writingUrl', 'supervisorFeedback', 'agreedActionItems'],
  experiments: ['runId', 'title', 'date', 'config', 'metric', 'status', 'outcome', 'repoUrl', 'notes'],
  literature: ['title', 'authorsYear', 'venue', 'doi', 'doiVerified', 'method', 'dataset', 'limitations', 'relevance'],
  publications: ['title', 'venue', 'tier', 'authors', 'status', 'deadline', 'draftUrl', 'doi'],
  reviews: ['type', 'date', 'outcome', 'notes'],
  files: ['fileName', 'category', 'driveUrl', 'notes', 'uploadedBy', 'uploadedAt'],
  comments: ['text', 'section']
};
const CHILD_COLLS = Object.keys(FIELDS).filter(c => c !== 'students');
const SUPERVISOR_ONLY_FIELDS = { logs: ['supervisorFeedback', 'agreedActionItems'] };

const newId = (p) => `${p}_${Date.now().toString(36)}_${crypto.randomBytes(4).toString('hex')}`;
const today = () => new Date().toISOString().slice(0, 10);

function pick(coll, body, user) {
  const out = {};
  for (const k of FIELDS[coll]) {
    if (!(k in body)) continue;
    if (user.role === 'student' && (SUPERVISOR_ONLY_FIELDS[coll] || []).includes(k)) continue;
    let v = body[k];
    if (k === 'nextPlan') {
      v = Array.isArray(v) ? v.slice(0, 50).map(x => ({ id: String(x.id || newId('np')).slice(0, 60), text: String(x.text || '').slice(0, 1000), done: !!x.done })) : [];
    } else if (k === 'progress') {
      v = Math.max(0, Math.min(100, Number(v) || 0));
    } else if (typeof v === 'boolean') {
      // keep
    } else {
      v = String(v ?? '').slice(0, 20000);
    }
    out[k] = v;
  }
  return out;
}

// ---------- App ----------
let db, bucket;
const app = express();
app.set('trust proxy', 1);
app.use(express.json({ limit: '5mb' }));
app.use(cookieParser());

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false });
const aiLimiter = rateLimit({ windowMs: 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });

const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const publicUser = u => ({ id: u.id, email: u.email, name: u.name, role: u.role, studentId: u.studentId || null, assignedStudents: u.assignedStudents || [], mustChangePassword: !!u.mustChangePassword });

function setSession(res, user) {
  const token = jwt.sign({ uid: user.id, v: user.tokenVersion || 0 }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('rh_session', token, { httpOnly: true, sameSite: 'lax', secure: COOKIE_SECURE, maxAge: 7 * 24 * 3600 * 1000 });
}

const auth = wrap(async (req, res, next) => {
  const token = req.cookies.rh_session;
  if (!token) return res.status(401).json({ error: 'Not signed in' });
  let payload;
  try { payload = jwt.verify(token, JWT_SECRET); } catch { return res.status(401).json({ error: 'Session expired' }); }
  const user = await db.collection('users').findOne({ id: payload.uid });
  if (!user || user.disabled || (user.tokenVersion || 0) !== payload.v) return res.status(401).json({ error: 'Not signed in' });
  req.user = user;
  next();
});
const requireRole = (...roles) => (req, res, next) => roles.includes(req.user.role) ? next() : res.status(403).json({ error: 'Not allowed' });

async function visibleStudentIds(user) {
  if (user.role === 'admin') return (await db.collection('students').find({}, { projection: { id: 1 } }).toArray()).map(s => s.id);
  if (user.role === 'supervisor') return (await db.collection('students').find({ supervisorIds: user.id }, { projection: { id: 1 } }).toArray()).map(s => s.id);
  if (user.role === 'reviewer') return user.assignedStudents || [];
  if (user.role === 'student') return user.studentId ? [user.studentId] : [];
  return [];
}
async function canSee(user, studentId) { return (await visibleStudentIds(user)).includes(studentId); }

// What a role may write in a child collection
function canWriteColl(user, coll) {
  if (user.role === 'admin' || user.role === 'supervisor') return true;
  if (user.role === 'reviewer') return coll === 'comments';
  if (user.role === 'student') return coll !== 'reviews';
  return false;
}

// ---------- Auth routes ----------
app.post('/api/auth/login', loginLimiter, wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const user = await db.collection('users').findOne({ email });
  const ok = user && !user.disabled && await bcrypt.compare(String(req.body.password || ''), user.passwordHash);
  if (!ok) return res.status(401).json({ error: 'Wrong email or password' });
  await db.collection('users').updateOne({ id: user.id }, { $set: { lastLoginAt: new Date() } });
  setSession(res, user);
  res.json({ user: publicUser(user) });
}));
app.post('/api/auth/logout', (req, res) => { res.clearCookie('rh_session'); res.json({ ok: true }); });
app.get('/api/me', auth, (req, res) => res.json({ user: publicUser(req.user), aiEnabled: !!ANTHROPIC_API_KEY, maxUploadMb: MAX_UPLOAD_MB }));
app.post('/api/auth/change-password', auth, wrap(async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!newPassword || String(newPassword).length < 8) return res.status(400).json({ error: 'New password must be at least 8 characters' });
  if (!req.user.mustChangePassword && !(await bcrypt.compare(String(currentPassword || ''), req.user.passwordHash))) return res.status(400).json({ error: 'Current password is wrong' });
  const tokenVersion = (req.user.tokenVersion || 0) + 1;
  await db.collection('users').updateOne({ id: req.user.id }, { $set: { passwordHash: await bcrypt.hash(String(newPassword), 11), mustChangePassword: false, tokenVersion } });
  setSession(res, { ...req.user, tokenVersion });
  res.json({ ok: true });
}));

// ---------- Data ----------
app.get('/api/data', auth, wrap(async (req, res) => {
  const ids = await visibleStudentIds(req.user);
  const strip = d => { const { _id, ...rest } = d; return rest; };
  const out = { students: (await db.collection('students').find({ id: { $in: ids } }).sort({ name: 1 }).toArray()).map(strip) };
  for (const c of CHILD_COLLS) out[c] = (await db.collection(c).find({ studentId: { $in: ids } }).toArray()).map(strip);
  // People the viewer may see by name (for supervisor lists, comment authors)
  const users = await db.collection('users').find({}, { projection: { id: 1, name: 1, role: 1, email: 1 } }).toArray();
  out.people = users.filter(u => req.user.role !== 'student' || u.role !== 'student' || u.id === req.user.id).map(u => ({ id: u.id, name: u.name, role: u.role, email: req.user.role === 'admin' ? u.email : undefined }));
  res.json(out);
}));

// Students
app.post('/api/students', auth, requireRole('admin', 'supervisor'), wrap(async (req, res) => {
  const doc = { id: newId('stu'), ...pick('students', req.body, req.user), createdAt: new Date(), createdBy: req.user.id };
  if (!doc.name) return res.status(400).json({ error: 'Name is required' });
  doc.supervisorIds = req.user.role === 'admin' && Array.isArray(req.body.supervisorIds) ? req.body.supervisorIds.map(String) : [req.user.id];
  if (req.user.role === 'admin' && !doc.supervisorIds.includes(req.user.id) && !req.body.supervisorIds) doc.supervisorIds.push(req.user.id);
  await db.collection('students').insertOne(doc);
  if (req.body.seedMilestones !== false) {
    const phases = doc.track === 'PhD'
      ? ['1. Coursework & Qualifying Exam', '2. Systematic Lit Review', '3. Proposal & Candidacy', '4. Multi-Study Research', '5. Publications & Dissertation', '6. Pre-Defense & Final Viva']
      : ['1. Literature Review', '2. Research Proposal', '3. Experiments & Build', '4. Paper / Thesis Draft', '5. Final Defense'];
    await db.collection('milestones').insertMany(phases.map(p => ({ id: newId('ms'), studentId: doc.id, phase: p, title: p.replace(/^\d+\.\s*/, ''), startDate: '', endDate: '', status: 'Not Started', progress: 0, deliverableUrl: '' })));
  }
  res.json({ id: doc.id });
}));
app.put('/api/students/:id', auth, wrap(async (req, res) => {
  const id = req.params.id;
  if (!(await canSee(req.user, id))) return res.status(404).json({ error: 'Not found' });
  if (!['admin', 'supervisor'].includes(req.user.role)) return res.status(403).json({ error: 'Only supervisors can edit the student profile' });
  const set = pick('students', req.body, req.user);
  if (req.user.role === 'admin' && Array.isArray(req.body.supervisorIds)) set.supervisorIds = req.body.supervisorIds.map(String);
  await db.collection('students').updateOne({ id }, { $set: { ...set, updatedAt: new Date() } });
  res.json({ ok: true });
}));
app.delete('/api/students/:id', auth, requireRole('admin', 'supervisor'), wrap(async (req, res) => {
  const id = req.params.id;
  if (!(await canSee(req.user, id))) return res.status(404).json({ error: 'Not found' });
  const files = await db.collection('files').find({ studentId: id, gridId: { $exists: true } }).toArray();
  for (const f of files) { try { await bucket.delete(new ObjectId(f.gridId)); } catch {} }
  for (const c of CHILD_COLLS) await db.collection(c).deleteMany({ studentId: id });
  await db.collection('students').deleteOne({ id });
  await db.collection('users').updateMany({ studentId: id }, { $set: { studentId: null } });
  await db.collection('users').updateMany({}, { $pull: { assignedStudents: id } });
  res.json({ ok: true });
}));

// Generic child collections
app.post('/api/:coll(milestones|logs|experiments|literature|publications|reviews|files|comments)', auth, wrap(async (req, res) => {
  const coll = req.params.coll, studentId = String(req.body.studentId || '');
  if (!(await canSee(req.user, studentId))) return res.status(404).json({ error: 'Student not found' });
  if (!canWriteColl(req.user, coll)) return res.status(403).json({ error: 'Not allowed' });
  const doc = { id: newId(coll.slice(0, 3)), studentId, ...pick(coll, req.body, req.user), createdBy: req.user.id, createdAt: new Date() };
  if (coll === 'comments') { if (!doc.text) return res.status(400).json({ error: 'Empty comment' }); doc.authorId = req.user.id; doc.authorName = req.user.name; doc.authorRole = req.user.role; }
  await db.collection(coll).insertOne(doc);
  res.json({ id: doc.id });
}));
app.put('/api/:coll(milestones|logs|experiments|literature|publications|reviews|files|comments)/:id', auth, wrap(async (req, res) => {
  const coll = req.params.coll;
  const item = await db.collection(coll).findOne({ id: req.params.id });
  if (!item || !(await canSee(req.user, item.studentId))) return res.status(404).json({ error: 'Not found' });
  if (!canWriteColl(req.user, coll)) return res.status(403).json({ error: 'Not allowed' });
  if (coll === 'comments' && item.authorId !== req.user.id) return res.status(403).json({ error: 'You can only edit your own comments' });
  await db.collection(coll).updateOne({ id: item.id }, { $set: { ...pick(coll, req.body, req.user), updatedAt: new Date(), updatedBy: req.user.id } });
  res.json({ ok: true });
}));
app.delete('/api/:coll(milestones|logs|experiments|literature|publications|reviews|files|comments)/:id', auth, wrap(async (req, res) => {
  const coll = req.params.coll;
  const item = await db.collection(coll).findOne({ id: req.params.id });
  if (!item || !(await canSee(req.user, item.studentId))) return res.status(404).json({ error: 'Not found' });
  if (!canWriteColl(req.user, coll)) return res.status(403).json({ error: 'Not allowed' });
  if (coll === 'comments' && item.authorId !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'You can only delete your own comments' });
  if (coll === 'files' && item.gridId) { try { await bucket.delete(new ObjectId(item.gridId)); } catch {} }
  await db.collection(coll).deleteOne({ id: item.id });
  res.json({ ok: true });
}));

// ---------- File uploads (GridFS) ----------
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: MAX_UPLOAD_MB * 1024 * 1024, files: 10 } });
app.post('/api/upload', auth, upload.array('files', 10), wrap(async (req, res) => {
  const studentId = String(req.body.studentId || '');
  if (!(await canSee(req.user, studentId))) return res.status(404).json({ error: 'Student not found' });
  if (!canWriteColl(req.user, 'files')) return res.status(403).json({ error: 'Not allowed' });
  const saved = [];
  for (const f of req.files || []) {
    const name = String(f.originalname || 'file').replace(/[\\/\0]/g, '_').slice(0, 200);
    const gridId = await new Promise((resolve, reject) => {
      const s = bucket.openUploadStream(name, { metadata: { studentId, uploadedBy: req.user.id, contentType: f.mimetype } });
      s.on('error', reject); s.on('finish', () => resolve(s.id)); s.end(f.buffer);
    });
    const doc = {
      id: newId('fil'), studentId, gridId: String(gridId), fileName: name, size: f.size, mimeType: f.mimetype,
      category: String(req.body.category || 'Other').slice(0, 60), notes: String(req.body.notes || '').slice(0, 5000),
      uploadedBy: req.user.name, uploadedAt: today(), createdBy: req.user.id, createdAt: new Date(), driveUrl: ''
    };
    await db.collection('files').insertOne(doc);
    saved.push(doc.id);
  }
  res.json({ ids: saved });
}));
app.get('/api/files/:id/download', auth, wrap(async (req, res) => {
  const f = await db.collection('files').findOne({ id: req.params.id });
  if (!f || !f.gridId || !(await canSee(req.user, f.studentId))) return res.status(404).send('Not found');
  res.setHeader('Content-Type', f.mimeType || 'application/octet-stream');
  res.setHeader('Content-Disposition', `${req.query.inline ? 'inline' : 'attachment'}; filename*=UTF-8''${encodeURIComponent(f.fileName)}`);
  res.setHeader('X-Content-Type-Options', 'nosniff');
  bucket.openDownloadStream(new ObjectId(f.gridId)).on('error', () => res.status(404).end()).pipe(res);
}));

// ---------- Import (sample lab / backup merge) ----------
app.post('/api/import', auth, requireRole('admin', 'supervisor'), wrap(async (req, res) => {
  const data = req.body || {};
  const students = Array.isArray(data.students) ? data.students : [];
  const idMap = {};
  for (const s of students) {
    const doc = { id: newId('stu'), ...pick('students', s, req.user), supervisorIds: [req.user.id], createdAt: new Date(), createdBy: req.user.id };
    if (!doc.name) continue;
    idMap[s.id] = doc.id;
    await db.collection('students').insertOne(doc);
  }
  let n = 0;
  for (const c of CHILD_COLLS) {
    const items = (Array.isArray(data[c]) ? data[c] : []).filter(x => idMap[x.studentId]);
    if (!items.length) continue;
    await db.collection(c).insertMany(items.map(x => ({ id: newId(c.slice(0, 3)), studentId: idMap[x.studentId], ...pick(c, x, req.user), createdBy: req.user.id, createdAt: new Date() })));
    n += items.length;
  }
  res.json({ students: Object.keys(idMap).length, items: n, idMap });
}));

// ---------- User management (admin) ----------
app.get('/api/users', auth, requireRole('admin'), wrap(async (req, res) => {
  const users = await db.collection('users').find({}).sort({ role: 1, name: 1 }).toArray();
  res.json(users.map(u => ({ ...publicUser(u), disabled: !!u.disabled, lastLoginAt: u.lastLoginAt || null })));
}));
function tempPassword() { return crypto.randomBytes(9).toString('base64').replace(/[+/=]/g, '').slice(0, 12); }
app.post('/api/users', auth, requireRole('admin'), wrap(async (req, res) => {
  const email = String(req.body.email || '').trim().toLowerCase();
  const role = String(req.body.role || '');
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return res.status(400).json({ error: 'Enter a valid email' });
  if (!ROLES.includes(role)) return res.status(400).json({ error: 'Invalid role' });
  if (await db.collection('users').findOne({ email })) return res.status(400).json({ error: 'A user with this email already exists' });
  const password = tempPassword();
  const user = {
    id: newId('usr'), email, name: String(req.body.name || email).slice(0, 120), role,
    studentId: role === 'student' ? String(req.body.studentId || '') || null : null,
    assignedStudents: role === 'reviewer' && Array.isArray(req.body.assignedStudents) ? req.body.assignedStudents.map(String) : [],
    passwordHash: await bcrypt.hash(password, 11), mustChangePassword: true, tokenVersion: 0, createdAt: new Date()
  };
  await db.collection('users').insertOne(user);
  if (role === 'supervisor' && Array.isArray(req.body.assignedStudents)) await db.collection('students').updateMany({ id: { $in: req.body.assignedStudents.map(String) } }, { $addToSet: { supervisorIds: user.id } });
  res.json({ user: publicUser(user), tempPassword: password });
}));
app.put('/api/users/:id', auth, requireRole('admin'), wrap(async (req, res) => {
  const u = await db.collection('users').findOne({ id: req.params.id });
  if (!u) return res.status(404).json({ error: 'Not found' });
  const set = {};
  if (req.body.name !== undefined) set.name = String(req.body.name).slice(0, 120);
  if (req.body.role !== undefined && ROLES.includes(req.body.role)) {
    if (u.id === req.user.id && req.body.role !== 'admin') return res.status(400).json({ error: 'You cannot remove your own admin role' });
    set.role = req.body.role;
  }
  const role = set.role || u.role;
  if (req.body.studentId !== undefined) set.studentId = role === 'student' ? (String(req.body.studentId) || null) : null;
  if (Array.isArray(req.body.assignedStudents)) {
    if (role === 'reviewer') set.assignedStudents = req.body.assignedStudents.map(String);
    if (role === 'supervisor') {
      const ids = req.body.assignedStudents.map(String);
      await db.collection('students').updateMany({ supervisorIds: u.id, id: { $nin: ids } }, { $pull: { supervisorIds: u.id } });
      await db.collection('students').updateMany({ id: { $in: ids } }, { $addToSet: { supervisorIds: u.id } });
    }
  }
  if (req.body.disabled !== undefined) {
    if (u.id === req.user.id) return res.status(400).json({ error: 'You cannot disable yourself' });
    set.disabled = !!req.body.disabled; set.tokenVersion = (u.tokenVersion || 0) + 1;
  }
  let tempPw = null;
  if (req.body.resetPassword) { tempPw = tempPassword(); set.passwordHash = await bcrypt.hash(tempPw, 11); set.mustChangePassword = true; set.tokenVersion = (u.tokenVersion || 0) + 1; }
  await db.collection('users').updateOne({ id: u.id }, { $set: set });
  res.json({ ok: true, tempPassword: tempPw });
}));
app.delete('/api/users/:id', auth, requireRole('admin'), wrap(async (req, res) => {
  if (req.params.id === req.user.id) return res.status(400).json({ error: 'You cannot delete yourself' });
  await db.collection('users').deleteOne({ id: req.params.id });
  await db.collection('students').updateMany({}, { $pull: { supervisorIds: req.params.id } });
  res.json({ ok: true });
}));

// ---------- AI (optional, needs ANTHROPIC_API_KEY) ----------
async function callClaude(prompt, maxTokens = 2000) {
  const r = await fetch('https://api.anthropic.com/v1/messages', {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-api-key': ANTHROPIC_API_KEY, 'anthropic-version': '2023-06-01' },
    body: JSON.stringify({ model: ANTHROPIC_MODEL, max_tokens: maxTokens, messages: [{ role: 'user', content: prompt }] })
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(j?.error?.message || `AI request failed (${r.status})`);
  return (j.content || []).filter(b => b.type === 'text').map(b => b.text).join('');
}
async function digest(ids) {
  const out = [];
  for (const id of ids) {
    const s = await db.collection('students').findOne({ id });
    if (!s) continue;
    const q = c => db.collection(c).find({ studentId: id }).toArray();
    const [ms, logs, ex, pubs, revs, coms] = await Promise.all(['milestones', 'logs', 'experiments', 'publications', 'reviews', 'comments'].map(q));
    out.push({
      name: s.name, track: s.track, degree: s.degree, topic: s.topic, targetGraduation: s.targetGraduation, nextMeeting: s.nextMeetingDate,
      milestones: ms.map(m => ({ phase: m.phase, title: m.title, due: m.endDate, status: m.status, progress: m.progress })),
      recentLogs: logs.sort((a, b) => (b.date || '').localeCompare(a.date || '')).slice(0, 3).map(l => ({ date: l.date, completed: l.completed, openBlocker: l.hasBlocker && !l.blockerResolved ? l.blockers : '', nextPlan: (l.nextPlan || []).map(n => (n.done ? '[done] ' : '') + n.text), feedback: l.supervisorFeedback })),
      experiments: ex.map(e => ({ run: e.runId, title: e.title, status: e.status, metric: e.metric, outcome: e.outcome })),
      publications: pubs.map(p => ({ title: p.title, venue: p.venue, status: p.status, deadline: p.deadline })),
      reviews: revs.map(r => ({ type: r.type, date: r.date, outcome: r.outcome })),
      reviewerFeedback: coms.slice(-5).map(c => ({ by: c.authorName, text: c.text }))
    });
  }
  return out;
}
app.post('/api/ai/:kind(lab|student|extract)', auth, aiLimiter, wrap(async (req, res) => {
  if (!ANTHROPIC_API_KEY) return res.status(501).json({ error: 'AI is not set up on this server (ANTHROPIC_API_KEY missing).' });
  const kind = req.params.kind;
  if (kind === 'lab') {
    if (req.user.role === 'student') return res.status(403).json({ error: 'Not allowed' });
    const data = await digest(await visibleStudentIds(req.user));
    const text = await callClaude(`You are helping a university research supervisor prepare for the week. Using ONLY the JSON data below about their Master's and PhD students (today is ${today()}), write a concise lab briefing in plain text: 2-3 sentences on the overall picture, one short paragraph per student (progress, risks, deadlines within 30 days), then 'This week' with at most 6 concrete actions for the supervisor. Do not invent facts. No markdown headings or asterisks.\n\nDATA:\n${JSON.stringify(data)}`);
    return res.json({ text });
  }
  const studentId = String(req.body.studentId || '');
  if (!(await canSee(req.user, studentId))) return res.status(404).json({ error: 'Not found' });
  if (kind === 'student') {
    const audience = req.user.role === 'student' ? 'the student themselves preparing for a supervision meeting' : 'a research supervisor preparing for a one-to-one meeting';
    const text = await callClaude(`You are helping ${audience}. Using ONLY this JSON data about one student (today is ${today()}), write in plain text: 'Where things stand' (3 sentences), 'Risks' (bullets using •), and 'Questions for the meeting' (3-5 bullets using •). Do not invent facts. No markdown headings or asterisks.\n\nDATA:\n${JSON.stringify(await digest([studentId]))}`);
    return res.json({ text });
  }
  // extract
  const s = await db.collection('students').findOne({ id: studentId });
  const phases = s.track === 'PhD'
    ? ['1. Coursework & Qualifying Exam', '2. Systematic Lit Review', '3. Proposal & Candidacy', '4. Multi-Study Research', '5. Publications & Dissertation', '6. Pre-Defense & Final Viva']
    : ['1. Literature Review', '2. Research Proposal', '3. Experiments & Build', '4. Paper / Thesis Draft', '5. Final Defense'];
  const docText = String(req.body.text || '').slice(0, 60000);
  if (!docText.trim()) return res.status(400).json({ error: 'No text to read' });
  const raw = await callClaude(`Extract structured research-progress data from this graduate student's document. Today is ${today()}. Return ONLY a JSON object, no prose, with this shape:
{"milestones":[{"phase":"one of: ${phases.join(' | ')}","title":"","startDate":"YYYY-MM-DD","endDate":"YYYY-MM-DD","status":"Not Started|In Progress|Needs Review|Behind Schedule|Completed","progress":0}],
"logs":[{"date":"YYYY-MM-DD","completed":"","blockers":"","hasBlocker":false,"nextPlan":["..."]}],
"literature":[{"title":"","authorsYear":"","venue":"","doi":"","method":"","dataset":"","limitations":"","relevance":"High|Medium|Low"}],
"experiments":[{"runId":"","title":"","date":"","config":"","metric":"","status":"Backlog|In Progress|Needs Review|Done","outcome":"Baseline|Improved|Failed|Final","notes":""}],
"publications":[{"title":"","venue":"","tier":"","authors":"","status":"Idea|Drafting|Supervisor Review|Submitted|Under Review|Revision|Accepted|Published","deadline":""}]}
Use empty arrays when a section has nothing. Never invent DOIs, numbers or dates that are not in the text; leave them empty.

DOCUMENT:
${docText}`, 4000);
  const m = raw.match(/\{[\s\S]*\}/);
  let parsed = {};
  try { parsed = JSON.parse(m ? m[0] : raw); } catch { return res.status(502).json({ error: 'Could not read the AI answer. Try a shorter document.' }); }
  res.json({ parsed });
}));

// ---------- Static front end ----------
app.use(express.static(path.join(__dirname, 'public'), { index: 'index.html' }));
app.get('*', (req, res, next) => req.path.startsWith('/api/') ? next() : res.sendFile(path.join(__dirname, 'public', 'index.html')));
app.use((err, req, res, next) => {
  if (err && err.code === 'LIMIT_FILE_SIZE') return res.status(413).json({ error: `File too large (max ${MAX_UPLOAD_MB} MB)` });
  console.error(err);
  res.status(500).json({ error: 'Server error' });
});

// ---------- Start ----------
async function start() {
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  db = client.db(DB_NAME);
  bucket = new GridFSBucket(db, { bucketName: 'uploads' });
  await db.collection('users').createIndex({ email: 1 }, { unique: true });
  await db.collection('users').createIndex({ id: 1 }, { unique: true });
  await db.collection('students').createIndex({ id: 1 }, { unique: true });
  for (const c of CHILD_COLLS) { await db.collection(c).createIndex({ id: 1 }, { unique: true }); await db.collection(c).createIndex({ studentId: 1 }); }

  // First run: create the admin account from ADMIN_EMAIL / ADMIN_PASSWORD
  if ((await db.collection('users').countDocuments()) === 0) {
    const email = String(process.env.ADMIN_EMAIL || '').trim().toLowerCase();
    const password = String(process.env.ADMIN_PASSWORD || '');
    if (!email || password.length < 8) { console.error('First run: set ADMIN_EMAIL and ADMIN_PASSWORD (8+ chars) to create the admin account.'); process.exit(1); }
    await db.collection('users').insertOne({ id: newId('usr'), email, name: process.env.ADMIN_NAME || 'Administrator', role: 'admin', passwordHash: await bcrypt.hash(password, 11), mustChangePassword: false, tokenVersion: 0, createdAt: new Date() });
    console.log(`Created admin account for ${email}`);
  }
  app.listen(PORT, () => console.log(`ResearchHub running on http://localhost:${PORT}`));
}
if (require.main === module) start().catch(e => { console.error('Failed to start:', e.message); process.exit(1); });
module.exports = { app, start };
