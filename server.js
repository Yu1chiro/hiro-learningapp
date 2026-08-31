/**
 * PERSONAL JLPT N3 LEARNING OS — server.js
 * ---------------------------------------------------------
 * Node.js + Express + PostgreSQL (Neon) backend.
 * Session-based auth. Every registered user is `admin` — this
 * is a single-user personal application, role is always
 * decided server-side and never trusted from the client.
 * ---------------------------------------------------------
 */

require('dotenv').config();

const path = require('path');
const crypto = require('crypto');
const express = require('express');
const rateLimit = require('express-rate-limit');
const session = require('express-session');
const pgSessionFactory = require('connect-pg-simple');
const bcrypt = require('bcrypt');
const sanitizeHtml = require('sanitize-html');
const { Pool } = require('pg');

const NODE_ENV = process.env.NODE_ENV || 'development';
const IS_PROD = NODE_ENV === 'production';
const PORT = process.env.PORT || 3000;

if (!process.env.DATABASE_URL) {
  console.error('FATAL: DATABASE_URL is not set. Copy .env.example to .env and configure it.');
  process.exit(1);
}
if (!process.env.SESSION_SECRET) {
  console.error('FATAL: SESSION_SECRET is not set. Copy .env.example to .env and configure it.');
  process.exit(1);
}

// ---------------------------------------------------------
// Database pool
// ---------------------------------------------------------
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: IS_PROD ? { rejectUnauthorized: false } : false,
});

pool.on('error', (err) => {
  console.error('Unexpected PostgreSQL pool error:', err.message);
});

// ---------------------------------------------------------
// App-level error type + response helpers (section 42 format)
// ---------------------------------------------------------
class AppError extends Error {
  constructor(message, status = 400, details) {
    super(message);
    this.status = status;
    this.details = details;
  }
}

const ok = (res, data, status = 200) => res.status(status).json({ success: true, data });
const fail = (res, message, status = 400, details) => {
  const body = { success: false, message };
  if (details !== undefined) body.details = details;
  return res.status(status).json(body);
};

const ah = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ---------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------
const isNonEmptyString = (v) => typeof v === 'string' && v.trim().length > 0;
const isEmail = (v) => typeof v === 'string' && /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/.test(v);
const isUsername = (v) => typeof v === 'string' && /^[A-Za-z0-9_.-]{3,50}$/.test(v);
const isStrongPassword = (v) => typeof v === 'string' && v.length >= 8 && /[A-Za-z]/.test(v) && /[0-9]/.test(v);
const toInt = (v) => {
  const n = Number(v);
  return Number.isInteger(n) ? n : NaN;
};
const isPositiveInt = (v) => Number.isInteger(v) && v > 0;
const ANSWER_KEYS = ['a', 'b', 'c', 'd'];
const CONTENT_TYPES = ['grammar', 'vocabulary', 'kanji'];
const MATERIAL_TYPES = ['grammar', 'vocabulary', 'kanji', 'reading', 'note', 'general'];
const DIFFICULTIES = ['easy', 'medium', 'hard'];
const QUESTION_TYPES = [
  'meaning', 'reading', 'usage', 'context', 'grammar_selection',
  'sentence_completion', 'kanji_reading', 'kanji_meaning',
  'vocabulary_reading', 'vocabulary_meaning', 'similar_word_discrimination',
];

const CONTENT_TABLE = { grammar: 'grammar', vocabulary: 'vocabulary', kanji: 'kanji' };
const CONTENT_LABEL_COLUMN = { grammar: 'pattern', vocabulary: 'word', kanji: 'character' };

const toSafeUser = (u) => ({
  id: u.id,
  username: u.username,
  email: u.email,
  role: u.role,
  created_at: u.created_at,
  updated_at: u.updated_at,
});

// ---------------------------------------------------------
// HTML sanitization for Quill-authored content (stored XSS guard)
// ---------------------------------------------------------
function sanitizeQuillHtml(html) {
  return sanitizeHtml(html || '', {
    allowedTags: [
      'p', 'br', 'strong', 'em', 'u', 's', 'a', 'span', 'div',
      'h1', 'h2', 'h3', 'ol', 'ul', 'li', 'blockquote', 'pre', 'code',
    ],
    allowedAttributes: {
      a: ['href', 'target', 'rel'],
      span: ['class'],
      div: ['class'],
      p: ['class'],
      li: ['class', 'data-list'],
      ol: ['class'],
      ul: ['class'],
      pre: ['class', 'spellcheck'],
      code: ['class'],
    },
    allowedClasses: { '*': [/^ql-/] },
    allowedSchemes: ['http', 'https', 'mailto'],
    disallowedTagsMode: 'discard',
    transformTags: {
      a: sanitizeHtml.simpleTransform('a', { target: '_blank', rel: 'noopener noreferrer' }),
    },
  });
}

// ---------------------------------------------------------
// Content resolution
// ---------------------------------------------------------
async function resolveContentId(client, lessonId, contentType, ref) {
  const table = CONTENT_TABLE[contentType];
  const labelCol = CONTENT_LABEL_COLUMN[contentType];
  if (!table) throw new AppError(`content_type tidak valid: ${contentType}`, 422);

  if (ref.content_id !== undefined && ref.content_id !== null && ref.content_id !== '') {
    const cid = toInt(ref.content_id);
    if (!isPositiveInt(cid)) throw new AppError('content_id tidak valid', 422);
    const r = await client.query(
      `SELECT id FROM ${table} WHERE id = $1 AND lesson_id = $2`,
      [cid, lessonId]
    );
    if (r.rowCount === 0) {
      throw new AppError(`content_id ${cid} tidak ditemukan pada lesson ini (${contentType})`, 422);
    }
    return cid;
  }

  if (isNonEmptyString(ref.content_reference)) {
    const r = await client.query(
      `SELECT id FROM ${table} WHERE lesson_id = $1 AND ${labelCol} = $2 LIMIT 1`,
      [lessonId, ref.content_reference.trim()]
    );
    if (r.rowCount === 0) {
      throw new AppError(
        `content_reference "${ref.content_reference}" tidak ditemukan pada ${contentType} di lesson ini`,
        422
      );
    }
    return r.rows[0].id;
  }

  throw new AppError('content_id atau content_reference wajib diisi', 422);
}

// ---------------------------------------------------------
// Express app setup
// ---------------------------------------------------------
const app = express();
if (IS_PROD) app.set('trust proxy', 1);

app.use(express.json({ limit: '300kb' }));
app.use(express.urlencoded({ extended: false, limit: '300kb' }));

app.use((err, req, res, next) => {
  if (err && err.type === 'entity.parse.failed') {
    return fail(res, 'JSON body tidak valid', 400);
  }
  if (err && err.type === 'entity.too.large') {
    return fail(res, 'Ukuran request terlalu besar', 413);
  }
  next(err);
});

// ---------------------------------------------------------
// Session
// ---------------------------------------------------------
const PgSession = pgSessionFactory(session);
const SEVEN_DAYS_MS = 7 * 24 * 60 * 60 * 1000;

app.use(session({
  name: 'jlpt_sid',
  store: new PgSession({ pool, tableName: 'user_sessions', createTableIfMissing: true }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,
    secure: IS_PROD,
    sameSite: 'lax',
    maxAge: SEVEN_DAYS_MS,
  },
}));

// ---------------------------------------------------------
// Rate limiting
// ---------------------------------------------------------
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => fail(res, 'Terlalu banyak permintaan, coba lagi nanti', 429),
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => fail(res, 'Terlalu banyak percobaan, coba lagi nanti', 429),
});

function verifyOrigin(req, res, next) {
  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(req.method)) {
    const originHeader = req.headers.origin || req.headers.referer;
    if (originHeader) {
      try {
        const originHost = new URL(originHeader).host;
        if (originHost !== req.headers.host) {
          return fail(res, 'Permintaan ditolak (origin tidak valid)', 403);
        }
      } catch (e) {
        return fail(res, 'Permintaan ditolak', 403);
      }
    }
  }
  next();
}

function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return fail(res, 'Sesi tidak valid atau telah berakhir. Silakan login kembali.', 401);
  }
  next();
}

const apiRouter = express.Router();
apiRouter.use(apiLimiter);
apiRouter.use(verifyOrigin);

// =========================================================
// AUTH ROUTES
// =========================================================
apiRouter.post('/auth/register', authLimiter, ah(async (req, res) => {
  const { username, email, password } = req.body || {};

  if (!isUsername(username)) {
    return fail(res, 'Username harus 3-50 karakter (huruf, angka, titik, garis bawah, atau strip)', 422);
  }
  if (!isEmail(email)) {
    return fail(res, 'Format email tidak valid', 422);
  }
  if (!isStrongPassword(password)) {
    return fail(res, 'Password minimal 8 karakter dan mengandung huruf serta angka', 422);
  }

  const client = await pool.connect();
  try {
    const existing = await client.query(
      'SELECT id FROM users WHERE username = $1 OR email = $2',
      [username, email]
    );
    if (existing.rowCount > 0) {
      return fail(res, 'Username atau email sudah digunakan', 409);
    }

    const passwordHash = await bcrypt.hash(password, 12);
    const result = await client.query(
      `INSERT INTO users (username, email, password_hash, role)
       VALUES ($1, $2, $3, 'admin')
       RETURNING id, username, email, role, created_at, updated_at`,
      [username, email, passwordHash]
    );
    const user = result.rows[0];

    req.session.regenerate((err) => {
      if (err) return fail(res, 'Gagal membuat sesi', 500);
      req.session.userId = user.id;
      req.session.save(() => ok(res, { user: toSafeUser(user) }, 201));
    });
  } finally {
    client.release();
  }
}));

apiRouter.post('/auth/login', authLimiter, ah(async (req, res) => {
  const { identifier, username, email, password } = req.body || {};
  const loginId = identifier || username || email;

  if (!isNonEmptyString(loginId) || !isNonEmptyString(password)) {
    return fail(res, 'Username/email dan password wajib diisi', 422);
  }

  const result = await pool.query(
    'SELECT * FROM users WHERE username = $1 OR email = $1',
    [loginId]
  );

  const GENERIC_ERROR = 'Username/email atau password salah';
  if (result.rowCount === 0) {
    return fail(res, GENERIC_ERROR, 401);
  }

  const user = result.rows[0];
  const matches = await bcrypt.compare(password, user.password_hash);
  if (!matches) {
    return fail(res, GENERIC_ERROR, 401);
  }

  req.session.regenerate((err) => {
    if (err) return fail(res, 'Gagal membuat sesi', 500);
    req.session.userId = user.id;
    req.session.save(() => ok(res, { user: toSafeUser(user) }));
  });
}));

apiRouter.post('/auth/logout', ah(async (req, res) => {
  const cookieName = 'jlpt_sid';
  req.session.destroy((err) => {
    res.clearCookie(cookieName);
    if (err) return fail(res, 'Gagal logout', 500);
    return ok(res, { loggedOut: true });
  });
}));

apiRouter.get('/auth/me', requireAuth, ah(async (req, res) => {
  const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.session.userId]);
  if (result.rowCount === 0) {
    req.session.destroy(() => {});
    return fail(res, 'Sesi tidak valid atau telah berakhir. Silakan login kembali.', 401);
  }
  return ok(res, { user: toSafeUser(result.rows[0]) });
}));

// =========================================================
// LESSONS
// =========================================================
apiRouter.get('/lessons', requireAuth, ah(async (req, res) => {
  const result = await pool.query('SELECT * FROM lessons ORDER BY study_date DESC NULLS LAST, created_at DESC');
  return ok(res, result.rows);
}));

apiRouter.get('/lessons/:id', requireAuth, ah(async (req, res) => {
  const id = toInt(req.params.id);
  if (!isPositiveInt(id)) return fail(res, 'ID lesson tidak valid', 422);
  const result = await pool.query('SELECT * FROM lessons WHERE id = $1', [id]);
  if (result.rowCount === 0) return fail(res, 'Lesson tidak ditemukan', 404);
  return ok(res, result.rows[0]);
}));

apiRouter.get('/lessons/:id/export', requireAuth, ah(async (req, res) => {
  const id = toInt(req.params.id);
  if (!isPositiveInt(id)) return fail(res, 'ID lesson tidak valid', 422);

  const lessonResult = await pool.query('SELECT * FROM lessons WHERE id = $1', [id]);
  if (lessonResult.rowCount === 0) return fail(res, 'Lesson tidak ditemukan', 404);

  const materials = await pool.query('SELECT * FROM study_materials WHERE lesson_id = $1 ORDER BY order_index ASC', [id]);
  const grammar = await pool.query('SELECT * FROM grammar WHERE lesson_id = $1 ORDER BY created_at ASC', [id]);
  const vocabulary = await pool.query('SELECT * FROM vocabulary WHERE lesson_id = $1 ORDER BY created_at ASC', [id]);
  const kanji = await pool.query('SELECT * FROM kanji WHERE lesson_id = $1 ORDER BY created_at ASC', [id]);
  const questions = await pool.query('SELECT * FROM questions WHERE lesson_id = $1 ORDER BY created_at ASC', [id]);

  return ok(res, {
    lesson: lessonResult.rows[0],
    materials: materials.rows,
    grammar: grammar.rows,
    vocabulary: vocabulary.rows,
    kanji: kanji.rows,
    questions: questions.rows
  });
}));

apiRouter.post('/lessons', requireAuth, ah(async (req, res) => {
  const { title, description, study_date } = req.body || {};
  if (!isNonEmptyString(title)) return fail(res, 'Judul lesson wajib diisi', 422);
  const result = await pool.query(
    `INSERT INTO lessons (title, description, study_date) VALUES ($1, $2, $3) RETURNING *`,
    [title.trim(), description || null, study_date || null]
  );
  return ok(res, result.rows[0], 201);
}));

apiRouter.put('/lessons/:id', requireAuth, ah(async (req, res) => {
  const id = toInt(req.params.id);
  if (!isPositiveInt(id)) return fail(res, 'ID lesson tidak valid', 422);
  const { title, description, study_date } = req.body || {};
  if (!isNonEmptyString(title)) return fail(res, 'Judul lesson wajib diisi', 422);
  const result = await pool.query(
    `UPDATE lessons SET title = $1, description = $2, study_date = $3 WHERE id = $4 RETURNING *`,
    [title.trim(), description || null, study_date || null, id]
  );
  if (result.rowCount === 0) return fail(res, 'Lesson tidak ditemukan', 404);
  return ok(res, result.rows[0]);
}));

apiRouter.delete('/lessons/:id', requireAuth, ah(async (req, res) => {
  const id = toInt(req.params.id);
  if (!isPositiveInt(id)) return fail(res, 'ID lesson tidak valid', 422);
  const result = await pool.query('DELETE FROM lessons WHERE id = $1 RETURNING id', [id]);
  if (result.rowCount === 0) return fail(res, 'Lesson tidak ditemukan', 404);
  return ok(res, { deleted: true });
}));

// =========================================================
// STUDY MATERIALS
// =========================================================
apiRouter.get('/materials', requireAuth, ah(async (req, res) => {
  const lessonId = req.query.lesson_id ? toInt(req.query.lesson_id) : null;
  if (req.query.lesson_id && !isPositiveInt(lessonId)) return fail(res, 'lesson_id tidak valid', 422);
  const result = lessonId
    ? await pool.query('SELECT * FROM study_materials WHERE lesson_id = $1 ORDER BY order_index ASC, created_at ASC', [lessonId])
    : await pool.query('SELECT * FROM study_materials ORDER BY created_at DESC');
  return ok(res, result.rows);
}));

apiRouter.get('/materials/:id', requireAuth, ah(async (req, res) => {
  const id = toInt(req.params.id);
  if (!isPositiveInt(id)) return fail(res, 'ID material tidak valid', 422);
  const result = await pool.query('SELECT * FROM study_materials WHERE id = $1', [id]);
  if (result.rowCount === 0) return fail(res, 'Study material tidak ditemukan', 404);
  return ok(res, result.rows[0]);
}));

apiRouter.post('/materials', requireAuth, ah(async (req, res) => {
  const { lesson_id, title, content_html, material_type, order_index } = req.body || {};
  const lessonId = toInt(lesson_id);
  if (!isPositiveInt(lessonId)) return fail(res, 'lesson_id wajib diisi dan valid', 422);
  if (!isNonEmptyString(title)) return fail(res, 'Judul material wajib diisi', 422);
  if (!isNonEmptyString(content_html)) return fail(res, 'Konten material wajib diisi', 422);
  const type = MATERIAL_TYPES.includes(material_type) ? material_type : 'general';

  const lessonCheck = await pool.query('SELECT id FROM lessons WHERE id = $1', [lessonId]);
  if (lessonCheck.rowCount === 0) return fail(res, 'Lesson tidak ditemukan', 404);

  const clean = sanitizeQuillHtml(content_html);
  const result = await pool.query(
    `INSERT INTO study_materials (lesson_id, title, content_html, material_type, order_index)
     VALUES ($1, $2, $3, $4, $5) RETURNING *`,
    [lessonId, title.trim(), clean, type, Number.isInteger(order_index) ? order_index : 0]
  );
  return ok(res, result.rows[0], 201);
}));

apiRouter.put('/materials/:id', requireAuth, ah(async (req, res) => {
  const id = toInt(req.params.id);
  if (!isPositiveInt(id)) return fail(res, 'ID material tidak valid', 422);
  const { title, content_html, material_type, order_index } = req.body || {};
  if (!isNonEmptyString(title)) return fail(res, 'Judul material wajib diisi', 422);
  if (!isNonEmptyString(content_html)) return fail(res, 'Konten material wajib diisi', 422);
  const type = MATERIAL_TYPES.includes(material_type) ? material_type : 'general';
  const clean = sanitizeQuillHtml(content_html);

  const result = await pool.query(
    `UPDATE study_materials SET title = $1, content_html = $2, material_type = $3, order_index = $4
     WHERE id = $5 RETURNING *`,
    [title.trim(), clean, type, Number.isInteger(order_index) ? order_index : 0, id]
  );
  if (result.rowCount === 0) return fail(res, 'Study material tidak ditemukan', 404);
  return ok(res, result.rows[0]);
}));

apiRouter.delete('/materials/:id', requireAuth, ah(async (req, res) => {
  const id = toInt(req.params.id);
  if (!isPositiveInt(id)) return fail(res, 'ID material tidak valid', 422);
  const result = await pool.query('DELETE FROM study_materials WHERE id = $1 RETURNING id', [id]);
  if (result.rowCount === 0) return fail(res, 'Study material tidak ditemukan', 404);
  return ok(res, { deleted: true });
}));

// =========================================================
// GRAMMAR / VOCABULARY / KANJI
// =========================================================
function registerContentCrud(routePath, table, requiredFields, optionalFields) {
  const allFields = [...requiredFields, ...optionalFields];

  apiRouter.get(`/${routePath}`, requireAuth, ah(async (req, res) => {
    const lessonId = req.query.lesson_id ? toInt(req.query.lesson_id) : null;
    if (req.query.lesson_id && !isPositiveInt(lessonId)) return fail(res, 'lesson_id tidak valid', 422);
    const result = lessonId
      ? await pool.query(`SELECT * FROM ${table} WHERE lesson_id = $1 ORDER BY created_at ASC`, [lessonId])
      : await pool.query(`SELECT * FROM ${table} ORDER BY created_at DESC`);
    return ok(res, result.rows);
  }));

  apiRouter.get(`/${routePath}/:id`, requireAuth, ah(async (req, res) => {
    const id = toInt(req.params.id);
    if (!isPositiveInt(id)) return fail(res, 'ID tidak valid', 422);
    const result = await pool.query(`SELECT * FROM ${table} WHERE id = $1`, [id]);
    if (result.rowCount === 0) return fail(res, 'Data tidak ditemukan', 404);
    return ok(res, result.rows[0]);
  }));

  apiRouter.post(`/${routePath}`, requireAuth, ah(async (req, res) => {
    const body = req.body || {};
    const lessonId = toInt(body.lesson_id);
    if (!isPositiveInt(lessonId)) return fail(res, 'lesson_id wajib diisi dan valid', 422);
    for (const f of requiredFields) {
      if (!isNonEmptyString(body[f])) return fail(res, `Field "${f}" wajib diisi`, 422);
    }
    const lessonCheck = await pool.query('SELECT id FROM lessons WHERE id = $1', [lessonId]);
    if (lessonCheck.rowCount === 0) return fail(res, 'Lesson tidak ditemukan', 404);

    const cols = ['lesson_id', ...allFields];
    const vals = [lessonId, ...allFields.map((f) => (isNonEmptyString(body[f]) ? body[f].trim() : (body[f] || null)))];
    const placeholders = cols.map((_, i) => `$${i + 1}`).join(', ');
    const result = await pool.query(
      `INSERT INTO ${table} (${cols.join(', ')}) VALUES (${placeholders}) RETURNING *`,
      vals
    );
    return ok(res, result.rows[0], 201);
  }));

  apiRouter.put(`/${routePath}/:id`, requireAuth, ah(async (req, res) => {
    const id = toInt(req.params.id);
    if (!isPositiveInt(id)) return fail(res, 'ID tidak valid', 422);
    const body = req.body || {};
    for (const f of requiredFields) {
      if (!isNonEmptyString(body[f])) return fail(res, `Field "${f}" wajib diisi`, 422);
    }
    const setClauses = allFields.map((f, i) => `${f} = $${i + 1}`).join(', ');
    const vals = allFields.map((f) => (isNonEmptyString(body[f]) ? body[f].trim() : (body[f] || null)));
    vals.push(id);
    const result = await pool.query(
      `UPDATE ${table} SET ${setClauses} WHERE id = $${vals.length} RETURNING *`,
      vals
    );
    if (result.rowCount === 0) return fail(res, 'Data tidak ditemukan', 404);
    return ok(res, result.rows[0]);
  }));

  apiRouter.delete(`/${routePath}/:id`, requireAuth, ah(async (req, res) => {
    const id = toInt(req.params.id);
    if (!isPositiveInt(id)) return fail(res, 'ID tidak valid', 422);
    const result = await pool.query(`DELETE FROM ${table} WHERE id = $1 RETURNING id`, [id]);
    if (result.rowCount === 0) return fail(res, 'Data tidak ditemukan', 404);
    return ok(res, { deleted: true });
  }));
}

registerContentCrud('grammar', 'grammar', ['pattern', 'meaning'], ['explanation', 'example_sentence', 'example_translation']);
registerContentCrud('vocabulary', 'vocabulary', ['word', 'meaning'], ['reading', 'part_of_speech', 'example_sentence', 'example_translation']);
registerContentCrud('kanji', 'kanji', ['character', 'meaning'], ['onyomi', 'kunyomi', 'example_word', 'example_reading', 'example_sentence']);

// =========================================================
// QUESTIONS
// =========================================================
async function validateQuestionCore(client, lessonId, body) {
  const errors = [];
  const b = body || {};

  if (!CONTENT_TYPES.includes(b.content_type)) {
    errors.push('content_type wajib salah satu dari: grammar, vocabulary, kanji');
  }
  if (!QUESTION_TYPES.includes(b.question_type)) {
    errors.push(`question_type tidak valid (pilihan: ${QUESTION_TYPES.join(', ')})`);
  }
  if (!isNonEmptyString(b.question_text)) errors.push('question_text wajib diisi');

  const options = b.options && typeof b.options === 'object' ? b.options : b;
  const option_a = options.option_a ?? options.a;
  const option_b = options.option_b ?? options.b;
  const option_c = options.option_c ?? options.c;
  const option_d = options.option_d ?? options.d;
  if (!isNonEmptyString(option_a)) errors.push('option_a wajib diisi');
  if (!isNonEmptyString(option_b)) errors.push('option_b wajib diisi');
  if (!isNonEmptyString(option_c)) errors.push('option_c wajib diisi');
  if (!isNonEmptyString(option_d)) errors.push('option_d wajib diisi');

  const correct_answer = typeof b.correct_answer === 'string' ? b.correct_answer.trim().toLowerCase() : b.correct_answer;
  if (!ANSWER_KEYS.includes(correct_answer)) {
    errors.push('correct_answer wajib salah satu dari: a, b, c, d');
  }

  if (!isNonEmptyString(b.explanation)) errors.push('explanation wajib diisi');

  const difficulty = typeof b.difficulty === 'string' ? b.difficulty.trim().toLowerCase() : b.difficulty;
  if (!DIFFICULTIES.includes(difficulty)) {
    errors.push('difficulty wajib salah satu dari: easy, medium, hard');
  }

  let points = 10;
  if (b.points !== undefined && b.points !== null && b.points !== '') {
    const p = toInt(b.points);
    if (!isPositiveInt(p)) errors.push('points harus bilangan bulat positif');
    else points = p;
  }

  let content_id = null;
  if (CONTENT_TYPES.includes(b.content_type)) {
    try {
      content_id = await resolveContentId(client, lessonId, b.content_type, {
        content_id: b.content_id,
        content_reference: b.content_reference,
      });
    } catch (e) {
      errors.push(e.message);
    }
  } else {
    errors.push('content_id/content_reference tidak dapat divalidasi karena content_type tidak valid');
  }

  if (errors.length > 0) {
    const err = new AppError('Validasi question gagal', 422, errors);
    err.fieldErrors = errors;
    throw err;
  }

  return {
    lesson_id: lessonId,
    content_type: b.content_type,
    content_id,
    question_type: b.question_type,
    question_text: b.question_text.trim(),
    option_a: option_a.trim(),
    option_b: option_b.trim(),
    option_c: option_c.trim(),
    option_d: option_d.trim(),
    correct_answer,
    explanation: b.explanation.trim(),
    difficulty,
    points,
  };
}

apiRouter.get('/questions', requireAuth, ah(async (req, res) => {
  const lessonId = req.query.lesson_id ? toInt(req.query.lesson_id) : null;
  if (req.query.lesson_id && !isPositiveInt(lessonId)) return fail(res, 'lesson_id tidak valid', 422);
  const params = [];
  let sql = 'SELECT * FROM questions';
  if (lessonId) {
    params.push(lessonId);
    sql += ' WHERE lesson_id = $1';
  }
  sql += ' ORDER BY created_at DESC';
  const result = await pool.query(sql, params);
  return ok(res, result.rows);
}));

apiRouter.get('/questions/:id', requireAuth, ah(async (req, res) => {
  const id = toInt(req.params.id);
  if (!isPositiveInt(id)) return fail(res, 'ID question tidak valid', 422);
  const result = await pool.query('SELECT * FROM questions WHERE id = $1', [id]);
  if (result.rowCount === 0) return fail(res, 'Question tidak ditemukan', 404);
  return ok(res, result.rows[0]);
}));

apiRouter.post('/questions', requireAuth, ah(async (req, res) => {
  const lessonId = toInt((req.body || {}).lesson_id);
  if (!isPositiveInt(lessonId)) return fail(res, 'lesson_id wajib diisi dan valid', 422);
  const lessonCheck = await pool.query('SELECT id FROM lessons WHERE id = $1', [lessonId]);
  if (lessonCheck.rowCount === 0) return fail(res, 'Lesson tidak ditemukan', 404);

  const q = await validateQuestionCore(pool, lessonId, req.body);
  const result = await pool.query(
    `INSERT INTO questions
       (lesson_id, content_type, content_id, question_type, question_text,
        option_a, option_b, option_c, option_d, correct_answer, explanation, difficulty, points)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING *`,
    [q.lesson_id, q.content_type, q.content_id, q.question_type, q.question_text,
     q.option_a, q.option_b, q.option_c, q.option_d, q.correct_answer, q.explanation, q.difficulty, q.points]
  );
  return ok(res, result.rows[0], 201);
}));

apiRouter.put('/questions/:id', requireAuth, ah(async (req, res) => {
  const id = toInt(req.params.id);
  if (!isPositiveInt(id)) return fail(res, 'ID question tidak valid', 422);

  const existing = await pool.query('SELECT lesson_id FROM questions WHERE id = $1', [id]);
  if (existing.rowCount === 0) return fail(res, 'Question tidak ditemukan', 404);
  const lessonId = existing.rows[0].lesson_id;

  const q = await validateQuestionCore(pool, lessonId, req.body);
  const result = await pool.query(
    `UPDATE questions SET content_type=$1, content_id=$2, question_type=$3, question_text=$4,
       option_a=$5, option_b=$6, option_c=$7, option_d=$8, correct_answer=$9,
       explanation=$10, difficulty=$11, points=$12
     WHERE id = $13 RETURNING *`,
    [q.content_type, q.content_id, q.question_type, q.question_text,
     q.option_a, q.option_b, q.option_c, q.option_d, q.correct_answer,
     q.explanation, q.difficulty, q.points, id]
  );
  return ok(res, result.rows[0]);
}));

apiRouter.delete('/questions/:id', requireAuth, ah(async (req, res) => {
  const id = toInt(req.params.id);
  if (!isPositiveInt(id)) return fail(res, 'ID question tidak valid', 422);
  const result = await pool.query('DELETE FROM questions WHERE id = $1 RETURNING id', [id]);
  if (result.rowCount === 0) return fail(res, 'Question tidak ditemukan', 404);
  return ok(res, { deleted: true });
}));

// =========================================================
// QUESTION IMPORT
// =========================================================
async function validateImportBatch(client, lessonId, questions) {
  const results = [];
  for (let i = 0; i < questions.length; i++) {
    try {
      const resolved = await validateQuestionCore(client, lessonId, questions[i]);
      results.push({ index: i, valid: true, errors: [], resolved });
    } catch (e) {
      const errors = e.fieldErrors || [e.message];
      results.push({ index: i, valid: false, errors, resolved: null });
    }
  }
  return results;
}

apiRouter.post('/questions/validate-import', requireAuth, ah(async (req, res) => {
  const { lesson_id, questions } = req.body || {};
  const lessonId = toInt(lesson_id);
  if (!isPositiveInt(lessonId)) return fail(res, 'lesson_id wajib diisi dan valid', 422);
  if (!Array.isArray(questions) || questions.length === 0) {
    return fail(res, 'questions harus berupa array dan tidak boleh kosong', 422);
  }
  if (questions.length > 200) {
    return fail(res, 'Maksimal 200 question per import', 422);
  }

  const lessonCheck = await pool.query('SELECT id, title FROM lessons WHERE id = $1', [lessonId]);
  if (lessonCheck.rowCount === 0) return fail(res, 'Lesson tidak ditemukan', 404);

  const results = await validateImportBatch(pool, lessonId, questions);
  const valid_count = results.filter((r) => r.valid).length;
  const invalid_count = results.length - valid_count;

  return ok(res, {
    lesson: lessonCheck.rows[0],
    total: results.length,
    valid_count,
    invalid_count,
    can_import: invalid_count === 0,
    results,
  });
}));

apiRouter.post('/questions/import', requireAuth, ah(async (req, res) => {
  const { lesson_id, questions, confirm } = req.body || {};
  const lessonId = toInt(lesson_id);
  if (!isPositiveInt(lessonId)) return fail(res, 'lesson_id wajib diisi dan valid', 422);
  if (!Array.isArray(questions) || questions.length === 0) {
    return fail(res, 'questions harus berupa array dan tidak boleh kosong', 422);
  }
  if (confirm !== true) {
    return fail(res, 'Import harus dikonfirmasi setelah preview (confirm: true)', 422);
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const lessonCheck = await client.query('SELECT id FROM lessons WHERE id = $1', [lessonId]);
    if (lessonCheck.rowCount === 0) {
      await client.query('ROLLBACK');
      return fail(res, 'Lesson tidak ditemukan', 404);
    }

    const results = await validateImportBatch(client, lessonId, questions);
    const invalid = results.filter((r) => !r.valid);
    if (invalid.length > 0) {
      await client.query('ROLLBACK');
      return fail(res, `${invalid.length} question tidak valid, import dibatalkan`, 422, results);
    }

    const inserted = [];
    for (const r of results) {
      const q = r.resolved;
      const insertResult = await client.query(
        `INSERT INTO questions
           (lesson_id, content_type, content_id, question_type, question_text,
            option_a, option_b, option_c, option_d, correct_answer, explanation, difficulty, points)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13) RETURNING id`,
        [q.lesson_id, q.content_type, q.content_id, q.question_type, q.question_text,
         q.option_a, q.option_b, q.option_c, q.option_d, q.correct_answer, q.explanation, q.difficulty, q.points]
      );
      inserted.push(insertResult.rows[0].id);
    }

    await client.query('COMMIT');
    return ok(res, { imported_count: inserted.length, question_ids: inserted }, 201);
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }
}));

// =========================================================
// QUIZ ENGINE
// =========================================================
function shuffle(arr) {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = crypto.randomInt(0, i + 1);
    [a[i], a[j]] = [a[j], a[i]];
  }
  return a;
}

apiRouter.get('/quiz/:lessonId', requireAuth, ah(async (req, res) => {
  const lessonId = toInt(req.params.lessonId);
  if (!isPositiveInt(lessonId)) return fail(res, 'lessonId tidak valid', 422);

  const lessonResult = await pool.query('SELECT * FROM lessons WHERE id = $1', [lessonId]);
  if (lessonResult.rowCount === 0) return fail(res, 'Lesson tidak ditemukan', 404);

  const questionsResult = await pool.query(
    'SELECT * FROM questions WHERE lesson_id = $1',
    [lessonId]
  );
  if (questionsResult.rowCount === 0) {
    return fail(res, 'Lesson ini belum memiliki question. Tambahkan question terlebih dahulu.', 404);
  }

  const shuffled = shuffle(questionsResult.rows);
  const questionIds = shuffled.map((q) => q.id);

  const sessionResult = await pool.query(
    `INSERT INTO quiz_sessions (user_id, lesson_id, status, total_questions, question_ids)
     VALUES ($1, $2, 'in_progress', $3, $4) RETURNING id, started_at`,
    [req.session.userId, lessonId, shuffled.length, questionIds]
  );

  const safeQuestions = shuffled.map((q) => ({
    id: q.id,
    content_type: q.content_type,
    question_type: q.question_type,
    question_text: q.question_text,
    option_a: q.option_a,
    option_b: q.option_b,
    option_c: q.option_c,
    option_d: q.option_d,
    difficulty: q.difficulty,
    points: q.points,
  }));

  return ok(res, {
    quiz_session_id: sessionResult.rows[0].id,
    lesson: lessonResult.rows[0],
    total_questions: shuffled.length,
    questions: safeQuestions,
  });
}));

function nextReviewInterval(mastery) {
  if (mastery >= 0.9) return 14;
  if (mastery >= 0.7) return 7;
  if (mastery >= 0.5) return 3;
  return 1;
}

apiRouter.post('/quiz/submit', requireAuth, ah(async (req, res) => {
  const { quiz_session_id, answers } = req.body || {};
  const sessionId = toInt(quiz_session_id);
  if (!isPositiveInt(sessionId)) return fail(res, 'quiz_session_id tidak valid', 422);
  if (!Array.isArray(answers) || answers.length === 0) {
    return fail(res, 'answers harus berupa array dan tidak boleh kosong', 422);
  }

  const sessionResult = await pool.query(
    'SELECT * FROM quiz_sessions WHERE id = $1 AND user_id = $2',
    [sessionId, req.session.userId]
  );
  if (sessionResult.rowCount === 0) return fail(res, 'Quiz session tidak ditemukan', 404);
  const session = sessionResult.rows[0];

  if (session.status === 'completed') {
    const breakdown = await buildSessionBreakdown(sessionId);
    return ok(res, breakdown);
  }

  const validQuestionIds = new Set(session.question_ids);
  for (const a of answers) {
    if (!validQuestionIds.has(toInt(a.question_id))) {
      return fail(res, `question_id ${a.question_id} bukan bagian dari quiz session ini`, 422);
    }
    const sel = typeof a.selected_answer === 'string' ? a.selected_answer.trim().toLowerCase() : a.selected_answer;
    if (!ANSWER_KEYS.includes(sel)) {
      return fail(res, 'selected_answer wajib salah satu dari: a, b, c, d', 422);
    }
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const lockResult = await client.query(
      'SELECT * FROM quiz_sessions WHERE id = $1 FOR UPDATE',
      [sessionId]
    );
    const lockedSession = lockResult.rows[0];
    if (lockedSession.status === 'completed') {
      await client.query('ROLLBACK');
      const breakdown = await buildSessionBreakdown(sessionId);
      return ok(res, breakdown);
    }

    const questionRows = await client.query(
      `SELECT * FROM questions WHERE id = ANY($1::int[])`,
      [Array.from(validQuestionIds)]
    );
    const questionsById = new Map(questionRows.rows.map((q) => [q.id, q]));

    let correctCount = 0;
    let totalResponseTime = 0;
    let score = 0;

    for (const a of answers) {
      const qid = toInt(a.question_id);
      const question = questionsById.get(qid);
      if (!question) continue;
      const selected = a.selected_answer.trim().toLowerCase();
      const responseTime = Number.isFinite(Number(a.response_time)) ? Math.max(0, Math.round(Number(a.response_time))) : 0;
      const isCorrect = selected === question.correct_answer;

      await client.query(
        `INSERT INTO quiz_attempts
           (session_id, user_id, question_id, selected_answer, correct_answer, is_correct, response_time)
         VALUES ($1,$2,$3,$4,$5,$6,$7)
         ON CONFLICT (session_id, question_id) DO NOTHING`,
        [sessionId, req.session.userId, qid, selected, question.correct_answer, isCorrect, responseTime]
      );

      totalResponseTime += responseTime;
      if (isCorrect) {
        correctCount++;
        score += question.points;
      } else {
        await client.query(
          `INSERT INTO mistakes (user_id, question_id, lesson_id, mistake_type, wrong_answer, correct_answer)
           VALUES ($1,$2,$3,$4,$5,$6)`,
          [req.session.userId, qid, question.lesson_id, question.content_type, selected, question.correct_answer]
        );
      }

      const progressResult = await client.query(
        `SELECT * FROM learning_progress WHERE user_id = $1 AND content_type = $2 AND content_id = $3`,
        [req.session.userId, question.content_type, question.content_id]
      );
      let correct_count, wrong_count;
      if (progressResult.rowCount === 0) {
        correct_count = isCorrect ? 1 : 0;
        wrong_count = isCorrect ? 0 : 1;
      } else {
        correct_count = progressResult.rows[0].correct_count + (isCorrect ? 1 : 0);
        wrong_count = progressResult.rows[0].wrong_count + (isCorrect ? 0 : 1);
      }
      const accuracy = (correct_count / (correct_count + wrong_count)) * 100;
      const mastery = correct_count / (correct_count + wrong_count);
      const intervalDays = nextReviewInterval(mastery);

      await client.query(
        `INSERT INTO learning_progress
           (user_id, content_type, content_id, correct_count, wrong_count, accuracy, mastery_score, last_reviewed_at, next_review_at)
         VALUES ($1,$2,$3,$4,$5,$6,$7, NOW(), NOW() + ($8 || ' days')::interval)
         ON CONFLICT (user_id, content_type, content_id) DO UPDATE SET
           correct_count = EXCLUDED.correct_count,
           wrong_count = EXCLUDED.wrong_count,
           accuracy = EXCLUDED.accuracy,
           mastery_score = EXCLUDED.mastery_score,
           last_reviewed_at = NOW(),
           next_review_at = EXCLUDED.next_review_at`,
        [req.session.userId, question.content_type, question.content_id, correct_count, wrong_count, accuracy, mastery, String(intervalDays)]
      );
    }

    const totalAnswered = answers.length;
    const wrongCount = totalAnswered - correctCount;
    const accuracy = totalAnswered > 0 ? (correctCount / totalAnswered) * 100 : 0;
    const avgResponseTime = totalAnswered > 0 ? Math.round(totalResponseTime / totalAnswered) : 0;

    await client.query(
      `UPDATE quiz_sessions SET status = 'completed', correct_count = $1, wrong_count = $2,
         accuracy = $3, score = $4, avg_response_time_ms = $5, completed_at = NOW()
       WHERE id = $6`,
      [correctCount, wrongCount, accuracy, score, avgResponseTime, sessionId]
    );

    await client.query('COMMIT');
  } catch (e) {
    await client.query('ROLLBACK');
    throw e;
  } finally {
    client.release();
  }

  const breakdown = await buildSessionBreakdown(sessionId);
  return ok(res, breakdown);
}));

async function buildSessionBreakdown(sessionId) {
  const sessionResult = await pool.query(
    `SELECT qs.*, l.title AS lesson_title FROM quiz_sessions qs
     JOIN lessons l ON l.id = qs.lesson_id WHERE qs.id = $1`,
    [sessionId]
  );
  const session = sessionResult.rows[0];

  const attemptsResult = await pool.query(
    `SELECT qa.*, q.question_text, q.option_a, q.option_b, q.option_c, q.option_d,
            q.explanation, q.content_type, q.question_type, q.points
     FROM quiz_attempts qa
     JOIN questions q ON q.id = qa.question_id
     WHERE qa.session_id = $1
     ORDER BY qa.attempted_at ASC`,
    [sessionId]
  );

  const byType = { grammar: { correct: 0, total: 0 }, vocabulary: { correct: 0, total: 0 }, kanji: { correct: 0, total: 0 } };
  for (const a of attemptsResult.rows) {
    if (!byType[a.content_type]) continue;
    byType[a.content_type].total++;
    if (a.is_correct) byType[a.content_type].correct++;
  }
  const breakdown = {};
  for (const type of CONTENT_TYPES) {
    const { correct, total } = byType[type];
    breakdown[type] = { correct, total, accuracy: total > 0 ? Math.round((correct / total) * 10000) / 100 : null };
  }

  return {
    session: {
      id: session.id,
      lesson_id: session.lesson_id,
      lesson_title: session.lesson_title,
      status: session.status,
      total_questions: session.total_questions,
      correct_count: session.correct_count,
      wrong_count: session.wrong_count,
      accuracy: Number(session.accuracy),
      score: session.score,
      avg_response_time_ms: session.avg_response_time_ms,
      started_at: session.started_at,
      completed_at: session.completed_at,
    },
    breakdown,
    attempts: attemptsResult.rows.map((a) => ({
      question_id: a.question_id,
      question_text: a.question_text,
      content_type: a.content_type,
      question_type: a.question_type,
      options: { a: a.option_a, b: a.option_b, c: a.option_c, d: a.option_d },
      selected_answer: a.selected_answer,
      correct_answer: a.correct_answer,
      is_correct: a.is_correct,
      explanation: a.explanation,
      response_time: a.response_time,
      points: a.points,
    })),
  };
}

// =========================================================
// STATISTICS
// =========================================================
const QUESTION_TYPE_LABELS = {
  meaning: 'Meaning', reading: 'Reading', usage: 'Usage', context: 'Context',
  grammar_selection: 'Selection', sentence_completion: 'Completion',
  kanji_reading: 'Reading', kanji_meaning: 'Meaning',
  vocabulary_reading: 'Reading', vocabulary_meaning: 'Meaning',
  similar_word_discrimination: 'Discrimination',
};
const capitalize = (s) => s.charAt(0).toUpperCase() + s.slice(1);

apiRouter.get('/statistics', requireAuth, ah(async (req, res) => {
  const userId = req.session.userId;

  const overallResult = await pool.query(
    `SELECT COUNT(*)::int AS total, COUNT(*) FILTER (WHERE is_correct)::int AS correct
     FROM quiz_attempts WHERE user_id = $1`,
    [userId]
  );
  const total = overallResult.rows[0].total;
  const correct = overallResult.rows[0].correct;
  const wrong = total - correct;
  const overall_accuracy = total > 0 ? Math.round((correct / total) * 10000) / 100 : 0;

  const lessonsCountResult = await pool.query('SELECT COUNT(*)::int AS c FROM lessons');
  const masteryResult = await pool.query(
    'SELECT COALESCE(AVG(mastery_score), 0)::float AS avg_mastery FROM learning_progress WHERE user_id = $1',
    [userId]
  );

  const byTypeResult = await pool.query(
    `SELECT q.content_type,
            COUNT(*)::int AS total,
            COUNT(*) FILTER (WHERE qa.is_correct)::int AS correct
     FROM quiz_attempts qa JOIN questions q ON q.id = qa.question_id
     WHERE qa.user_id = $1
     GROUP BY q.content_type`,
    [userId]
  );
  const breakdown = { grammar: { total: 0, correct: 0, accuracy: null }, vocabulary: { total: 0, correct: 0, accuracy: null }, kanji: { total: 0, correct: 0, accuracy: null } };
  for (const row of byTypeResult.rows) {
    breakdown[row.content_type] = {
      total: row.total,
      correct: row.correct,
      accuracy: Math.round((row.correct / row.total) * 10000) / 100,
    };
  }

  const groupResult = await pool.query(
    `SELECT q.content_type, q.question_type,
            COUNT(*)::int AS total,
            COUNT(*) FILTER (WHERE qa.is_correct)::int AS correct
     FROM quiz_attempts qa JOIN questions q ON q.id = qa.question_id
     WHERE qa.user_id = $1
     GROUP BY q.content_type, q.question_type`,
    [userId]
  );
  let groups = groupResult.rows.map((r) => ({
    label: `${capitalize(r.content_type)} ${QUESTION_TYPE_LABELS[r.question_type] || capitalize(r.question_type)}`,
    total: r.total,
    accuracy: Math.round((r.correct / r.total) * 10000) / 100,
  }));
  const withEnoughData = groups.filter((g) => g.total >= 3);
  if (withEnoughData.length > 0) groups = withEnoughData;
  const sorted = [...groups].sort((a, b) => a.accuracy - b.accuracy);
  const weak_areas = sorted.slice(0, 3);
  const strong_areas = sorted.slice(-3).reverse().filter((g) => !weak_areas.includes(g));

  return ok(res, {
    overall_accuracy,
    total_questions: total,
    correct,
    wrong,
    total_lessons: lessonsCountResult.rows[0].c,
    avg_mastery: Math.round(masteryResult.rows[0].avg_mastery * 1000) / 1000,
    breakdown,
    weak_areas,
    strong_areas,
  });
}));

function registerContentStatistics(routePath, table, labelCol, contentType) {
  apiRouter.get(`/statistics/${routePath}`, requireAuth, ah(async (req, res) => {
    const userId = req.session.userId;
    const result = await pool.query(
      `SELECT c.id, c.${labelCol} AS label, c.lesson_id,
              COALESCE(lp.correct_count, 0) AS correct_count,
              COALESCE(lp.wrong_count, 0) AS wrong_count,
              COALESCE(lp.accuracy, 0) AS accuracy,
              COALESCE(lp.mastery_score, 0) AS mastery_score,
              lp.last_reviewed_at, lp.next_review_at
       FROM ${table} c
       LEFT JOIN learning_progress lp
         ON lp.content_type = $1 AND lp.content_id = c.id AND lp.user_id = $2
       ORDER BY (COALESCE(lp.correct_count,0) + COALESCE(lp.wrong_count,0)) DESC NULLS LAST, accuracy ASC`,
      [contentType, userId]
    );
    return ok(res, result.rows);
  }));
}
registerContentStatistics('grammar', 'grammar', 'pattern', 'grammar');
registerContentStatistics('vocabulary', 'vocabulary', 'word', 'vocabulary');
registerContentStatistics('kanji', 'kanji', 'character', 'kanji');

// =========================================================
// LEARNING PROGRESS
// =========================================================
apiRouter.get('/progress', requireAuth, ah(async (req, res) => {
  const userId = req.session.userId;
  const result = await pool.query(
    `SELECT lp.*, v.word AS vocabulary_label, g.pattern AS grammar_label, k.character AS kanji_label
     FROM learning_progress lp
     LEFT JOIN vocabulary v ON lp.content_type = 'vocabulary' AND lp.content_id = v.id
     LEFT JOIN grammar g ON lp.content_type = 'grammar' AND lp.content_id = g.id
     LEFT JOIN kanji k ON lp.content_type = 'kanji' AND lp.content_id = k.id
     WHERE lp.user_id = $1
     ORDER BY lp.updated_at DESC`,
    [userId]
  );
  const rows = result.rows.map((r) => ({
    ...r,
    label: r.vocabulary_label || r.grammar_label || r.kanji_label,
  }));
  return ok(res, rows);
}));

apiRouter.get('/progress/:contentType/:contentId', requireAuth, ah(async (req, res) => {
  const { contentType, contentId } = req.params;
  const cid = toInt(contentId);
  if (!CONTENT_TYPES.includes(contentType)) return fail(res, 'content_type tidak valid', 422);
  if (!isPositiveInt(cid)) return fail(res, 'content_id tidak valid', 422);
  const result = await pool.query(
    `SELECT * FROM learning_progress WHERE user_id = $1 AND content_type = $2 AND content_id = $3`,
    [req.session.userId, contentType, cid]
  );
  if (result.rowCount === 0) return fail(res, 'Belum ada progress untuk item ini', 404);
  return ok(res, result.rows[0]);
}));

// =========================================================
// MISTAKES
// =========================================================
apiRouter.get('/mistakes', requireAuth, ah(async (req, res) => {
  const userId = req.session.userId;
  const result = await pool.query(
    `SELECT m.*, q.question_text, q.content_type, l.title AS lesson_title,
            v.word AS vocabulary_label, g.pattern AS grammar_label, k.character AS kanji_label
     FROM mistakes m
     JOIN questions q ON q.id = m.question_id
     JOIN lessons l ON l.id = m.lesson_id
     LEFT JOIN vocabulary v ON q.content_type = 'vocabulary' AND q.content_id = v.id
     LEFT JOIN grammar g ON q.content_type = 'grammar' AND q.content_id = g.id
     LEFT JOIN kanji k ON q.content_type = 'kanji' AND q.content_id = k.id
     WHERE m.user_id = $1
     ORDER BY m.created_at DESC
     LIMIT 200`,
    [userId]
  );
  const rows = result.rows.map((r) => ({ ...r, content_label: r.vocabulary_label || r.grammar_label || r.kanji_label }));
  return ok(res, rows);
}));

apiRouter.delete('/mistakes/:id', requireAuth, ah(async (req, res) => {
  const id = toInt(req.params.id);
  if (!isPositiveInt(id)) return fail(res, 'ID tidak valid', 422);
  const result = await pool.query('DELETE FROM mistakes WHERE id = $1 AND user_id = $2 RETURNING id', [id, req.session.userId]);
  if (result.rowCount === 0) return fail(res, 'Data mistake tidak ditemukan', 404);
  return ok(res, { deleted: true });
}));

// =========================================================
// Mount API router
// =========================================================
app.use('/api', apiRouter);
app.use('/api', (req, res) => fail(res, 'Endpoint tidak ditemukan', 404));

// =========================================================
// View routes
// =========================================================
const VIEWS = {
  '/': path.join(__dirname, 'public', 'index.html'),
  '/login': path.join(__dirname, 'public', 'login.html'),
  '/study': path.join(__dirname, 'public', 'study.html'),
  '/quiz': path.join(__dirname, 'public', 'quiz.html'),
  '/admin': path.join(__dirname, 'public', 'admin.html'),
};

const LEGACY_HTML_REDIRECTS = {
  '/index.html': '/',
  '/login.html': '/login',
  '/study.html': '/study',
  '/quiz.html': '/quiz',
  '/admin.html': '/admin',
};
for (const [legacyPath, cleanPath] of Object.entries(LEGACY_HTML_REDIRECTS)) {
  app.get(legacyPath, (req, res) => {
    const qs = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
    res.redirect(301, cleanPath + qs);
  });
}

app.get('/', (req, res) => res.sendFile(VIEWS['/']));
app.get('/login', (req, res) => res.sendFile(VIEWS['/login']));
app.get('/study', (req, res) => res.sendFile(VIEWS['/study']));
app.get('/quiz', (req, res) => res.sendFile(VIEWS['/quiz']));
app.get('/admin', (req, res) => res.sendFile(VIEWS['/admin']));

app.use(express.static(path.join(__dirname, 'public'), { index: false }));

// =========================================================
// Generic error handler
// =========================================================
app.use((err, req, res, next) => {
  if (err instanceof AppError) {
    return fail(res, err.message, err.status, err.details);
  }

  if (err && err.code === '23505') {
    return fail(res, 'Data sudah ada (konflik unik)', 409);
  }
  if (err && err.code && err.code.startsWith('23')) {
    return fail(res, 'Data tidak memenuhi aturan validasi database', 422);
  }

  console.error('Unhandled error:', err);
  return fail(res, 'Terjadi kesalahan pada server', 500);
});

// =========================================================
// START SERVER / VERCEL EXPORT
// =========================================================
// Jika dijalankan di Vercel, Vercel yang akan menjadi servernya.
// Jika dijalankan di lokal, kita gunakan app.listen.
if (process.env.NODE_ENV !== 'production' || require.main === module) {
  app.listen(PORT, () => {
    console.log(`JLPT N3 Learning OS running on port ${PORT} [${NODE_ENV}]`);
  });
}

// EXPORT WAJIB UNTUK VERCEL SERVERLESS FUNCTION
module.exports = app;