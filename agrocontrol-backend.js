const express  = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const Database = require('better-sqlite3');
const path     = require('path');
const crypto   = require('crypto');

const app    = express();
const PORT   = process.env.PORT       || 3000;
const SECRET = process.env.JWT_SECRET || 'agrocontrol_secreto_dev_cambiar_en_produccion';

app.use(cors());
app.use(express.json());

const db = new Database(path.join(__dirname, 'agrocontrol.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE,
    password_hash TEXT    NOT NULL,
    rol           TEXT    NOT NULL DEFAULT 'dueno',
    codigo_invite TEXT    UNIQUE,
    created_at    TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS vinculaciones (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    dueno_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    trabajador_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now')),
    UNIQUE(dueno_id, trabajador_id)
  );

  CREATE TABLE IF NOT EXISTS campos (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    nombre     TEXT    NOT NULL,
    cultivo    TEXT    NOT NULL,
    area       REAL    NOT NULL DEFAULT 0,
    ubic       TEXT    NOT NULL DEFAULT '',
    created_at TEXT    NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS insumos (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    nombre   TEXT    NOT NULL,
    unidad   TEXT    NOT NULL,
    stock    REAL    NOT NULL DEFAULT 0,
    costo    REAL    NOT NULL DEFAULT 0,
    prov     TEXT    NOT NULL DEFAULT '',
    fecha    TEXT    NOT NULL
  );

  CREATE TABLE IF NOT EXISTS gastos (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    cat          TEXT    NOT NULL,
    campo_id     INTEGER NOT NULL REFERENCES campos(id) ON DELETE CASCADE,
    campo_nombre TEXT    NOT NULL DEFAULT '',
    monto        REAL    NOT NULL,
    fecha        TEXT    NOT NULL,
    nota         TEXT    NOT NULL DEFAULT '',
    desc         TEXT    NOT NULL DEFAULT '',
    insumo_id    INTEGER REFERENCES insumos(id) ON DELETE SET NULL
  );

  CREATE TABLE IF NOT EXISTS ventas (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    prod    TEXT    NOT NULL,
    kg      REAL    NOT NULL,
    precio  REAL    NOT NULL,
    total   REAL    NOT NULL,
    fecha   TEXT    NOT NULL
  );

  CREATE TABLE IF NOT EXISTS usos (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    dueno_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    campo_id      INTEGER NOT NULL REFERENCES campos(id) ON DELETE CASCADE,
    insumo_id     INTEGER NOT NULL REFERENCES insumos(id) ON DELETE CASCADE,
    cant          REAL    NOT NULL,
    etapa         TEXT    NOT NULL,
    fecha         TEXT    NOT NULL,
    campo_nombre  TEXT    NOT NULL DEFAULT '',
    insumo_nombre TEXT    NOT NULL DEFAULT '',
    unidad        TEXT    NOT NULL DEFAULT ''
  );
`);

// Migraciones para DBs existentes
['rol TEXT NOT NULL DEFAULT dueno',
 'codigo_invite TEXT'].forEach(col => {
  try { db.exec(`ALTER TABLE users ADD COLUMN ${col}`); } catch {}
});
try { db.exec(`ALTER TABLE usos ADD COLUMN dueno_id INTEGER NOT NULL DEFAULT 0`); } catch {}

console.log('✅ Base de datos lista');

// ── HELPERS ─────────────────────────────────────────

function authMiddleware(req, res, next) {
  const header = req.headers['authorization'];
  if (!header || !header.startsWith('Bearer '))
    return res.status(401).json({ error: 'No autorizado' });
  try {
    const payload = jwt.verify(header.slice(7), SECRET);
    req.userId = payload.userId;
    next();
  } catch {
    res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

function hoy() { return new Date().toISOString().slice(0, 10); }

// Obtiene el dueño efectivo: si es trabajador vinculado → retorna dueno_id, si es dueño → retorna su propio id
function getDuenoId(userId) {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
  if (!user) return null;
  if (user.rol === 'dueno') return userId;
  // Es trabajador — buscar su dueño vinculado
  const vinc = db.prepare('SELECT dueno_id FROM vinculaciones WHERE trabajador_id = ?').get(userId);
  return vinc ? vinc.dueno_id : null;
}

// ── AUTH ────────────────────────────────────────────

app.post('/api/auth/register', async (req, res) => {
  const { username, password, rol, codigoInvite } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
  if (password.length < 4)
    return res.status(400).json({ error: 'Mínimo 4 caracteres en la contraseña' });
  if (!['dueno', 'trabajador'].includes(rol))
    return res.status(400).json({ error: 'Rol inválido' });

  // Si es trabajador, debe tener código de invitación
  let duenoId = null;
  if (rol === 'trabajador') {
    if (!codigoInvite) return res.status(400).json({ error: 'Ingresa el código de invitación del dueño' });
    const dueno = db.prepare("SELECT * FROM users WHERE codigo_invite = ? AND rol = 'dueno'").get(codigoInvite.toUpperCase());
    if (!dueno) return res.status(404).json({ error: 'Código de invitación inválido' });
    duenoId = dueno.id;
  }

  const existe = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existe) return res.status(409).json({ error: 'El usuario ya existe' });

  const passwordHash = await bcrypt.hash(password, 10);

  const registro = db.transaction(() => {
    const result = db.prepare(
      'INSERT INTO users (username, password_hash, rol) VALUES (?, ?, ?)'
    ).run(username, passwordHash, rol);

    const newId = result.lastInsertRowid;

    // Si es dueño, generar código de invitación único
    if (rol === 'dueno') {
      const codigo = crypto.randomBytes(3).toString('hex').toUpperCase(); // ej: A3F9B2
      db.prepare('UPDATE users SET codigo_invite = ? WHERE id = ?').run(codigo, newId);
    }

    // Si es trabajador, crear vinculación
    if (rol === 'trabajador' && duenoId) {
      db.prepare('INSERT INTO vinculaciones (dueno_id, trabajador_id) VALUES (?, ?)').run(duenoId, newId);
    }

    return newId;
  });

  const newId = registro();
  const newUser = db.prepare('SELECT * FROM users WHERE id = ?').get(newId);
  const token = jwt.sign({ userId: newId }, SECRET, { expiresIn: '30d' });

  res.status(201).json({
    token,
    user: { id: newId, username: newUser.username, rol: newUser.rol, codigoInvite: newUser.codigo_invite }
  });
});

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Usuario y contraseña requeridos' });

  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });

  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });

  const token = jwt.sign({ userId: user.id }, SECRET, { expiresIn: '30d' });
  res.json({ token, user: { id: user.id, username: user.username, rol: user.rol, codigoInvite: user.codigo_invite } });
});

app.post('/api/auth/verify', authMiddleware, async (req, res) => {
  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Contraseña requerida' });
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
  if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) return res.status(401).json({ error: 'Contraseña incorrecta' });
  res.json({ ok: true });
});

// ── EQUIPO (solo dueño) ──────────────────────────────

// GET /api/equipo — lista trabajadores vinculados
app.get('/api/equipo', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
  if (!user || user.rol !== 'dueno')
    return res.status(403).json({ error: 'Solo el dueño puede ver el equipo' });

  const trabajadores = db.prepare(`
    SELECT u.id, u.username, u.rol, v.created_at as vinculado_desde
    FROM vinculaciones v
    JOIN users u ON u.id = v.trabajador_id
    WHERE v.dueno_id = ?
    ORDER BY v.created_at DESC
  `).all(req.userId);

  res.json({ trabajadores, codigoInvite: user.codigo_invite });
});

// DELETE /api/equipo/:trabajadorId — desvincular trabajador
app.delete('/api/equipo/:trabajadorId', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
  if (!user || user.rol !== 'dueno')
    return res.status(403).json({ error: 'Solo el dueño puede desvincular trabajadores' });

  const result = db.prepare(
    'DELETE FROM vinculaciones WHERE dueno_id = ? AND trabajador_id = ?'
  ).run(req.userId, req.params.trabajadorId);

  if (result.changes === 0) return res.status(404).json({ error: 'Trabajador no encontrado' });
  res.json({ ok: true });
});

// POST /api/equipo/regenerar-codigo — genera nuevo código
app.post('/api/equipo/regenerar-codigo', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
  if (!user || user.rol !== 'dueno')
    return res.status(403).json({ error: 'Solo el dueño puede regenerar el código' });

  const codigo = crypto.randomBytes(3).toString('hex').toUpperCase();
  db.prepare('UPDATE users SET codigo_invite = ? WHERE id = ?').run(codigo, req.userId);
  res.json({ codigoInvite: codigo });
});

// ── CAMPOS ──────────────────────────────────────────

app.get('/api/campos', authMiddleware, (req, res) => {
  const duenoId = getDuenoId(req.userId);
  if (!duenoId) return res.status(403).json({ error: 'No vinculado a ningún dueño' });
  res.json(db.prepare('SELECT * FROM campos WHERE user_id = ? ORDER BY id DESC').all(duenoId));
});

app.post('/api/campos', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
  if (user?.rol !== 'dueno') return res.status(403).json({ error: 'Solo el dueño puede agregar campos' });
  const { nombre, cultivo, area, ubic } = req.body;
  if (!nombre || !cultivo) return res.status(400).json({ error: 'Nombre y cultivo requeridos' });
  const result = db.prepare(
    'INSERT INTO campos (user_id, nombre, cultivo, area, ubic) VALUES (?, ?, ?, ?, ?)'
  ).run(req.userId, nombre, cultivo, area || 0, ubic || '');
  res.status(201).json({ id: result.lastInsertRowid, nombre, cultivo, area: area || 0, ubic: ubic || '' });
});

app.delete('/api/campos/:id', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
  if (user?.rol !== 'dueno') return res.status(403).json({ error: 'Solo el dueño puede eliminar campos' });
  const result = db.prepare('DELETE FROM campos WHERE id = ? AND user_id = ?').run(req.params.id, req.userId);
  if (result.changes === 0) return res.status(404).json({ error: 'Campo no encontrado' });
  res.json({ ok: true });
});

// ── INSUMOS ─────────────────────────────────────────

app.get('/api/insumos', authMiddleware, (req, res) => {
  const duenoId = getDuenoId(req.userId);
  if (!duenoId) return res.status(403).json({ error: 'No vinculado a ningún dueño' });
  res.json(db.prepare('SELECT * FROM insumos WHERE user_id = ? ORDER BY id DESC').all(duenoId));
});

app.post('/api/insumos', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
  if (user?.rol !== 'dueno') return res.status(403).json({ error: 'Solo el dueño puede agregar insumos' });
  const { nombre, unidad, stock, costo, prov, fecha } = req.body;
  if (!nombre || !unidad) return res.status(400).json({ error: 'Nombre y unidad requeridos' });
  const result = db.prepare(
    'INSERT INTO insumos (user_id, nombre, unidad, stock, costo, prov, fecha) VALUES (?, ?, ?, ?, ?, ?, ?)'
  ).run(req.userId, nombre, unidad, stock || 0, costo || 0, prov || '', fecha || hoy());
  res.status(201).json({ id: result.lastInsertRowid, nombre, unidad, stock: stock || 0, costo: costo || 0, prov: prov || '', fecha: fecha || hoy() });
});

app.delete('/api/insumos/:id', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
  if (user?.rol !== 'dueno') return res.status(403).json({ error: 'Solo el dueño puede eliminar insumos' });
  const result = db.prepare('DELETE FROM insumos WHERE id = ? AND user_id = ?').run(req.params.id, req.userId);
  if (result.changes === 0) return res.status(404).json({ error: 'Insumo no encontrado' });
  res.json({ ok: true });
});

// ── GASTOS ──────────────────────────────────────────

app.get('/api/gastos', authMiddleware, (req, res) => {
  const duenoId = getDuenoId(req.userId);
  if (!duenoId) return res.status(403).json({ error: 'No vinculado' });
  res.json(db.prepare('SELECT * FROM gastos WHERE user_id = ? ORDER BY fecha DESC, id DESC').all(duenoId));
});

app.post('/api/gastos', authMiddleware, (req, res) => {
  const duenoId = getDuenoId(req.userId);
  if (!duenoId) return res.status(403).json({ error: 'No vinculado' });
  const { cat, campoId, monto, fecha, nota, desc, insumoId, cant } = req.body;
  if (!cat || !campoId || !monto) return res.status(400).json({ error: 'Categoría, campo y monto requeridos' });

  const campo = db.prepare('SELECT * FROM campos WHERE id = ? AND user_id = ?').get(campoId, duenoId);
  if (!campo) return res.status(404).json({ error: 'Campo no encontrado' });

  let finalDesc = desc || '';
  const saveGasto = db.transaction(() => {
    if (cat === 'Insumos' && insumoId && cant) {
      const ins = db.prepare('SELECT * FROM insumos WHERE id = ? AND user_id = ?').get(insumoId, duenoId);
      if (!ins) throw new Error('Insumo no encontrado');
      if (ins.stock < cant) throw new Error('Stock insuficiente');
      db.prepare('UPDATE insumos SET stock = stock - ? WHERE id = ?').run(cant, insumoId);
      finalDesc = ins.nombre + ' x' + cant;
    }
    const result = db.prepare(
      'INSERT INTO gastos (user_id, cat, campo_id, campo_nombre, monto, fecha, nota, desc, insumo_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(duenoId, cat, campoId, campo.nombre, monto, fecha || hoy(), nota || '', finalDesc, insumoId || null);
    return result.lastInsertRowid;
  });

  try {
    const id = saveGasto();
    res.status(201).json({ id, cat, campoId, campoNombre: campo.nombre, monto, fecha: fecha || hoy(), nota: nota || '', desc: finalDesc });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.delete('/api/gastos/:id', authMiddleware, (req, res) => {
  const duenoId = getDuenoId(req.userId);
  if (!duenoId) return res.status(403).json({ error: 'No vinculado' });
  const result = db.prepare('DELETE FROM gastos WHERE id = ? AND user_id = ?').run(req.params.id, duenoId);
  if (result.changes === 0) return res.status(404).json({ error: 'Gasto no encontrado' });
  res.json({ ok: true });
});

// ── VENTAS ──────────────────────────────────────────

app.get('/api/ventas', authMiddleware, (req, res) => {
  const duenoId = getDuenoId(req.userId);
  if (!duenoId) return res.status(403).json({ error: 'No vinculado' });
  res.json(db.prepare('SELECT * FROM ventas WHERE user_id = ? ORDER BY fecha DESC, id DESC').all(duenoId));
});

app.post('/api/ventas', authMiddleware, (req, res) => {
  const duenoId = getDuenoId(req.userId);
  if (!duenoId) return res.status(403).json({ error: 'No vinculado' });
  const { prod, kg, precio, total, fecha } = req.body;
  if (!prod || !kg || !precio) return res.status(400).json({ error: 'Producto, kg y precio requeridos' });
  const totalFinal = Number(total || kg * precio);
  const result = db.prepare(
    'INSERT INTO ventas (user_id, prod, kg, precio, total, fecha) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(duenoId, prod, Number(kg), Number(precio), totalFinal, fecha || hoy());
  res.status(201).json({ id: result.lastInsertRowid, prod, kg: Number(kg), precio: Number(precio), total: totalFinal, fecha: fecha || hoy() });
});

app.delete('/api/ventas/:id', authMiddleware, (req, res) => {
  const duenoId = getDuenoId(req.userId);
  if (!duenoId) return res.status(403).json({ error: 'No vinculado' });
  const result = db.prepare('DELETE FROM ventas WHERE id = ? AND user_id = ?').run(req.params.id, duenoId);
  if (result.changes === 0) return res.status(404).json({ error: 'Venta no encontrada' });
  res.json({ ok: true });
});

// ── USOS ────────────────────────────────────────────

app.post('/api/usos', authMiddleware, (req, res) => {
  const duenoId = getDuenoId(req.userId);
  if (!duenoId) return res.status(403).json({ error: 'No vinculado a ningún dueño' });

  const { campoId, insumoId, cant, etapa, fecha } = req.body;
  if (!campoId || !insumoId || !cant || !etapa)
    return res.status(400).json({ error: 'Todos los campos son requeridos' });

  const saveUso = db.transaction(() => {
    const campo  = db.prepare('SELECT * FROM campos  WHERE id = ? AND user_id = ?').get(campoId, duenoId);
    const insumo = db.prepare('SELECT * FROM insumos WHERE id = ? AND user_id = ?').get(insumoId, duenoId);
    if (!campo)  throw new Error('Campo no encontrado');
    if (!insumo) throw new Error('Insumo no encontrado');
    if (insumo.stock < cant) throw new Error(`Stock insuficiente. Disponible: ${insumo.stock} ${insumo.unidad}`);
    db.prepare('UPDATE insumos SET stock = stock - ? WHERE id = ?').run(cant, insumoId);
    const result = db.prepare(
      'INSERT INTO usos (user_id, dueno_id, campo_id, insumo_id, cant, etapa, fecha, campo_nombre, insumo_nombre, unidad) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
    ).run(req.userId, duenoId, campoId, insumoId, cant, etapa, fecha || hoy(), campo.nombre, insumo.nombre, insumo.unidad);
    return result.lastInsertRowid;
  });

  try {
    const id = saveUso();
    res.status(201).json({ id, ok: true });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

// ── REPORTES ─────────────────────────────────────────

app.get('/api/reportes', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
  if (user?.rol !== 'dueno') return res.status(403).json({ error: 'Solo el dueño puede ver reportes' });
  const { total_gastos }   = db.prepare('SELECT COALESCE(SUM(monto), 0) as total_gastos FROM gastos WHERE user_id = ?').get(req.userId);
  const { total_ingresos } = db.prepare('SELECT COALESCE(SUM(total), 0) as total_ingresos FROM ventas WHERE user_id = ?').get(req.userId);
  res.json({ gastos: total_gastos, ingresos: total_ingresos, neta: total_ingresos - total_gastos });
});

// ── HISTORIAL ────────────────────────────────────────

app.get('/api/historial', authMiddleware, (req, res) => {
  const duenoId = getDuenoId(req.userId);
  if (!duenoId) return res.status(403).json({ error: 'No vinculado' });

  const gastos = db.prepare(
    "SELECT 'gasto' as tipo, g.id, COALESCE(g.desc, g.cat) as desc, g.monto, g.fecha, g.campo_nombre as campoNombre, NULL as trabajador FROM gastos g WHERE g.user_id = ? ORDER BY g.fecha DESC, g.id DESC"
  ).all(duenoId);

  const ventas = db.prepare(
    "SELECT 'venta' as tipo, v.id, v.prod as desc, v.total as monto, v.fecha, '' as campoNombre, NULL as trabajador FROM ventas v WHERE v.user_id = ? ORDER BY v.fecha DESC, v.id DESC"
  ).all(duenoId);

  // Usos de trabajadores (solo el dueño los ve en historial)
  const usos = db.prepare(`
    SELECT 'uso' as tipo, u.id,
      u.insumo_nombre || ' x' || u.cant || ' ' || u.unidad as desc,
      0 as monto, u.fecha, u.campo_nombre as campoNombre,
      usr.username as trabajador
    FROM usos u
    JOIN users usr ON usr.id = u.user_id
    WHERE u.dueno_id = ?
    ORDER BY u.fecha DESC, u.id DESC
  `).all(duenoId);

  const todos = [...gastos, ...ventas, ...usos].sort((a, b) => b.fecha.localeCompare(a.fecha) || b.id - a.id);
  res.json(todos);
});

// ── HISTORIAL TRABAJADORES (solo dueño) ─────────────

app.get('/api/historial/trabajadores', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.userId);
  if (user?.rol !== 'dueno') return res.status(403).json({ error: 'Solo el dueño puede ver esto' });

  const usos = db.prepare(`
    SELECT u.id, u.insumo_nombre, u.cant, u.unidad, u.etapa,
           u.campo_nombre, u.fecha, usr.username as trabajador
    FROM usos u
    JOIN users usr ON usr.id = u.user_id
    WHERE u.dueno_id = ?
    ORDER BY u.fecha DESC, u.id DESC
  `).all(req.userId);

  res.json(usos);
});

app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.listen(PORT, () => {
  console.log(`🌱 AgroControl corriendo en http://localhost:${PORT}`);
});