// index.js — Express + MySQL (pool) + dotenv + logs de login + SESSÕES SEGURAS
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const MySQLStoreFactory = require('express-mysql-session')(session);
const bcrypt = require('bcryptjs');
require('dotenv').config();

// fetch shim (Node 18+ já tem global.fetch)
const fetch = global.fetch || ((...args) =>
  import('node-fetch').then(({ default: f }) => f(...args)));

const app = express();

/* =====================
   Server
===================== */
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';

// atrás do Nginx/Cloudflare
app.set('trust proxy', true);

/* =====================
   Middlewares
===================== */
app.use(cors({
  origin: process.env.FRONTEND_URL || true,
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

/* =====================
   DB (POOL — resiliente)
===================== */
const db = mysql.createPool({
  host: process.env.DB_HOST || '127.0.0.1',
  user: process.env.DB_USER || 'agro_user',
  password: process.env.DB_PASSWORD || 'SenhaF0rte!',
  database: process.env.DB_NAME || 'agro',
  port: Number(process.env.DB_PORT || 3306),
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// teste/boot
db.getConnection((err, conn) => {
  if (err) console.error('❌ Erro ao conectar no MySQL:', err.message);
  else { console.log('✅ Pool MySQL conectado'); conn.release(); }
});
// keepalive com log de erro
setInterval(() => db.query('SELECT 1', (e) => {
  if (e) console.error('Keepalive MySQL:', e.message);
}), 30_000);

/* =====================
   SESSÕES SEGURAS (MySQL Store + Idle + Absoluta)
===================== */
const IDLE_TIMEOUT_MS = 5 * 60 * 1000;       // 5 minutos sem atividade
const ABSOLUTE_TIMEOUT_MS = 60 * 60 * 1000;  // 1 hora de vida máxima da sessão

const sessionStore = new MySQLStoreFactory({
  host: process.env.DB_HOST || '127.0.0.1',
  port: Number(process.env.DB_PORT || 3306),
  user: process.env.DB_USER || 'agro_user',
  password: process.env.DB_PASSWORD || 'SenhaF0rte!',
  database: process.env.DB_NAME || 'agro',
  createDatabaseTable: true
});

app.use(session({
  name: 'sf.sid',
  secret: process.env.SESSION_SECRET || 'smartfarm-secret-change-in-production',
  store: sessionStore,
  resave: false,
  saveUninitialized: false,
  rolling: true, // renova o maxAge a cada request (controle de inatividade)
  cookie: {
    secure: process.env.NODE_ENV === 'production', // true em produção com HTTPS
    httpOnly: true,
    sameSite: 'lax',
    maxAge: IDLE_TIMEOUT_MS // idle timeout no cookie
  }
}));

// Middleware de timeout absoluto + marcação de atividade
app.use((req, res, next) => {
  const now = Date.now();

  if (!req.session.createdAt) {
    req.session.createdAt = now;
  } else if (now - req.session.createdAt > ABSOLUTE_TIMEOUT_MS) {
    return req.session.destroy(() => {
      res.clearCookie('sf.sid');
      return res.status(401).json({ success: false, message: 'Sessão expirada (tempo máximo).' });
    });
  }

  // reforço de inatividade (além do cookie rolling)
  if (!req.session.lastActivity) {
    req.session.lastActivity = now;
  } else if (now - req.session.lastActivity > IDLE_TIMEOUT_MS) {
    return req.session.destroy(() => {
      res.clearCookie('sf.sid');
      return res.status(401).json({ success: false, message: 'Sessão expirada por inatividade.' });
    });
  } else {
    req.session.lastActivity = now;
  }

  next();
});

// estáticos
app.use(express.static(path.join(__dirname, 'public')));

// raiz -> login.html
app.get('/', (req, res) => {
  const p = path.join(__dirname, 'public', 'login.html');
  if (fs.existsSync(p)) return res.sendFile(p);
  res.status(404).send('login.html não encontrado em /public');
});

/* =====================
   Helpers + Auth (ANTES das rotas)
===================== */
function getClientIp(req) {
  const xff = (req.headers['x-forwarded-for'] || '')
    .split(',').map(s => s.trim()).filter(Boolean);
  if (xff.length) return xff[0];
  if (req.headers['x-real-ip']) return req.headers['x-real-ip'];
  return req.ip ||
         req.connection?.remoteAddress ||
         req.socket?.remoteAddress ||
         req.connection?.socket?.remoteAddress ||
         '0.0.0.0';
}
const getUA  = req => req.headers['user-agent'] || '';
const getRef = req => req.headers['referer'] || req.headers['referrer'] || '';

// "sessão" simples em memória para contagem de usuários online
const usuariosOnline = new Set();

function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) {
    // Verifica se é uma requisição AJAX/API (espera JSON)
    if (req.xhr || (req.headers.accept || '').includes('json')) {
      return res.status(401).json({
        success: false,
        message: 'Não autenticado. Faça login primeiro.'
      });
    }
    // Se for navegação normal, redireciona
    return res.redirect('/login.html');
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.user || !req.session.user.isAdmin) {
    return res.status(403).json({
      success: false,
      message: 'Acesso negado. Apenas administradores.'
    });
  }
  next();
}

function forbidSerialChange(req, res, next) {
  if (typeof req.body?.serialnumber !== 'undefined') {
    return res.status(400).json({ success:false, message:'Serial não pode ser alterado.' });
  }
  next();
}

/* =====================
   Admin - ESP32 Dispositivos
===================== */
app.get('/esp32/dispositivos/ativos', requireAdmin, (req, res) => {
  const sql = `
    SELECT d.id, d.serialnumber, d.fk_usuarios, u.usuario AS usuario_login, u.nome AS usuario_nome,
           c.cultura AS nome_cultura
    FROM esp32_dispositivos d
    LEFT JOIN usuarios u ON u.id = d.fk_usuarios
    LEFT JOIN culturas c ON c.id = d.fk_culturas
    WHERE d.fk_usuarios IS NOT NULL
    ORDER BY d.update_em DESC, d.criado_em DESC
  `;
  db.query(sql, (err, rows) => {
    if (err) return res.status(500).json({ success:false, error: err.message });
    res.json({ success:true, dispositivos: rows });
  });
});

// Atualizar o usuário vinculado a um ESP32 (aceita /esp32/... ou /admin/esp32/...)
app.put(
  ['/esp32/dispositivos/:id/usuario', '/admin/esp32/dispositivos/:id/usuario'],
  requireAdmin,
  (req, res) => {
    const { id } = req.params;
    const { fk_usuarios } = req.body || {};

    const userId = Number(fk_usuarios);
    if (!Number.isInteger(userId) || userId <= 0) {
      return res.status(400).json({ success: false, message: 'ID de usuário inválido.' });
    }

    const sql = 'UPDATE esp32_dispositivos SET fk_usuarios = ?, update_em = NOW() WHERE id = ?';
    db.query(sql, [userId, id], (err, r) => {
      if (err) return res.status(500).json({ success: false, error: err.message });
      if (!r.affectedRows) {
        return res.status(404).json({ success: false, message: 'Dispositivo não encontrado.' });
      }
      res.json({ success: true, message: 'Usuário do dispositivo atualizado.' });
    });
  }
);

// Adicionar dispositivo (robusta para esquemas diferentes)
app.post('/esp32/dispositivos', requireAdmin, (req, res) => {
  const { serial } = req.body || {};
  if (!serial || !String(serial).trim()) {
    return res.status(400).json({ success:false, message:'Serial é obrigatório.' });
  }
  const s = String(serial).trim();

  // 1ª tentativa: esquema "completo" com SERIALNUMBER
  const insertFullSerialNumber = `
    INSERT INTO esp32_dispositivos
      (serialnumber, fk_usuarios, fk_culturas, CEP, rua, numero, bairro, cidade, estado, latitude, longitude, criado_em, update_em)
    VALUES (?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NOW(), NOW())
  `;
  db.query(insertFullSerialNumber, [s], (err, r) => {
    if (!err) return res.json({ success:true, id:r.insertId, message:'Dispositivo adicionado.' });

    // Campos NOT NULL sem default?
    if (err.code === 'ER_BAD_NULL_ERROR') {
      return res.status(400).json({
        success:false,
        message:'Esquema do banco exige campos adicionais (NOT NULL). Ajuste a tabela para permitir NULL ou use o fluxo de cadastro completo.'
      });
    }

    // Coluna/estrutura não bateu: tentar com SERIALNUMBER mínimo
    if (err.code === 'ER_BAD_FIELD_ERROR') {
      const insertMinSerialNumber = `
        INSERT INTO esp32_dispositivos (serialnumber, criado_em, update_em)
        VALUES (?, NOW(), NOW())
      `;
      return db.query(insertMinSerialNumber, [s], (e2, r2) => {
        if (!e2) return res.json({ success:true, id:r2.insertId, message:'Dispositivo adicionado.' });

        // Ainda deu erro? Tentar com coluna 'serial'
        if (e2.code === 'ER_BAD_FIELD_ERROR') {
          // full com 'serial'
          const insertFullSerial = `
            INSERT INTO esp32_dispositivos
              (serial, fk_usuarios, fk_culturas, CEP, rua, numero, bairro, cidade, estado, latitude, longitude, criado_em, update_em)
            VALUES (?, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NOW(), NOW())
          `;
          return db.query(insertFullSerial, [s], (e3, r3) => {
            if (!e3) return res.json({ success:true, id:r3.insertId, message:'Dispositivo adicionado.' });

            if (e3.code === 'ER_BAD_NULL_ERROR') {
              return res.status(400).json({
                success:false,
                message:'Esquema do banco exige campos adicionais (NOT NULL). Ajuste a tabela ou use cadastro completo.'
              });
            }
            if (e3.code === 'ER_BAD_FIELD_ERROR') {
              // mínimo com 'serial'
              const insertMinSerial = `
                INSERT INTO esp32_dispositivos (serial, criado_em, update_em)
                VALUES (?, NOW(), NOW())
              `;
              return db.query(insertMinSerial, [s], (e4, r4) => {
                if (!e4) return res.json({ success:true, id:r4.insertId, message:'Dispositivo adicionado.' });
                if (e4.code === 'ER_DUP_ENTRY') {
                  return res.status(400).json({ success:false, message:'Serial já cadastrado.' });
                }
                if (e4.code === 'ER_NO_SUCH_TABLE') {
                  return res.status(500).json({ success:false, message:'Tabela esp32_dispositivos não existe.' });
                }
                console.error('[POST /esp32/dispositivos] serial mínimo erro:', e4);
                return res.status(500).json({ success:false, message:'Erro ao adicionar.', error:e4.code });
              });
            }

            if (e3.code === 'ER_DUP_ENTRY') {
              return res.status(400).json({ success:false, message:'Serial já cadastrado.' });
            }
            if (e3.code === 'ER_NO_SUCH_TABLE') {
              return res.status(500).json({ success:false, message:'Tabela esp32_dispositivos não existe.' });
            }
            console.error('[POST /esp32/dispositivos] full serial erro:', e3);
            return res.status(500).json({ success:false, message:'Erro ao adicionar.', error:e3.code });
          });
        }

        if (e2.code === 'ER_DUP_ENTRY') {
          return res.status(400).json({ success:false, message:'Serial já cadastrado.' });
        }
        if (e2.code === 'ER_NO_SUCH_TABLE') {
          return res.status(500).json({ success:false, message:'Tabela esp32_dispositivos não existe.' });
        }
        console.error('[POST /esp32/dispositivos] min serialnumber erro:', e2);
        return res.status(500).json({ success:false, message:'Erro ao adicionar.', error:e2.code });
      });
    }

    if (err.code === 'ER_DUP_ENTRY') {
      return res.status(400).json({ success:false, message:'Serial já cadastrado.' });
    }
    if (err.code === 'ER_NO_SUCH_TABLE') {
      return res.status(500).json({ success:false, message:'Tabela esp32_dispositivos não existe.' });
    }

    console.error('[POST /esp32/dispositivos] erro inesperado:', err);
    return res.status(500).json({ success:false, message:'Erro ao adicionar.', error:err.code });
  });
});

// Desvincular (remover do usuário) — não apaga o registro
app.delete('/admin/esp32/dispositivos/:id/vinculo', requireAdmin, (req, res) => {
  const { id } = req.params;
  const sql = `UPDATE esp32_dispositivos SET fk_usuarios = NULL, update_em = NOW() WHERE id = ?`;
  db.query(sql, [id], (err, r) => {
    if (err) return res.status(500).json({ success:false, error: err.message });
    if (!r.affectedRows) return res.status(404).json({ success:false, message:'Dispositivo não encontrado.' });
    res.json({ success:true, message:'Vínculo removido.' });
  });
});

// Apagar registro (bloqueado se estiver em uso)
app.delete('/esp32/dispositivos/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  db.query('SELECT fk_usuarios FROM esp32_dispositivos WHERE id=? LIMIT 1', [id], (e, rows) => {
    if (e) return res.status(500).json({ success:false, error:e.message });
    if (!rows.length) return res.status(404).json({ success:false, message:'Dispositivo não encontrado.' });
    if (rows[0].fk_usuarios) {
      return res.status(409).json({ success:false, message:'Dispositivo está vinculado a um usuário. Use a lixeira de “desvincular”.' });
    }
    db.query('DELETE FROM esp32_dispositivos WHERE id=?', [id], (e2) => {
      if (e2) return res.status(500).json({ success:false, error:e2.message });
      res.json({ success:true, message:'Dispositivo apagado.' });
    });
  });
});

/* =====================
   Auth + logs
===================== */
app.post('/login', (req, res) => {
  const { usuario, senha } = req.body || {};
  if (!usuario || !senha) return res.status(400).json({ success: false, message: 'Dados inválidos' });

  const ip = getClientIp(req);
  const ua = getUA(req);
  const origem = getRef(req);

  const sql = 'SELECT id, usuario, nome, senha FROM usuarios WHERE usuario = ? LIMIT 1';
  db.query(sql, [usuario], (err, rows) => {
    if (err) {
      console.error('Erro /login:', err.message);
      db.query(
        'INSERT INTO login_logs (usuario, sucesso, ip, user_agent, origem) VALUES (?,?,?,?,?)',
        [usuario || null, 0, ip, ua, origem]
      );
      return res.status(500).json({ success: false });
    }

    if (rows.length > 0) {
      const u = rows[0];

      // Verificar senha (suporta hash bcrypt e texto plano em migração)
      const senhaValida = u.senha?.startsWith?.('$2a$') || u.senha?.startsWith?.('$2b$')
        ? bcrypt.compareSync(senha, u.senha)
        : senha === u.senha;

      if (senhaValida) {
        // Criar sessão
        req.session.user = {
          id: u.id,
          usuario: u.usuario,
          nome: u.nome,
          isAdmin: u.usuario === 'admin'
        };
        req.session.createdAt = Date.now();
        req.session.lastActivity = Date.now();

        db.query(
          'INSERT INTO login_logs (usuario, user_id, sucesso, ip, user_agent, origem) VALUES (?,?,?,?,?,?)',
          [u.usuario, u.id, 1, ip, ua, origem]
        );
        usuariosOnline.add(u.usuario);

        return res.json({
          success: true,
          isAdmin: req.session.user.isAdmin,
          nome: u.nome,
          usuario: u.usuario
        });
      }
    }

    db.query(
      'INSERT INTO login_logs (usuario, sucesso, ip, user_agent, origem) VALUES (?,?,?,?,?)',
      [usuario || null, 0, ip, ua, origem]
    );
    res.json({ success: false, message: 'Usuário ou senha incorretos' });
  });
});

app.post('/logout', (req, res) => {
  if (req.session && req.session.user?.usuario) {
    usuariosOnline.delete(req.session.user.usuario);
    req.session.destroy((err) => {
      if (err) return res.status(500).json({ success: false, message: 'Erro ao fazer logout' });
      res.clearCookie('sf.sid');
      return res.json({ success: true });
    });
  } else {
    res.clearCookie('sf.sid');
    res.json({ success: true });
  }
});

// Nova rota para verificar sessão
app.get('/session', (req, res) => {
  if (req.session && req.session.user) {
    const u = req.session.user; // { id, usuario, nome, ... }
    return res.json({
      authenticated: true,
      user: {
        id: u.id,
        usuario: u.usuario,
        nome: u.nome,
        isAdmin: u.usuario === 'admin'
      }
    });
  }
  res.json({ authenticated: false });
});

app.get('/online', (_req, res) => res.json({ online: usuariosOnline.size }));

/* =====================
   Usuários (PROTEGIDO)
===================== */
app.post('/usuarios', requireAdmin, (req, res) => {
  const { usuario, senha, nome, email } = req.body || {};
  const senhaHash = bcrypt.hashSync(senha, 10);
  const sql = 'INSERT INTO usuarios (usuario, senha, nome, email) VALUES (?, ?, ?, ?)';
  db.query(sql, [usuario, senhaHash, nome, email], (err) => {
    if (err) {
      if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ success: false, message: 'Usuário já existe!' });
      console.error('Erro /usuarios POST:', err.message);
      return res.status(500).json({ success: false, error: err.message });
    }
    res.json({ success: true, message: 'Usuário criado com sucesso!' });
  });
});

app.get('/usuarios', requireAdmin, (req, res) => {
  const login = (req.query.login || '').trim();
  if (login) {
    db.query('SELECT id, usuario, nome, email FROM usuarios WHERE usuario = ?', [login], (err, rows) => {
      if (err) return res.status(500).json({ success: false });
      res.json(rows);
    });
  } else {
    db.query('SELECT id, usuario, nome, email FROM usuarios', (err, rows) => {
      if (err) return res.status(500).json({ success: false });
      res.json(rows);
    });
  }
});

app.get('/usuarios/busca', requireAdmin, (req, res) => {
  let q = (req.query.q || '').trim();
  const listarTodos = q === '' || q === '*';

  let sql = 'SELECT id, usuario, nome, email FROM usuarios';
  const params = [];

  if (!listarTodos) {
    q = q.replace(/\s+/g, '');
    if (/^\d+$/.test(q)) {
      sql += ' WHERE id = ? OR usuario LIKE ? OR usuario LIKE ?';
      params.push(Number(q), q + '%', '%' + q + '%');
    } else {
      sql += ' WHERE usuario LIKE ? OR usuario LIKE ?';
      params.push(q + '%', '%' + q + '%');
    }
  }

  sql += ' ORDER BY usuario LIMIT 20';

  db.query(sql, params, (err, rows) => {
    if (err) {
      console.error('Erro /usuarios/busca:', err.message);
      return res.status(500).json({ success: false, error: 'erro interno' });
    }
    res.json({ success: true, usuarios: rows });
  });
});

app.put('/usuarios/:id', requireAdmin, (req, res) => {
  const { id } = req.params;
  const { usuario, senha, nome, email } = req.body || {};
  const senhaHash = senha ? bcrypt.hashSync(senha, 10) : null;

  let sql, params;
  if (senhaHash) {
    sql = 'UPDATE usuarios SET usuario = ?, senha = ?, nome = ?, email = ? WHERE id = ?';
    params = [usuario, senhaHash, nome, email, id];
  } else {
    sql = 'UPDATE usuarios SET usuario = ?, nome = ?, email = ? WHERE id = ?';
    params = [usuario, nome, email, id];
  }

  db.query(sql, params, (err) => {
    if (err) return res.status(500).json({ success: false });
    res.json({ success: true, message: 'Usuário atualizado com sucesso!' });
  });
});

app.put('/usuarios/login/:login', requireAdmin, (req, res) => {
  const { login } = req.params;
  const { usuario, senha, nome, email } = req.body || {};
  const senhaHash = senha ? bcrypt.hashSync(senha, 10) : null;

  let sql, params;
  if (senhaHash) {
    sql = 'UPDATE usuarios SET usuario = ?, senha = ?, nome = ?, email = ? WHERE usuario = ?';
    params = [usuario, senhaHash, nome, email, login];
  } else {
    sql = 'UPDATE usuarios SET usuario = ?, nome = ?, email = ? WHERE usuario = ?';
    params = [usuario, nome, email, login];
  }

  db.query(sql, params, (err, result) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    if (result.affectedRows === 0) return res.status(404).json({ success: false, message: 'Usuário não encontrado' });
    res.json({ success: true, message: 'Usuário atualizado com sucesso!' });
  });
});

app.delete('/usuarios/:id', requireAdmin, (req, res) => {
  db.query('DELETE FROM usuarios WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ success: false });
    res.json({ success: true, message: 'Usuário excluído com sucesso!' });
  });
});

/* =====================
   Dispositivos do usuário logado
===================== */

// VINCULAR dispositivo existente pelo serial ao usuário logado
app.post('/me/dispositivos/vincular', requireAuth, (req, res) => {
  const userId = req.session.user.id;
  const {
    serialnumber,
    fk_culturas = null,
    CEP = null, rua = null, numero = null, bairro = null,
    cidade = null, estado = null, latitude = null, longitude = null
  } = req.body || {};

  if (!serialnumber || !String(serialnumber).trim()) {
    return res.status(400).json({ success:false, message:'Informe o serial.' });
  }

  const serial = String(serialnumber).trim();

  // 1) Verifica se o serial existe
  const sqlSel = `
    SELECT id, fk_usuarios
    FROM esp32_dispositivos
    WHERE serialnumber = ?
    LIMIT 1
  `;
  db.query(sqlSel, [serial], (err, rows) => {
    if (err) {
      console.error('ERRO ao buscar serial:', err.message);
      return res.status(500).json({ success:false, message:'Erro interno' });
    }
    if (!rows.length) {
      return res.status(404).json({ success:false, message:'Serial não encontrado no sistema.' });
    }

    const dev = rows[0];

    // 2) Já vinculado em outra conta?
    if (dev.fk_usuarios && dev.fk_usuarios !== userId) {
      return res.status(409).json({ success:false, message:'Serial já vinculado em outra conta.' });
    }

    // 3) Vincula ao usuário (e opcionalmente atualiza metadados)
    const sqlUpd = `
      UPDATE esp32_dispositivos
         SET fk_usuarios = ?,
             fk_culturas = COALESCE(?, fk_culturas),
             CEP         = COALESCE(?, CEP),
             rua         = COALESCE(?, rua),
             numero      = COALESCE(?, numero),
             bairro      = COALESCE(?, bairro),
             cidade      = COALESCE(?, cidade),
             estado      = COALESCE(?, estado),
             latitude    = COALESCE(?, latitude),
             longitude   = COALESCE(?, longitude),
             update_em   = NOW()
       WHERE id = ?
    `;
    const params = [
      userId,
      fk_culturas, CEP, rua, numero, bairro, cidade, estado, latitude, longitude,
      dev.id
    ];

    db.query(sqlUpd, params, (e2) => {
      if (e2) {
        console.error('ERRO ao vincular serial:', e2.message);
        return res.status(500).json({ success:false, message:'Erro ao vincular dispositivo.' });
      }
      return res.json({ success:true, message:'Dispositivo vinculado à sua conta.', id: dev.id });
    });
  });
});

// ATUALIZAR (sem permitir alterar serialnumber)
app.put('/me/dispositivos/:id', requireAuth, forbidSerialChange, (req, res) => {
  const { id } = req.params;
  const userId = req.session.user.id;

  // Garante que o dispositivo pertence ao usuário
  db.query(
    'SELECT fk_usuarios FROM esp32_dispositivos WHERE id = ?',
    [id],
    (err, r) => {
      if (err) {
        console.error('Erro ao checar dono do dispositivo:', err.message);
        return res.status(500).json({ success:false, message:'Erro interno' });
      }
      if (!r.length) {
        return res.status(404).json({ success:false, message:'Dispositivo não encontrado.' });
      }
      if (r[0].fk_usuarios != userId && !req.session.user.isAdmin) {
        return res.status(403).json({ success:false, message:'Sem permissão.' });
      }

      const {
        fk_culturas, CEP, rua, numero, bairro, cidade, estado, latitude, longitude
      } = req.body || {};

      const sql = `
        UPDATE esp32_dispositivos
           SET fk_culturas = ?,
               CEP = ?,
               rua = ?,
               numero = ?,
               bairro = ?,
               cidade = ?,
               estado = ?,
               latitude = ?,
               longitude = ?,
               update_em = NOW()
         WHERE id = ?
      `;
      const params = [
        fk_culturas ?? null,
        CEP ? String(CEP).trim() : null,
        rua ? String(rua).trim() : null,
        numero ? String(numero).trim() : null,
        bairro ? String(bairro).trim() : null,
        cidade ? String(cidade).trim() : null,
        estado ? String(estado).trim() : null,
        latitude ?? null,
        longitude ?? null,
        id
      ];

      db.query(sql, params, (err2) => {
        if (err2) {
          console.error('Erro PUT /me/dispositivos/:id:', err2.message);
          return res.status(500).json({ success:false, message:'Erro ao atualizar.' });
        }
        return res.json({ success:true });
      });
    }
  );
});

// Desvincular dispositivo da conta (não apaga o dispositivo)
app.delete('/me/dispositivos/:id', requireAuth, (req, res) => {
  const { id } = req.params;
  const userId = req.session.user.id;

  const sql = 'UPDATE esp32_dispositivos SET fk_usuarios = NULL, update_em = NOW() WHERE id = ? AND fk_usuarios = ?';
  db.query(sql, [id, userId], (err, result) => {
    if (err) {
      console.error('Erro ao desvincular dispositivo:', err.message);
      return res.status(500).json({ success: false, message: 'Erro ao desvincular' });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Dispositivo não encontrado ou não pertence a você.' });
    }
    res.json({ success: true, message: 'Dispositivo desvinculado da sua conta.' });
  });
});

/* =====================
   Vínculos Usuário-Dispositivo (PROTEGIDO) — legado
===================== */
app.post('/usuario-dispositivos', requireAdmin, (req, res) => {
  const { usuario_login, serial, nome_plantacao } = req.body || {};

  if (!usuario_login || !serial || !nome_plantacao) {
    return res.status(400).json({
      success: false,
      message: 'Usuário, serial e nome da plantação são obrigatórios'
    });
  }

  db.query('SELECT id FROM usuarios WHERE usuario = ?', [usuario_login], (err, userRows) => {
    if (err) {
      console.error('Erro ao buscar usuário:', err.message);
      return res.status(500).json({ success: false, error: err.message });
    }

    if (userRows.length === 0) {
      return res.status(404).json({ success: false, message: 'Usuário não encontrado' });
    }

    const usuario_id = userRows[0].id;

    db.query('SELECT id FROM dispositivos WHERE serial = ?', [serial], (err, devRows) => {
      if (err) {
        console.error('Erro ao buscar dispositivo:', err.message);
        return res.status(500).json({ success: false, error: err.message });
      }

      if (devRows.length === 0) {
        return res.status(404).json({
          success: false,
          message: 'Dispositivo não encontrado. Verifique se o serial está correto.'
        });
      }

      const dispositivo_id = devRows[0].id;

      const sql = 'INSERT INTO usuario_dispositivos (usuario_id, dispositivo_id, nome_plantacao) VALUES (?, ?, ?)';
      db.query(sql, [usuario_id, dispositivo_id, nome_plantacao], (err, result) => {
        if (err) {
          if (err.code === 'ER_DUP_ENTRY') {
            return res.status(400).json({
              success: false,
              message: 'Este dispositivo já está vinculado à sua conta!'
            });
          }
          console.error('Erro ao vincular dispositivo:', err.message);
          return res.status(500).json({ success: false, error: err.message });
        }

        res.json({
          success: true,
          message: 'Dispositivo vinculado com sucesso!',
          vinculo_id: result.insertId
        });
      });
    });
  });
});

app.get('/usuario-dispositivos/:usuario_login', requireAuth, (req, res) => {
  const { usuario_login } = req.params;

  if (req.session.user.usuario !== usuario_login && !req.session.user.isAdmin) {
    return res.status(403).json({ success:false, message:'Você não tem permissão para acessar esses dados.' });
  }

  db.query('SELECT id FROM usuarios WHERE usuario = ? LIMIT 1', [usuario_login], (e, urows) => {
    if (e) return res.status(500).json({ success:false });
    if (!urows.length) return res.status(404).json({ success:false, message:'Usuário não encontrado' });

    const userId = urows[0].id;
    const sql = `
      SELECT d.id, d.serialnumber, d.fk_culturas, d.fk_usuarios,
             d.CEP, d.rua, d.numero, d.bairro, d.cidade, d.estado,
             d.latitude, d.longitude,
             c.cultura AS nome_cultura, c.agua_litros_m2 AS agua_necessaria, c.frequencia_irrigacao_dias
      FROM esp32_dispositivos d
      LEFT JOIN culturas c ON d.fk_culturas = c.id
      WHERE d.fk_usuarios = ?
      ORDER BY d.criado_em DESC
    `;
    db.query(sql, [userId], (err, rows) => {
      if (err) return res.status(500).json({ success:false, error: err.message });
      res.json({ success:true, dispositivos: rows });
    });
  });
});

app.delete('/usuario-dispositivos/:vinculo_id', requireAdmin, (req, res) => {
  const { vinculo_id } = req.params;

  const sql = 'DELETE FROM usuario_dispositivos WHERE id = ?';
  db.query(sql, [vinculo_id], (err, result) => {
    if (err) {
      console.error('Erro ao remover vínculo:', err.message);
      return res.status(500).json({ success: false, error: err.message });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Vínculo não encontrado' });
    }

    res.json({ success: true, message: 'Dispositivo desvinculado com sucesso!' });
  });
});

// =====================
// Culturas (PROTEGIDO)
// =====================
// rota principal
app.get('/culturas', requireAuth, (req, res) => {
  const sql = `
    SELECT id, cultura, agua_litros_m2, frequencia_irrigacao_dias
    FROM culturas
    ORDER BY cultura
  `;
  db.query(sql, (err, rows) => {
    if (err) return res.status(500).json({ success:false, error: err.message });
    res.json({ success:true, culturas: rows });
  });
});

// alias para compatibilidade com o front atual
app.get('/api/culturas', requireAuth, (req, res) => {
  const sql = `
    SELECT id, cultura, agua_litros_m2, frequencia_irrigacao_dias
    FROM culturas
    ORDER BY cultura
  `;
  db.query(sql, (err, rows) => {
    if (err) return res.status(500).json({ success:false, error: err.message });
    res.json({ success:true, culturas: rows });
  });
});

/* =====================
   Dados dos Sensores ESP32 (PROTEGIDO)
===================== */
app.get('/esp32/dispositivos/:usuario_id', requireAuth, (req, res) => {
  const { usuario_id } = req.params;

  if (req.session.user.id != usuario_id && !req.session.user.isAdmin) {
    return res.status(403).json({
      success: false,
      message: 'Você não tem permissão para acessar esses dispositivos.'
    });
  }

  const sql = `
    SELECT
      d.id,
      d.serialnumber,
      d.fk_culturas,
      d.fk_usuarios,
      c.cultura as nome_cultura,
      c.agua_litros_m2 as agua_necessaria,
      c.frequencia_irrigacao_dias
    FROM esp32_dispositivos d
    LEFT JOIN culturas c ON d.fk_culturas = c.id
    WHERE d.fk_usuarios = ?
    ORDER BY d.criado_em DESC
  `;

  db.query(sql, [usuario_id], (err, rows) => {
    if (err) {
      console.error('Erro ao buscar dispositivos ESP32:', err.message);
      return res.status(500).json({ success: false, error: err.message });
    }

    res.json({ success: true, dispositivos: rows });
  });
});

app.get('/esp32/sensores/:dispositivo_id/latest', requireAuth, (req, res) => {
  const { dispositivo_id } = req.params;

  const checkSql = 'SELECT fk_usuarios FROM esp32_dispositivos WHERE id = ?';
  db.query(checkSql, [dispositivo_id], (err, rows) => {
    if (err) {
      console.error('Erro ao verificar propriedade do dispositivo:', err.message);
      return res.status(500).json({ success: false, error: err.message });
    }

    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Dispositivo não encontrado' });
    }

    if (rows[0].fk_usuarios != req.session.user.id && !req.session.user.isAdmin) {
      return res.status(403).json({
        success: false,
        message: 'Você não tem permissão para acessar esse dispositivo.'
      });
    }

    const sql = `
      SELECT
        umidade_solo_bruto,
        umidade_solo_perc,
        umidade_ar,
        temperatura,
        criado_em,
        update_em
      FROM esp32_sensores
      WHERE fk_esp32_dispositivos = ?
      ORDER BY criado_em DESC
      LIMIT 1
    `;

    db.query(sql, [dispositivo_id], (err, rows) => {
      if (err) {
        console.error('Erro ao buscar dados dos sensores:', err.message);
        return res.status(500).json({ success: false, error: err.message });
      }

      if (rows.length === 0) {
        return res.json({ success: true, dados: null, message: 'Nenhuma leitura encontrada' });
      }

      res.json({ success: true, dados: rows[0] });
    });
  });
});

// Geocode no servidor (evita CORS e permite setar User-Agent)
app.get('/api/geocode', requireAuth, async (req, res) => {
  try {
    const q = (req.query.q || '').trim();
    if (!q) return res.status(400).json({ success: false, message: 'Parâmetro q é obrigatório' });

    const url = `https://nominatim.openstreetmap.org/search?format=json&limit=1&addressdetails=1&q=${encodeURIComponent(q)}`;
    const resp = await fetch(url, {
      headers: {
        'User-Agent': 'SmartFarm/1.0 (contato@smartfarm.com)',
        'Accept-Language': 'pt-BR'
      }
    });
    const data = await resp.json();
    if (!Array.isArray(data) || data.length === 0) {
      return res.json({ success: true, found: false });
    }
    const { lat, lon } = data[0];
    res.json({ success: true, found: true, lat: Number(lat), lon: Number(lon) });
  } catch (e) {
    console.error('Erro /api/geocode:', e.message);
    res.status(500).json({ success: false, message: 'Falha ao geocodificar' });
  }
});

app.get('/esp32/sensores/:dispositivo_id/historico', requireAuth, (req, res) => {
  const { dispositivo_id } = req.params;
  const { horas = 24 } = req.query;

  const checkSql = 'SELECT fk_usuarios FROM esp32_dispositivos WHERE id = ?';
  db.query(checkSql, [dispositivo_id], (err, rows) => {
    if (err) {
      console.error('Erro ao verificar propriedade do dispositivo:', err.message);
      return res.status(500).json({ success: false, error: err.message });
    }

    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Dispositivo não encontrado' });
    }

    if (rows[0].fk_usuarios != req.session.user.id && !req.session.user.isAdmin) {
      return res.status(403).json({
        success: false,
        message: 'Você não tem permissão para acessar esse dispositivo.'
      });
    }

    const sql = `
      SELECT
        umidade_solo_bruto,
        umidade_solo_perc,
        umidade_ar,
        temperatura,
        criado_em
      FROM esp32_sensores
      WHERE fk_esp32_dispositivos = ?
        AND criado_em >= DATE_SUB(NOW(), INTERVAL ? HOUR)
      ORDER BY criado_em ASC
    `;

    db.query(sql, [dispositivo_id, horas], (err, rows) => {
      if (err) {
        console.error('Erro ao buscar histórico dos sensores:', err.message);
        return res.status(500).json({ success: false, error: err.message });
      }

      res.json({ success: true, historico: rows });
    });
  });
});

// =================================================================
// NOVA ROTA ADICIONADA PARA BUSCAR O ÚLTIMO AGENDAMENTO
// =================================================================
app.get('/esp32/agendamentos/:dispositivo_id/latest', requireAuth, (req, res) => {
  const { dispositivo_id } = req.params;

  const checkSql = 'SELECT fk_usuarios FROM esp32_dispositivos WHERE id = ?';
  db.query(checkSql, [dispositivo_id], (err, checkRows) => {
    if (err) {
      console.error('[Agendamentos] Erro ao verificar dono do dispositivo:', err.message);
      return res.status(500).json({ success: false, message: 'Erro interno ao verificar permissão.' });
    }

    if (checkRows.length === 0) {
      return res.status(404).json({ success: false, message: 'Dispositivo não encontrado.' });
    }

    if (checkRows[0].fk_usuarios != req.session.user.id && !req.session.user.isAdmin) {
      return res.status(403).json({ success: false, message: 'Acesso negado a este dispositivo.' });
    }

    const sql = `
      SELECT 
        when_local,
        pump_seconds,
        flow_lps
      FROM esp32_agendamentos
      WHERE fk_esp32_dispositivos = ?
      ORDER BY id DESC
      LIMIT 1
    `;

    db.query(sql, [dispositivo_id], (err, rows) => {
      if (err) {
        console.error('[Agendamentos] Erro ao buscar último agendamento:', err.message);
        return res.status(500).json({ success: false, error: err.message });
      }

      if (rows.length === 0) {
        return res.json({ success: true, dados: null, message: 'Nenhum agendamento encontrado' });
      }

      res.json({ success: true, dados: rows[0] });
    });
  });
});

/* =====================
   Configurações do Usuário (PROTEGIDO)
===================== */
app.get('/usuario/perfil', requireAuth, (req, res) => {
  const sql = 'SELECT id, usuario, nome, email FROM usuarios WHERE id = ?';
  db.query(sql, [req.session.user.id], (err, rows) => {
    if (err) {
      console.error('Erro ao buscar perfil:', err.message);
      return res.status(500).json({ success: false, error: err.message });
    }

    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Usuário não encontrado' });
    }

    res.json({ success: true, perfil: rows[0] });
  });
});

app.put('/usuario/perfil', requireAuth, (req, res) => {
  const { nome, email } = req.body;

  if (!nome || !email) {
    return res.status(400).json({
      success: false,
      message: 'Nome e email são obrigatórios'
    });
  }

  const checkEmailSql = 'SELECT id FROM usuarios WHERE email = ? AND id != ?';
  db.query(checkEmailSql, [email, req.session.user.id], (err, rows) => {
    if (err) {
      console.error('Erro ao verificar email:', err.message);
      return res.status(500).json({ success: false, error: err.message });
    }

    if (rows.length > 0) {
      return res.status(400).json({
        success: false,
        message: 'Este email já está em uso por outro usuário'
      });
    }

    const updateSql = 'UPDATE usuarios SET nome = ?, email = ? WHERE id = ?';
    db.query(updateSql, [nome, email, req.session.user.id], (err2) => {
      if (err2) {
        console.error('Erro ao atualizar perfil:', err2.message);
        return res.status(500).json({ success: false, error: err2.message });
      }

      // Atualiza também a sessão para refletir o novo nome
      req.session.user.nome = nome;

      res.json({
        success: true,
        message: 'Perfil atualizado com sucesso!',
        perfil: { nome, email }
      });
    });
  });
});

app.put('/usuario/senha', requireAuth, (req, res) => {
  const { senhaAtual, novaSenha, confirmarSenha } = req.body;

  if (!senhaAtual || !novaSenha || !confirmarSenha) {
    return res.status(400).json({
      success: false,
      message: 'Todos os campos são obrigatórios'
    });
  }

  if (novaSenha !== confirmarSenha) {
    return res.status(400).json({
      success: false,
      message: 'A nova senha e a confirmação não coincidem'
    });
  }

  if (novaSenha.length < 6) {
    return res.status(400).json({
      success: false,
      message: 'A nova senha deve ter no mínimo 6 caracteres'
    });
  }

  const sql = 'SELECT senha FROM usuarios WHERE id = ?';
  db.query(sql, [req.session.user.id], (err, rows) => {
    if (err) {
      console.error('Erro ao buscar usuário:', err.message);
      return res.status(500).json({ success: false, error: err.message });
    }

    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Usuário não encontrado' });
    }

    const senhaHash = rows[0].senha;
    const senhaValida = senhaHash?.startsWith?.('$2a$') || senhaHash?.startsWith?.('$2b$')
      ? bcrypt.compareSync(senhaAtual, senhaHash)
      : senhaAtual === senhaHash;

    if (!senhaValida) {
      return res.status(400).json({
        success: false,
        message: 'Senha atual incorreta'
      });
    }

    const novaSenhaHash = bcrypt.hashSync(novaSenha, 10);
    const updateSql = 'UPDATE usuarios SET senha = ? WHERE id = ?';
    db.query(updateSql, [novaSenhaHash, req.session.user.id], (err2) => {
      if (err2) {
        console.error('Erro ao atualizar senha:', err2.message);
        return res.status(500).json({ success: false, error: err2.message });
      }

      res.json({ success: true, message: 'Senha alterada com sucesso!' });
    });
  });
});

/* =====================
   Projeção de Irrigação (PROTEGIDO)
===================== */
app.get('/esp32/projecao/:dispositivo_id', requireAuth, (req, res) => {
  const { dispositivo_id } = req.params;

  const checkSql = `
    SELECT
      d.fk_usuarios,
      c.frequencia_irrigacao_dias,
      c.agua_litros_m2
    FROM esp32_dispositivos d
    LEFT JOIN culturas c ON d.fk_culturas = c.id
    WHERE d.id = ?
  `;

  db.query(checkSql, [dispositivo_id], (err, rows) => {
    if (err) {
      console.error('Erro ao verificar propriedade do dispositivo:', err.message);
      return res.status(500).json({ success: false, error: err.message });
    }

    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Dispositivo não encontrado' });
    }

    if (rows[0].fk_usuarios != req.session.user.id && !req.session.user.isAdmin) {
      return res.status(403).json({
        success: false,
        message: 'Você não tem permissão para acessar esse dispositivo.'
      });
    }

    const frequencia = rows[0].frequencia_irrigacao_dias;
    const aguaPorM2 = rows[0].agua_litros_m2;

    const sqlUltimaIrrigacao = `
      SELECT criado_em, umidade_solo_perc
      FROM esp32_sensores
      WHERE fk_esp32_dispositivos = ?
        AND umidade_solo_perc >= 80
      ORDER BY criado_em DESC
      LIMIT 1
    `;

    db.query(sqlUltimaIrrigacao, [dispositivo_id], (err2, irrigacaoRows) => {
      if (err2) {
        console.error('Erro ao buscar última irrigação:', err2.message);
        return res.status(500).json({ success: false, error: err2.message });
      }

      let dataProximaIrrigacao = null;
      let diasRestantes = null;

      if (irrigacaoRows.length > 0 && frequencia) {
        const ultimaIrrigacao = new Date(irrigacaoRows[0].criado_em);
        dataProximaIrrigacao = new Date(ultimaIrrigacao);
        dataProximaIrrigacao.setDate(dataProximaIrrigacao.getDate() + frequencia);

        const hoje = new Date();
        const diffTime = dataProximaIrrigacao - hoje;
        diasRestantes = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
      }

      const areaCultivada = 100; // m² - valor padrão
      const quantidadeAgua = aguaPorM2 ? (aguaPorM2 * areaCultivada) : null;

      res.json({
        success: true,
        projecao: {
          data_proxima_irrigacao: dataProximaIrrigacao,
          dias_restantes: diasRestantes,
          quantidade_agua_litros: quantidadeAgua,
          area_cultivada_m2: areaCultivada,
          agua_por_m2: aguaPorM2,
          frequencia_dias: frequencia
        }
      });
    });
  });
});

/* =====================
   Admin: logs
===================== */
app.get('/admin/logins', requireAdmin, (req, res) => {
  const { usuario, sucesso, limit = 50, offset = 0 } = req.query;
  const params = [];
  let sql =
    'SELECT id, usuario, user_id, sucesso, ip, user_agent, origem, criado_em ' +
    'FROM login_logs';

  const where = [];
  if (usuario) { where.push('usuario LIKE ?'); params.push('%' + usuario + '%'); }
  if (sucesso === '0' || sucesso === '1') { where.push('sucesso = ?'); params.push(Number(sucesso)); }
  if (where.length) sql += ' WHERE ' + where.join(' AND ');
  sql += ' ORDER BY id DESC LIMIT ? OFFSET ?';
  params.push(Number(limit), Number(offset));

  db.query(sql, params, (err, rows) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    res.json({ success: true, logs: rows });
  });
});

/* =====================
   Rota para migrar senhas existentes (executar uma vez)
===================== */
app.post('/admin/migrate-passwords', requireAdmin, (req, res) => {
  const sql = 'SELECT id, usuario, senha FROM usuarios';
  db.query(sql, (err, rows) => {
    if (err) {
      return res.status(500).json({ success: false, error: err.message });
    }

    let migrated = 0;
    let skipped = 0;

    rows.forEach(user => {
      if (user.senha?.startsWith?.('$2a$') || user.senha?.startsWith?.('$2b$')) {
        skipped++;
        return;
      }

      const senhaHash = bcrypt.hashSync(user.senha, 10);
      db.query('UPDATE usuarios SET senha = ? WHERE id = ?', [senhaHash, user.id], (err2) => {
        if (err2) {
          console.error(`Erro ao migrar senha do usuário ${user.usuario}:`, err2.message);
        } else {
          migrated++;
        }
      });
    });

    res.json({
      success: true,
      message: `Migração iniciada. ${migrated} senhas serão migradas, ${skipped} já estavam em hash.`
    });
  });
});

/* =====================
   Start
===================== */
app.listen(PORT, HOST, () => {
  console.log(`🚀 Servidor rodando em http://${HOST}:${PORT}`);
  console.log(`🔒 Autenticação com idle=${IDLE_TIMEOUT_MS/60000}min e absoluto=${ABSOLUTE_TIMEOUT_MS/60000}min`);
});
