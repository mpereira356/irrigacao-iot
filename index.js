// index.js — Express + MySQL (pool) + dotenv + logs de login + /ping + /debug-ip
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
require('dotenv').config();

const app = express();

// =====================
// Server
// =====================
const PORT = Number(process.env.PORT || 3000);
const HOST = process.env.HOST || '0.0.0.0';

// atrás do Nginx/Cloudflare
app.set('trust proxy', true);

// =====================
// Middlewares
// =====================
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// estáticos
app.use(express.static(path.join(__dirname, 'public')));

// raiz -> login.html
app.get('/', (req, res) => {
  const p = path.join(__dirname, 'public', 'login.html');
  if (fs.existsSync(p)) return res.sendFile(p);
  res.status(404).send('login.html não encontrado em /public');
});

// =====================
// DB (POOL — resiliente)
// =====================
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
// keepalive simples
setInterval(() => db.query('SELECT 1'), 30_000);

// =====================
// Helpers
// =====================
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
const getUA = req => req.headers['user-agent'] || '';
const getRef = req => req.headers['referer'] || req.headers['referrer'] || '';

// "sessão" simples em memória
const usuariosOnline = new Set();

// =====================
// Rotas de saúde / debug
// =====================
app.get('/ping', (_req, res) => res.json({ ok: true, time: new Date().toISOString() }));

app.get('/debug-ip', (req, res) => {
  const xffArr = (req.headers['x-forwarded-for'] || '')
    .split(',').map(s => s.trim()).filter(Boolean);
  res.json({
    ip: (xffArr[0] || req.headers['x-real-ip'] || req.ip),
    req_ip: req.ip,
    xff: xffArr.join(', ') || null,
    xreal: req.headers['x-real-ip'] || null,
    ua: req.headers['user-agent'] || null
  });
});

// =====================
// Auth + logs
// =====================
app.post('/login', (req, res) => {
  const { usuario, senha } = req.body || {};
  if (!usuario || !senha) return res.status(400).json({ success: false, message: 'Dados inválidos' });

  const ip = getClientIp(req);
  const ua = getUA(req);
  const origem = getRef(req);

  const sql = 'SELECT id, usuario, nome FROM usuarios WHERE usuario = ? AND senha = ? LIMIT 1';
  db.query(sql, [usuario, senha], (err, rows) => {
    if (err) {
      console.error('Erro /login:', err.message);
      db.query('INSERT INTO login_logs (usuario, sucesso, ip, user_agent, origem) VALUES (?,?,?,?,?)',
               [usuario || null, 0, ip, ua, origem]);
      return res.status(500).json({ success: false });
    }

    if (rows.length > 0) {
      const u = rows[0];
      db.query('INSERT INTO login_logs (usuario, user_id, sucesso, ip, user_agent, origem) VALUES (?,?,?,?,?,?)',
               [u.usuario, u.id, 1, ip, ua, origem]);
      usuariosOnline.add(u.usuario);
      return res.json({ success: true, isAdmin: u.usuario === 'admin', nome: u.nome, usuario: u.usuario });
    }

    db.query('INSERT INTO login_logs (usuario, sucesso, ip, user_agent, origem) VALUES (?,?,?,?,?)',
             [usuario || null, 0, ip, ua, origem]);
    res.json({ success: false, message: 'Usuário ou senha incorretos' });
  });
});

app.post('/logout', (req, res) => {
  const { usuario } = req.body || {};
  if (usuario) usuariosOnline.delete(usuario);
  res.json({ success: true });
});

app.get('/online', (_req, res) => res.json({ online: usuariosOnline.size }));

// =====================
// Usuários
// =====================
app.post('/usuarios', (req, res) => {
  const { usuario, senha, nome, email } = req.body || {};
  const sql = 'INSERT INTO usuarios (usuario, senha, nome, email) VALUES (?, ?, ?, ?)';
  db.query(sql, [usuario, senha, nome, email], (err) => {
    if (err) {
      if (err.code === 'ER_DUP_ENTRY') return res.status(400).json({ success: false, message: 'Usuário já existe!' });
      console.error('Erro /usuarios POST:', err.message);
      return res.status(500).json({ success: false, error: err.message });
    }
    res.json({ success: true, message: 'Usuário criado com sucesso!' });
  });
});

app.get('/usuarios', (req, res) => {
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

app.get('/usuarios/busca', (req, res) => {
  let q = (req.query.q || '').trim();
  const listarTodos = q === '' || q === '*';

  let sql = 'SELECT id, usuario, nome, email FROM usuarios';
  const params = [];

  if (!listarTodos) {
  q = q.replace(/\s+/g, '');
  if (/^\d+$/.test(q)) {
    // se for número, pesquisa também por ID
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

app.put('/usuarios/:id', (req, res) => {
  const { id } = req.params;
  const { usuario, senha, nome, email } = req.body || {};
  const sql = 'UPDATE usuarios SET usuario = ?, senha = ?, nome = ?, email = ? WHERE id = ?';
  db.query(sql, [usuario, senha, nome, email, id], (err) => {
    if (err) return res.status(500).json({ success: false });
    res.json({ success: true, message: 'Usuário atualizado com sucesso!' });
  });
});

app.put('/usuarios/login/:login', (req, res) => {
  const { login } = req.params;
  const { usuario, senha, nome, email } = req.body || {};
  const sql = 'UPDATE usuarios SET usuario = ?, senha = ?, nome = ?, email = ? WHERE usuario = ?';
  db.query(sql, [usuario, senha, nome, email, login], (err, result) => {
    if (err) return res.status(500).json({ success: false, error: err.message });
    if (result.affectedRows === 0) return res.status(404).json({ success: false, message: 'Usuário não encontrado' });
    res.json({ success: true, message: 'Usuário atualizado com sucesso!' });
  });
});

app.delete('/usuarios/:id', (req, res) => {
  db.query('DELETE FROM usuarios WHERE id = ?', [req.params.id], (err) => {
    if (err) return res.status(500).json({ success: false });
    res.json({ success: true, message: 'Usuário excluído com sucesso!' });
  });
});

// =====================
// Dispositivos (NOVO)
// =====================
app.post('/dispositivos', (req, res) => {
  const { serial } = req.body || {};
  
  if (!serial || !serial.trim()) {
    return res.status(400).json({ 
      success: false, 
      message: 'Serial do dispositivo é obrigatório' 
    });
  }

  const sql = 'INSERT INTO dispositivos (serial) VALUES (?)';
  db.query(sql, [serial.trim()], (err, result) => {
    if (err) {
      if (err.code === 'ER_DUP_ENTRY') {
        return res.status(400).json({ 
          success: false, 
          message: 'Dispositivo com este serial já existe!' 
        });
      }
      console.error('Erro /dispositivos POST:', err.message);
      return res.status(500).json({ 
        success: false, 
        error: err.message 
      });
    }
    res.json({ 
      success: true, 
      message: 'Dispositivo criado com sucesso!',
      id: result.insertId
    });
  });
});

app.get('/dispositivos', (req, res) => {
  const sql = 'SELECT id, serial, criado_em FROM dispositivos ORDER BY criado_em DESC';
  db.query(sql, (err, rows) => {
    if (err) {
      console.error('Erro /dispositivos GET:', err.message);
      return res.status(500).json({ success: false, error: err.message });
    }
    res.json({ success: true, dispositivos: rows });
  });
});

app.get('/dispositivos/:id', (req, res) => {
  const { id } = req.params;
  const sql = 'SELECT id, serial, criado_em FROM dispositivos WHERE id = ?';
  db.query(sql, [id], (err, rows) => {
    if (err) {
      console.error('Erro /dispositivos/:id GET:', err.message);
      return res.status(500).json({ success: false, error: err.message });
    }
    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Dispositivo não encontrado' });
    }
    res.json({ success: true, dispositivo: rows[0] });
  });
});

app.delete('/dispositivos/:id', (req, res) => {
  const { id } = req.params;
  const sql = 'DELETE FROM dispositivos WHERE id = ?';
  db.query(sql, [id], (err, result) => {
    if (err) {
      console.error('Erro /dispositivos/:id DELETE:', err.message);
      return res.status(500).json({ success: false, error: err.message });
    }
    if (result.affectedRows === 0) {
      return res.status(404).json({ success: false, message: 'Dispositivo não encontrado' });
    }
    res.json({ success: true, message: 'Dispositivo excluído com sucesso!' });
  });
});

// =====================
// Vínculos Usuário-Dispositivo (NOVO)
// =====================

// Vincular dispositivo a usuário
app.post('/usuario-dispositivos', (req, res) => {
  const { usuario_login, serial, nome_plantacao } = req.body || {};
  
  if (!usuario_login || !serial || !nome_plantacao) {
    return res.status(400).json({ 
      success: false, 
      message: 'Usuário, serial e nome da plantação são obrigatórios' 
    });
  }

  // Primeiro, buscar o ID do usuário pelo login
  db.query('SELECT id FROM usuarios WHERE usuario = ?', [usuario_login], (err, userRows) => {
    if (err) {
      console.error('Erro ao buscar usuário:', err.message);
      return res.status(500).json({ success: false, error: err.message });
    }
    
    if (userRows.length === 0) {
      return res.status(404).json({ success: false, message: 'Usuário não encontrado' });
    }
    
    const usuario_id = userRows[0].id;
    
    // Buscar o ID do dispositivo pelo serial
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
      
      // Inserir o vínculo
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

// Listar dispositivos de um usuário
app.get('/usuario-dispositivos/:usuario_login', (req, res) => {
  const { usuario_login } = req.params;
  
  const sql = `
    SELECT 
      ud.id as vinculo_id,
      ud.nome_plantacao,
      ud.criado_em,
      d.id as dispositivo_id,
      d.serial
    FROM usuario_dispositivos ud
    INNER JOIN usuarios u ON ud.usuario_id = u.id
    INNER JOIN dispositivos d ON ud.dispositivo_id = d.id
    WHERE u.usuario = ?
    ORDER BY ud.criado_em DESC
  `;
  
  db.query(sql, [usuario_login], (err, rows) => {
    if (err) {
      console.error('Erro ao listar dispositivos do usuário:', err.message);
      return res.status(500).json({ success: false, error: err.message });
    }
    
    res.json({ success: true, dispositivos: rows });
  });
});

// Remover vínculo
app.delete('/usuario-dispositivos/:vinculo_id', (req, res) => {
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
// Dados dos Sensores ESP32 (NOVO)
// =====================

// Buscar dispositivos ESP32 de um usuário
app.get('/esp32/dispositivos/:usuario_id', (req, res) => {
  const { usuario_id } = req.params;
  
  // ==================================================================
  // CORREÇÃO FINAL APLICADA AQUI
  // ==================================================================
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

// Buscar dados mais recentes dos sensores de um dispositivo
app.get('/esp32/sensores/:dispositivo_id/latest', (req, res) => {
  const { dispositivo_id } = req.params;
  
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

// Buscar histórico de leituras dos sensores (últimas 24h)
app.get('/esp32/sensores/:dispositivo_id/historico', (req, res) => {
  const { dispositivo_id } = req.params;
  const { horas = 24 } = req.query;
  
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

// =====================
// Admin: logs
// =====================
function requireAdmin(req, res, next) {
  const ok = req.headers['x-admin'] === '1' && usuariosOnline.has('admin');
  if (!ok) return res.status(401).json({ success: false, error: 'não autorizado' });
  next();
}

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

// =====================
// Start
// =====================
app.listen(PORT, HOST, () => {
  console.log(`Servidor rodando em http://${HOST}:${PORT}` );
});

