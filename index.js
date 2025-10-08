// index.js — Express + MySQL (pool) + dotenv + logs de login + SESSÕES SEGURAS
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const session = require('express-session');
const bcrypt = require('bcryptjs');
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
app.use(cors({
  origin: process.env.FRONTEND_URL || true,
  credentials: true
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// =====================
// SESSÕES SEGURAS
// =====================
app.use(session({
  secret: process.env.SESSION_SECRET || 'smartfarm-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // true em produção com HTTPS
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 // 24 horas
  }
}));

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

// "sessão" simples em memória para contagem de usuários online
const usuariosOnline = new Set();

// =====================
// MIDDLEWARE DE AUTENTICAÇÃO
// =====================
function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ 
      success: false, 
      message: 'Não autenticado. Faça login primeiro.',
      redirectTo: '/login.html'
    });
  }
  next();
}

function requireAdmin(req, res, next) {
  if (!req.session || !req.session.userId || !req.session.isAdmin) {
    return res.status(403).json({ 
      success: false, 
      message: 'Acesso negado. Apenas administradores.'
    });
  }
  next();
}

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

  const sql = 'SELECT id, usuario, nome, senha FROM usuarios WHERE usuario = ? LIMIT 1';
  db.query(sql, [usuario], (err, rows) => {
    if (err) {
      console.error('Erro /login:', err.message);
      db.query('INSERT INTO login_logs (usuario, sucesso, ip, user_agent, origem) VALUES (?,?,?,?,?)',
               [usuario || null, 0, ip, ua, origem]);
      return res.status(500).json({ success: false });
    }

    if (rows.length > 0) {
      const u = rows[0];
      
      // Verificar senha (suporta tanto hash bcrypt quanto texto plano para migração)
      const senhaValida = u.senha.startsWith('$2a$') || u.senha.startsWith('$2b$') 
        ? bcrypt.compareSync(senha, u.senha)
        : senha === u.senha;

      if (senhaValida) {
        // Criar sessão
        req.session.userId = u.id;
        req.session.usuario = u.usuario;
        req.session.nome = u.nome;
        req.session.isAdmin = u.usuario === 'admin';

        db.query('INSERT INTO login_logs (usuario, user_id, sucesso, ip, user_agent, origem) VALUES (?,?,?,?,?,?)',
                 [u.usuario, u.id, 1, ip, ua, origem]);
        usuariosOnline.add(u.usuario);
        
        return res.json({ 
          success: true, 
          isAdmin: req.session.isAdmin, 
          nome: u.nome, 
          usuario: u.usuario 
        });
      }
    }

    db.query('INSERT INTO login_logs (usuario, sucesso, ip, user_agent, origem) VALUES (?,?,?,?,?)',
             [usuario || null, 0, ip, ua, origem]);
    res.json({ success: false, message: 'Usuário ou senha incorretos' });
  });
});

app.post('/logout', (req, res) => {
  if (req.session && req.session.usuario) {
    usuariosOnline.delete(req.session.usuario);
    req.session.destroy((err) => {
      if (err) {
        return res.status(500).json({ success: false, message: 'Erro ao fazer logout' });
      }
      res.json({ success: true });
    });
  } else {
    res.json({ success: true });
  }
});

// Nova rota para verificar sessão
app.get('/session', (req, res) => {
  if (req.session && req.session.userId) {
    return res.json({
      success: true,
      authenticated: true,
      user: {
        id: req.session.userId,
        usuario: req.session.usuario,
        nome: req.session.nome,
        isAdmin: req.session.isAdmin
      }
    });
  }
  res.json({ success: true, authenticated: false });
});

app.get('/online', (_req, res) => res.json({ online: usuariosOnline.size }));

// =====================
// Usuários (PROTEGIDO)
// =====================
app.post('/usuarios', requireAdmin, (req, res) => {
  const { usuario, senha, nome, email } = req.body || {};
  
  // Hash da senha
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
  
  // Hash da senha se foi fornecida
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
  
  // Hash da senha se foi fornecida
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

// =====================
// Dispositivos (PROTEGIDO)
// =====================
app.post('/dispositivos', requireAdmin, (req, res) => {
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

app.get('/dispositivos', requireAdmin, (req, res) => {
  const sql = 'SELECT id, serial, criado_em FROM dispositivos ORDER BY criado_em DESC';
  db.query(sql, (err, rows) => {
    if (err) {
      console.error('Erro /dispositivos GET:', err.message);
      return res.status(500).json({ success: false, error: err.message });
    }
    res.json({ success: true, dispositivos: rows });
  });
});

app.get('/dispositivos/:id', requireAdmin, (req, res) => {
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

app.delete('/dispositivos/:id', requireAdmin, (req, res) => {
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
// Vínculos Usuário-Dispositivo (PROTEGIDO)
// =====================
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
  
  // Verificar se o usuário está tentando acessar seus próprios dados ou se é admin
  if (req.session.usuario !== usuario_login && !req.session.isAdmin) {
    return res.status(403).json({ 
      success: false, 
      message: 'Você não tem permissão para acessar esses dados.' 
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
  
  db.query(sql, [usuario_login], (err, rows) => {
    if (err) {
      console.error('Erro ao listar dispositivos do usuário:', err.message);
      return res.status(500).json({ success: false, error: err.message });
    }
    
    res.json({ success: true, dispositivos: rows });
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
// Dados dos Sensores ESP32 (PROTEGIDO)
// =====================
app.get('/esp32/dispositivos/:usuario_id', requireAuth, (req, res) => {
  const { usuario_id } = req.params;
  
  // Verificar se o usuário está acessando seus próprios dispositivos ou se é admin
  if (req.session.userId != usuario_id && !req.session.isAdmin) {
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
  
  // Verificar se o dispositivo pertence ao usuário logado
  const checkSql = 'SELECT fk_usuarios FROM esp32_dispositivos WHERE id = ?';
  db.query(checkSql, [dispositivo_id], (err, rows) => {
    if (err) {
      console.error('Erro ao verificar propriedade do dispositivo:', err.message);
      return res.status(500).json({ success: false, error: err.message });
    }
    
    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Dispositivo não encontrado' });
    }
    
    if (rows[0].fk_usuarios != req.session.userId && !req.session.isAdmin) {
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

app.get('/esp32/sensores/:dispositivo_id/historico', requireAuth, (req, res) => {
  const { dispositivo_id } = req.params;
  const { horas = 24 } = req.query;
  
  // Verificar se o dispositivo pertence ao usuário logado
  const checkSql = 'SELECT fk_usuarios FROM esp32_dispositivos WHERE id = ?';
  db.query(checkSql, [dispositivo_id], (err, rows) => {
    if (err) {
      console.error('Erro ao verificar propriedade do dispositivo:', err.message);
      return res.status(500).json({ success: false, error: err.message });
    }
    
    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Dispositivo não encontrado' });
    }
    
    if (rows[0].fk_usuarios != req.session.userId && !req.session.isAdmin) {
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

// =====================
// Configurações do Usuário (PROTEGIDO)
// =====================

// Obter dados do perfil do usuário logado
app.get('/usuario/perfil', requireAuth, (req, res) => {
  const sql = 'SELECT id, usuario, nome, email FROM usuarios WHERE id = ?';
  db.query(sql, [req.session.userId], (err, rows) => {
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

// Atualizar perfil do usuário
app.put('/usuario/perfil', requireAuth, (req, res) => {
  const { nome, email } = req.body;
  
  if (!nome || !email) {
    return res.status(400).json({ 
      success: false, 
      message: 'Nome e email são obrigatórios' 
    });
  }
  
  // Verificar se o email já está em uso por outro usuário
  const checkEmailSql = 'SELECT id FROM usuarios WHERE email = ? AND id != ?';
  db.query(checkEmailSql, [email, req.session.userId], (err, rows) => {
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
    
    // Atualizar perfil
    const updateSql = 'UPDATE usuarios SET nome = ?, email = ? WHERE id = ?';
    db.query(updateSql, [nome, email, req.session.userId], (err, result) => {
      if (err) {
        console.error('Erro ao atualizar perfil:', err.message);
        return res.status(500).json({ success: false, error: err.message });
      }
      
      // Atualizar nome na sessão
      req.session.nome = nome;
      
      res.json({ 
        success: true, 
        message: 'Perfil atualizado com sucesso!',
        perfil: { nome, email }
      });
    });
  });
});

// Trocar senha
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
  
  // Buscar senha atual do usuário
  const sql = 'SELECT senha FROM usuarios WHERE id = ?';
  db.query(sql, [req.session.userId], (err, rows) => {
    if (err) {
      console.error('Erro ao buscar usuário:', err.message);
      return res.status(500).json({ success: false, error: err.message });
    }
    
    if (rows.length === 0) {
      return res.status(404).json({ success: false, message: 'Usuário não encontrado' });
    }
    
    const senhaHash = rows[0].senha;
    
    // Verificar senha atual
    const senhaValida = senhaHash.startsWith('$2a$') || senhaHash.startsWith('$2b$') 
      ? bcrypt.compareSync(senhaAtual, senhaHash)
      : senhaAtual === senhaHash;
    
    if (!senhaValida) {
      return res.status(400).json({ 
        success: false, 
        message: 'Senha atual incorreta' 
      });
    }
    
    // Hash da nova senha
    const novaSenhaHash = bcrypt.hashSync(novaSenha, 10);
    
    // Atualizar senha
    const updateSql = 'UPDATE usuarios SET senha = ? WHERE id = ?';
    db.query(updateSql, [novaSenhaHash, req.session.userId], (err) => {
      if (err) {
        console.error('Erro ao atualizar senha:', err.message);
        return res.status(500).json({ success: false, error: err.message });
      }
      
      res.json({ 
        success: true, 
        message: 'Senha alterada com sucesso!' 
      });
    });
  });
});



// =====================
// Projeção de Irrigação (PROTEGIDO)
// =====================
app.get('/esp32/projecao/:dispositivo_id', requireAuth, (req, res) => {
  const { dispositivo_id } = req.params;
  
  // Verificar se o dispositivo pertence ao usuário logado
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
    
    if (rows[0].fk_usuarios != req.session.userId && !req.session.isAdmin) {
      return res.status(403).json({ 
        success: false, 
        message: 'Você não tem permissão para acessar esse dispositivo.' 
      });
    }
    
    const frequencia = rows[0].frequencia_irrigacao_dias;
    const aguaPorM2 = rows[0].agua_litros_m2;
    
    // Buscar a última irrigação registrada (considerando quando a umidade estava alta)
    // Vamos buscar o último registro com umidade > 80% como indicativo de irrigação
    const sqlUltimaIrrigacao = `
      SELECT criado_em, umidade_solo_perc
      FROM esp32_sensores
      WHERE fk_esp32_dispositivos = ?
        AND umidade_solo_perc >= 80
      ORDER BY criado_em DESC
      LIMIT 1
    `;
    
    db.query(sqlUltimaIrrigacao, [dispositivo_id], (err, irrigacaoRows) => {
      if (err) {
        console.error('Erro ao buscar última irrigação:', err.message);
        return res.status(500).json({ success: false, error: err.message });
      }
      
      let dataProximaIrrigacao = null;
      let diasRestantes = null;
      
      if (irrigacaoRows.length > 0 && frequencia) {
        const ultimaIrrigacao = new Date(irrigacaoRows[0].criado_em);
        dataProximaIrrigacao = new Date(ultimaIrrigacao);
        dataProximaIrrigacao.setDate(dataProximaIrrigacao.getDate() + frequencia);
        
        // Calcular dias restantes
        const hoje = new Date();
        const diffTime = dataProximaIrrigacao - hoje;
        diasRestantes = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
      }
      
      // Buscar área cultivada (assumindo 100m² como padrão se não houver registro)
      // Você pode adicionar um campo na tabela esp32_dispositivos para armazenar a área
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

// =====================
// Admin: logs
// =====================
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
// Rota para migrar senhas existentes (executar uma vez)
// =====================
app.post('/admin/migrate-passwords', requireAdmin, (req, res) => {
  const sql = 'SELECT id, usuario, senha FROM usuarios';
  db.query(sql, (err, rows) => {
    if (err) {
      return res.status(500).json({ success: false, error: err.message });
    }
    
    let migrated = 0;
    let skipped = 0;
    
    rows.forEach(user => {
      // Verificar se já é hash bcrypt
      if (user.senha.startsWith('$2a$') || user.senha.startsWith('$2b$')) {
        skipped++;
        return;
      }
      
      // Fazer hash da senha
      const senhaHash = bcrypt.hashSync(user.senha, 10);
      db.query('UPDATE usuarios SET senha = ? WHERE id = ?', [senhaHash, user.id], (err) => {
        if (err) {
          console.error(`Erro ao migrar senha do usuário ${user.usuario}:`, err.message);
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

// =====================
// Start
// =====================
app.listen(PORT, HOST, () => {
  console.log(`🚀 Servidor rodando em http://${HOST}:${PORT}`);
  console.log(`🔒 Sistema de autenticação seguro ativado`);
});

