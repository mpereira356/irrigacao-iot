const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const app = express();

app.use(cors());
app.use(express.json());
const path = require('path');
app.use(express.static(path.join(__dirname, 'public')));

// Conexão com MySQL
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '', 
  database: 'irrigacao'
});

let usuariosOnline = new Set();


// ROTA DE LOGIN
app.post('/login', (req, res) => {
  const { usuario, senha } = req.body;

  const sql = 'SELECT * FROM usuarios WHERE usuario = ? AND senha = ?';
  db.query(sql, [usuario, senha], (err, results) => {
    if (err) return res.status(500).json({ success: false });

    if (results.length > 0) {
      const isAdmin = results[0].usuario === 'admin';
      const nome = results[0].nome;

      usuariosOnline.add(usuario); // ✅ Marca como online

      return res.json({ success: true, isAdmin, nome, usuario });
    } else {
      return res.json({ success: false, message: 'Usuário ou senha incorretos' });
    }
  });
});

app.post('/logout', (req, res) => {
  const { usuario } = req.body;
  usuariosOnline.delete(usuario); // ✅ Remove da lista
  res.json({ success: true });
});

app.get('/online', (req, res) => {
  res.json({ online: usuariosOnline.size });
});

// ROTA DE CRIAÇÃO DE USUÁRIO
app.post('/usuarios', (req, res) => {
  const { usuario, senha, nome, email } = req.body;
  const sql = 'INSERT INTO usuarios (usuario, senha, nome, email) VALUES (?, ?, ?, ?)';
  db.query(sql, [usuario, senha, nome, email], (err, result) => {
    if (err) {
      if (err.code === 'ER_DUP_ENTRY') {
        return res.status(400).json({ success: false, message: 'Usuário já existe!' });
      }
      return res.status(500).json({ success: false, error: err.message });
    }
    res.json({ success: true, message: 'Usuário criado com sucesso!' });
  });
});

app.get('/usuarios', (req, res) => {
  const login = req.query.login;
  if (login) {
    const sql = 'SELECT id, usuario, nome FROM usuarios WHERE usuario = ?';
    db.query(sql, [login], (err, results) => {
      if (err) return res.status(500).json({ success: false, error: err.message });
      res.json({ success: true, usuarios: results });
    });
  } else {
    const sql = 'SELECT id, usuario, nome FROM usuarios WHERE usuario != "admin"';
    db.query(sql, (err, results) => {
      if (err) return res.status(500).json({ success: false, error: err.message });
      res.json({ success: true, usuarios: results });
    });
  }
});

  app.get('/usuarios/busca', (req, res) => {
    const termo = `%${req.query.q || ''}%`;
    const sql = `
      SELECT id, usuario, nome, email
      FROM usuarios
      WHERE (usuario LIKE ? OR nome LIKE ?) AND usuario != 'admin'
    `;
    db.query(sql, [termo, termo], (err, results) => {
      if (err) return res.status(500).json({ success: false, error: err.message });
      res.json({ success: true, usuarios: results });
    });
  });
  
  // Excluir usuario por ID
  app.delete('/usuarios/:id', (req, res) => {
    const id = req.params.id;
    const sql = 'DELETE FROM usuarios WHERE id = ?';
    db.query(sql, [id], (err, result) => {
      if (err) return res.status(500).json({ success: false, error: err.message });
      res.json({ success: true, message: 'Usuário excluído com sucesso' });
    });
  });
  
  app.put('/usuarios/:login', (req, res) => {
    const loginAtual = req.params.login;
    const { nome, usuario, senha, email } = req.body;
  
   let sql, params;

if (senha && senha.trim() !== '') {
  sql = 'UPDATE usuarios SET nome = ?, usuario = ?, senha = ?, email = ? WHERE usuario = ?';
  params = [nome, usuario, senha, email, loginAtual];
} else {
  sql = 'UPDATE usuarios SET nome = ?, usuario = ?, email = ? WHERE usuario = ?';
  params = [nome, usuario, email, loginAtual];
}
    
    db.query(sql, params, (err, result) => {
      if (err) return res.status(500).json({ success: false, error: err.message });
      if (result.affectedRows === 0) {
        return res.status(404).json({ success: false, message: 'Usuário não encontrado.' });
      }
      res.json({ success: true, message: 'Usuário atualizado com sucesso.' });
    });
  });


 
  app.listen(3000, () => {
    console.log('Servidor rodando em http://localhost:3000');
  });
