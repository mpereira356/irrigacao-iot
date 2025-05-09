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

// ROTA DE LOGIN
app.post('/login', (req, res) => {
  const { user, pass } = req.body;
  const sql = 'SELECT * FROM usuarios WHERE usuario = ? AND senha = ?';
  db.query(sql, [user, pass], (err, results) => {
    if (err) return res.status(500).json({ success: false, error: err });

    if (results.length > 0) {
        const usuario = results[0].usuario;
        const nome = results[0].nome;
        const isAdmin = usuario === 'admin';
        res.json({ success: true, isAdmin, nome, usuario });
    } else {
      res.json({ success: false });
    }
  });
});

// ROTA DE CRIAÇÃO DE USUÁRIO
app.post('/usuarios', (req, res) => {
  const { usuario, senha, nome } = req.body;
  const sql = 'INSERT INTO usuarios (usuario, senha, nome) VALUES (?, ?, ?)';
  db.query(sql, [usuario, senha, nome], (err, result) => {
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
    const sql = 'SELECT id, usuario, nome FROM usuarios WHERE usuario != "admin"';
    db.query(sql, (err, results) => {
      if (err) return res.status(500).json({ success: false, error: err.message });
      res.json({ success: true, usuarios: results });
    });
  });

  app.get('/usuarios/busca', (req, res) => {
    const termo = `%${req.query.q || ''}%`;
    const sql = `
      SELECT id, usuario, nome
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
    const { nome, usuario, senha } = req.body;
  
    let sql, params;

    if (senha && senha.trim() !== '') {
      sql = 'UPDATE usuarios SET nome = ?, usuario = ?, senha = ? WHERE usuario = ?';
      params = [nome, usuario, senha, loginAtual];
    } else {
      sql = 'UPDATE usuarios SET nome = ?, usuario = ? WHERE usuario = ?';
      params = [nome, usuario, loginAtual];
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
