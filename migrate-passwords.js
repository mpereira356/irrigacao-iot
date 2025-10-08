// Script para migrar senhas de texto plano para bcrypt
// Execute este script UMA VEZ após fazer o deploy da versão segura

const mysql = require('mysql2');
const bcrypt = require('bcryptjs');
require('dotenv').config();

const db = mysql.createConnection({
  host: process.env.DB_HOST || '127.0.0.1',
  user: process.env.DB_USER || 'agro_user',
  password: process.env.DB_PASSWORD || 'SenhaF0rte!',
  database: process.env.DB_NAME || 'agro',
  port: Number(process.env.DB_PORT || 3306)
});

db.connect((err) => {
  if (err) {
    console.error('❌ Erro ao conectar no MySQL:', err.message);
    process.exit(1);
  }
  console.log('✅ Conectado ao MySQL');
  migrarSenhas();
});

function migrarSenhas() {
  const sql = 'SELECT id, usuario, senha FROM usuarios';
  
  db.query(sql, (err, rows) => {
    if (err) {
      console.error('❌ Erro ao buscar usuários:', err.message);
      db.end();
      process.exit(1);
    }
    
    console.log(`\n📊 Total de usuários encontrados: ${rows.length}\n`);
    
    let migrated = 0;
    let skipped = 0;
    let errors = 0;
    let processed = 0;
    
    if (rows.length === 0) {
      console.log('⚠️  Nenhum usuário encontrado no banco de dados.');
      db.end();
      return;
    }
    
    rows.forEach((user, index) => {
      // Verificar se já é hash bcrypt
      if (user.senha.startsWith('$2a$') || user.senha.startsWith('$2b$')) {
        console.log(`⏭️  [${index + 1}/${rows.length}] ${user.usuario} - Já está em hash, pulando...`);
        skipped++;
        processed++;
        
        if (processed === rows.length) {
          finalizarMigracao(migrated, skipped, errors);
        }
        return;
      }
      
      // Fazer hash da senha
      const senhaHash = bcrypt.hashSync(user.senha, 10);
      
      db.query('UPDATE usuarios SET senha = ? WHERE id = ?', [senhaHash, user.id], (err) => {
        processed++;
        
        if (err) {
          console.error(`❌ [${processed}/${rows.length}] Erro ao migrar senha do usuário ${user.usuario}:`, err.message);
          errors++;
        } else {
          console.log(`✅ [${processed}/${rows.length}] ${user.usuario} - Senha migrada com sucesso!`);
          migrated++;
        }
        
        if (processed === rows.length) {
          finalizarMigracao(migrated, skipped, errors);
        }
      });
    });
  });
}

function finalizarMigracao(migrated, skipped, errors) {
  console.log('\n' + '='.repeat(50));
  console.log('📋 RESUMO DA MIGRAÇÃO');
  console.log('='.repeat(50));
  console.log(`✅ Senhas migradas: ${migrated}`);
  console.log(`⏭️  Senhas já em hash (puladas): ${skipped}`);
  console.log(`❌ Erros: ${errors}`);
  console.log('='.repeat(50) + '\n');
  
  if (errors > 0) {
    console.log('⚠️  Alguns erros ocorreram durante a migração.');
    console.log('   Verifique os logs acima e tente novamente se necessário.\n');
  } else if (migrated > 0) {
    console.log('🎉 Migração concluída com sucesso!');
    console.log('   Todas as senhas agora estão protegidas com bcrypt.\n');
  } else {
    console.log('ℹ️  Nenhuma senha precisou ser migrada.');
    console.log('   Todas as senhas já estavam em formato hash.\n');
  }
  
  db.end();
  process.exit(errors > 0 ? 1 : 0);
}

