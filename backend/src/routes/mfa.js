const express = require('express');
const rateLimit = require('express-rate-limit');
const MFAService = require('../services/mfaService');
const { verifyToken } = require('../middlewares/auth');
const { log } = require('../utils/logger');
const router = express.Router();

const mfaLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutos
  max: 10,
  message: { error: 'Muitas tentativas de MFA. Aguarde 5 minutos.' },
  standardHeaders: true,
  legacyHeaders: false
});

// Gerar secret TOTP e QR Code para setup
router.post('/setup', verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const mfaService = new MFAService();
    
    const result = await mfaService.generateTOTPSecret(userId);
    
    log('info', `MFA setup initiated for user ${userId}`);
    
    res.json({
      success: true,
      data: {
        secret: result.secret,
        qrCode: result.qrCode,
        instructions: [
          '1. Escaneie o QR Code com seu app autenticador (Google Authenticator, Authy, etc.)',
          '2. Ou digite o manualmente: ' + result.secret,
          '3. Use o código de 6 dígitos para ativar MFA'
        ]
      }
    });
  } catch (error) {
    log('error', 'MFA setup failed', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Erro ao configurar MFA' 
    });
  }
});

// Ativar MFA com token TOTP
router.post('/enable', mfaLimiter, verifyToken, async (req, res) => {
  try {
    const { token } = req.body;
    const userId = req.user.id;
    
    if (!token || token.length !== 6) {
      return res.status(400).json({ 
        success: false, 
        error: 'Token TOTP inválido' 
      });
    }

    const mfaService = new MFAService();
    await mfaService.enableMFA(userId, token);
    
    log('info', `MFA enabled for user ${userId}`);
    
    res.json({
      success: true,
      message: 'MFA ativado com sucesso! Use o código do seu app para fazer login.'
    });
  } catch (error) {
    log('error', 'MFA enable failed', error.message);
    res.status(400).json({ 
      success: false, 
      error: error.message || 'Falha ao ativar MFA' 
    });
  }
});

// Desativar MFA
router.post('/disable', mfaLimiter, verifyToken, async (req, res) => {
  try {
    const { token } = req.body;
    const userId = req.user.id;
    
    if (!token || token.length !== 6) {
      return res.status(400).json({ 
        success: false, 
        error: 'Token TOTP inválido' 
      });
    }

    const mfaService = new MFAService();
    await mfaService.disableMFA(userId, token);
    
    log('info', `MFA disabled for user ${userId}`);
    
    res.json({
      success: true,
      message: 'MFA desativado com sucesso!'
    });
  } catch (error) {
    log('error', 'MFA disable failed', error.message);
    res.status(400).json({ 
      success: false, 
      error: error.message || 'Falha ao desativar MFA' 
    });
  }
});

// Verificar código de backup
router.post('/verify-backup', mfaLimiter, verifyToken, async (req, res) => {
  try {
    const { code } = req.body;
    const userId = req.user.id;
    
    if (!code || code.length !== 8) {
      return res.status(400).json({ 
        success: false, 
        error: 'Código de backup inválido' 
      });
    }

    const mfaService = new MFAService();
    const isValid = await mfaService.verifyBackupCode(userId, code);
    
    if (!isValid) {
      return res.status(400).json({ 
        success: false, 
        error: 'Código de backup inválido ou já utilizado' 
      });
    }
    
    log('info', `Backup code used for user ${userId}`);
    
    res.json({
      success: true,
      message: 'Código de backup verificado com sucesso!'
    });
  } catch (error) {
    log('error', 'Backup code verification failed', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Erro ao verificar código de backup' 
    });
  }
});

// Verificar status do MFA do usuário
router.get('/status', verifyToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const mfaService = new MFAService();
    
    const enabled = await mfaService.isMFAEnabled(userId);
    
    res.json({
      success: true,
      data: {
        mfa_enabled: enabled,
        setup_required: !enabled
      }
    });
  } catch (error) {
    log('error', 'MFA status check failed', error.message);
    res.status(500).json({ 
      success: false, 
      error: 'Erro ao verificar status do MFA' 
    });
  }
});

module.exports = router;
