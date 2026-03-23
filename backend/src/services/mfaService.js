const crypto = require('crypto');
const qrcode = require('qrcode');
const { authenticator } = require('otplib');
const supabase = require('../services/supabase');
const { log } = require('../utils/logger');

class MFAService {
  constructor() {
    this.ISSUER = 'VulnexusAI';
    this.SERVICE_NAME = 'vulnexusai';
  }

  // Gerar secret TOTP para usuário
  async generateTOTPSecret(userId) {
    const secret = authenticator.generateSecret();
    
    // Salvar secret no banco
    await supabase.from('user_mfa').upsert({
      user_id: userId,
      secret: secret.base32,
      backup_codes: this.generateBackupCodes(),
      enabled: false,
      created_at: new Date().toISOString()
    }).eq('user_id', userId);

    return {
      secret: secret.base32,
      qrCode: await this.generateQRCode(secret.base32, userId)
    };
  }

  // Gerar QR Code para setup
  async generateQRCode(secret, userId) {
    try {
      const otpauthUrl = authenticator.keyuri(userId, this.ISSUER, secret);
      return await qrcode.toDataURL(otpauthUrl);
    } catch (error) {
      log('error', 'MFA QR Code generation failed', error.message);
      throw new Error('Failed to generate QR code');
    }
  }

  // Verificar token TOTP
  verifyTOTP(token, secret) {
    try {
      return authenticator.verify({ token, secret });
    } catch (error) {
      log('error', 'MFA TOTP verification failed', error.message);
      return false;
    }
  }

  // Gerar códigos de backup
  generateBackupCodes() {
    const codes = [];
    for (let i = 0; i < 10; i++) {
      codes.push(crypto.randomBytes(4).toString('hex').toUpperCase());
    }
    return codes;
  }

  // Verificar código de backup
  async verifyBackupCode(userId, code) {
    try {
      const { data } = await supabase
        .from('user_mfa')
        .select('backup_codes')
        .eq('user_id', userId)
        .single();

      if (!data || !data.backup_codes) {
        return false;
      }

      const isValid = data.backup_codes.includes(code.toUpperCase());
      
      if (isValid) {
        // Remover código usado
        const updatedCodes = data.backup_codes.filter(c => c !== code.toUpperCase());
        await supabase
          .from('user_mfa')
          .update({ backup_codes: updatedCodes })
          .eq('user_id', userId);
        
        log('info', `Backup code used for user ${userId}`);
      }

      return isValid;
    } catch (error) {
      log('error', 'Backup code verification failed', error.message);
      return false;
    }
  }

  // Ativar MFA para usuário
  async enableMFA(userId, token) {
    try {
      const { data } = await supabase
        .from('user_mfa')
        .select('secret')
        .eq('user_id', userId)
        .single();

      if (!data || !data.secret) {
        throw new Error('MFA secret not found');
      }

      const isValid = this.verifyTOTP(token, data.secret);
      
      if (!isValid) {
        throw new Error('Invalid TOTP token');
      }

      await supabase
        .from('user_mfa')
        .update({ enabled: true })
        .eq('user_id', userId);

      log('info', `MFA enabled for user ${userId}`);
      return true;
    } catch (error) {
      log('error', 'MFA enable failed', error.message);
      throw error;
    }
  }

  // Desativar MFA para usuário
  async disableMFA(userId, token) {
    try {
      const { data } = await supabase
        .from('user_mfa')
        .select('secret, enabled')
        .eq('user_id', userId)
        .single();

      if (!data) {
        throw new Error('MFA not configured');
      }

      // Se MFA está ativo, verificar token
      if (data.enabled) {
        const isValid = this.verifyTOTP(token, data.secret);
        if (!isValid) {
          throw new Error('Invalid TOTP token');
        }
      }

      await supabase
        .from('user_mfa')
        .update({ enabled: false })
        .eq('user_id', userId);

      log('info', `MFA disabled for user ${userId}`);
      return true;
    } catch (error) {
      log('error', 'MFA disable failed', error.message);
      throw error;
    }
  }

  // Verificar se MFA está ativo para usuário
  async isMFAEnabled(userId) {
    try {
      const { data } = await supabase
        .from('user_mfa')
        .select('enabled')
        .eq('user_id', userId)
        .single();

      return data?.enabled || false;
    } catch (error) {
      log('error', 'MFA status check failed', error.message);
      return false;
    }
  }
}

module.exports = MFAService;
