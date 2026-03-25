import { createCipheriv, createHash, randomBytes } from 'crypto';
import axios from 'axios';
import { VercelRequest, VercelResponse } from '@vercel/node';

// ============================================================
// CONFIGURAÇÃO DO FIRESTORE (REST API) - VERSÃO DEBUG
// ============================================================

const FIREBASE_PROJECT_ID = 'gen-lang-client-0364203262';
// Vamos tentar SEM o database ID primeiro (usando o padrão)
// const FIREBASE_DATABASE_ID = 'ai-studio-ee7c5fd5-11f5-4e50-a979-3316fea33a21';
const FIREBASE_CLIENT_EMAIL = process.env.FIREBASE_CLIENT_EMAIL || 'firebase-adminsdk-fbsvc@gen-lang-client-0364203262.iam.gserviceaccount.com';
const FIREBASE_PRIVATE_KEY = process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n') || '';

let cachedToken: string | null = null;
let tokenExpiry = 0;

async function getFirebaseToken() {
  try {
    if (cachedToken && Date.now() < tokenExpiry) return cachedToken;
    
    console.log('[Firebase] Gerando novo token JWT...');
    console.log('[Firebase] Client Email:', FIREBASE_CLIENT_EMAIL);
    console.log('[Firebase] Private Key length:', FIREBASE_PRIVATE_KEY?.length || 0);
    
    const header = { alg: 'RS256', typ: 'JWT' };
    const now = Math.floor(Date.now() / 1000);
    const payload = {
      iss: FIREBASE_CLIENT_EMAIL,
      sub: FIREBASE_CLIENT_EMAIL,
      scope: 'https://www.googleapis.com/auth/datastore',
      aud: 'https://oauth2.googleapis.com/token',
      iat: now,
      exp: now + 3600,
    };

    const sHeader = Buffer.from(JSON.stringify(header)).toString('base64url');
    const sPayload = Buffer.from(JSON.stringify(payload)).toString('base64url');
    const { sign } = await import('crypto');
    const signature = sign('sha256', Buffer.from(`${sHeader}.${sPayload}`), FIREBASE_PRIVATE_KEY).toString('base64url');

    const res = await axios.post('https://oauth2.googleapis.com/token', {
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: `${sHeader}.${sPayload}.${signature}`,
    });

    cachedToken = res.data.access_token;
    tokenExpiry = Date.now() + 3500 * 1000;
    console.log('[Firebase] Token obtido com sucesso');
    return cachedToken;
  } catch (error: any) {
    console.error('[Firebase] Erro ao obter token:', error.response?.data || error.message);
    throw error;
  }
}

// Função para fazer requisição direta sem Database ID
async function fsDirectRequest(method: string, path: string, data?: any) {
  const token = await getFirebaseToken();
  // URL SEM databaseId (usando o banco padrão)
  let url = `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/databases/(default)/documents/${path}`;
  
  console.log('[Firestore] URL:', url);

  if (method === 'PATCH' && data) {
    const fields = Object.keys(data);
    const mask = fields.map(f => `updateMask.fieldPaths=${f}`).join('&');
    url += `?${mask}`;
  }

  const res = await axios({
    method,
    url,
    data: data ? { fields: encodeFields(data) } : undefined,
    headers: { Authorization: `Bearer ${token}` },
  });
  return decodeFields(res.data.fields || {});
}

async function fsListDirect(collection: string) {
  const token = await getFirebaseToken();
  const url = `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/databases/(default)/documents/${collection}`;
  console.log('[Firestore] List URL:', url);
  try {
    const res = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } });
    console.log(`[Firestore] List ${collection}: found ${res.data.documents?.length || 0} docs`);
    return (res.data.documents || []).map((doc: any) => ({
      id: doc.name.split('/').pop(),
      ...decodeFields(doc.fields || {}),
    }));
  } catch (e: any) {
    console.error(`[Firestore] List ${collection} error:`, e.response?.status, e.response?.data);
    if (e.response?.status === 404) return [];
    throw e;
  }
}

async function fsGetDirect(collection: string, id: string) {
  try { 
    return await fsDirectRequest('GET', `${collection}/${id}`);
  } catch (e: any) { 
    if (e.response?.status === 404) return null; 
    throw e;
  }
}

async function fsSetDirect(collection: string, id: string, data: any) {
  return fsDirectRequest('PATCH', `${collection}/${id}`, data);
}

function encodeFields(obj: any): any {
  const fields: any = {};
  for (const [key, val] of Object.entries(obj)) {
    if (typeof val === 'string') fields[key] = { stringValue: val };
    else if (typeof val === 'number') fields[key] = { doubleValue: val };
    else if (typeof val === 'boolean') fields[key] = { booleanValue: val };
    else if (Array.isArray(val)) fields[key] = { arrayValue: { values: val.map(v => encodeFields({ temp: v }).temp) } };
    else if (val && typeof val === 'object') fields[key] = { mapValue: { fields: encodeFields(val) } };
    else fields[key] = { nullValue: null };
  }
  return fields;
}

function decodeFields(fields: any): any {
  const obj: any = {};
  for (const [key, val] of Object.entries(fields)) {
    const v: any = val;
    if ('stringValue' in v) obj[key] = v.stringValue;
    else if ('doubleValue' in v) obj[key] = Number(v.doubleValue);
    else if ('integerValue' in v) obj[key] = Number(v.integerValue);
    else if ('booleanValue' in v) obj[key] = v.booleanValue;
    else if ('arrayValue' in v) obj[key] = (v.arrayValue.values || []).map((item: any) => decodeFields({ temp: item }).temp);
    else if ('mapValue' in v) obj[key] = decodeFields(v.mapValue.fields || {});
    else obj[key] = null;
  }
  return obj;
}

// ============================================================
// FUNÇÕES AUXILIARES
// ============================================================

async function sendEmail(to: string, subject: string, html: string) {
  if (!process.env.RESEND_API_KEY) {
    console.warn('RESEND_API_KEY ausente, e-mail não enviado');
    return;
  }
  try {
    await axios.post('https://api.resend.com/emails', {
      from: 'R3D Pro <contato@r3dprintmanagerpro.com.br>',
      to,
      subject,
      html
    }, { headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}` } });
    console.log(`E-mail enviado para ${to}`);
  } catch (e: any) {
    console.error('Erro Resend:', e.response?.data || e.message);
  }
}

const asaasUrl = () => process.env.ASAAS_ENV === 'production' ? 'https://api.asaas.com/v3' : 'https://sandbox.asaas.com/api/v3';

function generateLicenseKey(payload: any) {
  const secret = process.env.KEYGEN_SECRET || 'R3D_SECRET_KEY_2026_XPTO_MANAGER';
  const key = createHash('sha256').update(secret).digest();
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-cbc', key, iv);
  let encrypted = cipher.update(JSON.stringify(payload), 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return `${iv.toString('hex')}:${encrypted}`;
}

// ============================================================
// HANDLER PRINCIPAL
// ============================================================

export default async function handler(req: VercelRequest, res: VercelResponse) {
  // Configuração CORS
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, x-admin-password, asaas-access-token');
  
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  try {
    const url = req.url || '';
    const method = req.method || 'GET';
    console.log(`[API] Request: ${method} ${url}`);
    
    const ADMIN_PASS = process.env.ADMIN_PASSWORD || 'admin123';
    const clientPass = req.headers['x-admin-password'];
    const isAdmin = clientPass === ADMIN_PASS;

    // ── Health Check COM DEBUG ────────────────────────────────────────────────
    if (url === '/api/health' || url === '/api/health/') {
      const debugInfo: any = {
        timestamp: new Date().toISOString(),
        projectId: FIREBASE_PROJECT_ID,
        hasPrivateKey: !!FIREBASE_PRIVATE_KEY,
        privateKeyLength: FIREBASE_PRIVATE_KEY?.length || 0,
        hasClientEmail: !!FIREBASE_CLIENT_EMAIL,
        clientEmail: FIREBASE_CLIENT_EMAIL,
        asaasEnv: process.env.ASAAS_ENV || 'sandbox',
      };
      
      try {
        // Teste 1: Obter token
        debugInfo.step1_token = 'tentando...';
        const token = await getFirebaseToken();
        debugInfo.step1_token = 'ok';
        debugInfo.tokenLength = token?.length || 0;
        
        // Teste 2: Listar coleções (tentativa)
        debugInfo.step2_list = 'tentando...';
        const collections = await fsListDirect('activations');
        debugInfo.step2_list = 'ok';
        debugInfo.collectionsCount = collections.length;
        
        // Teste 3: Escrever no banco
        debugInfo.step3_write = 'tentando...';
        await fsSetDirect('_health_check', 'test', { 
          timestamp: new Date().toISOString(),
          message: 'R3D Pro API is alive'
        });
        debugInfo.step3_write = 'ok';
        
        return res.json({ 
          status: 'ok', 
          firebase: true,
          debug: debugInfo
        });
        
      } catch (e: any) {
        console.error('[Health] Erro detalhado:', e);
        
        debugInfo.error = {
          message: e.message,
          response: e.response?.data,
          status: e.response?.status,
          stack: e.stack
        };
        
        return res.json({
          status: 'degraded',
          firebase: false,
          debug: debugInfo
        });
      }
    }

    // ── Validar cupom ─────────────────────────────────────────────────────────
    if (url.includes('/api/cupom/validar') && method === 'GET') {
      const codigo = req.query?.codigo || url.split('codigo=')[1]?.split('&')[0];
      if (!codigo) return res.status(400).json({ message: 'Código ausente' });
      
      const coupon = await fsGetDirect('cupons', String(codigo).toUpperCase());
      if (!coupon || !coupon.ativo) return res.status(404).json({ message: 'Cupom inválido ou inativo' });
      if (coupon.limite_usos && coupon.usos >= coupon.limite_usos) {
        return res.status(400).json({ message: 'Limite de usos atingido' });
      }
      if (coupon.validade && new Date(coupon.validade) < new Date()) {
        return res.status(400).json({ message: 'Cupom expirado' });
      }
      return res.json({ id: codigo, ...coupon });
    }

    // ── Admin: Listar cupons ───────────────────────────────────────────────────
    if (url.includes('/api/admin/cupons') && method === 'GET') {
      if (!isAdmin) return res.status(401).json({ message: 'Senha incorreta' });
      try { 
        const cupons = await fsListDirect('cupons');
        return res.json(cupons);
      } catch (e: any) { 
        return res.status(500).json({ message: 'Erro ao listar', error: e.message }); 
      }
    }

    // ── Admin: Criar cupom ─────────────────────────────────────────────────────
    if (url.includes('/api/admin/cupom/criar') && method === 'POST') {
      if (!isAdmin) return res.status(401).json({ message: 'Senha incorreta' });
      try {
        const data = req.body;
        const codigo = String(data.codigo).toUpperCase().trim();
        
        await fsSetDirect('cupons', codigo, {
          codigo,
          tipo: data.tipo || 'PERCENTUAL',
          valor: Number(data.valor) || 0,
          afiliado_nome: data.afiliado_nome || '',
          afiliado_email: data.afiliado_email || '',
          afiliado_telefone: data.afiliado_telefone || '',
          limite_usos: Number(data.limite_usos) || 0,
          validade: data.validade || '',
          ativo: data.ativo !== undefined ? data.ativo : true,
          usos: 0,
          vendas: [],
          criado_em: new Date().toISOString(),
        });
        
        if (data.afiliado_email) {
          await sendEmail(data.afiliado_email, 'Seu cupom de afiliado foi criado!',
            `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
              <h2 style="color:#C67D3D">Olá ${data.afiliado_nome}! 🎉</h2>
              <p>Seu cupom foi criado no R3D Print Manager Pro!</p>
              <div style="background:#1a1a1a;color:white;padding:20px;border-radius:12px;text-align:center;margin:20px 0">
                <p style="margin:0;color:#999">Seu código:</p>
                <h1 style="color:#C67D3D;font-size:36px;margin:10px 0">${codigo}</h1>
                <p style="margin:0;color:#ccc">${data.tipo === 'PERCENTUAL' ? `${data.valor}% de desconto` : `R$ ${Number(data.valor).toFixed(2)} de desconto`}</p>
              </div>
              <p>Você receberá um e-mail a cada venda realizada com seu cupom.</p>
            </div>`
          );
        }
        return res.json({ success: true });
      } catch (e: any) { 
        return res.status(500).json({ message: 'Erro ao criar', error: e.message }); 
      }
    }

    // ── Admin: Atualizar cupom ─────────────────────────────────────────────────
    if (url.includes('/api/admin/cupom/') && !url.includes('/criar') && method === 'PUT') {
      if (!isAdmin) return res.status(401).json({ message: 'Senha incorreta' });
      const id = url.split('/api/admin/cupom/')[1]?.split('?')[0];
      try {
        const existing = await fsGetDirect('cupons', id);
        await fsSetDirect('cupons', id, { ...existing, ...req.body });
        return res.json({ success: true });
      } catch (e: any) { 
        return res.status(500).json({ message: 'Erro ao atualizar', error: e.message }); 
      }
    }

    // ── Admin: Excluir cupom ───────────────────────────────────────────────────
    if (url.includes('/api/admin/cupom/') && method === 'DELETE') {
      if (!isAdmin) return res.status(401).json({ message: 'Senha incorreta' });
      const id = url.split('/').pop();
      if (!id) return res.status(400).json({ error: 'ID ausente' });
      // Implementar delete via REST
      const token = await getFirebaseToken();
      const deleteUrl = `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/databases/(default)/documents/cupons/${id}`;
      await axios.delete(deleteUrl, { headers: { Authorization: `Bearer ${token}` } });
      return res.json({ success: true });
    }

    // ── Asaas: Criar cliente ───────────────────────────────────────────────────
    if (url.includes('/api/asaas/customer') && method === 'POST') {
      try {
        const r = await axios.post(`${asaasUrl()}/customers`, req.body, {
          headers: { access_token: process.env.ASAAS_API_KEY || '' }
        });
        return res.json(r.data);
      } catch (e: any) {
        return res.status(e.response?.status || 500).json(e.response?.data || { message: 'Erro ao criar cliente' });
      }
    }

    // ── Asaas: Criar pagamento ─────────────────────────────────────────────────
    if (url.includes('/api/asaas/payment') && method === 'POST') {
      try {
        const r = await axios.post(`${asaasUrl()}/payments`, req.body, {
          headers: { access_token: process.env.ASAAS_API_KEY || '' }
        });
        return res.json(r.data);
      } catch (e: any) {
        return res.status(e.response?.status || 500).json(e.response?.data || { message: 'Erro ao processar pagamento' });
      }
    }

    // ── Asaas: PIX QR Code ─────────────────────────────────────────────────────
    if (url.includes('/api/asaas/pix-qrcode') && method === 'GET') {
      const paymentId = req.query?.paymentId || url.split('paymentId=')[1]?.split('&')[0];
      if (!paymentId) return res.status(400).json({ message: 'paymentId ausente' });
      try {
        const r = await axios.get(`${asaasUrl()}/payments/${paymentId}/pixQrCode`, {
          headers: { access_token: process.env.ASAAS_API_KEY || '' }
        });
        return res.json(r.data);
      } catch (e: any) {
        return res.status(e.response?.status || 500).json({ message: 'Erro ao buscar QR Code PIX' });
      }
    }

    // ── Asaas: Webhook ─────────────────────────────────────────────────────────
    if (url.includes('/api/asaas/webhook') && method === 'POST') {
      const body = req.body;
      const event = Array.isArray(body) ? body[0] : body;
      const payment = event?.payment;

      const webhookToken = req.headers['asaas-access-token'];
      const isSimulated = webhookToken === 'SIMULATED_TOKEN';
      const configuredToken = process.env.ASAAS_WEBHOOK_TOKEN;

      console.log(`[Webhook] Evento: ${event?.event}, Pagamento: ${payment?.id}, Simulado: ${isSimulated}`);

      if (configuredToken && !isSimulated && webhookToken !== configuredToken) {
        console.warn('[Webhook] Token inválido');
        return res.status(401).json({ message: 'Unauthorized' });
      }

      if (!payment) {
        console.warn('[Webhook] Pagamento ausente no corpo');
        return res.status(400).json({ message: 'Missing payment' });
      }

      res.status(200).send('OK');

      (async () => {
        try {
          await fsSetDirect('payments', payment.id, {
            paymentId: payment.id,
            status: payment.status,
            event: event.event,
            value: payment.value,
            customer: payment.customer,
            billingType: payment.billingType || '',
            installmentNumber: payment.installmentNumber || 1,
            processedAt: new Date().toISOString(),
            externalReference: payment.externalReference || '',
            isSimulated,
          });

          if (event.event === 'PAYMENT_CONFIRMED' || event.event === 'PAYMENT_RECEIVED') {
            const extRef = payment.externalReference || '';
            const parts = extRef.split(':');
            const hasCoupon = parts[0] === 'COUPON';
            const couponCode = hasCoupon ? parts[1] : '';
            const planName = hasCoupon
              ? parts.slice(2, parts.length - 1).join(' ')
              : parts.slice(1, parts.length - 1).join(' ');

            const isFirstInstallment = (payment.installmentNumber || 1) === 1;

            let customerEmail = '';
            let customerName = '';

            if (isSimulated) {
              customerEmail = payment.customerEmail || 'teste@exemplo.com';
              customerName = payment.customerName || 'Cliente Teste';
            } else {
              try {
                const cr = await axios.get(`${asaasUrl()}/customers/${payment.customer}`, {
                  headers: { access_token: process.env.ASAAS_API_KEY || '' }
                });
                customerEmail = cr.data.email || '';
                customerName = cr.data.name || '';
              } catch (e) {
                console.error('Erro ao buscar cliente:', e);
              }
            }

            if (customerEmail && isFirstInstallment) {
              await fsSetDirect('users', customerEmail, {
                email: customerEmail,
                isPro: true,
                subscriptionId: payment.installment || payment.id,
                plano: planName,
                updatedAt: new Date().toISOString(),
              });

              const code = `R3D-ACT-${randomBytes(6).toString('hex').toUpperCase().match(/.{1,4}/g)?.join('-')}`;
              const expirationDate = new Date();
              expirationDate.setDate(expirationDate.getDate() + 7);

              await fsSetDirect('activations', code, {
                code,
                paymentId: payment.id,
                email: customerEmail,
                name: customerName,
                plano: planName || 'PRO',
                status: 'PENDING',
                createdAt: new Date().toISOString(),
                expiresAt: expirationDate.toISOString(),
              });

              const emailHtml = `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
                <h2 style="color:#C67D3D">Parabéns pela sua compra! 🎉</h2>
                <p>Olá ${customerName}, seu pagamento foi confirmado.</p>
                <p>Aqui está seu código de ativação:</p>
                <div style="background:#1a1a1a;color:white;padding:20px;border-radius:12px;text-align:center;margin:20px 0">
                  <h1 style="color:#C67D3D;font-size:32px;margin:10px 0">${code}</h1>
                </div>
                <p>Dúvidas? Responda este e-mail.</p>
              </div>`;
              await sendEmail(customerEmail, 'Seu código de ativação R3D Print Manager Pro', emailHtml);
            }
          }
        } catch (e: any) {
          console.error('[Webhook] Erro:', e);
        }
      })();
      return;
    }

    // ── Status do usuário ─────────────────────────────────────────────────────
    if (url.includes('/api/user/status/') && method === 'GET') {
      const email = decodeURIComponent(url.split('/api/user/status/')[1]);
      const data = await fsGetDirect('users', email);
      return res.json(data || { isPro: false });
    }

    // ── Download ───────────────────────────────────────────────────────────────
    if (url.includes('/api/download')) {
      return res.redirect(302, 'https://github.com/rovateduino/R3D-PRINT-MANAGER-PRO/releases/download/v2.5.0/Setup_R3D_PrintManager_Pro.exe');
    }

    console.warn(`[API] 404 Not Found: ${method} ${url}`);
    return res.status(404).json({ message: 'Not found', path: url });
    
  } catch (error: any) {
    console.error(`[API] Global Error:`, error);
    return res.status(500).json({
      error: 'Internal Server Error',
      message: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined
    });
  }
}
