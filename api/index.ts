import { createCipheriv, createHash, randomBytes } from 'crypto';
import { readFileSync } from 'fs';
import { join } from 'path';
import axios from 'axios';

// ── Fix ERR_IMPORT_ATTRIBUTE_MISSING (Node 22+ ESM não aceita import de JSON sem "with { type: 'json' }")
// Usa readFileSync que funciona em qualquer versão sem atributos especiais
let firebaseConfig: { projectId?: string; firestoreDatabaseId?: string } = {};
try {
  const paths = [
    join(process.cwd(), 'firebase-applet-config.json'),
    join(process.cwd(), '..', 'firebase-applet-config.json'),
    join(__dirname, '..', 'firebase-applet-config.json'),
  ];
  for (const p of paths) {
    try { firebaseConfig = JSON.parse(readFileSync(p, 'utf-8')); break; } catch { /* tenta próximo */ }
  }
} catch {
  console.warn('[Config] firebase-applet-config.json não encontrado — usando apenas variáveis de ambiente');
}

const FIREBASE_PROJECT_ID = process.env.FIREBASE_PROJECT_ID || firebaseConfig.projectId;
const FIREBASE_CLIENT_EMAIL = process.env.FIREBASE_CLIENT_EMAIL;
const FIREBASE_PRIVATE_KEY = process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n');
const DB_ID = process.env.DB_ID || firebaseConfig.firestoreDatabaseId || '(default)';

let cachedToken: string | null = null;
let tokenExpiry = 0;

async function getToken() {
  try {
    if (cachedToken && Date.now() < tokenExpiry) return cachedToken;
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
    const signature = sign('sha256', Buffer.from(`${sHeader}.${sPayload}`), FIREBASE_PRIVATE_KEY!).toString('base64url');

    const res = await axios.post('https://oauth2.googleapis.com/token', {
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: `${sHeader}.${sPayload}.${signature}`,
    });

    cachedToken = res.data.access_token;
    tokenExpiry = Date.now() + 3500 * 1000;
    return cachedToken;
  } catch (error: any) {
    console.error('Error getting Firebase token:', error.response?.data || error.message);
    throw error;
  }
}

async function fsRequest(method: string, path: string, data?: any) {
  const token = await getToken();
  let url = `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/databases/${DB_ID}/documents/${path}`;

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

async function fsList(collection: string) {
  const token = await getToken();
  const url = `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/databases/${DB_ID}/documents/${collection}`;
  try {
    const res = await axios.get(url, { headers: { Authorization: `Bearer ${token}` } });
    console.log(`[Firestore] List ${collection}: found ${res.data.documents?.length || 0} docs`);
    return (res.data.documents || []).map((doc: any) => ({
      id: doc.name.split('/').pop(),
      ...decodeFields(doc.fields || {}),
    }));
  } catch (e: any) {
    if (e.response?.status === 404) return [];
    console.error(`[Firestore] List ${collection} error:`, e.response?.data || e.message);
    throw e;
  }
}

async function fsGet(collection: string, id: string) {
  try { return await fsRequest('GET', `${collection}/${id}`); }
  catch (e: any) { if (e.response?.status === 404) return null; throw e; }
}

async function fsSet(collection: string, id: string, data: any) {
  return fsRequest('PATCH', `${collection}/${id}`, data);
}

async function fsDelete(collection: string, id: string) {
  const token = await getToken();
  const url = `https://firestore.googleapis.com/v1/projects/${FIREBASE_PROJECT_ID}/databases/${DB_ID}/documents/${collection}/${id}`;
  console.log(`[Firestore] Deleting ${collection}/${id}...`);
  try {
    const res = await axios.delete(url, { headers: { Authorization: `Bearer ${token}` } });
    console.log(`[Firestore] Deleted ${collection}/${id} successfully`);
    return res.data;
  } catch (e: any) {
    console.error(`[Firestore] Delete ${collection}/${id} error:`, e.response?.data || e.message);
    throw e;
  }
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

async function sendEmail(to: string, subject: string, html: string) {
  if (!process.env.RESEND_API_KEY) return console.warn('RESEND_API_KEY ausente');
  try {
    await axios.post('https://api.resend.com/emails', {
      from: 'R3D Pro <contato@r3dprintmanagerpro.com.br>',
      to, subject, html
    }, { headers: { Authorization: `Bearer ${process.env.RESEND_API_KEY}` } });
  } catch (e: any) { console.error('Erro Resend:', e.response?.data || e.message); }
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

// ── Eventos do Asaas que requerem processamento de pagamento ──────────────────
const PAYMENT_CONFIRMED_EVENTS = new Set([
  'PAYMENT_CONFIRMED',
  'PAYMENT_RECEIVED',
]);

export default async function handler(req: any, res: any) {
  try {
    const url = req.url || '';
    const method = req.method || 'GET';
    console.log(`[API] Request: ${method} ${url}`);
    const ADMIN_PASS = process.env.ADMIN_PASSWORD || 'admin123';
    const clientPass = req.headers['x-admin-password'];
    const isAdmin = clientPass === ADMIN_PASS;

    if (url.includes('/admin/') && !isAdmin) {
      console.warn(`[API] Unauthorized admin access attempt: ${method} ${url}`);
    }

    // ── Health ──────────────────────────────────────────────────────────────────
    if (url.includes('/api/health')) {
      try {
        await getToken();
        return res.json({ status: 'ok', firebase: true, dbId: DB_ID, asaasEnv: process.env.ASAAS_ENV || 'sandbox', hasApiKey: !!process.env.ASAAS_API_KEY, hasAdminPassword: !!process.env.ADMIN_PASSWORD });
      } catch (e: any) {
        const errorDetail = e.response?.data || e.message;
        return res.json({
          status: 'ok', firebase: false, dbId: DB_ID,
          error: typeof errorDetail === 'object' ? JSON.stringify(errorDetail) : errorDetail,
          config: { hasProjectId: !!FIREBASE_PROJECT_ID, hasClientEmail: !!FIREBASE_CLIENT_EMAIL, hasPrivateKey: !!FIREBASE_PRIVATE_KEY }
        });
      }
    }

    // ── Validar cupom ───────────────────────────────────────────────────────────
    if (url.includes('/api/cupom/validar') && method === 'GET') {
      const codigo = req.query?.codigo || url.split('codigo=')[1]?.split('&')[0];
      if (!codigo) return res.status(400).json({ message: 'Código ausente' });
      const coupon = await fsGet('cupons', String(codigo).toUpperCase());
      if (!coupon || !coupon.ativo) return res.status(404).json({ message: 'Cupom inválido ou inativo' });
      if (coupon.limite_usos && coupon.usos >= coupon.limite_usos) return res.status(400).json({ message: 'Limite de usos atingido' });
      if (coupon.validade && new Date(coupon.validade) < new Date()) return res.status(400).json({ message: 'Cupom expirado' });
      return res.json(coupon);
    }

    // ── Admin: Listar cupons ────────────────────────────────────────────────────
    if (url.includes('/api/admin/cupons') && method === 'GET') {
      if (!isAdmin) return res.status(401).json({ message: 'Senha incorreta' });
      try { return res.json(await fsList('cupons')); }
      catch (e: any) { return res.status(500).json({ message: 'Erro ao listar', error: e.message }); }
    }

    // ── Admin: Criar cupom ──────────────────────────────────────────────────────
    if (url.includes('/api/admin/cupom/criar') && method === 'POST') {
      if (!isAdmin) return res.status(401).json({ message: 'Senha incorreta' });
      try {
        const data = req.body;
        const codigo = String(data.codigo).toUpperCase().trim();
        await fsSet('cupons', codigo, {
          codigo, tipo: data.tipo || 'PERCENTUAL', valor: Number(data.valor) || 0,
          afiliado_nome: data.afiliado_nome || '', afiliado_email: data.afiliado_email || '',
          afiliado_telefone: data.afiliado_telefone || '', limite_usos: Number(data.limite_usos) || 0,
          validade: data.validade || '', ativo: data.ativo !== undefined ? data.ativo : true,
          usos: 0, vendas: [], criado_em: new Date().toISOString(),
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
      } catch (e: any) { return res.status(500).json({ message: 'Erro ao criar', error: e.message }); }
    }

    // ── Admin: Atualizar cupom ──────────────────────────────────────────────────
    if (url.includes('/api/admin/cupom/') && !url.includes('/criar') && method === 'PUT') {
      if (!isAdmin) return res.status(401).json({ message: 'Senha incorreta' });
      const id = url.split('/api/admin/cupom/')[1]?.split('?')[0];
      try {
        const existing = await fsGet('cupons', id);
        await fsSet('cupons', id, { ...existing, ...req.body });
        return res.json({ success: true });
      } catch (e: any) { return res.status(500).json({ message: 'Erro ao atualizar', error: e.message }); }
    }

    // ── Admin: Deletar cupom ────────────────────────────────────────────────────
    if (url.includes('/api/admin/cupom/') && !url.includes('/criar') && method === 'DELETE') {
      if (!isAdmin) return res.status(401).json({ message: 'Senha incorreta' });
      let id = url.split('/api/admin/cupom/')[1]?.split('?')[0];
      if (id) id = decodeURIComponent(id).trim().replace(/\/$/, '');
      console.log(`[API] Deleting coupon: "${id}"`);
      if (!id) return res.status(400).json({ message: 'ID é obrigatório' });
      try {
        await fsDelete('cupons', id);
        return res.json({ success: true });
      } catch (e: any) {
        return res.status(500).json({ message: 'Erro ao deletar cupom', error: e.response?.data || e.message });
      }
    }

    // ── Asaas: Criar cliente ────────────────────────────────────────────────────
    if (url.includes('/api/asaas/customer') && method === 'POST') {
      try {
        const r = await axios.post(`${asaasUrl()}/customers`, req.body, { headers: { access_token: process.env.ASAAS_API_KEY || '' } });
        return res.json(r.data);
      } catch (e: any) { return res.status(e.response?.status || 500).json(e.response?.data || { message: 'Erro ao criar cliente' }); }
    }

    // ── Asaas: Criar pagamento ──────────────────────────────────────────────────
    if (url.includes('/api/asaas/payment') && method === 'POST') {
      try {
        const r = await axios.post(`${asaasUrl()}/payments`, req.body, { headers: { access_token: process.env.ASAAS_API_KEY || '' } });
        return res.json(r.data);
      } catch (e: any) { return res.status(e.response?.status || 500).json(e.response?.data || { message: 'Erro ao processar pagamento' }); }
    }

    // ── Asaas: PIX QR Code ──────────────────────────────────────────────────────
    if (url.includes('/api/asaas/pix-qrcode') && method === 'GET') {
      const paymentId = req.query?.paymentId || url.split('paymentId=')[1]?.split('&')[0];
      if (!paymentId) return res.status(400).json({ message: 'paymentId ausente' });
      try {
        const r = await axios.get(`${asaasUrl()}/payments/${paymentId}/pixQrCode`, { headers: { access_token: process.env.ASAAS_API_KEY || '' } });
        return res.json(r.data);
      } catch (e: any) { return res.status(e.response?.status || 500).json({ message: 'Erro ao buscar QR Code PIX' }); }
    }

    // ── Asaas: Webhook ──────────────────────────────────────────────────────────
    if (url.includes('/api/asaas/webhook') && method === 'POST') {
      const body = req.body;
      const event = Array.isArray(body) ? body[0] : body;
      const eventType: string = event?.event || '';
      const payment = event?.payment;

      const webhookToken = req.headers['asaas-access-token'];
      const isSimulated = webhookToken === 'SIMULATED_TOKEN';
      const configuredToken = process.env.ASAAS_WEBHOOK_TOKEN;

      console.log(`[Webhook] Evento: "${eventType}", ID: ${payment?.id || 'N/A'}, Simulado: ${isSimulated}`);

      if (configuredToken && !isSimulated && webhookToken !== configuredToken) {
        console.warn('[Webhook] Token inválido');
        return res.status(401).json({ message: 'Unauthorized' });
      }

      // ── Ignora eventos que não são de pagamento confirmado ────────────────────
      if (!PAYMENT_CONFIRMED_EVENTS.has(eventType)) {
        console.log(`[Webhook] Evento "${eventType}" ignorado.`);
        return res.status(200).json({ status: 'ignored', event: eventType });
      }

      if (!payment) {
        console.warn('[Webhook] Pagamento ausente no corpo');
        return res.status(400).json({ message: 'Missing payment data' });
      }

      const paymentValue = typeof payment.value === 'number' ? payment.value : parseFloat(payment.value) || 0;
      let generatedCode: string | null = null;

      try {
        await fsSet('payments', payment.id, {
          paymentId: payment.id,
          status: payment.status || '',
          event: eventType,
          value: paymentValue,
          customer: payment.customer || '',
          billingType: payment.billingType || '',
          installmentNumber: payment.installmentNumber || 1,
          processedAt: new Date().toISOString(),
          externalReference: payment.externalReference || '',
          isSimulated,
        });

        const extRef: string = payment.externalReference || '';
        const parts = extRef.split(':');
        const hasCoupon = parts[0] === 'COUPON' && parts.length >= 4;
        const couponCode = hasCoupon ? parts[1] : '';
        const planName = hasCoupon
          ? parts.slice(2, parts.length - 1).join(' ').trim()
          : parts.slice(1, parts.length - 1).join(' ').trim();

        const installmentNumber = typeof payment.installmentNumber === 'number' ? payment.installmentNumber : 1;
        const isFirstInstallment = installmentNumber === 1;

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
          } catch (e: any) {
            console.error('[Webhook] Erro ao buscar cliente:', e.response?.data || e.message);
          }
        }

        console.log(`[Webhook] Cliente: ${customerName} <${customerEmail}>, Plano: "${planName}", Parcela: ${installmentNumber}`);

        if (customerEmail && isFirstInstallment) {
          await fsSet('users', customerEmail, {
            email: customerEmail, isPro: true,
            subscriptionId: payment.installment || payment.id,
            plano: planName || 'PRO',
            updatedAt: new Date().toISOString(),
          });

          const existingActivation = await fsGet('activations_by_payment', payment.id);
          if (existingActivation?.code) {
            generatedCode = existingActivation.code;
          } else {
            const code = `R3D-ACT-${randomBytes(6).toString('hex').toUpperCase().match(/.{1,4}/g)?.join('-')}`;
            generatedCode = code;
            const expirationDate = new Date();
            expirationDate.setDate(expirationDate.getDate() + 7);

            await fsSet('activations', code, {
              code, paymentId: payment.id,
              email: customerEmail, name: customerName,
              plano: planName || 'PRO', status: 'PENDING',
              createdAt: new Date().toISOString(),
              expiresAt: expirationDate.toISOString(),
            });
            await fsSet('activations_by_payment', payment.id, { code });

            try {
              await sendEmail(customerEmail, 'Seu código de ativação R3D Print Manager Pro',
                `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
                  <h2 style="color:#C67D3D">Parabéns pela sua compra! 🎉</h2>
                  <p>Olá ${customerName}, seu pagamento foi confirmado.</p>
                  <div style="background:#1a1a1a;color:white;padding:20px;border-radius:12px;text-align:center;margin:20px 0">
                    <h1 style="color:#C67D3D;font-size:32px;margin:10px 0">${code}</h1>
                  </div>
                  <ol>
                    <li>Baixe: <a href="https://r3dprintmanagerpro.com.br/api/download">r3dprintmanagerpro.com.br/api/download</a></li>
                    <li>Abra o app e insira o código acima.</li>
                  </ol>
                  <p style="color:#ff4444"><strong>Atenção:</strong> Expira em 7 dias se não utilizado.</p>
                </div>`
              );
            } catch (e: any) { console.error('[Webhook] Erro e-mail ativação:', e.message); }
          }
        }

        if (couponCode && isFirstInstallment) {
          const coupon = await fsGet('cupons', couponCode.toUpperCase());
          if (coupon) {
            const existingVendas = Array.isArray(coupon.vendas) ? coupon.vendas : [];
            const installmentId = payment.installment || payment.id;
            const jaProcessado = existingVendas.some((v: any) =>
              v.installmentId === installmentId || v.paymentId === payment.id
            );
            if (!jaProcessado) {
              const novosUsos = (Number(coupon.usos) || 0) + 1;
              await fsSet('cupons', coupon.codigo || couponCode.toUpperCase(), {
                ...coupon,
                usos: novosUsos,
                vendas: [...existingVendas, {
                  paymentId: payment.id, installmentId,
                  plano: planName || 'N/A', valor: paymentValue,
                  cliente: customerName, email: customerEmail,
                  data: new Date().toISOString(),
                }],
              });
              if (coupon.afiliado_email) {
                try {
                  await sendEmail(coupon.afiliado_email, `🎉 Nova venda com seu cupom ${coupon.codigo}!`,
                    `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
                      <h2 style="color:#C67D3D">Nova venda! 🚀</h2>
                      <p><strong>Cupom:</strong> ${coupon.codigo} | <strong>Plano:</strong> ${planName} | <strong>Valor:</strong> R$ ${paymentValue.toFixed(2)}</p>
                    </div>`
                  );
                } catch (e: any) { console.error('[Webhook] Erro e-mail afiliado:', e.message); }
              }
            }
          }
        }

        if (isSimulated) return res.json({ status: 'success', code: generatedCode });
        return res.status(200).json({ status: 'success' });

      } catch (e: any) {
        console.error('[Webhook] Erro interno:', e.message);
        return res.status(500).json({ error: e.message });
      }
    }

    // ── Status do usuário ───────────────────────────────────────────────────────
    if (url.includes('/api/user/status/') && method === 'GET') {
      const email = decodeURIComponent(url.split('/api/user/status/')[1]);
      const data = await fsGet('users', email);
      return res.json(data || { isPro: false });
    }

    // ── Trial direto por HWID ───────────────────────────────────────────────────
    if (url.includes('/api/license/trial-hwid') && method === 'POST') {
      const { hwid, email } = req.body;
      if (!hwid) return res.status(400).json({ message: 'HWID é obrigatório' });

      const hwidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
      if (!hwidRegex.test(hwid)) {
        return res.status(400).json({ message: 'Formato de HWID inválido. Use: 00000000-0000-0000-0000-000000000000' });
      }

      const trialHistory = await fsGet('trials_hwid', hwid);
      if (trialHistory) {
        return res.status(400).json({ message: 'Este computador já utilizou o período de teste gratuito. Adquira um plano para continuar.' });
      }

      const existingLicense = await fsGet('licenses', hwid);
      if (existingLicense) {
        if (existingLicense.plano === 'Trial') return res.status(400).json({ message: 'Este computador já possui um teste ativo.' });
        return res.status(400).json({ message: 'Este computador já possui uma licença ativa.' });
      }

      const expiration = new Date();
      expiration.setDate(expiration.getDate() + 7);

      const licenseKey = generateLicenseKey({
        hwid, type: 'Trial', issued: new Date().toISOString(),
        expiration: expiration.toISOString(), version: 1, nonce: randomBytes(8).toString('hex')
      });

      await fsSet('licenses', hwid, { hwid, plano: 'Trial', licenseKey, email: email || '', activatedAt: new Date().toISOString(), expiration: expiration.toISOString() });
      await fsSet('trials_hwid', hwid, { hwid, email: email || '', usedAt: new Date().toISOString(), expiration: expiration.toISOString() });

      if (email) {
        try {
          await sendEmail(email, 'Seu Teste Gratuito R3D Pro foi ativado! 🚀',
            `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
              <h2 style="color:#C67D3D">Teste gratuito ativo! 🎉</h2>
              <div style="background:#1a1a1a;color:white;padding:20px;border-radius:12px;margin:20px 0">
                <p style="color:#C67D3D;font-family:monospace;font-size:12px">${hwid}</p>
                <p>Expira em: <strong>${expiration.toLocaleDateString('pt-BR')}</strong></p>
              </div>
              <p>Após o prazo, adquira um plano em <a href="https://r3dprintmanagerpro.com.br/#pricing">r3dprintmanagerpro.com.br</a>.</p>
            </div>`
          );
        } catch (e: any) { console.error('[Trial-HWID] Erro e-mail:', e.message); }
      }

      return res.json({ success: true, plano: 'Trial', expiration: expiration.toISOString(), licenseKey, diasRestantes: 7 });
    }

    // ── Ativar Licença ──────────────────────────────────────────────────────────
    if (url.includes('/api/license/activate') && method === 'POST') {
      const { code, activationCode, hwid } = req.body;
      const finalCode = code || activationCode;
      if (!finalCode || !hwid) return res.status(400).json({ message: 'Código e HWID são obrigatórios' });

      const hwidRegex = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
      if (!hwidRegex.test(hwid)) return res.status(400).json({ message: 'Formato de HWID inválido' });

      const activation = await fsGet('activations', String(finalCode).toUpperCase());
      if (!activation) return res.status(404).json({ message: 'Código de ativação não encontrado' });
      if (activation.status === 'USED') return res.status(400).json({ message: 'Este código já foi utilizado' });
      if (new Date(activation.expiresAt) < new Date()) return res.status(400).json({ message: 'Este código expirou' });

      const now = new Date();
      let expiration: string | null = null;
      const plano = activation.plano || 'Mensal';
      if (plano === 'Trial') { now.setDate(now.getDate() + 7); expiration = now.toISOString(); }
      else if (plano === 'Mensal') { now.setDate(now.getDate() + 30); expiration = now.toISOString(); }
      else if (plano === 'Trimestral') { now.setDate(now.getDate() + 90); expiration = now.toISOString(); }
      else if (plano === 'Semestral') { now.setDate(now.getDate() + 180); expiration = now.toISOString(); }
      else if (plano === 'Anual') { now.setDate(now.getDate() + 365); expiration = now.toISOString(); }

      const licenseKey = generateLicenseKey({ hwid, type: plano, issued: new Date().toISOString(), expiration, version: 1, nonce: randomBytes(8).toString('hex') });

      await fsSet('activations', String(finalCode).toUpperCase(), { ...activation, status: 'USED', hwid, licenseKey, activatedAt: new Date().toISOString() });
      await fsSet('licenses', hwid, { hwid, plano, licenseKey, email: activation.email, activatedAt: new Date().toISOString(), expiration });
      await fsSet('logs_activation', `${Date.now()}_${hwid.replace(/-/g, '')}`, { event: 'ACTIVATION_SUCCESS', code: finalCode, hwid, email: activation.email, timestamp: new Date().toISOString() });

      return res.json({ success: true, licenseKey, plano: activation.plano, expiration });
    }

    // ── Validar Licença ─────────────────────────────────────────────────────────
    if (url.includes('/api/license/validate') && method === 'GET') {
      const hwid = req.query?.hwid || url.split('hwid=')[1]?.split('&')[0];
      if (!hwid) return res.status(400).json({ message: 'HWID ausente' });

      const license = await fsGet('licenses', hwid);
      if (!license) return res.status(404).json({ message: 'Licença não encontrada', valid: false });

      const now = new Date();
      const isExpired = license.expiration && new Date(license.expiration) < now;
      if (isExpired) return res.json({ valid: false, message: 'Licença expirada.', plano: license.plano, expiration: license.expiration, diasRestantes: 0 });

      let diasRestantes = 9999;
      if (license.expiration) {
        diasRestantes = Math.max(0, Math.ceil((new Date(license.expiration).getTime() - now.getTime()) / 86400000));
      }

      return res.json({ valid: true, plano: license.plano, expiration: license.expiration || null, diasRestantes });
    }

    // ── Recuperar Códigos ───────────────────────────────────────────────────────
    if (url.includes('/api/license/recover') && method === 'GET') {
      const email = req.query?.email || url.split('email=')[1]?.split('&')[0];
      if (!email) return res.status(400).json({ message: 'E-mail é obrigatório' });
      try {
        const all = await fsList('activations');
        const found = all.filter((a: any) => a.email?.toLowerCase() === decodeURIComponent(email).toLowerCase());
        if (!found.length) return res.status(404).json({ message: 'Nenhuma ativação encontrada para este e-mail' });
        return res.json(found.map((a: any) => ({ code: a.code, status: a.status, createdAt: a.createdAt, plano: a.plano })));
      } catch (e: any) { return res.status(500).json({ message: 'Erro ao recuperar códigos' }); }
    }

    // ── Admin: Listar ativações ─────────────────────────────────────────────────
    if (url.includes('/api/admin/activations') && method === 'GET') {
      if (!isAdmin) return res.status(401).json({ message: 'Senha incorreta' });
      try { return res.json(await fsList('activations')); }
      catch (e: any) { return res.status(500).json({ message: 'Erro ao listar ativações', error: e.message }); }
    }

    // ── Admin: Resetar ativação ─────────────────────────────────────────────────
    if (url.includes('/api/admin/activation/reset/') && method === 'POST') {
      if (!isAdmin) return res.status(401).json({ message: 'Senha incorreta' });
      const code = url.split('/reset/')[1]?.split('?')[0];
      if (!code) return res.status(400).json({ message: 'Código é obrigatório' });
      try {
        const activation = await fsGet('activations', code.toUpperCase());
        if (!activation) return res.status(404).json({ message: 'Ativação não encontrada' });
        await fsSet('activations', code.toUpperCase(), { ...activation, status: 'AVAILABLE', usedAt: null, hwid: null });
        return res.json({ message: 'Ativação resetada com sucesso' });
      } catch (e: any) { return res.status(500).json({ message: 'Erro ao resetar' }); }
    }

    // ── Admin: Listar licenças ──────────────────────────────────────────────────
    if (url.includes('/api/admin/licenses') && method === 'GET') {
      if (!isAdmin) return res.status(401).json({ message: 'Senha incorreta' });
      try { return res.json(await fsList('licenses')); }
      catch (e: any) { return res.status(500).json({ message: 'Erro ao listar licenças' }); }
    }

    // ── Admin: Deletar licença ──────────────────────────────────────────────────
    if (url.includes('/api/admin/license/delete/') && method === 'DELETE') {
      if (!isAdmin) return res.status(401).json({ message: 'Senha incorreta' });
      let hwid = url.split('/delete/')[1]?.split('?')[0];
      if (hwid) hwid = decodeURIComponent(hwid).trim().replace(/\/$/, '');
      if (!hwid) return res.status(400).json({ message: 'HWID é obrigatório' });
      try { await fsDelete('licenses', hwid); return res.json({ message: 'Licença removida' }); }
      catch (e: any) { return res.status(500).json({ message: 'Erro ao deletar licença', error: e.response?.data || e.message }); }
    }

    // ── Admin: Deletar ativação ─────────────────────────────────────────────────
    if (url.includes('/api/admin/activation/delete/') && method === 'DELETE') {
      if (!isAdmin) return res.status(401).json({ message: 'Senha incorreta' });
      let code = url.split('/delete/')[1]?.split('?')[0];
      if (code) code = decodeURIComponent(code).trim().replace(/\/$/, '');
      if (!code) return res.status(400).json({ message: 'Código é obrigatório' });
      try { await fsDelete('activations', code.toUpperCase()); return res.json({ message: 'Ativação excluída' }); }
      catch (e: any) { return res.status(500).json({ message: 'Erro ao deletar ativação', error: e.response?.data || e.message }); }
    }

    // ── Trial por e-mail (modal hero) ────────────────────────────────────────────
    if (url.includes('/api/license/trial') && !url.includes('/trial-hwid') && method === 'POST') {
      const { email, name } = req.body;
      if (!email) return res.status(400).json({ message: 'E-mail é obrigatório' });

      // fsGet direto no índice — evita fsList que varre tudo e causa timeout
      const trialKey = `trial_${email.toLowerCase().replace(/[^a-z0-9]/g, '_')}`;
      const existingTrial = await fsGet('trials_email', trialKey);
      if (existingTrial) return res.status(400).json({ message: 'Você já solicitou um período de teste para este e-mail.' });

      const code = `R3D-TRIAL-${randomBytes(4).toString('hex').toUpperCase()}`;
      const expirationDate = new Date();
      expirationDate.setDate(expirationDate.getDate() + 7);

      await fsSet('activations', code, {
        code, email, name: name || 'Usuário Trial',
        plano: 'Trial', status: 'PENDING',
        createdAt: new Date().toISOString(),
        expiresAt: expirationDate.toISOString(),
      });

      // Índice para lookup rápido sem fsList
      await fsSet('trials_email', trialKey, { email, code, createdAt: new Date().toISOString() });

      try {
        await sendEmail(email, 'Seu código TRIAL - R3D Print Manager Pro',
          `<div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
            <h2 style="color:#C67D3D">Seu período de teste começou! 🚀</h2>
            <p>Olá ${name || ''}! Seu código de ativação TRIAL (7 dias):</p>
            <div style="background:#1a1a1a;color:white;padding:20px;border-radius:12px;text-align:center;margin:20px 0">
              <h1 style="color:#C67D3D;font-size:32px;margin:10px 0">${code}</h1>
            </div>
            <p>Acesse <a href="https://r3dprintmanagerpro.com.br/#license-activation">r3dprintmanagerpro.com.br</a>, insira seu HWID + este código para ativar.</p>
          </div>`
        );
      } catch (emailErr: any) {
        console.error('[Trial] Erro e-mail (não crítico):', emailErr.message);
      }

      return res.json({ success: true, message: 'Código enviado para seu e-mail!' });
    }

    // ── Admin: Backup Total ─────────────────────────────────────────────────────
    if (url.includes('/api/admin/backup') && method === 'GET') {
      if (!isAdmin) return res.status(401).json({ message: 'Senha incorreta' });
      try {
        const [activations, licenses, cupons, payments, trialsHwid] = await Promise.all([
          fsList('activations'), fsList('licenses'), fsList('cupons'),
          fsList('payments'), fsList('trials_hwid')
        ]);
        return res.json({ timestamp: new Date().toISOString(), activations, licenses, cupons, payments, trialsHwid });
      } catch (e: any) { return res.status(500).json({ message: 'Erro ao gerar backup' }); }
    }

    // ── Download ────────────────────────────────────────────────────────────────
    if (url.includes('/api/download')) {
      return res.redirect(302, 'https://github.com/rovateduino/R3D-PRINT-MANAGER-PRO/releases/download/v2.5.0/Setup_R3D_PrintManager_Pro.exe');
    }

    console.warn(`[API] 404: ${method} ${url}`);
    return res.status(404).json({ message: 'Not found', path: url });

  } catch (error: any) {
    console.error(`[API] Global Error:`, error.message);
    return res.status(500).json({ error: 'Internal Server Error', message: error.message });
  }
}
