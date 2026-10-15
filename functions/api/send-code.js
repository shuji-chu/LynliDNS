export async function onRequestPost(context) {
  const { request, env } = context;
  try {
    const { email } = await request.json();
    if (!email) return new Response(JSON.stringify({ success: false, msg: '请输入邮箱' }), { status: 400 });

    // 生成6位随机验证码
    const code = Math.floor(100000 + Math.random() * 900000).toString();
    const expireAt = Date.now() + 5 * 60 * 1000; // 5分钟有效

    // 存入 D1 数据库（需要建表：CREATE TABLE email_codes (email TEXT PRIMARY KEY, code TEXT, expire_at INTEGER);）
    await env.DB.prepare('INSERT OR REPLACE INTO email_codes (email, code, expire_at) VALUES (?, ?, ?)').bind(email, code, expireAt).run();

    // 阿里云 API 签名逻辑
    const params = {
      Action: 'SingleSendMail',
      AccountName: env.ALI_DM_ACCOUNT, // 发信地址
      ReplyToAddress: 'false',
      AddressType: '1',
      ToAddress: email,
      Subject: 'LynliDNS 注册验证码',
      HtmlBody: `您的验证码是：<b>${code}</b>，5分钟内有效。`,
      Format: 'JSON',
      Version: '2015-11-23',
      AccessKeyId: env.ALI_ACCESS_KEY_ID,
      SignatureMethod: 'HMAC-SHA1',
      Timestamp: new Date().toISOString().replace(/\.\d{3}Z$/, 'Z'),
      SignatureVersion: '1.0',
      SignatureNonce: Math.random().toString(36).substring(2)
    };

    // 按字典序排序参数
    const sortedKeys = Object.keys(params).sort();
    const canonicalizedQuery = sortedKeys.map(k => `${encodeURIComponent(k)}=${encodeURIComponent(params[k])}`).join('&');
    
    // 构造 StringToSign
    const stringToSign = `POST&${encodeURIComponent('/')}&${encodeURIComponent(canonicalizedQuery)}`;
    
    // HMAC-SHA1 计算签名
    const key = env.ALI_ACCESS_KEY_SECRET + '&';
    const encoder = new TextEncoder();
    const keyData = encoder.encode(key);
    const msgData = encoder.encode(stringToSign);
    
    const cryptoKey = await crypto.subtle.importKey('raw', keyData, { name: 'HMAC', hash: 'SHA-1' }, false, ['sign']);
    const signatureBuffer = await crypto.subtle.sign('HMAC', cryptoKey, msgData);
    const signature = btoa(String.fromCharCode(...new Uint8Array(signatureBuffer)));

    params.Signature = signature;

    // 发送请求给阿里云
    const res = await fetch('https://dm.aliyuncs.com/', { method: 'POST', body: new URLSearchParams(params) });
    const data = await res.json();

    if (data.Code === 'OK') {
      return new Response(JSON.stringify({ success: true, msg: '验证码已发送，请查收邮箱' }), { status: 200 });
    } else {
      return new Response(JSON.stringify({ success: false, msg: '发送失败: ' + (data.Message || '检查阿里云配置') }), { status: 500 });
    }
  } catch (err) {
    return new Response(JSON.stringify({ success: false, msg: '发送出错: ' + err.message }), { status: 500 });
  }
}