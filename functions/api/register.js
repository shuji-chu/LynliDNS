export async function onRequestPost(context) {
  const { request, env } = context;
  try {
    const { username, email, password, turnstileToken, code } = await request.json();

    // 1. 校验 Turnstile 人机验证
    const verifyRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret: env.TURNSTILE_SECRET_KEY, response: turnstileToken })
    });
    const verifyData = await verifyRes.json();
    if (!verifyData.success) {
      return new Response(JSON.stringify({ success: false, msg: '人机验证失败' }), { status: 400 });
    }

    // 2. 校验邮箱验证码
    const record = await env.DB.prepare('SELECT code, expire_at FROM email_codes WHERE email = ?').bind(email).first();
    if (!record || record.code !== code || Date.now() > record.expire_at) {
      return new Response(JSON.stringify({ success: false, msg: '验证码错误或已过期' }), { status: 400 });
    }

    // 3. 密码哈希 (SHA-256)
    const msgBuffer = new TextEncoder().encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashedPassword = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');

    // 4. 写入数据库
    await env.DB.prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)').bind(username, email, hashedPassword).run();
    
    // 5. 注册成功后清理验证码
    await env.DB.prepare('DELETE FROM email_codes WHERE email = ?').bind(email).run();

    return new Response(JSON.stringify({ success: true, msg: '注册成功' }), { status: 200 });
  } catch (err) {
    // 捕获唯一约束冲突等错误
    return new Response(JSON.stringify({ success: false, msg: '用户名或邮箱已存在' }), { status: 500 });
  }
}