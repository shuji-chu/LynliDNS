export async function onRequestPost(context) {
  const { request, env } = context;
  try {
    const { username, email, password, turnstileToken } = await request.json();

    const verifyRes = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ secret: env.TURNSTILE_SECRET_KEY, response: turnstileToken })
    });
    const verifyData = await verifyRes.json();
    if (!verifyData.success) return new Response(JSON.stringify({ success: false, msg: '人机验证失败' }), { status: 400 });

    const msgBuffer = new TextEncoder().encode(password);
    const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
    const hashedPassword = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');

    await env.DB.prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)').bind(username, email, hashedPassword).run();

    return new Response(JSON.stringify({ success: true, msg: '注册成功' }), { status: 200 });
  } catch (err) {
    return new Response(JSON.stringify({ success: false, msg: '用户名或邮箱已存在' }), { status: 500 });
  }
}