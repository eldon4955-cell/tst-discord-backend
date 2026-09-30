const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const app = express();

const PORT = process.env.PORT || 3000;
const FRONTEND_URL = process.env.FRONTEND_URL || 'https://YOUR-USERNAME.github.io/YOUR-REPO/';
const DISCORD_CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const DISCORD_CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const DISCORD_REDIRECT_URI = process.env.DISCORD_REDIRECT_URI || `http://localhost:${PORT}/auth/discord/callback`;
const DISCORD_GUILD_ID = process.env.DISCORD_GUILD_ID;
const SESSION_SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');

if (!DISCORD_CLIENT_ID || !DISCORD_CLIENT_SECRET || !DISCORD_GUILD_ID) {
  console.warn('Missing DISCORD_CLIENT_ID, DISCORD_CLIENT_SECRET, or DISCORD_GUILD_ID');
}

app.use(cors({ origin: FRONTEND_URL.replace(/\/$/, ''), credentials: true }));
app.use(cookieParser());

const sessions = new Map();
function sign(value) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('hex');
}
function makeSession(user) {
  const id = crypto.randomBytes(24).toString('hex');
  sessions.set(id, { user, expires: Date.now() + 7*24*60*60*1000 });
  return `${id}.${sign(id)}`;
}
function getSession(req) {
  const raw = req.cookies.tst_session;
  if (!raw) return null;
  const [id, sig] = raw.split('.');
  if (!id || !sig || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(sign(id)))) return null;
  const session = sessions.get(id);
  if (!session || session.expires < Date.now()) { sessions.delete(id); return null; }
  return session;
}

app.get('/auth/discord', (req,res) => {
  const state = crypto.randomBytes(24).toString('hex');
  res.cookie('tst_oauth_state', state, { httpOnly:true, secure:true, sameSite:'lax', maxAge:10*60*1000 });
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    response_type: 'code',
    redirect_uri: DISCORD_REDIRECT_URI,
    scope: 'identify guilds',
    state
  });
  res.redirect('https://discord.com/oauth2/authorize?' + params.toString());
});

app.get('/auth/discord/callback', async (req,res) => {
  try {
    if (!req.query.code || !req.query.state || req.query.state !== req.cookies.tst_oauth_state) return res.status(400).send('Invalid OAuth state.');
    res.clearCookie('tst_oauth_state');
    const tokenBody = new URLSearchParams({
      client_id: DISCORD_CLIENT_ID,
      client_secret: DISCORD_CLIENT_SECRET,
      grant_type: 'authorization_code',
      code: req.query.code,
      redirect_uri: DISCORD_REDIRECT_URI
    });
    const tokenRes = await fetch('https://discord.com/api/v10/oauth2/token', { method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded'}, body:tokenBody });
    if (!tokenRes.ok) return res.status(401).send('Discord OAuth failed.');
    const token = await tokenRes.json();
    const headers = { Authorization: `Bearer ${token.access_token}` };
    const userRes = await fetch('https://discord.com/api/v10/users/@me', { headers });
    const guildsRes = await fetch('https://discord.com/api/v10/users/@me/guilds', { headers });
    if (!userRes.ok || !guildsRes.ok) return res.status(401).send('Could not read Discord account.');
    const user = await userRes.json();
    const guilds = await guildsRes.json();
    const member = guilds.some(g => g.id === DISCORD_GUILD_ID);
    if (!member) return res.status(403).send('Your Discord account is not a member of the TST server. Join the server, then try verification again.');
    const sessionCookie = makeSession({ id:user.id, username:user.username });
    res.cookie('tst_session', sessionCookie, { httpOnly:true, secure:true, sameSite:'none', maxAge:7*24*60*60*1000 });
    res.redirect(FRONTEND_URL);
  } catch (e) {
    console.error(e);
    res.status(500).send('Verification failed.');
  }
});

app.get('/api/discord/status', (req,res) => {
  const session = getSession(req);
  res.json({ verified: !!session, user: session ? session.user : null });
});

app.post('/auth/logout', (req,res) => { res.clearCookie('tst_session'); res.json({ok:true}); });

app.get('/health', (req,res) => res.json({ok:true}));
app.listen(PORT, () => console.log(`TST Discord gate listening on ${PORT}`));
