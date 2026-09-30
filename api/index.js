const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");

const app = express();

const {
  DISCORD_CLIENT_ID,
  DISCORD_CLIENT_SECRET,
  DISCORD_GUILD_ID,
  FRONTEND_URL,
  SESSION_SECRET
} = process.env;

const DISCORD_REDIRECT_URI =
  "https://tst-discord-backend.vercel.app/auth/discord/callback";

const frontend = (FRONTEND_URL || "").replace(/\/$/, "");

app.use(express.json());
app.use(cookieParser());

app.use(
  cors({
    origin: frontend,
    credentials: true
  })
);

// -------------------------
// Session helpers
// -------------------------

function sign(value) {
  return crypto
    .createHmac("sha256", SESSION_SECRET || "change-me")
    .update(value)
    .digest("hex");
}

function createSession(user) {
  const payload = Buffer.from(
    JSON.stringify({
      id: user.id,
      username: user.username,
      global_name: user.global_name || null,
      exp: Date.now() + 7 * 24 * 60 * 60 * 1000
    })
  ).toString("base64url");

  return `${payload}.${sign(payload)}`;
}

function getSession(req) {
  const raw = req.cookies.tst_session;

  if (!raw) return null;

  const dot = raw.lastIndexOf(".");

  if (dot < 1) return null;

  const payload = raw.slice(0, dot);
  const signature = raw.slice(dot + 1);
  const expected = sign(payload);

  const a = Buffer.from(signature);
  const b = Buffer.from(expected);

  if (
    a.length !== b.length ||
    !crypto.timingSafeEqual(a, b)
  ) {
    return null;
  }

  try {
    const data = JSON.parse(
      Buffer.from(payload, "base64url").toString("utf8")
    );

    if (!data.exp || data.exp < Date.now()) {
      return null;
    }

    return data;
  } catch {
    return null;
  }
}

// -------------------------
// Health check
// -------------------------

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "TST Discord Backend"
  });
});

// -------------------------
// Discord OAuth
// -------------------------

app.get("/auth/discord", (req, res) => {
  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    response_type: "code",
    redirect_uri: DISCORD_REDIRECT_URI,
    scope: "identify guilds"
  });

  res.redirect(
    `https://discord.com/oauth2/authorize?${params.toString()}`
  );
});

// -------------------------
// Discord OAuth callback
// -------------------------

app.get("/auth/discord/callback", async (req, res) => {
  try {
    const code = req.query.code;

    if (!code) {
      return res
        .status(400)
        .send("Missing Discord authorization code.");
    }

    // Exchange OAuth code for token
    const tokenResponse = await fetch(
      "https://discord.com/api/oauth2/token",
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          client_id: DISCORD_CLIENT_ID,
          client_secret: DISCORD_CLIENT_SECRET,
          grant_type: "authorization_code",
          code,
          redirect_uri: DISCORD_REDIRECT_URI
        })
      }
    );

    if (!tokenResponse.ok) {
  const discordError = await tokenResponse.text();

  console.error("Discord token error:", discordError);

  return res
    .status(401)
    .send("Discord token error: " + discordError);
    }

    const token = await tokenResponse.json();

    const headers = {
      Authorization: `Bearer ${token.access_token}`
    };

    // Get Discord user + servers
    const [userResponse, guildResponse] =
      await Promise.all([
        fetch(
          "https://discord.com/api/users/@me",
          { headers }
        ),
        fetch(
          "https://discord.com/api/users/@me/guilds",
          { headers }
        )
      ]);

    if (!userResponse.ok || !guildResponse.ok) {
      return res
        .status(401)
        .send("Could not verify Discord account.");
    }

    const user = await userResponse.json();
    const guilds = await guildResponse.json();

    // Check TST Discord membership
    const isMember =
      Array.isArray(guilds) &&
      guilds.some(
        guild => guild.id === DISCORD_GUILD_ID
      );

    if (!isMember) {
      return res
        .status(403)
        .send(
          "You must be a member of the TST Discord server to continue."
        );
    }

    // Create login session
    const session = createSession(user);

    res.cookie("tst_session", session, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/"
    });

    // Send user back to website
    res.redirect(frontend);

  } catch (error) {
    console.error("Discord OAuth error:", error);

    res
      .status(500)
      .send("Discord verification failed.");
  }
});

// -------------------------
// Verification status
// -------------------------

app.get("/api/discord/status", (req, res) => {
  const session = getSession(req);

  res.json({
    verified: Boolean(session),

    user: session
      ? {
          id: session.id,
          username: session.username,
          global_name: session.global_name
        }
      : null
  });
});

// -------------------------
// Logout
// -------------------------

app.post("/auth/logout", (req, res) => {
  res.clearCookie("tst_session", {
    httpOnly: true,
    secure: true,
    sameSite: "none",
    path: "/"
  });

  res.json({
    ok: true
  });
});

// -------------------------
// Vercel export
// -------------------------

module.exports = app;
