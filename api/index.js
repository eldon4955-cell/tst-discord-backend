const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const crypto = require("crypto");

const app = express();

const CLIENT_ID = process.env.DISCORD_CLIENT_ID;
const CLIENT_SECRET = process.env.DISCORD_CLIENT_SECRET;
const GUILD_ID = process.env.DISCORD_GUILD_ID;
const FRONTEND_URL = (process.env.FRONTEND_URL || "").replace(/\/$/, "");
const SESSION_SECRET = process.env.SESSION_SECRET || "tst-session-secret";

const REDIRECT_URI =
  "https://tst-discord-backend.vercel.app/auth/discord/callback";

app.use(express.json());
app.use(cookieParser());

app.use(
  cors({
    origin: FRONTEND_URL,
    credentials: true
  })
);

function makeSignature(value) {
  return crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(value)
    .digest("hex");
}

function makeSession(user) {
  const payload = Buffer.from(
    JSON.stringify({
      id: user.id,
      username: user.username,
      global_name: user.global_name || null,
      expires: Date.now() + 7 * 24 * 60 * 60 * 1000
    })
  ).toString("base64url");

  return payload + "." + makeSignature(payload);
}

function readSession(req) {
  const session = req.cookies.tst_session;

  if (!session) return null;

  const dot = session.lastIndexOf(".");

  if (dot === -1) return null;

  const payload = session.slice(0, dot);
  const signature = session.slice(dot + 1);
  const expected = makeSignature(payload);

  if (signature !== expected) return null;

  try {
    const data = JSON.parse(
      Buffer.from(payload, "base64url").toString()
    );

    if (data.expires < Date.now()) return null;

    return data;
  } catch {
    return null;
  }
}

/* HOME */

app.get("/", (req, res) => {
  res.status(200).send("TST Discord Backend is online.");
});

/* HEALTH */

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "TST Discord Backend"
  });
});

/* START DISCORD LOGIN */

app.get("/auth/discord", (req, res) => {
  const params = new URLSearchParams({
    client_id: CLIENT_ID,
    response_type: "code",
    redirect_uri: REDIRECT_URI,
    scope: "identify guilds"
  });

  res.redirect(
    "https://discord.com/oauth2/authorize?" +
      params.toString()
  );
});

/* DISCORD CALLBACK */

app.get("/auth/discord/callback", async (req, res) => {
  try {
    const code = req.query.code;

    if (!code) {
      return res.status(400).send("Missing Discord code.");
    }

    const tokenResponse = await fetch(
      "https://discord.com/api/oauth2/token",
      {
        method: "POST",
        headers: {
          "Content-Type":
            "application/x-www-form-urlencoded"
        },
        body: new URLSearchParams({
          client_id: CLIENT_ID,
          client_secret: CLIENT_SECRET,
          grant_type: "authorization_code",
          code: code,
          redirect_uri: REDIRECT_URI
        })
      }
    );

    if (!tokenResponse.ok) {
      const error = await tokenResponse.text();

      console.error("Discord token error:", error);

      return res.status(401).send(
        "Discord token exchange failed.<br><br>" +
        error
      );
    }

    const token = await tokenResponse.json();

    const discordHeaders = {
      Authorization: `Bearer ${token.access_token}`
    };

    const userResponse = await fetch(
      "https://discord.com/api/users/@me",
      {
        headers: discordHeaders
      }
    );

    const guildResponse = await fetch(
      "https://discord.com/api/users/@me/guilds",
      {
        headers: discordHeaders
      }
    );

    if (!userResponse.ok || !guildResponse.ok) {
      return res
        .status(401)
        .send("Could not read your Discord account.");
    }

    const user = await userResponse.json();
    const guilds = await guildResponse.json();

    const member = guilds.some(
      guild => guild.id === GUILD_ID
    );

    if (!member) {
      return res
        .status(403)
        .send(
          "You must be a member of the TST Discord server."
        );
    }

    const session = makeSession(user);

    res.cookie("tst_session", session, {
      httpOnly: true,
      secure: true,
      sameSite: "none",
      maxAge: 7 * 24 * 60 * 60 * 1000,
      path: "/"
    });

    res.redirect(FRONTEND_URL || "/");

  } catch (error) {
    console.error(error);

    res.status(500).send(
      "Discord verification failed.<br><br>" +
      error.message
    );
  }
});

/* CHECK STATUS */

app.get("/api/discord/status", (req, res) => {
  const session = readSession(req);

  res.json({
    verified: !!session,
    user: session
      ? {
          id: session.id,
          username: session.username,
          global_name: session.global_name
        }
      : null
  });
});

/* LOGOUT */

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

module.exports = app;
