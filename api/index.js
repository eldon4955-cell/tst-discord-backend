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

// Exact Discord OAuth callback URL
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

// ===============================
// SESSION
// ===============================

function sign(value) {
  return crypto
    .createHmac(
      "sha256",
      SESSION_SECRET || "change-this-session-secret"
    )
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

  if (!raw) {
    return null;
  }

  const dot = raw.lastIndexOf(".");

  if (dot < 1) {
    return null;
  }

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

// ===============================
// HEALTH CHECK
// ===============================

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "TST Discord Backend"
  });
});

// ===============================
// DISCORD LOGIN
// ===============================

app.get("/auth/discord", (req, res) => {
  if (!DISCORD_CLIENT_ID) {
    return res
      .status(500)
      .send("DISCORD_CLIENT_ID is missing.");
  }

  const params = new URLSearchParams({
    client_id: DISCORD_CLIENT_ID,
    response_type: "code",
    redirect_uri: DISCORD_REDIRECT_URI,
    scope: "identify guilds"
  });

  const discordURL =
    "https://discord.com/oauth2/authorize?" +
    params.toString();

  console.log("Discord OAuth URL:", discordURL);

  res.redirect(discordURL);
});

// ===============================
// DISCORD CALLBACK
// ===============================

app.get("/auth/discord/callback", async (req, res) => {
  try {
    const code = req.query.code;

    if (!code) {
      return res
        .status(400)
        .send("Missing Discord authorization code.");
    }

    if (!DISCORD_CLIENT_ID) {
      return res
        .status(500)
        .send("DISCORD_CLIENT_ID is missing.");
    }

    if (!DISCORD_CLIENT_SECRET) {
      return res
        .status(500)
        .send("DISCORD_CLIENT_SECRET is missing.");
    }

    // ===========================
    // GET DISCORD ACCESS TOKEN
    // ===========================

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
          code: code,
          redirect_uri: DISCORD_REDIRECT_URI
        })
      }
    );

    if (!tokenResponse.ok) {
      const discordError =
        await tokenResponse.text();

      console.error(
        "Discord token error:",
        discordError
      );

      return res
        .status(401)
        .send(
          "Discord token error: " +
            discordError
        );
    }

    const token = await tokenResponse.json();

    if (!token.access_token) {
      return res
        .status(401)
        .send(
          "Discord did not return an access token."
        );
    }

    // ===========================
    // DISCORD USER + SERVERS
    // ===========================

    const headers = {
      Authorization:
        `Bearer ${token.access_token}`
    };

    const [
      userResponse,
      guildResponse
    ] = await Promise.all([
      fetch(
        "https://discord.com/api/users/@me",
        {
          headers
        }
      ),

      fetch(
        "https://discord.com/api/users/@me/guilds",
        {
          headers
        }
      )
    ]);

    if (!userResponse.ok) {
      const error =
        await userResponse.text();

      return res
        .status(401)
        .send(
          "Could not get Discord user: " +
            error
        );
    }

    if (!guildResponse.ok) {
      const error =
        await guildResponse.text();

      return res
        .status(401)
        .send(
          "Could not get Discord servers: " +
            error
        );
    }

    const user =
      await userResponse.json();

    const guilds =
      await guildResponse.json();

    // ===========================
    // CHECK TST SERVER
    // ===========================

    const isMember =
      Array.isArray(guilds) &&
      guilds.some(
        guild =>
          guild.id === DISCORD_GUILD_ID
      );

    if (!isMember) {
      return res
        .status(403)
        .send(
          "You must be a member of the TST Discord server to continue."
        );
    }

    // ===========================
    // CREATE SESSION
    // ===========================

    const session =
      createSession(user);

    res.cookie(
      "tst_session",
      session,
      {
        httpOnly: true,
        secure: true,
        sameSite: "none",
        maxAge:
          7 * 24 * 60 * 60 * 1000,
        path: "/"
      }
    );

    // ===========================
    // SEND USER BACK TO WEBSITE
    // ===========================

    res.redirect(
      frontend || "/"
    );

  } catch (error) {
    console.error(
      "Discord OAuth error:",
      error
    );

    res
      .status(500)
      .send(
        "Discord verification failed: " +
          error.message
      );
  }
});

// ===============================
// CHECK LOGIN STATUS
// ===============================

app.get(
  "/api/discord/status",
  (req, res) => {
    const session =
      getSession(req);

    res.json({
      verified: Boolean(session),

      user: session
        ? {
            id: session.id,
            username:
              session.username,
            global_name:
              session.global_name
          }
        : null
    });
  }
);

// ===============================
// LOGOUT
// ===============================

app.post(
  "/auth/logout",
  (req, res) => {
    res.clearCookie(
      "tst_session",
      {
        httpOnly: true,
        secure: true,
        sameSite: "none",
        path: "/"
      }
    );

    res.json({
      ok: true
    });
  }
);

// ===============================
// VERCEL
// ===============================

module.exports = app;
