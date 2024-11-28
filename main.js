import { DB } from "https://deno.land/x/sqlite/mod.ts";

const db = new DB("mlinkTest.db");
db.execute(`
  CREATE TABLE IF NOT EXISTS users (
    user TEXT PRIMARY KEY NOT NULL,
    token TEXT NOT NULL UNIQUE,
    permissions TEXT NOT NULL,
    password TEXT NOT NULL
  );
`);
db.execute(`
  CREATE TABLE IF NOT EXISTS follows (
    followed TEXT PRIMARY KEY,
    follower TEXT NOT NULL
  )
`);
db.execute(`
  CREATE TABLE IF NOT EXISTS posts (
    id TEXT PRIMARY KEY,
    post TEXT NOT NULL,
    user TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    reply_to TEXT
  )
`);
db.execute(`
  CREATE TABLE IF NOT EXISTS comments (
    post_id TEXT PRIMARY KEY,
    post TEXT NOT NULL,
    user TEXT NOT NULL,
    created_at INTEGER NOT NULL
  )
`);

async function handleRegister(req) {
  const data = await req.json();
  try {
    if (!data.user || !data.password) {
      return new Response(JSON.stringify({
        status: "error",
        message: "Username and password are required"
      }), {
        status: 400,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization"
        }
      });
    }

    const token = crypto.randomUUID();
    const hashedPassword = Array.from(
      new Uint8Array(
        await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data.password))
      )
    ).map(b => b.toString(16).padStart(2, "0")).join("");

    const stmt = db.prepareQuery(
      "INSERT INTO users (user, token, permissions, password) VALUES (?, ?, ?, ?)"
    );
    stmt.execute([data.user, token, "user", hashedPassword]);
    stmt.finalize();

    return new Response(JSON.stringify({
      status: "success",
      token: token
    }), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"
      }
    });
  } catch (e) {
    console.error("Registration error:", e);
    return new Response(JSON.stringify({
      status: "error",
      message: `Registration failed: ${e.message}`
    }), {
      status: 500,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS", 
        "Access-Control-Allow-Headers": "Content-Type, Authorization"
      }
    });
  }
}

async function handleLogin(req) {
  const data = await req.json();
  try {
    if (!data.username || !data.password) {
      return new Response(JSON.stringify({
        status: "error",
        message: "Username and password are required"
      }), {
        status: 400,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization"
        }
      });
    }

    const hashedPassword = Array.from(
      new Uint8Array(
        await crypto.subtle.digest("SHA-256", new TextEncoder().encode(data.password))
      )
    ).map(b => b.toString(16).padStart(2, "0")).join("");

    const user = db.queryEntries(
      "SELECT * FROM users WHERE user = ? AND password = ?",
      [data.username, hashedPassword]
    );

    if (user && user.length > 0) {
      const userData = user[0];
      if (userData.banned) {
        return new Response(JSON.stringify({
          status: "error",
          message: "This account has been banned"
        }), {
          status: 403,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization"
          }
        });
      }

      return new Response(JSON.stringify({
        status: "success",
        token: userData.token
      }), {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization"
        }
      });
    }

    return new Response(JSON.stringify({
      status: "error",
      message: "Invalid credentials"
    }), {
      status: 401,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"
      }
    });
  } catch (e) {
    return new Response(JSON.stringify({
      status: "error",
      message: `Login failed: ${e.message}`
    }), {
      status: 500,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"
      }
    });
  }
}

async function handlePost(req) {
  const auth = req.headers.get("Authorization");
  if (!auth) {
    return new Response(JSON.stringify({
      status: "error",
      message: "Unauthorized"
    }), {
      status: 401,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"
      }
    });
  }

  const user = db.queryEntries(
    "SELECT * FROM users WHERE token = ?",
    [auth]
  )[0];

  if (!user) {
    return new Response(JSON.stringify({
      status: "error",
      message: "Invalid token"
    }), {
      status: 401,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"
      }
    });
  }

  const data = await req.json();
  try {
    const id = crypto.randomUUID();
    const timestamp = Date.now();
    const replyToId = data.replyTo || null;

    const stmt = db.prepareQuery(
      "INSERT INTO posts (id, post, user, created_at, reply_to) VALUES (?, ?, ?, ?, ?)"
    );
    stmt.execute([id, data.post, user.user, timestamp, replyToId]);
    stmt.finalize();

    return new Response(JSON.stringify({
      status: "success",
      id: id,
      timestamp: timestamp
    }), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"
      }
    });
  } catch (e) {
    return new Response(JSON.stringify({
      status: "error",
      message: "Failed to save post"
    }), {
      status: 500,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"
      }
    });
  }
}

async function handleFetch(req) {
  const auth = req.headers.get("Authorization");
  if (!auth) {
    return new Response(JSON.stringify({
      status: "error",
      message: "Unauthorized"
    }), {
      status: 401,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"
      }
    });
  }

  const user = db.queryEntries(
    "SELECT * FROM users WHERE token = ?",
    [auth]
  )[0];

  if (!user) {
    return new Response(JSON.stringify({
      status: "error",
      message: "Invalid token"
    }), {
      status: 401,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"
      }
    });
  }

  const url = new URL(req.url);
  const username = url.searchParams.get("username");
  const offset = parseInt(url.searchParams.get("offset") || "0");

  try {
    const posts = db.queryEntries(
      "SELECT post, user, created_at, id, reply_to FROM posts WHERE user = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
      [username, 10, offset]
    );

    return new Response(JSON.stringify({
      status: "success",
      posts: posts
    }), {
      status: 200,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"
      }
    });
  } catch (e) {
    return new Response(JSON.stringify({
      status: "error",
      message: "Failed to fetch posts"
    }), {
      status: 500,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"
      }
    });
  }
}

Deno.serve((req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization"
      }
    });
  }

  const url = new URL(req.url);
  const path = url.pathname;

  switch (path) {
    case "/register":
      if (req.method !== "POST") {
        return new Response(null, { 
          status: 405,
          headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization"
          }
        });
      }
      return handleRegister(req);

    case "/login":
      if (req.method !== "POST") {
        return new Response(null, { 
          status: 405,
          headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization"
          }
        });
      }
      return handleLogin(req);

    case "/post":
      if (req.method !== "POST") {
        return new Response(null, { 
          status: 405,
          headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization"
          }
        });
      }
      return handlePost(req);

    case "/posts":
      if (req.method !== "GET") {
        return new Response(null, { 
          status: 405,
          headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization"
          }
        });
      }
      return handleFetch(req);

    default:
      return new Response(null, { 
        status: 404,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization"
        }
      });
  }
});
