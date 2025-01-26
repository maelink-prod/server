// deno-lint-ignore-file
console.log(`Dependencies: Chalk (npm:chalk)
Install with "deno install <package_name>"`);
import { DB } from "https://deno.land/x/sqlite@v3.9.1/mod.ts";
import chalk from "npm:chalk";
console.log(chalk.blue(`Server is starting...`));
const dev = 0
const db = new DB("main.db");
const clients = new Map();
const current = "r1-prev2-1.5";
function returndata(data, code) {
  return new Response(
    data,
    {
      status: code,
      headers: {
        "Content-Type": "application/json",
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods":
          "GET, POST, PATCH, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
      },
    },
  );
}
console.log(
  chalk.red.bold(
    `                       _        _    
                      | (_)     | |   
  _ __ ___   __ _  ___| |_ _ __ | | __
 | '_ \` _  \\ / _\`|/ _ \\ | | '_ \\| |/ /
 | | | | | | (_| |  __/ | | | | |   < 
 |_| |_| |_|\\__,_|\\___|_|_|_| |_|_|\\_\\
  `
  )
);

if (dev === 1) {
  console.log(chalk.red.bold(`
server - version (${current}) | DEV`));
} else {
  console.log(chalk.red.bold(`
server - version (${current})`));
}

if (dev === 1) {
  console.log(chalk.yellow(`
This is a development server! May be unstable, may crash, may do unexplainable things that transcend what is thought to be humanly possible. Use at your own risk.`));
} else {
  console.log(chalk.green.bold(`
This is the public preview of Release 1. It has the baseline features maelink needs to be functional, but there are still a few cool features I want to add back that I deleted in past versions due to code refactors.
If you find any bugs, please don't hesitate to make an issue on the GitHub repository!
-delusions`));
}
console.log(chalk.blueBright.bold(`
HTTP: port 2387 | WS: port 3783`));
async function autoPromote() {
  try {
    db.execute("UPDATE users SET is_mod = 1 WHERE user = 'delusions'");
  } catch (e) {
  }
}
autoPromote();
db.execute(`
  CREATE TABLE IF NOT EXISTS users (
    user TEXT PRIMARY KEY NOT NULL,
    token TEXT NOT NULL UNIQUE,
    permissions TEXT NOT NULL,
    password TEXT NOT NULL,
    is_mod INTEGER NOT NULL
  );
`);
db.execute(`
  CREATE TABLE IF NOT EXISTS bans (
    created_at TEXT PRIMARY KEY NOT NULL,
    banned_by TEXT NOT NULL UNIQUE,
    reason TEXT NOT NULL,
    user TEXT NOT NULL UNIQUE
  );
`);
db.execute(`
  CREATE TABLE IF NOT EXISTS follows (
    following TEXT PRIMARY KEY,
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
db.execute(`
  CREATE TABLE IF NOT EXISTS rtposts (
    _id TEXT PRIMARY KEY,
    p TEXT,
    u TEXT,
    e INTEGER NOT NULL,
    reply_to TEXT,
    post_id TEXT NOT NULL
  )
`);
Deno.serve({
  port: 3783,
  handler: (req) => {
    if (req.headers.get("upgrade") != "websocket") {
      return new Response(null, { status: 501 });
    }
    const { socket, response } = Deno.upgradeWebSocket(req);
    let lastClientsSize = 0;
    setInterval(() => {
      if (clients.size !== lastClientsSize) {
        lastClientsSize = clients.size;
      }
    }, 1000);
    socket.addEventListener("open", () => {
      clients.set(socket, {
        authenticated: false,
        user: null,
      });
    });
    socket.addEventListener("close", () => {
      clients.delete(socket);
    });
    socket.addEventListener("message", (event) => {
      try {
        const data = JSON.parse(event.data);
        // Lissener has friends: Lissiner, Lisserner, Isserner, and Listerner
        const listener = {listener: data.listener ?? null}
        switch (data.cmd) {
          case "login":
            try {
              if (typeof data !== "object" || data === null) {
                socket.send(JSON.stringify({
                  cmd: "login",
                  status: "error",
                  message: "Invalid data format",
                  ...listener
                }));
                return;
              }
              if (data.token) {
                const query = "SELECT * FROM users WHERE token = ?";
                const params = [data.token];
                const user = db.queryEntries(query, params);
                if (user && user.length > 0) {
                  const userData = user[0];
                  if (userData.banned) {
                    console.log(chalk.red.bold("Banned user attempted token login:", userData.user));
                    socket.send(JSON.stringify({
                      cmd: "login",
                      status: "error",
                      message: "This account has been banned",
                      ...listener
                    }));
                    return;
                  }
                  console.log(`User ${userData.user} authenticated via token`);
                  console.log("Current clients map size:", clients.size);
                  clients.set(socket, {
                    authenticated: true,
                    user: userData.user
                  });
                  socket.send(JSON.stringify({
                    cmd: "login",
                    status: "success",
                    payload: JSON.stringify({ token: userData.token }),
                    ...listener
                  }));
                  return;
                } else {
                  socket.send(JSON.stringify({
                    cmd: "login",
                    status: "error",
                    message: "Invalid token",
                    ...listener
                  }));
                  return;
                }
              }
              if (!data.username || !data.password) {
                socket.send(JSON.stringify({
                  cmd: "login",
                  status: "error",
                  message: "Username and password are required",
                  ...listener
                }));
                return;
              }
              crypto.subtle.digest(
                "SHA-256",
                new TextEncoder().encode(data.password),
              ).then((hash) => {
                const hashedPassword = Array.from(new Uint8Array(hash))
                  .map((b) => b.toString(16).padStart(2, "0"))
                  .join("");

                const query =
                  "SELECT * FROM users WHERE user = ? AND password = ?";
                const params = [data.username, hashedPassword];
                const user = db.queryEntries(query, params);
                if (user && user.length > 0) {
                  const userData = user[0];
                  if (userData.banned) {
                    socket.send(JSON.stringify({
                      cmd: "login",
                      status: "error",
                      message: "This account has been banned",
                      ...listener
                    }));
                    return;
                  }
                  if (userData.token) {
                    if (user && user.length > 0) {
                      clients.set(socket, {
                        authenticated: true,
                        user: data.username,
                      });
                      console.log("Updated client state:", clients.get(socket));
                    }
                    socket.send(JSON.stringify({
                      cmd: "login",
                      status: "success",
                      payload: JSON.stringify({ token: userData.token }),
                      ...listener
                    }));
                    console.log("Login successful for user:", data.username);
                  } else {
                    socket.send(JSON.stringify({
                      cmd: "login",
                      status: "error",
                      message: "Invalid user data - missing token",
                      ...listener
                    }));
                  }
                } else {
                  socket.send(JSON.stringify({
                    cmd: "login",
                    status: "error",
                    message: "Invalid username or password",
                  }));
                }
              }).catch((error) => {
                console.log(chalk.red.bold("Hashing error:", error));
                socket.send(JSON.stringify({
                  cmd: "login",
                  status: "error",
                  message: "Error processing login",
                  ...listener
                }));
              });
            } catch (dbError) {
              console.log(chalk.red.bold("Login error:", dbError));
              socket.send(JSON.stringify({
                cmd: "login",
                status: "error",
                message: "Database error during login",
                ...listener
              }));
            }
            break;
          case "post":
            let postClient;
            if (data.token) {
              const user = db.queryEntries(
                "SELECT * FROM users WHERE token = ?",
                [data.token]
              )[0];
              if (user) {
                postClient = {
                  authenticated: true,
                  user: user.user
                };
              }
            }
            if (!postClient) {
              postClient = clients.get(socket);
            }
            if (!postClient?.authenticated) {
              socket.send(JSON.stringify({
                cmd: "post_home",
                status: "error",
                message: "Unauthorized",
                ...listener
              }));
              return;
            }
            if (!data.p || typeof data.p !== "string") {
              socket.send(JSON.stringify({
                cmd: "post",
                status: "error",
                message: "Invalid post data",
                ...listener
              }));
              return;
            }
            const sanitizedPost = data.p
              .replace(/&/g, "&amp;")
              .replace(/</g, "&lt;")
              .replace(/>/g, "&gt;")
              .replace(/"/g, "&quot;")
              .replace(/'/g, "&#x27;")
              .replace(/\//g, "&#x2F;")
              .trim();

            if (sanitizedPost.length === 0) {
              socket.send(JSON.stringify({
                cmd: "post",
                status: "error",
                message: "Post content cannot be empty",
                ...listener
              }));
              return;
            }
            try {
              let replyToId = null;
              if (data.reply_to) {
                const replyPost = db.queryEntries(
                  "SELECT _id FROM rtposts WHERE _id = ?",
                  [data.reply_to],
                );
                if (replyPost && replyPost.length > 0) {
                  replyToId = data.reply_to;
                } else {
                  socket.send(JSON.stringify({
                    cmd: "post",
                    status: "error",
                    message: "Invalid reply_to post ID",
                    ...listener
                  }));
                  return;
                }
              }
              const timestamp = Date.now();
              const id = crypto.randomUUID();
              const stmt = db.prepareQuery(
                "INSERT INTO rtposts (_id, p, u, e, reply_to, post_id) VALUES (?, ?, ?, ?, ?, ?)",
              );
              stmt.execute([
                id,
                sanitizedPost,
                postClient.user.replace(/[<>]/g, ''),
                JSON.stringify({ t: timestamp }),
                replyToId,
                id
              ]);
              stmt.finalize();
              const postNotification = JSON.stringify({
                cmd: "post_home",
                post: {
                  _id: id,
                  p: sanitizedPost,
                  u: postClient.user.replace(/[<>]/g, ''),
                  e: JSON.stringify({ "t": timestamp }),
                  reply_to: replyToId,
                  post_id: id
                }
              });
              function broadcast(message) {
                const messageStr = typeof message === "string"
                  ? message
                  : JSON.stringify(message);
                let sentCount = 0;
                for (const [clientSocket, client] of clients) {
                  if (clientSocket.readyState === WebSocket.OPEN) {
                    try {
                      clientSocket.send(messageStr);
                      sentCount++;
                    } catch (error) {
                      console.error("Broadcast error for client:", error);
                    }
                  }
                }
              }
              broadcast(postNotification);
            } catch (error) {
              console.log(chalk.red.bold("Post error:", error));
              socket.send(JSON.stringify({
                cmd: "post",
                status: "error",
                message: "Failed to save post",
                ...listener
              }));
            }
            break;
          case "login":
            try {
              if (typeof data !== "object" || data === null) {
                socket.send(JSON.stringify({
                  cmd: "login",
                  status: "error",
                  message: "Invalid data format",
                  ...listener
                }));
                return;
              }
              if (!data.username || !data.password) {
                console.log(chalk.red.bold("Missing credentials:", {
                  username: data.username,
                  password: !!data.password,
                }));
                socket.send(JSON.stringify({
                  cmd: "login",
                  status: "error",
                  message: "Username and password are required",
                  ...listener
                }));
                return;
              }
              crypto.subtle.digest(
                "SHA-256",
                new TextEncoder().encode(data.password),
              ).then((hash) => {
                const hashedPassword = Array.from(new Uint8Array(hash))
                  .map((b) => b.toString(16).padStart(2, "0"))
                  .join("");

                const query =
                  "SELECT * FROM users WHERE user = ? AND password = ?";
                const params = [data.username, hashedPassword];
                const user = db.queryEntries(query, params);
                if (user && user.length > 0) {
                  const userData = user[0];
                  if (userData.banned) {
                    console.error(
                      "Banned user attempted login:",
                      data.username,
                      "Reason:",
                      userData.ban_reason || "No reason provided",
                      "Banned at:",
                      userData.ban_created_at || "Unknown date",
                    );
                    socket.send(JSON.stringify({
                      cmd: "login",
                      status: "error",
                      message: {
                        "message": "ban",
                        "reason": `${userData.ban_reason || "No reason provided"
                          }`,
                        "bannedDate": `${userData.ban_created_at || "Unknown date"
                          }`,
                      },
                      ...listener
                    }));
                    return;
                  }
                  if (userData.token) {
                    clients.set(socket, {
                      socket,
                      authenticated: true,
                      user: data.username,
                    });
                    socket.send(JSON.stringify({
                      cmd: "login",
                      status: "success",
                      token: userData.token,
                      ...listener
                    }));
                    console.log("Login successful for user:", data.username);
                  } else {
                    console.log(
                      chalk.red.bold("Missing token for user:", data.username),
                    );
                    socket.send(JSON.stringify({
                      cmd: "login",
                      status: "error",
                      message: "Invalid user data - missing token",
                      ...listener
                    }));
                  }
                } else {
                  console.log(chalk.red.bold("No user found for credentials"));
                  socket.send(JSON.stringify({
                    cmd: "login",
                    status: "error",
                    message: "Invalid username or password",
                    ...listener
                  }));
                }
              }).catch((error) => {
                console.log(chalk.red.bold("Hashing error:", error));
                socket.send(JSON.stringify({
                  cmd: "login",
                  status: "error",
                  message: "Error processing login",
                  ...listener
                }));
              });
            } catch (dbError) {
              console.log(chalk.red.bold("Login error:", dbError));
              socket.send(JSON.stringify({
                cmd: "login",
                status: "error",
                message: "Database error during login",
                ...listener
              }));
            }
            break;
          case "register":
            const token = crypto.randomUUID();
            try {
              const hashedPassword = crypto.subtle.digest(
                "SHA-256",
                new TextEncoder().encode(data.password),
              )
                .then((hash) =>
                  Array.from(new Uint8Array(hash))
                    .map((b) => b.toString(16).padStart(2, "0"))
                    .join("")
                )
                .then((hashedPassword) => {
                  const stmt = db.prepareQuery(
                    "INSERT INTO users (user, token, permissions, password) VALUES (?, ?, ?, ?)",
                  );
                  const result = stmt.execute([
                    data.user,
                    token,
                    "user",
                    hashedPassword,
                  ]);
                  stmt.finalize();
                  return result;
                })
                .then((result) => {
                  socket.send(JSON.stringify({
                    cmd: "register",
                    status: "success",
                    token: token,
                    ...listener
                  }));
                });
            } catch (e) {
              console.log(chalk.red.bold("Registration error:", e));
              try {
                const existingUsers = db.queryEntries("SELECT * FROM users");
                console.log("Existing users:", existingUsers);
              } catch (queryError) {
                console.log(chalk.red.bold("Query error:", queryError));
              }
              socket.send(JSON.stringify({
                cmd: "register",
                status: "error",
                message: `Registration failed: ${e.message}`,
                ...listener
              }));
            }
            break;
          case "fetch":
            const fetchClient = clients.get(socket);
            try {
              const offset = data.offset || 0;
              const posts = db.queryEntries(
                `SELECT _id, p, u, e, reply_to FROM rtposts ORDER BY json_extract(e, '$.t') DESC LIMIT 10 OFFSET ${offset}`,
              );
              socket.send(JSON.stringify({
                cmd: "fetch",
                status: "success",
                posts: posts,
                ...listener
              }));
            } catch (error) {
              console.log(chalk.red.bold("Fetch error:", error));
              socket.send(JSON.stringify({
                cmd: "fetch",
                status: "error",
                message: "Failed to fetch posts",
                ...listener
              }));
            }
            break;
            case "fetchInd":
            try {
              const id = data.id
                const posts = db.queryEntries(
                `SELECT _id, p, u, e, reply_to FROM rtposts WHERE _id = ?`,
                [id]
                );
              socket.send(JSON.stringify({
                cmd: "fetchInd",
                status: "success",
                post: posts,
                ...listener
              }));
            } catch (error) {
              console.log(chalk.red.bold("Fetch (individual) error:", error));
              socket.send(JSON.stringify({
                cmd: "fetchInd",
                status: "error",
                message: "Failed to fetch posts",
                ...listener
              }));
            }
            break;
          case "purge":
            const purgeClient = clients.get(socket);
            if (
              !purgeClient?.authenticated || purgeClient.user !== "delusions"
            ) {
              socket.send(JSON.stringify({
                cmd: "purge",
                status: "error",
                message: "unauthorized",
                ...listener
              }));
              return;
            }
            try {
              db.query("DELETE FROM rtposts");
              socket.send(JSON.stringify({
                cmd: "purge",
                status: "success",
                ...listener
              }));
            } catch (error) {
              console.log(chalk.red.bold("Purge error:", error));
              socket.send(JSON.stringify({
                cmd: "purge",
                status: "error",
                message: "Failed to purge posts",
                ...listener
              }));
            }
            break;
        }
      } catch (e) {
        console.log(chalk.red.bold("Message handling error:", e));
        socket.send(JSON.stringify({
          status: "error",
          message: "Error processing message",
          ...listener
        }));
      }
    });
    return response;
  },
});
async function handleRegister(req) {
  const data = await req.json();
  try {
    if (!data.user || !data.password) {
      return returndata(
        JSON.stringify({
          status: "error",
          message: "Username and password are required",
        }),
        400,
      );
    }
    const token = crypto.randomUUID();
    const hashedPassword = Array.from(
      new Uint8Array(
        await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(data.password),
        ),
      ),
    ).map((b) => b.toString(16).padStart(2, "0")).join("");
    const stmt = db.prepareQuery(
      "INSERT INTO users (user, token, permissions, password, is_mod) VALUES (?, ?, ?, ?, ?)",
    );
    stmt.execute([data.user, token, "user", hashedPassword, 0]);
    stmt.finalize();
    autoPromote();
    return returndata(
      JSON.stringify({
        status: "success",
        token: token,
      }),
      200,
    );
  } catch (e) {
    console.log(chalk.red.bold("Registration error:", e));
    return returndata(
      JSON.stringify({
        status: "error",
        message: `Registration failed: ${e.message}`,
      }),
      500,
    );
  }
}
async function handleLogin(req) {
  const data = await req.json();
  try {
    if (!data.username || !data.password) {
      return returndata(
        JSON.stringify({
          status: "error",
          message: "Username and password are required",
        }),
        400,
      );
    }
    const hashedPassword = Array.from(
      new Uint8Array(
        await crypto.subtle.digest(
          "SHA-256",
          new TextEncoder().encode(data.password),
        ),
      ),
    ).map((b) => b.toString(16).padStart(2, "0")).join("");
    const user = db.queryEntries(
      "SELECT * FROM users WHERE user = ? AND password = ?",
      [data.username, hashedPassword],
    );
    if (user && user.length > 0) {
      const userData = user[0];
      const userAccess = await checkUserAccess(userData.token);
      if (!userAccess) {
        return returndata(
          JSON.stringify({
            status: "error",
            message: "This account has been banned",
          }),
          403,
        );
      }
      return returndata(
        JSON.stringify({
          status: "success",
          token: userData.token,
        }),
        200,
      );
    }
    return returndata(
      JSON.stringify({
        status: "error",
        message: "Invalid credentials",
      }),
      401,
    );
  } catch (e) {
    return returndata(
      JSON.stringify({
        status: "error",
        message: `Login failed: ${e.message}`,
      }),
      500,
    );
  }
}
async function checkUserAccess(auth, target_user = null) {
  if (!auth) return null;
  const user = db.queryEntries(
    "SELECT * FROM users WHERE token = ?",
    [auth],
  )[0];
  if (!user) return null;
  const banned = db.queryEntries(
    "SELECT * FROM bans WHERE user = ?",
    [user.user],
  )[0];
  if (banned) return null;
  if (target_user) {
    const blocked = db.queryEntries(
      "SELECT * FROM blocked_users WHERE blocker = ? AND blocked = ?",
      [target_user, user.user],
    )[0];
    if (blocked) return null;
  }
  return user;
}
async function handlePost(req) {
  const auth = req.headers.get("Authorization");
  if (!auth) {
    return returndata(
      JSON.stringify({
        status: "error",
        message: "Unauthorized",
      }),
      401,
    );
  }
  const user = db.queryEntries(
    "SELECT * FROM users WHERE token = ?",
    [auth],
  )[0];
  if (!user) {
    return returndata(
      JSON.stringify({
        status: "error",
        message: "Invalid token",
      }),
      401,
    );
  }
  const data = await req.json();
  try {
    const id = crypto.randomUUID();
    const timestamp = Date.now();
    const replyToId = data.replyTo || null;
    const stmt = db.prepareQuery(
      "INSERT INTO posts (id, post, user, created_at, reply_to) VALUES (?, ?, ?, ?, ?)",
    );
    stmt.execute([id, data.post, user.user, timestamp, replyToId]);
    stmt.finalize();
    return returndata(
      JSON.stringify({
        status: "success",
        id: id,
        timestamp: timestamp,
      }),
      200,
    );
  } catch (e) {
    return returndata(
      JSON.stringify({
        status: "error",
        message: "Failed to save post",
      }),
      500,
    );
  }
}
async function handleFetch(req) {
  const auth = req.headers.get("Authorization");
  if (!auth) {
    return returndata(
      JSON.stringify({
        status: "error",
        message: "Unauthorized",
      }),
      401,
    );
  }
  const user = await checkUserAccess(auth);
  if (!user) {
    return returndata(
      JSON.stringify({
        status: "error",
        message: "Invalid token",
      }),
      401,
    );
  }
  const url = new URL(req.url);
  const offset = parseInt(url.searchParams.get("offset") || "0");
  if (isNaN(offset) || offset < 0) {
    return returndata(
      JSON.stringify({
        status: "error",
        message: "Invalid offset parameter",
      }),
      400,
    );
  }
  try {
    const posts = db.queryEntries(
      `SELECT p.post, p.user, p.created_at, p.id, p.reply_to 
       FROM posts p
       INNER JOIN follows f ON p.user = f.following
       WHERE f.follower = ?
       ORDER BY p.created_at DESC 
       LIMIT ? OFFSET ?`,
      [user.user, 10, offset],
    );
    const safePostsArray = Array.isArray(posts) ? posts : [];
    return returndata(
      JSON.stringify({
        status: "success",
        posts: safePostsArray,
      }),
      200,
    );
  } catch (e) {
    console.log(chalk.red.bold("Post fetch error:"), e);
    return returndata(
      JSON.stringify({
        status: "error",
        message: `Failed to fetch posts: ${e.message}`,
      }),
      500,
    );
  }
}
async function handleExplore(req) {
  const url = new URL(req.url);
  const offset = parseInt(url.searchParams.get("offset") || "0");
  if (isNaN(offset) || offset < 0) {
    return returndata(
      JSON.stringify({
        status: "error",
        message: "Invalid offset parameter",
      }),
      400,
    );
  }
  try {
    const posts = db.queryEntries(
      `SELECT p.post, p.user, p.created_at, p.id, p.reply_to 
       FROM posts p
       ORDER BY p.created_at DESC 
       LIMIT ? OFFSET ?`,
      [10, offset],
    );
    const safePostsArray = Array.isArray(posts) ? posts : [];
    return returndata(
      JSON.stringify({
        status: "success",
        posts: safePostsArray,
      }),
      200,
    );
  } catch (e) {
    console.log(chalk.red.bold("Post fetch error:"), e);
    return returndata(
      JSON.stringify({
        status: "error",
        message: `Failed to fetch posts: ${e.message}`,
      }),
      500,
    );
  }
}
async function handleFollows(req) {
  const auth = req.headers.get("Authorization");
  if (!auth) {
    return returndata(
      JSON.stringify({
        status: "error",
        message: "Unauthorized",
      }),
      401,
    );
  }
  const user = db.queryEntries(
    "SELECT * FROM users WHERE token = ?",
    [auth],
  )[0];
  if (!user) {
    return returndata(
      JSON.stringify({
        status: "error",
        message: "Invalid token",
      }),
      401,
    );
  }
  const url = new URL(req.url);
  const username = url.searchParams.get("user");
  try {
    const follows = db.queryEntries(
      "SELECT following FROM follows WHERE follower = ?",
      [username],
    );
    return returndata(
      JSON.stringify({
        status: "success",
        follows: follows.map((f) => f.following),
      }),
      200,
    );
  } catch (e) {
    console.log(e);
    return returndata(
      JSON.stringify({
        status: "error",
        message: "Failed to fetch follows",
      }),
      500,
    );
  }
}
async function handleBlock(req) {
  const auth = req.headers.get("Authorization");
  const user = await checkUserAccess(auth);
  if (!user) {
    return returndata(
      JSON.stringify({
        status: "error",
        message: "Unauthorized",
      }),
      401,
    );
  }
  if (req.method === "POST") {
    const data = await req.json();
    if (!data.user) {
      return returndata(
        JSON.stringify({
          status: "error",
          message: "User to block is required",
        }),
        400,
      );
    }
    try {
      db.execute(
        "INSERT INTO blocked_users (blocker, blocked, created_at) VALUES (?, ?, ?)",
        [user.user, data.user, Date.now()],
      );
      return returndata(
        JSON.stringify({
          status: "success",
          message: "User blocked successfully",
        }),
        200,
      );
    } catch (e) {
      return returndata(
        JSON.stringify({
          status: "error",
          message: "Failed to block user",
        }),
        500,
      );
    }
  } else if (req.method === "DELETE") {
    const url = new URL(req.url);
    const blocked_user = url.searchParams.get("user");
    if (!blocked_user) {
      return returndata(
        JSON.stringify({
          status: "error",
          message: "User parameter is required",
        }),
        400,
      );
    }
    try {
      db.execute(
        "DELETE FROM blocked_users WHERE blocker = ? AND blocked = ?",
        [user.user, blocked_user],
      );
      return returndata(
        JSON.stringify({
          status: "success",
          message: "User unblocked successfully",
        }),
        200,
      );
    } catch (e) {
      return returndata(
        JSON.stringify({
          status: "error",
          message: "Failed to unblock user",
        }),
        500,
      );
    }
  }
}
async function handleBan(req) {
  const auth = req.headers.get("Authorization");
  const user = await checkUserAccess(auth);
  if (!user || !user.is_mod) {
    return returndata(
      JSON.stringify({
        status: "error",
        message: "Unauthorized - Admin access required",
      }),
      401,
    );
  }
  if (req.method === "POST") {
    const data = await req.json();
    if (!data.user) {
      return returndata(
        JSON.stringify({
          status: "error",
          message: "User to ban is required",
        }),
        400,
      );
    }
    try {
      db.execute(
        "INSERT INTO bans (user, banned_by, reason, created_at) VALUES (?, ?, ?, ?)",
        [data.user, user.user, data.reason || null, Date.now()],
      );
      return returndata(
        JSON.stringify({
          status: "success",
          message: "User banned successfully",
        }),
        200,
      );
    } catch (e) {
      return returndata(
        JSON.stringify({
          status: "error",
          message: "Failed to ban user",
        }),
        500,
      );
    }
  } else if (req.method === "DELETE") {
    const url = new URL(req.url);
    const banned_user = url.searchParams.get("user");

    if (!banned_user) {
      return returndata(
        JSON.stringify({
          status: "error",
          message: "User parameter is required",
        }),
        400,
      );
    }
    try {
      db.execute(
        "DELETE FROM bans WHERE user = ?",
        [banned_user],
      );
      return returndata(
        JSON.stringify({
          status: "success",
          message: "User unbanned successfully",
        }),
        200,
      );
    } catch (e) {
      return returndata(
        JSON.stringify({
          status: "error",
          message: "Failed to unban user",
        }),
        500,
      );
    }
  }
}
async function handleUserPosts(req) {
  const auth = req.headers.get("Authorization");
  if (!auth) {
    return returndata(
      JSON.stringify({
        status: "error",
        message: "Unauthorized",
      }),
      401,
    );
  }
  const user = db.queryEntries(
    "SELECT * FROM users WHERE token = ?",
    [auth],
  )[0];
  if (!user) {
    return returndata(
      JSON.stringify({
        status: "error",
        message: "Invalid token",
      }),
      401,
    );
  }
  const url = new URL(req.url);
  const username = url.searchParams.get("user");
  const offset = parseInt(url.searchParams.get("offset") || "0");
  try {
    const posts = db.queryEntries(
      "SELECT post, user, created_at, id, reply_to FROM posts WHERE user = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
      [username, 10, offset],
    );
    return returndata(
      JSON.stringify({
        status: "success",
        posts: posts,
      }),
      200,
    );
  } catch (e) {
    return returndata(
      JSON.stringify({
        status: "error",
        message: "Failed to fetch user posts",
      }),
      500,
    );
  }
}
async function handleFollow(req) {
  const auth = req.headers.get("Authorization");
  const user = await checkUserAccess(auth);
  if (!user) {
    return returndata(
      JSON.stringify({
        status: "error",
        message: "Unauthorized",
      }),
      401,
    );
  }
  if (req.method === "POST") {
    const data = await req.json();
    if (!data.user) {
      return returndata(
        JSON.stringify({
          status: "error",
          message: "User to follow is required",
        }),
        400,
      );
    }
    try {
      db.execute(
        "INSERT INTO follows (follower, following, created_at) VALUES (?, ?, ?)",
        [user.user, data.user, Date.now()],
      );
      return returndata(
        JSON.stringify({
          status: "success",
          message: "User followed successfully",
        }),
        200,
      );
    } catch (e) {
      return returndata(
        JSON.stringify({
          status: "error",
          message: "Failed to follow user",
        }),
        500,
      );
    }
  }
}
async function handleSearch(req) {
  const auth = req.headers.get("Authorization");
  const user = await checkUserAccess(auth);
  if (!user) {
    return returndata(
      JSON.stringify({
        status: "error",
        message: "Unauthorized",
      }),
      401,
    );
  }
  const url = new URL(req.url);
  const query = url.searchParams.get("q");
  if (!query) {
    return returndata(
      JSON.stringify({
        status: "error",
        message: "Search query is required",
      }),
      400,
    );
  }
  try {
    const posts = db.queryEntries(
      "SELECT post, user, created_at, id, reply_to FROM posts WHERE post LIKE ? OR user LIKE ? ORDER BY created_at DESC LIMIT 20",
      [`%${query}%`, `%${query}%`],
    );
    return returndata(
      JSON.stringify({
        status: "success",
        posts: posts,
      }),
      200,
    );
  } catch (e) {
    return returndata(
      JSON.stringify({
        status: "error",
        message: "Failed to search posts",
      }),
      500,
    );
  }
}
async function handlePromote(req) {
  const auth = req.headers.get("Authorization");
  const user = await checkUserAccess(auth);
  if (!user || !user.is_mod) {
    return returndata(
      JSON.stringify({ status: "error", message: "Unauthorized" }),
      401,
    );
  }
  if (req.method === "POST") {
    const data = await req.json();
    if (!data.user) {
      return returndata(
        JSON.stringify({
          status: "error",
          message: "User to promote is required",
        }),
        400,
      );
    }
    try {
      db.execute("UPDATE users SET is_mod = 1 WHERE user = ?", [data.user]);
      return returndata(
        JSON.stringify({
          status: "success",
          message: "User promoted successfully",
        }),
        200,
      );
    } catch (e) {
      return returndata(
        JSON.stringify({ status: "error", message: "Failed to promote user" }),
        500,
      );
    }
  }
}
async function handleComment(req) {
  const auth = req.headers.get("Authorization");
  const user = await checkUserAccess(auth);
  if (!user) {
    return returndata(
      JSON.stringify({ status: "error", message: "Unauthorized" }),
      401,
    );
  }
  if (req.method === "POST") {
    const data = await req.json();
    if (!data.comment) {
      return returndata(
        JSON.stringify({
          status: "error",
          message: "Comment text is required",
        }),
        400,
      );
    }
    try {
      const commentId = crypto.randomUUID();
      db.execute(
        "INSERT INTO comments (id, post_id, user, comment, created_at) VALUES (?, ?, ?, ?, ?)",
        [commentId, data.post_id, user.user, data.comment, Date.now()],
      );
      return returndata(
        JSON.stringify({
          status: "success",
          message: "Comment added successfully",
        }),
        200,
      );
    } catch (e) {
      return returndata(
        JSON.stringify({ status: "error", message: "Failed to add comment" }),
        500,
      );
    }
  }
  if (req.method === "GET") {
    const url = new URL(req.url);
    const postId = url.searchParams.get("post_id");
    if (!postId) {
      return returndata(
        JSON.stringify({ status: "error", message: "Post ID is required" }),
        400,
      );
    }
    try {
      const comments = db.queryEntries(
        "SELECT user, comment, created_at FROM comments WHERE post_id = ? ORDER BY created_at DESC",
        [postId],
      );
      return returndata(
        JSON.stringify({ status: "success", comments: comments }),
        200,
      );
    } catch (e) {
      return returndata(
        JSON.stringify({
          status: "error",
          message: "Failed to fetch comments",
        }),
        500,
      );
    }
  }
}
Deno.serve({ port: 2387 }, async (req) => {
  const url = new URL(req.url);
  const path = url.pathname;
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
      },
    });
  }
  switch (path) {
    case "/post":
      return await handlePost(req);
    case "/posts":
      return await handleFetch(req);
    case "/userposts":
      return await handleUserPosts(req);
    case "/register":
      return await handleRegister(req);
    case "/login":
      return await handleLogin(req);
    case "/follows":
      return await handleFollows(req);
    case "/block":
      return await handleBlock(req);
    case "/ban":
      return await handleBan(req);
    case "/follow":
      return await handleFollow(req);
    case "/search":
      return await handleSearch(req);
    case "/promote":
      return await handlePromote(req);
    case "/comment":
      return await handleComment(req);
    case "/explore":
      return await handleExplore(req);
    default:
      return new Response("Not Found", { status: 404 });
  }
});
