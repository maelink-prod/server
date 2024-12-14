// deno-lint-ignore-file
console.log(`Dependencies: Chalk (npm:chalk), Octokit REST (npm:@octokit/rest)
Install with "deno install <package_name>"`);
import { DB } from "https://deno.land/x/sqlite@v3.9.1/mod.ts";
import { Octokit } from "npm:@octokit/rest";
import chalk from "npm:chalk";
console.log(chalk.blue(`Server is starting...`));
const db = new DB("main.db");
const clients = new Map();
const octokit = new Octokit();
const current = "token login finally (beta v2.4.0)";
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
async function commit(owner, repo, path, branch = "main") {
  try {
    const { data } = await octokit.repos.listCommits({
      owner,
      repo,
      path,
      per_page: 1,
      sha: branch,
    });
    const commitSha = data[0].sha.substring(0, 7);
    const commitName = data[0].commit.message;
    return { sha: commitSha, name: commitName };
  } catch (error) {
    console.log(chalk.red.bold("Error fetching commit:", error));
    throw error;
  }
}
console.log(
  chalk.green.bold(
    `maelink server BETA (${
      (await commit(
        "delusionsGH",
        "maelink",
        "main.js",
      )).sha
    } - ${
      (await commit(
        "delusionsGH",
        "maelink",
        "main.js",
      )).name
    })`,
  ),
);
if ((await commit("delusionsGH", "maelink", "main.js")).name !== current) {
  console.log(chalk.red.bold(`WARNING: Server version is outdated!
Please update to the latest version (${
    (await commit("delusionsGH", "maelink", "main.js")).sha
  })`));
}
console.log(chalk.redBright.bold(`
DISCLAIMER: This server is a public beta, it may be unstable or crash!
I will fix as much as I can but you are on your own if I can't reproduce an error.`));
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
    author TEXT NOT NULL,
    post_origin TEXT NOT NULL,
    isDeleted TEXT NOT NULL,
    emojis TEXT NOT NULL,
    pinned TEXT NOT NULL,
    post_id TEXT NOT NULL,
    attachments TEXT NOT NULL,
    reactions TEXT NOT NULL,
    type INTEGER NOT NULL
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
        console.log("Clients Map size changed:", {
          previous: lastClientsSize,
          current: clients.size,
          timestamp: new Date().toISOString(),
        });
        lastClientsSize = clients.size;
      }
    }, 1000);
    socket.addEventListener("open", () => {
      console.log("New connection established");
      console.log(`Total clients before adding: ${clients.size}`);
      clients.set(socket, {
        authenticated: false,
        user: null,
      });
      console.log(`Total clients after adding: ${clients.size}`);
    });
    socket.addEventListener("close", () => {
      console.log("Client disconnected");
      console.log(`Total clients before removal: ${clients.size}`);
      clients.delete(socket);
      console.log(`Total clients after removal: ${clients.size}`);
    });
    socket.addEventListener("message", (event) => {
      try {
        const data = JSON.parse(event.data);
        switch (data.cmd) {
          case "login":
            try {
              console.log(chalk.blue.bold("Attempting login..."));
              if (typeof data !== "object" || data === null) {
                console.log(chalk.red.bold("Invalid data format received"));
                socket.send(JSON.stringify({
                  cmd: "login", 
                  status: "error",
                  message: "Invalid data format"
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
                      message: "This account has been banned"
                    }));
                    return;
                  }
                  console.log(`User ${userData.user} authenticated via token`);
                  console.log("Current clients map size:", clients.size);
                  clients.set(socket, {
                    authenticated: true,
                    user: userData.user
                  });
                  console.log("Updated client state:", clients.get(socket));

                  socket.send(JSON.stringify({
                    cmd: "login",
                    status: "success",
                    payload: JSON.stringify({ token: userData.token })
                  }));
                  console.log("Token login successful for user:", userData.user);
                  return;
                } else {
                  console.log(chalk.red.bold("Invalid token login attempt"));
                  socket.send(JSON.stringify({
                    cmd: "login",
                    status: "error",
                    message: "Invalid token"
                  }));
                  return;
                }
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
                    );
                    socket.send(JSON.stringify({
                      cmd: "login",
                      status: "error",
                      message: "This account has been banned",
                    }));
                    return;
                  }
                  if (userData.token) {
                    if (user && user.length > 0) {
                      console.log(`User ${data.username} authenticated`);
                      console.log("Current clients map size:", clients.size);
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
                    }));
                  }
                } else {
                  console.log(
                    chalk.red.bold("User doesn't exist/Invalid credentials!"),
                  );
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
                }));
              });
            } catch (dbError) {
              console.log(chalk.red.bold("Login error:", dbError));
              socket.send(JSON.stringify({
                cmd: "login",
                status: "error",
                message: "Database error during login",
              }));
            }
            break;
          case "post":
            console.log("Post attempt:", data);
            const postClient = clients.get(socket);
            console.log("Client state:", postClient);
            if (!postClient?.authenticated) {
              console.log("Unauthorized post attempt");
              socket.send(JSON.stringify({
                cmd: "post_home",
                status: "error",
                message: "Unauthorized",
              }));
              return;
            }
            if (!data.p || typeof data.p !== "string") {
              console.log("Invalid post data:", data);
              socket.send(JSON.stringify({
                cmd: "post",
                status: "error",
                message: "Invalid post data",
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
                  }));
                  return;
                }
              }
              const timestamp = Date.now();
              const id = crypto.randomUUID();
              const stmt = db.prepareQuery(
                "INSERT INTO rtposts (_id, p, u, e, reply_to, author, post_origin, isDeleted, emojis, pinned, post_id, attachments, reactions, type) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
              );
              stmt.execute([
                id,
                data.p,
                postClient.user,
                JSON.stringify({ t: timestamp }),
                replyToId,
                JSON.stringify({
                  _id: postClient.user,
                  pfp_data: "24",
                  avatar: "null",
                  avatar_color: "000000",
                  flags: "0",
                  uuid: "00000000-0000-0000-0000-000000000000",
                }),
                "home",
                "false",
                "[]",
                "false",
                id,
                "[]",
                "[]",
                "1",
              ]);
              stmt.finalize();
              const postNotification = JSON.stringify({
                post: {
                  _id: id,
                  p: data.p,
                  u: postClient.user,
                  e: JSON.stringify({ "t": timestamp }),
                  reply_to: replyToId,
                  post_origin: "home",
                  author: JSON.stringify({
                    _id: postClient.user,
                    pfp_data: "24",
                    avatar: "null",
                    avatar_color: "000000",
                    flags: "0",
                    uuid: "00000000-0000-0000-0000-000000000000",
                  }),
                  isDeleted: "false",
                  emojis: [],
                  pinned: false,
                  post_id: id,
                  attachments: [],
                  reactions: [],
                  type: "1",
                },
              });
              function broadcast(message) {
                const messageStr = typeof message === "string"
                  ? message
                  : JSON.stringify(message);
                console.log(`Broadcasting to ${clients.size} total clients`);
                let sentCount = 0;
                let authenticatedCount = 0;

                clients.forEach((clientData, clientSocket) => {
                  console.log("Checking client:", {
                    user: clientData.user,
                    authenticated: clientData.authenticated,
                    readyState: clientSocket.readyState,
                    isOpen: clientSocket.readyState === WebSocket.OPEN,
                  });

                  if (clientData.authenticated) {
                    authenticatedCount++;
                  }

                  if (
                    clientData.authenticated &&
                    clientSocket.readyState === WebSocket.OPEN
                  ) {
                    try {
                      clientSocket.send(messageStr);
                      sentCount++;
                    } catch (error) {
                      console.error(
                        "Broadcast error for user:",
                        clientData.user,
                        error,
                      );
                    }
                  }
                });

                console.log(`Authentication summary:
                    Total clients: ${clients.size}
                    Authenticated clients: ${authenticatedCount}
                    Successfully sent to: ${sentCount}
                `);
              }
              broadcast(postNotification);
              socket.send(JSON.stringify({
                _id: id,
                p: data.p,
                u: postClient.user,
                e: JSON.stringify({ "t": timestamp }),
                reply_to: replyToId,
                post_origin: "home",
                author: JSON.stringify({
                  _id: postClient.user,
                  pfp_data: "24",
                  avatar: "null",
                  avatar_color: "000000",
                  flags: "0",
                  uuid: "00000000-0000-0000-0000-000000000000",
                }),
                isDeleted: "false",
                emojis: [],
                pinned: false,
                post_id: id,
                attachments: [],
                reactions: [],
                type: "1",
              }));
              console.log("Post successful:", {
                id: id,
                user: postClient.user,
                post: data.p,
                timestamp: timestamp,
                reply_to: replyToId,
              });
            } catch (error) {
              console.log(chalk.red.bold("Post error:", error));
              socket.send(JSON.stringify({
                cmd: "post",
                status: "error",
                message: "Failed to save post",
              }));
            }
            break;
          case "login":
            try {
              if (typeof data !== "object" || data === null) {
                console.log(chalk.red.bold("Invalid data format received"));
                socket.send(JSON.stringify({
                  cmd: "login",
                  status: "error",
                  message: "Invalid data format",
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
                        "reason": `${
                          userData.ban_reason || "No reason provided"
                        }`,
                        "bannedDate": `${
                          userData.ban_created_at || "Unknown date"
                        }`,
                      },
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
                    }));
                  }
                } else {
                  console.log(chalk.red.bold("No user found for credentials"));
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
                }));
              });
            } catch (dbError) {
              console.log(chalk.red.bold("Login error:", dbError));
              socket.send(JSON.stringify({
                cmd: "login",
                status: "error",
                message: "Database error during login",
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
              }));
            }
            break;
          case "fetch":
            console.log("Fetch attempt:", data);
            const fetchClient = clients.get(socket);
            if (!fetchClient?.authenticated) {
              console.log("Unauthorized fetch attempt");
              socket.send(JSON.stringify({
                cmd: "fetch",
                status: "error",
                message: "unauthorized",
              }));
              return;
            }
            try {
              const offset = data.offset || 0;
              console.log(
                "Fetching posts with offset:",
                offset,
              );
              const posts = db.queryEntries(
                `SELECT _id, p, u, e, reply_to, author, post_origin, isDeleted, emojis, pinned, post_id, attachments, reactions, type FROM rtposts ORDER BY json_extract(e, '$.t') DESC LIMIT 10 OFFSET ${offset}`,
              );
              socket.send(JSON.stringify({
                cmd: "fetch",
                status: "success",
                posts: posts,
              }));
            } catch (error) {
              console.log(chalk.red.bold("Fetch error:", error));
              socket.send(JSON.stringify({
                cmd: "fetch",
                status: "error",
                message: "Failed to fetch posts",
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
              }));
              return;
            }
            try {
              db.query("DELETE FROM rtposts");
              socket.send(JSON.stringify({
                cmd: "purge",
                status: "success",
              }));
            } catch (error) {
              console.log(chalk.red.bold("Purge error:", error));
              socket.send(JSON.stringify({
                cmd: "purge",
                status: "error",
                message: "Failed to purge posts",
              }));
            }
            break;
        }
      } catch (e) {
        console.log(chalk.red.bold("Message handling error:", e));
        socket.send(JSON.stringify({
          status: "error",
          message: "Error processing message",
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
    default:
      return new Response("Not Found", { status: 404 });
  }
});
