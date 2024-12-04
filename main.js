import { DB } from "https://deno.land/x/sqlite/mod.ts";
const db = new DB("mlinkTest.db");
console.log("HTTP: port 8000 | WS: port 3000")
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
db.execute(`
  CREATE TABLE IF NOT EXISTS rtposts (
    _id TEXT PRIMARY KEY,
    p TEXT NOT NULL,
    u TEXT NOT NULL,
    t TEXT NOT NULL,
    reply_to TEXT,
    author TEXT NOT NULL,
    post_origin TEXT NOT NULL
  )
`);
Deno.serve({port: 3000, handler: (req) => {
  if (req.headers.get("upgrade") != "websocket") {
    return new Response(null, { status: 501 });
  }
  const clients = new Map();
  function broadcast(message) {
    for (const [socket, client] of clients) {
      if (client.authenticated) {
        try {
          socket.send(message);
        } catch (error) {
          console.error("Error broadcasting to client:", error);
        }
      }
    }
  }
  const { socket, response } = Deno.upgradeWebSocket(req);
  socket.addEventListener("open", () => {
    clients.set(socket, { socket, authenticated: false });
    console.log("client connected");
    console.log(clients);
  });
  socket.addEventListener("close", () => {
    clients.delete(socket);
    console.log("client disconnected");
    console.log(clients);
  });
  socket.addEventListener("message", (event) => {
    try {
      const data = JSON.parse(event.data);
      switch (data.cmd) {
        case "ping":
          socket.send("pong");
          break;
          case "login":
          try {
            if (typeof data !== "object" || data === null) {
              console.error("Invalid data format received");
              socket.send(JSON.stringify({
                cmd: "login",
                status: "error",
                message: "Invalid data format",
              }));
              return;
            }
            if (!data.username || !data.password) {
              console.error("Missing credentials:", {
                username: data.username,
                password: !!data.password,
              });
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
                  console.error("Banned user attempted login:", data.username);
                  socket.send(JSON.stringify({
                    cmd: "login",
                    status: "error",
                    message: "This account has been banned",
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
                    payload: json.stringify({token: userData.token})
                  }));
                  console.log("Login successful for user:", data.username);
                } else {
                  console.error("Missing token for user:", data.username);
                  socket.send(JSON.stringify({
                    cmd: "login",
                    status: "error",
                    message: "Invalid user data - missing token",
                  }));
                }
              } else {
                console.error("No user found for credentials");
                socket.send(JSON.stringify({
                  cmd: "login",
                  status: "error",
                  message: "Invalid username or password",
                }));
              }
            }).catch((error) => {
              console.error("Hashing error:", error);
              socket.send(JSON.stringify({
                cmd: "login",
                status: "error",
                message: "Error processing login",
              }));
            });
          } catch (dbError) {
            console.error("Login error:", dbError);
            socket.send(JSON.stringify({
              cmd: "login",
              status: "error",
              message: "Database error during login",
            }));
          }
          break;
        case "post_home":
          console.log("Post attempt:", data);
          const postClient = clients.get(socket);
          console.log("Client state:", postClient);
          if (!postClient?.authenticated) {
            console.log("Unauthorized post attempt");
            socket.send(JSON.stringify({
              cmd: "post_home", 
              status: "error",
              message: "unauthorized",
            }));
            return;
          }
          if (!data.p || typeof data.p !== "string") {
            console.log("Invalid post data:", data);
            socket.send(JSON.stringify({
              cmd: "post",
              status: "error", 
              message: "invalid post data",
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
              `INSERT INTO rtposts _id, p, u, e, reply_to, author, post_origin, isDeleted, emojis, pinned, post_id, attachments, reactions, type VALUES ${id}, ${data.p}, ${postClient.u}, {"t": "${timestamp}"}, ${replyToId}, ${json.stringify({_id: postClient.user, pfp_data: "24", avatar: "null", avatar_color: "000000", flags: "0", uuid: "00000000-0000-0000-0000-000000000000"})}, "home", "false", "[]", "false", ${id}, "[]", "[]", "1"`,
            );
            stmt.finalize();
            const postNotification = JSON.stringify({
              cmd: "global",
              post: {
                _id: id,
                p: data.p,
                u: postClient.user,
                e: JSON.stringify({"t": timestamp}),
                reply_to: replyToId,
                post_origin: "home",
                author: json.stringify({_id: postClient.user, pfp_data: "24", avatar: "null", avatar_color: "000000", flags: "0", uuid: "00000000-0000-0000-0000-000000000000"}),
                isDeleted: "false",
                emojis: [],
                pinned: false,
                post_id: id,
                attachments: [],
                reactions: [],
                type: "1"
              }
            });
            for (const [clientSocket, clientData] of clients) {
              if (clientData.authenticated) {
                clientSocket.send(postNotification);
              }
            }
            socket.send(JSON.stringify({
              _id: id,
                p: data.p,
                u: postClient.user,
                e: JSON.stringify({"t": timestamp}),
                reply_to: replyToId,
                post_origin: "home",
                author: json.stringify({_id: postClient.user, pfp_data: "24", avatar: "null", avatar_color: "000000", flags: "0", uuid: "00000000-0000-0000-0000-000000000000"}),
                isDeleted: "false",
                emojis: [],
                pinned: false,
                post_id: id,
                attachments: [],
                reactions: [],
                type: "1"
            }));
            console.log("Post successful:", {
              id: id,
              user: postClient.user,
              post: data.post,
              timestamp: timestamp,
              reply_to: replyToId,
            });
          } catch (error) {
            console.error("Post error:", error);
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
              console.error("Invalid data format received");
              socket.send(JSON.stringify({
                cmd: "login",
                status: "error",
                message: "Invalid data format",
              }));
              return;
            }
            if (!data.username || !data.password) {
              console.error("Missing credentials:", {
                username: data.username,
                password: !!data.password,
              });
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
                  console.error("Banned user attempted login:", data.username);
                  socket.send(JSON.stringify({
                    cmd: "login",
                    status: "error",
                    message: "This account has been banned",
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
                  console.error("Missing token for user:", data.username);
                  socket.send(JSON.stringify({
                    cmd: "login",
                    status: "error",
                    message: "Invalid user data - missing token",
                  }));
                }
              } else {
                console.error("No user found for credentials");
                socket.send(JSON.stringify({
                  cmd: "login",
                  status: "error",
                  message: "Invalid username or password",
                }));
              }
            }).catch((error) => {
              console.error("Hashing error:", error);
              socket.send(JSON.stringify({
                cmd: "login",
                status: "error",
                message: "Error processing login",
              }));
            });
          } catch (dbError) {
            console.error("Login error:", dbError);
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
            console.error("Registration error:", e);
            try {
              const existingUsers = db.queryEntries("SELECT * FROM users");
              console.log("Existing users:", existingUsers);
            } catch (queryError) {
              console.error("Query error:", queryError);
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
          console.log("Client state for fetch:", fetchClient);
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
              `SELECT _id, p, u, e, reply_to, author, post_origin, isDeleted, emojis, pinned, post_id, attachments, reactions, type FROM rtposts ORDER BY t.e DESC LIMIT 10 OFFSET 0`,
            );
            console.log("Fetched posts:", posts);
            socket.send(JSON.stringify({
              cmd: "fetch",
              status: "success",
              posts: posts,
            }));
          } catch (error) {
            console.error("Fetch error:", error);
            socket.send(JSON.stringify({
              cmd: "fetch",
              status: "error",
              message: "Failed to fetch posts",
            }));
          }
          break;
      }
    } catch (e) {
      console.error("Message handling error:", e);
      socket.send(JSON.stringify({
        status: "error",
        message: "Error processing message",
      }));
    }
  });
  return response;
}});
async function handleRegister(req) {
  const data = await req.json();
  try {
    if (!data.user || !data.password) {
      return new Response(
        JSON.stringify({
          status: "error",
          message: "Username and password are required",
        }),
        {
          status: 400,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
          },
        },
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
      "INSERT INTO users (user, token, permissions, password) VALUES (?, ?, ?, ?)",
    );
    stmt.execute([data.user, token, "user", hashedPassword]);
    stmt.finalize();
    return new Response(
      JSON.stringify({
        status: "success",
        token: token,
      }),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      },
    );
  } catch (e) {
    console.error("Registration error:", e);
    return new Response(
      JSON.stringify({
        status: "error",
        message: `Registration failed: ${e.message}`,
      }),
      {
        status: 500,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      },
    );
  }
}
async function handleLogin(req) {
  const data = await req.json();
  try {
    if (!data.username || !data.password) {
      return new Response(
        JSON.stringify({
          status: "error",
          message: "Username and password are required",
        }),
        {
          status: 400,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
          },
        },
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
      if (userData.banned) {
        return new Response(
          JSON.stringify({
            status: "error",
            message: "This account has been banned",
          }),
          {
            status: 403,
            headers: {
              "Content-Type": "application/json",
              "Access-Control-Allow-Origin": "*",
              "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
              "Access-Control-Allow-Headers": "Content-Type, Authorization",
            },
          },
        );
      }
      return new Response(
        JSON.stringify({
          status: "success",
          token: userData.token,
        }),
        {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
          },
        },
      );
    }
    return new Response(
      JSON.stringify({
        status: "error",
        message: "Invalid credentials",
      }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      },
    );
  } catch (e) {
    return new Response(
      JSON.stringify({
        status: "error",
        message: `Login failed: ${e.message}`,
      }),
      {
        status: 500,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      },
    );
  }
}
async function handlePost(req) {
  const auth = req.headers.get("Authorization");
  if (!auth) {
    return new Response(
      JSON.stringify({
        status: "error",
        message: "Unauthorized",
      }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      },
    );
  }
  const user = db.queryEntries(
    "SELECT * FROM users WHERE token = ?",
    [auth],
  )[0];
  if (!user) {
    return new Response(
      JSON.stringify({
        status: "error",
        message: "Invalid token",
      }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      },
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
    return new Response(
      JSON.stringify({
        status: "success",
        id: id,
        timestamp: timestamp,
      }),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      },
    );
  } catch (e) {
    return new Response(
      JSON.stringify({
        status: "error",
        message: "Failed to save post",
      }),
      {
        status: 500,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      },
    );
  }
}
async function handleFetch(req) {
  const auth = req.headers.get("Authorization");
  if (!auth) {
    return new Response(
      JSON.stringify({
        status: "error",
        message: "Unauthorized",
      }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      },
    );
  }
  const user = db.queryEntries(
    "SELECT * FROM users WHERE token = ?",
    [auth],
  )[0];
  if (!user) {
    return new Response(
      JSON.stringify({
        status: "error",
        message: "Invalid token",
      }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      },
    );
  }
  const url = new URL(req.url);
  const username = url.searchParams.get("username");
  const offset = parseInt(url.searchParams.get("offset") || "0");
  try {
    const posts = db.queryEntries(
      `SELECT post, user, created_at, id, reply_to 
       FROM posts 
       WHERE user = ? 
       OR user IN (
         SELECT followed 
         FROM follows 
         WHERE follower = ?
       )
       ORDER BY created_at DESC 
       LIMIT ? OFFSET ?`,
      [username, username, 10, offset],
    );
    return new Response(
      JSON.stringify({
        status: "success",
        posts: posts,
      }),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      },
    );
  } catch (e) {
    return new Response(
      JSON.stringify({
        status: "error",
        message: "Failed to fetch posts",
      }),
      {
        status: 500,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      },
    );
  }
}
async function handleFollows(req) {
  const auth = req.headers.get("Authorization");
  if (!auth) {
    return new Response(
      JSON.stringify({
        status: "error",
        message: "Unauthorized",
      }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      },
    );
  }
  const user = db.queryEntries(
    "SELECT * FROM users WHERE token = ?",
    [auth],
  )[0];
  if (!user) {
    return new Response(
      JSON.stringify({
        status: "error",
        message: "Invalid token",
      }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      },
    );
  }
  const url = new URL(req.url);
  const username = url.searchParams.get("user");
  try {
    const follows = db.queryEntries(
      "SELECT followed FROM follows WHERE follower = ?",
      [username],
    );
    return new Response(
      JSON.stringify({
        status: "success",
        follows: follows.map((f) => f.followed),
      }),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      },
    );
  } catch (e) {
    console.log(e);
    return new Response(
      JSON.stringify({
        status: "error",
        message: "Failed to fetch follows",
      }),
      {
        status: 500,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      },
    );
  }
}
async function handleUserPosts(req) {
  const auth = req.headers.get("Authorization");
  if (!auth) {
    return new Response(
      JSON.stringify({
        status: "error",
        message: "Unauthorized",
      }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      },
    );
  }
  const user = db.queryEntries(
    "SELECT * FROM users WHERE token = ?",
    [auth],
  )[0];
  if (!user) {
    return new Response(
      JSON.stringify({
        status: "error",
        message: "Invalid token",
      }),
      {
        status: 401,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      },
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
    return new Response(
      JSON.stringify({
        status: "success",
        posts: posts,
      }),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      },
    );
  } catch (e) {
    return new Response(
      JSON.stringify({
        status: "error",
        message: "Failed to fetch user posts",
      }),
      {
        status: 500,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      },
    );
  }
}
Deno.serve((req) => {
  if (req.method === "OPTIONS") {
    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Authorization",
      },
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
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
          },
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
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
          },
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
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
          },
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
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
          },
        });
      }
      return handleFetch(req);
    case "/follows":
      if (req.method !== "GET") {
        return new Response(null, {
          status: 405,
          headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
          },
        });
      }
      return handleFollows(req);
    case "/userposts":
      if (req.method !== "GET") {
        return new Response(null, {
          status: 405,
          headers: {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
          },
        });
      }
      return handleUserPosts(req);
    default:
      return new Response(null, {
        status: 404,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
        },
      });
  }
});
