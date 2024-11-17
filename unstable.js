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
console.log("Users table schema:");
const schema = db.queryEntries(
  "SELECT sql FROM sqlite_master WHERE type='table' AND name='users'",
);
console.log(schema);
console.log("Current users in users table:");
const users = db.queryEntries("SELECT * FROM users");
console.log(users);
console.log("Posts table schema:");
const schemap = db.queryEntries(
  "SELECT sql FROM sqlite_master WHERE type='table' AND name='posts'",
);
console.log(schemap);
console.log("Current posts in posts table:");
const posts = db.queryEntries("SELECT * FROM posts");
console.log(posts);
Deno.serve((req) => {
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
        case "stop":
          const client = clients.get(socket);
          if (!client?.authenticated) {
            socket.send(
              JSON.stringify({ status: "error", message: "unauthorized" }),
            );
            return;
          }
          socket.send("stopping");
          Deno.exit();
          break;

        case "drop":
          const dropClient = clients.get(socket);
          if (!dropClient?.authenticated) {
            socket.send(
              JSON.stringify({ status: "error", message: "unauthorized" }),
            );
            return;
          }
          socket.send("dropping.");
          db.execute(`DROP TABLE IF EXISTS posts`);
          db.execute(`
            CREATE TABLE IF NOT EXISTS posts (
              id TEXT PRIMARY KEY,
              post TEXT NOT NULL,
              user TEXT NOT NULL,
              created_at INTEGER NOT NULL
            )
          `);
          break;
        case "post":
          console.log("Post attempt:", data);
          const postClient = clients.get(socket);
          console.log("Client state:", postClient);
          if (!postClient?.authenticated) {
            console.log("Unauthorized post attempt");
            socket.send(JSON.stringify({
              cmd: "post",
              status: "error",
              message: "unauthorized",
            }));
            return;
          }
          if (!data.post || typeof data.post !== "string") {
            console.log("Invalid post data:", data);
            socket.send(JSON.stringify({
              cmd: "post",
              status: "error",
              message: "invalid post data",
            }));
            return;
          }
          try {
            const timestamp = Math.floor(Date.now() / 1000);
            const id = crypto.randomUUID();
            const stmt = db.prepareQuery(
              "INSERT INTO posts (id, post, user, created_at) VALUES (?, ?, ?, ?)",
            );
            const result = stmt.execute([
              id,
              data.post,
              postClient.user,
              timestamp,
            ]);
            stmt.finalize();
            socket.send(JSON.stringify({
              cmd: "post",
              status: "success",
              id: id,
              timestamp: timestamp,
            }));
            console.log("Post successful:", {
              id: id,
              user: postClient.user,
              post: data.post,
              timestamp: timestamp,
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
            const username = data.username;
            console.log(
              "Fetching posts for user:",
              username,
              "with offset:",
              offset,
            );
            const posts = db.queryEntries(
              "SELECT post, user, created_at, id FROM posts WHERE user = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
              [username, 10, offset],
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
        case "postdata":
          console.log("Post data fetch attempt:", data);
          const postDataClient = clients.get(socket);
          console.log("Client state for post data fetch:", postDataClient);
          if (!postDataClient?.authenticated) {
            console.log("Unauthorized post data fetch attempt");
            socket.send(JSON.stringify({
              cmd: "postdata",
              status: "error",
              message: "unauthorized",
            }));
            return;
          }
          if (!data.id || typeof data.id !== "string") {
            console.log("Invalid post ID:", data);
            socket.send(JSON.stringify({
              cmd: "postdata",
              status: "error",
              message: "invalid post ID",
            }));
            return;
          }
          try {
            const post = db.queryEntries(
              "SELECT post, user, created_at, id FROM posts WHERE id = ?",
              [data.id],
            );
            if (post && post.length > 0) {
              console.log("Found post:", post[0]);
              socket.send(JSON.stringify({
                cmd: "postdata",
                status: "success",
                post: post[0],
              }));
            } else {
              console.log("No post found with ID:", data.id);
              socket.send(JSON.stringify({
                cmd: "postdata",
                status: "error",
                message: "post not found",
              }));
            }
          } catch (error) {
            console.error("Post data fetch error:", error);
            socket.send(JSON.stringify({
              cmd: "postdata",
              status: "error",
              message: "Failed to fetch post data",
            }));
          }
          break;
case "follow":
  console.log("Follow attempt:", data);
  const followClient = clients.get(socket);
  if (!followClient?.authenticated) {
    console.log("Unauthorized follow attempt");
    socket.send(JSON.stringify({
      cmd: "follow",
      status: "error", 
      message: "unauthorized"
    }));
    return;
  }
  if (!data.user || typeof data.user !== "string") {
    console.log("Invalid user to follow:", data);
    socket.send(JSON.stringify({
      cmd: "follow",
      status: "error",
      message: "invalid user"
    }));
    return;
  }
  try {
    const userExists = db.queryEntries(
      "SELECT user FROM users WHERE user = ?",
      [data.user]
    );
    if (!userExists || userExists.length === 0) {
      socket.send(JSON.stringify({
        cmd: "follow",
        status: "error",
        message: "user not found"
      }));
      return;
    }
    const stmt = db.prepareQuery(
      "INSERT INTO follows (follower, followed) VALUES (?, ?)"
    );
    stmt.execute([followClient.user, data.user]);
    stmt.finalize();
    socket.send(JSON.stringify({
      cmd: "follow",
      status: "success",
      following: data.user
    }));
    console.log("Follow successful:", {
      follower: followClient.user,
      following: data.user
    });
  } catch (error) {
    console.error("Follow error:", error);
    socket.send(JSON.stringify({
      cmd: "follow", 
      status: "error",
      message: "Failed to follow user"
    }));
  }
  break;
case "followdata":
  console.log("Follow data fetch attempt:", data);
  const followDataClient = clients.get(socket);
  if (!followDataClient?.authenticated) {
    console.log("Unauthorized follow data fetch attempt");
    socket.send(JSON.stringify({
      cmd: "followdata",
      status: "error",
      message: "unauthorized"
    }));
    return;
  }
  if (!data.follower || typeof data.follower !== "string") {
    console.log("Invalid follower:", data);
    socket.send(JSON.stringify({
      cmd: "followdata",
      status: "error",
      message: "invalid follower"
    }));
    return;
  }
  try {
    const following = db.queryEntries(
      "SELECT followed FROM follows WHERE follower = ?",
      [data.follower]
    );
    console.log("Found following relationships:", following);
    socket.send(JSON.stringify({
      cmd: "followdata",
      status: "success",
      following: following
    }));
  } catch (error) {
    console.error("Follow data fetch error:", error);
    socket.send(JSON.stringify({
      cmd: "followdata",
      status: "error",
      message: "Failed to fetch follow data"
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
});
