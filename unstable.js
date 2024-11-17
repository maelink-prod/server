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
    CREATE TABLE IF NOT EXISTS posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      post TEXT NOT NULL,
      user TEXT NOT NULL,
      created_at INTEGER NOT NULL
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
    for (const client of clients.values()) {
      client.socket.send(message);
    }
  }
  const { socket, response } = Deno.upgradeWebSocket(req);
  socket.addEventListener("open", () => {
    clients.set(socket, { socket, authenticated: false });
    console.log("client connected");
  });
  socket.addEventListener("close", () => {
    clients.delete(socket);
    console.log("client disconnected");
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
              'SHA-256',
              new TextEncoder().encode(data.password)
            )
            .then(hash => Array.from(new Uint8Array(hash))
                .map(b => b.toString(16).padStart(2, '0'))
                .join(''))
            .then(hashedPassword => {
              const stmt = db.prepareQuery(
                "INSERT INTO users (user, token, permissions, password) VALUES (?, ?, ?, ?)"
              );
              const result = stmt.execute([
                data.user,
                token,
                "user",
                hashedPassword
              ]);
              stmt.finalize();
              return result;
            })
            .then(result => {
              socket.send(JSON.stringify({
                cmd: "register",
                status: "success",
                token: token,
              }));
            })
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
              'SHA-256',
              new TextEncoder().encode(data.password)
            ).then(hash => {
              const hashedPassword = Array.from(new Uint8Array(hash))
                .map(b => b.toString(16).padStart(2, '0'))
                .join('');

              const query = "SELECT * FROM users WHERE user = ? AND password = ?";
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
            }).catch(error => {
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
              id INTEGER PRIMARY KEY AUTOINCREMENT,
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
            const stmt = db.prepareQuery(
              "INSERT INTO posts (post, user, created_at) VALUES (:post, :user, :timestamp)",
            );
            const result = stmt.execute({
              post: data.post,
              user: postClient.user,
              timestamp: timestamp,
            });
            stmt.finalize();
            const broadcastMessage = JSON.stringify({
              cmd: "rpost",
              user: postClient.user,
              post: data.post,
              timestamp: timestamp,
            });
            broadcast(broadcastMessage);
            socket.send(JSON.stringify({
              cmd: "post",
              status: "success",
              timestamp: timestamp,
            }));
            console.log("Post successful:", {
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
            console.log("Fetching posts with offset:", offset);
            const posts = db.queryEntries(
              "SELECT post, user, created_at FROM posts ORDER BY created_at DESC LIMIT ? OFFSET ?",
              [10, offset],
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
});
