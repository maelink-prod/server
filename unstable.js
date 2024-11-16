import { DB } from "https://deno.land/x/sqlite/mod.ts";
import * as bcrypt from "jsr:@ts-rex/bcrypt";
import { crypto } from "https://deno.land/std/crypto/mod.ts";

const db = new DB("users.db");
const postdb = new DB("mlinkTest.db")
const clients = new Map();
db.execute(`
  CREATE TABLE IF NOT EXISTS users (
    username TEXT PRIMARY KEY,
    password_hash TEXT NOT NULL,
    token TEXT UNIQUE
  );
`);
function generateToken() {
  const buffer = new Uint8Array(32);
  crypto.getRandomValues(buffer);
  return Array.from(buffer)
    .map(byte => byte.toString(16).padStart(2, '0'))
    .join('');
}
async function registerUser(username, password) {
  try {
    const passwordHash = await bcrypt.hash(password);
    
    db.execute(
      `INSERT INTO users (username, password_hash) VALUES (${username}, ${passwordHash})`
    );
    return { success: true, message: "User registered successfully" };
  } catch (error) {
    console.log(error);
    return { success: false, message: "Registration failed" };
  }
}
async function loginUser(username, password) {
  try {
    const user = db.execute(
      `SELECT username, password_hash FROM users WHERE username = ${username}`
    ).next().value;
    if (!user) {
      return { success: false, message: "Invalid credentials" };
    }
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return { success: false, message: "Invalid credentials" };
    }
    const token = generateToken();
    db.execute(
      `UPDATE users SET token = ${token} WHERE username = ${username}`
    );
    return { 
      success: true, 
      token,
      message: "Login successful" 
    };
  } catch (error) {
    console.log(error);
    return { success: false, message: "Login failed" };
  }
}
function verifyToken(token) {
  try {
    const user = db.execute(
      `SELECT username FROM users WHERE token = ${token}`
    ).next().value;
    
    return user ? true : false;
  } catch {
    return false;
  }
}
Deno.serve((req) => {
  if (req.headers.get("upgrade") != "websocket") {
    return new Response(null, { status: 501 });
  }
  const { socket, response } = Deno.upgradeWebSocket(req);
  socket.addEventListener("message", async (event) => {
    try {
      const data = JSON.parse(event.data);
      switch (data.cmd) {
        case "register":
          const registerResult = await registerUser(data.username, data.password);
          socket.send(JSON.stringify(registerResult));
          break;
        case "login":
          const loginResult = await loginUser(data.username, data.password);
          if (loginResult.success) {
            clients.set(socket, {
              username: data.username,
              token: loginResult.token
            });
          }
          socket.send(JSON.stringify(loginResult));
          break;
        case "message":
          const clientSession = clients.get(socket);
          if (!clientSession || !verifyToken(clientSession.token)) {
            socket.send(JSON.stringify({
              success: false,
              message: "Authentication required"
            }));
            return;
          }
          postdb.execute(`INSERT INTO posts (user, post)
          VALUES('${clientSession.username}', '${data.content}');`);
          broadcast(JSON.stringify({
            type: "message",
            username: clientSession.username,
            content: data.content
          }));
          break;
      }
    } catch (error) {
      socket.send(JSON.stringify({
        success: false,
        message: "Invalid request"
      }));
    }
  });
  socket.addEventListener("close", () => {
    clients.delete(socket);
  });
  return response;
});
function broadcast(message) {
  for (const [client, session] of clients.entries()) {
    if (client.readyState === WebSocket.OPEN && verifyToken(session.token)) {
      client.send(message);
    }
  }
}
