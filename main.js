import { DB } from "https://deno.land/x/sqlite/mod.ts";
const db = new DB("mlinkTest.db");
db.execute(`
CREATE TABLE users (
	user INTEGER PRIMARY KEY,
	token TEXT NOT NULL UNIQUE,
	permissions TEXT NOT NULL UNIQUE,
  passwords TEXT NOT NULL UNIQUE
);
`);
Deno.serve(
  (req) => {
    if (req.headers.get("upgrade") != "websocket") {
      return new Response(null, { status: 501 });
    }
  
    const { socket, response } = Deno.upgradeWebSocket(req);
    socket.addEventListener("open", () => {
      console.log("client connected");
    });
  
    socket.addEventListener("message", (event) => {
      if (event.data === "ping") {
        socket.send("pong");
      }
    });

    socket.addEventListener("message", (event) => {
      if (event.data === "stop") {
        socket.send("stopping");
        Deno.exit()
      }
    });

    socket.addEventListener("message", (event) => {
      if (event.data === "drop") {
        socket.send("dropping.");
        db.execute(`DROP TABLE users`)
      }
    });
    return response;
  }
);