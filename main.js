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
  UPDATE users 
  SET permissions = 'mod' 
  WHERE user = 'delusions'
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
              created_at INTEGER NOT NULL,
              reply_to TEXT
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
            let replyToId = null;
            if (data.reply_to) {
              const replyPost = db.queryEntries(
                "SELECT id FROM posts WHERE id = ?",
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
            const timestamp = Math.floor(Date.now() / 1000);
            const id = crypto.randomUUID();
            const stmt = db.prepareQuery(
              "INSERT INTO posts (id, post, user, created_at, reply_to) VALUES (?, ?, ?, ?, ?)",
            );
            const result = stmt.execute([
              id,
              data.post,
              postClient.user,
              timestamp,
              replyToId,
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
              "SELECT post, user, created_at, id, reply_to FROM posts WHERE user = ? ORDER BY created_at DESC LIMIT ? OFFSET ?",
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
              message: "unauthorized",
            }));
            return;
          }
          if (!data.user || typeof data.user !== "string") {
            console.log("Invalid user to follow:", data);
            socket.send(JSON.stringify({
              cmd: "follow",
              status: "error",
              message: "invalid user",
            }));
            return;
          }
          try {
            const userExists = db.queryEntries(
              "SELECT user FROM users WHERE user = ?",
              [data.user],
            );
            if (!userExists || userExists.length === 0) {
              socket.send(JSON.stringify({
                cmd: "follow",
                status: "error",
                message: "user not found",
              }));
              return;
            }
            const stmt = db.prepareQuery(
              "INSERT INTO follows (follower, followed) VALUES (?, ?)",
            );
            stmt.execute([followClient.user, data.user]);
            stmt.finalize();
            socket.send(JSON.stringify({
              cmd: "follow",
              status: "success",
              following: data.user,
            }));
            console.log("Follow successful:", {
              follower: followClient.user,
              following: data.user,
            });
          } catch (error) {
            console.error("Follow error:", error);
            socket.send(JSON.stringify({
              cmd: "follow",
              status: "error",
              message: "Failed to follow user",
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
              message: "unauthorized",
            }));
            return;
          }
          if (!data.follower || typeof data.follower !== "string") {
            console.log("Invalid follower:", data);
            socket.send(JSON.stringify({
              cmd: "followdata",
              status: "error",
              message: "invalid follower",
            }));
            return;
          }
          try {
            const following = db.queryEntries(
              "SELECT followed FROM follows WHERE follower = ?",
              [data.follower],
            );
            console.log("Found following relationships:", following);
            socket.send(JSON.stringify({
              cmd: "followdata",
              status: "success",
              following: following,
            }));
          } catch (error) {
            console.error("Follow data fetch error:", error);
            socket.send(JSON.stringify({
              cmd: "followdata",
              status: "error",
              message: "Failed to fetch follow data",
            }));
          }
          break;
        case "unfollow":
          console.log("Unfollow attempt:", data);
          const unfollowClient = clients.get(socket);
          if (!unfollowClient?.authenticated) {
            console.log("Unauthorized unfollow attempt");
            socket.send(JSON.stringify({
              cmd: "unfollow",
              status: "error",
              message: "unauthorized",
            }));
            return;
          }
          if (!data.user || typeof data.user !== "string") {
            console.log("Invalid user to unfollow:", data);
            socket.send(JSON.stringify({
              cmd: "unfollow",
              status: "error",
              message: "invalid user",
            }));
            return;
          }
          try {
            const stmt = db.prepareQuery(
              "DELETE FROM follows WHERE follower = ? AND followed = ?",
            );
            stmt.execute([unfollowClient.user, data.user]);
            stmt.finalize();
            socket.send(JSON.stringify({
              cmd: "unfollow",
              status: "success",
              unfollowed: data.user,
            }));
            console.log("Unfollow successful:", {
              unfollower: unfollowClient.user,
              unfollowed: data.user,
            });
          } catch (error) {
            console.error("Unfollow error:", error);
            socket.send(JSON.stringify({
              cmd: "unfollow",
              status: "error",
              message: "Failed to unfollow user",
            }));
          }
          break;
        case "timeline":
          console.log("Timeline fetch attempt:", data);
          const timelineClient = clients.get(socket);
          if (!timelineClient?.authenticated) {
            console.log("Unauthorized timeline fetch attempt");
            socket.send(JSON.stringify({
              cmd: "timeline",
              status: "error",
              message: "unauthorized",
            }));
            return;
          }
          try {
            const offset = data.offset || 0;
            console.log(
              "Fetching timeline for user:",
              timelineClient.user,
              "with offset:",
              offset,
            );
            const posts = db.queryEntries(
              `SELECT posts.post, posts.user, posts.created_at, posts.id, posts.reply_to 
       FROM posts 
       LEFT JOIN follows ON posts.user = follows.followed
       WHERE follows.follower = ? OR posts.user = ?
       ORDER BY posts.created_at DESC 
       LIMIT ? OFFSET ?`,
              [timelineClient.user, timelineClient.user, 20, offset],
            );

            console.log("Fetched timeline posts:", posts);
            socket.send(JSON.stringify({
              cmd: "timeline",
              status: "success",
              posts: posts,
            }));
          } catch (error) {
            console.error("Timeline fetch error:", error);
            socket.send(JSON.stringify({
              cmd: "timeline",
              status: "error",
              message: "Failed to fetch timeline",
            }));
          }
          break;
        case "search":
          console.log("Search attempt:", data);
          const searchClient = clients.get(socket);
          if (!searchClient?.authenticated) {
            console.log("Unauthorized search attempt");
            socket.send(JSON.stringify({
              cmd: "search",
              status: "error",
              message: "unauthorized",
            }));
            return;
          }
          if (!data.query || typeof data.query !== "string") {
            console.log("Invalid search query:", data);
            socket.send(JSON.stringify({
              cmd: "search",
              status: "error",
              message: "invalid search query",
            }));
            return;
          }
          try {
            const offset = data.offset || 0;
            const searchQuery = `%${data.query}%`;
            const results = db.queryEntries(
              `SELECT post, user, created_at, id, reply_to 
       FROM posts 
       WHERE post LIKE ? OR user LIKE ?
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
              [searchQuery, searchQuery, 20, offset],
            );
            console.log("Search results:", results);
            socket.send(JSON.stringify({
              cmd: "search",
              status: "success",
              results: results,
            }));
          } catch (error) {
            console.error("Search error:", error);
            socket.send(JSON.stringify({
              cmd: "search",
              status: "error",
              message: "Failed to perform search",
            }));
          }
          break;
        case "userProfile":
          console.log("User profile fetch attempt:", data);
          const profileClient = clients.get(socket);
          if (!profileClient?.authenticated) {
            console.log("Unauthorized profile fetch attempt");
            socket.send(JSON.stringify({
              cmd: "userProfile",
              status: "error",
              message: "unauthorized",
            }));
            return;
          }
          if (!data.username || typeof data.username !== "string") {
            console.log("Invalid username:", data);
            socket.send(JSON.stringify({
              cmd: "userProfile",
              status: "error",
              message: "invalid username",
            }));
            return;
          }
          try {
            const userDetails = db.queryEntries(
              "SELECT user, created_at FROM users WHERE user = ?",
              [data.username],
            );
            if (!userDetails || userDetails.length === 0) {
              socket.send(JSON.stringify({
                cmd: "userProfile",
                status: "error",
                message: "user not found",
              }));
              return;
            }
            const followers = db.queryEntries(
              "SELECT COUNT(*) as count FROM follows WHERE followed = ?",
              [data.username],
            );
            const following = db.queryEntries(
              "SELECT COUNT(*) as count FROM follows WHERE follower = ?",
              [data.username],
            );
            const posts = db.queryEntries(
              "SELECT COUNT(*) as count FROM posts WHERE user = ?",
              [data.username],
            );

            socket.send(JSON.stringify({
              cmd: "userProfile",
              status: "success",
              profile: {
                ...userDetails[0],
                followers: followers[0].count,
                following: following[0].count,
                posts: posts[0].count,
              },
            }));
          } catch (error) {
            console.error("Profile fetch error:", error);
            socket.send(JSON.stringify({
              cmd: "userProfile",
              status: "error",
              message: "Failed to fetch user profile",
            }));
          }
          break;
          case "deletePost":
  console.log("Delete post attempt:", data);
  const deleteClient = clients.get(socket);
  if (!deleteClient?.authenticated) {
    console.log("Unauthorized delete attempt");
    socket.send(JSON.stringify({
      cmd: "deletePost", 
      status: "error",
      message: "unauthorized"
    }));
    return;
  }
  if (!data.postId || typeof data.postId !== "string") {
    console.log("Invalid post ID:", data);
    socket.send(JSON.stringify({
      cmd: "deletePost",
      status: "error", 
      message: "invalid post id"
    }));
    return;
  }
  try {
    const post = db.queryEntries(
      "SELECT user FROM posts WHERE id = ?",
      [data.postId]
    );
    if (!post || post.length === 0) {
      socket.send(JSON.stringify({
        cmd: "deletePost",
        status: "error",
        message: "post not found"
      }));
      return;
    }
    const userPermissions = db.queryEntries(
      "SELECT permissions FROM users WHERE user = ?",
      [deleteClient.user]
    );
    if (post[0].user !== deleteClient.user && userPermissions[0]?.permissions !== "mod") {
      socket.send(JSON.stringify({
        cmd: "deletePost",
        status: "error",
        message: "unauthorized - you can only delete your own posts"
      }));
      return;
    }
    const stmt = db.prepareQuery(
      "DELETE FROM posts WHERE id = ?"
    );
    stmt.execute([data.postId]);
    stmt.finalize();
    socket.send(JSON.stringify({
      cmd: "deletePost",
      status: "success",
      deletedPostId: data.postId
    }));
    console.log("Post deleted successfully:", {
      postId: data.postId,
      deletedBy: deleteClient.user
    });
  } catch (error) {
    console.error("Delete post error:", error);
    socket.send(JSON.stringify({
      cmd: "deletePost",
      status: "error",
      message: "Failed to delete post"
    }));
  }
  break;
  case "setPermissions":
  console.log("Set permissions attempt:", data);
  const permissionsClient = clients.get(socket);
  if (!permissionsClient?.authenticated) {
    console.log("Unauthorized permissions change attempt");
    socket.send(JSON.stringify({
      cmd: "setPermissions",
      status: "error", 
      message: "unauthorized"
    }));
    return;
  }
  if (!data.username || typeof data.username !== "string" || 
      !data.permission || !["mod", "user"].includes(data.permission)) {
    console.log("Invalid permissions data:", data);
    socket.send(JSON.stringify({
      cmd: "setPermissions",
      status: "error",
      message: "invalid username or permission level"
    }));
    return;
  }
  try {
    const requesterPermissions = db.queryEntries(
      "SELECT permissions FROM users WHERE user = ?",
      [permissionsClient.user]
    );
    if (requesterPermissions[0]?.permissions !== "mod") {
      socket.send(JSON.stringify({
        cmd: "setPermissions",
        status: "error",
        message: "unauthorized - only mods can set permissions"
      }));
      return;
    }
    const targetUser = db.queryEntries(
      "SELECT user FROM users WHERE user = ?",
      [data.username]
    );
    if (!targetUser || targetUser.length === 0) {
      socket.send(JSON.stringify({
        cmd: "setPermissions",
        status: "error",
        message: "user not found"
      }));
      return;
    }
    const stmt = db.prepareQuery(
      "UPDATE users SET permissions = ? WHERE user = ?"
    );
    stmt.execute([data.permission, data.username]);
    stmt.finalize();
    socket.send(JSON.stringify({
      cmd: "setPermissions",
      status: "success",
      username: data.username,
      newPermission: data.permission
    }));
    console.log("Permissions updated successfully:", {
      username: data.username,
      newPermission: data.permission,
      setBy: permissionsClient.user
    });
  } catch (error) {
    console.error("Set permissions error:", error);
    socket.send(JSON.stringify({
      cmd: "setPermissions",
      status: "error",
      message: "Failed to update permissions"
    }));
  }
  break;
case "banUser":
  console.log("Ban user attempt:", data);
  const banClient = clients.get(socket);
  if (!banClient?.authenticated) {
    console.log("Unauthorized ban attempt");
    socket.send(JSON.stringify({
      cmd: "banUser",
      status: "error",
      message: "unauthorized"
    }));
    return;
  }
  if (!data.username || typeof data.username !== "string") {
    console.log("Invalid username for ban:", data);
    socket.send(JSON.stringify({
      cmd: "banUser", 
      status: "error",
      message: "invalid username"
    }));
    return;
  }
  try {
    const modPermissions = db.queryEntries(
      "SELECT permissions FROM users WHERE user = ?",
      [banClient.user]
    );
    if (modPermissions[0]?.permissions !== "mod") {
      socket.send(JSON.stringify({
        cmd: "banUser",
        status: "error",
        message: "unauthorized - only mods can ban users"
      }));
      return;
    }
    const targetUser = db.queryEntries(
      "SELECT permissions FROM users WHERE user = ?",
      [data.username]
    );
    if (!targetUser || targetUser.length === 0) {
      socket.send(JSON.stringify({
        cmd: "banUser",
        status: "error",
        message: "user not found"
      }));
      return;
    }
    if (targetUser[0].permissions === "mod") {
      socket.send(JSON.stringify({
        cmd: "banUser",
        status: "error",
        message: "cannot ban moderators"
      }));
      return;
    }
    const stmt = db.prepareQuery(
      "UPDATE users SET banned = TRUE WHERE user = ?"
    );
    stmt.execute([data.username]);
    stmt.finalize();
    socket.send(JSON.stringify({
      cmd: "banUser",
      status: "success",
      username: data.username
    }));
    console.log("User banned successfully:", {
      username: data.username,
      bannedBy: banClient.user
    });
  } catch (error) {
    console.error("Ban user error:", error);
    socket.send(JSON.stringify({
      cmd: "banUser",
      status: "error", 
      message: "Failed to ban user"
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
