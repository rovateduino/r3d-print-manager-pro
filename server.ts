import express from "express";
import path from "path";
import dotenv from "dotenv";
import cors from "cors";
import handler from "./api/index";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

// Delegate all /api routes to the Vercel handler
app.all("/api/*", (req, res) => {
  return handler(req, res);
});

// Serve static files
const distPath = path.join(process.cwd(), "dist");

async function initVite() {
  try {
    if (process.env.NODE_ENV !== "production") {
      console.log("📦 Loading Vite middleware...");
      const { createServer: createViteServer } = await import("vite");
      const vite = await createViteServer({
        server: { middlewareMode: true },
        appType: "spa",
      });
      app.use(vite.middlewares);
      console.log("✅ Vite loaded.");
    } else {
      app.use(express.static(distPath));
      app.get("*", (_req, res) =>
        res.sendFile(path.join(distPath, "index.html"))
      );
    }
  } catch (err) {
    console.error("❌ Error initializing Vite:", err);
  }
}

initVite();

const PORT = 3000;
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 Server listening on http://0.0.0.0:${PORT}`);
});

export default app;
