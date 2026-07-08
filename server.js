import express from "express";
import crypto from "crypto";
import fs from "fs/promises";
import path from "path";
import pg from "pg";

const { Pool } = pg;

const app = express();

app.use(express.json({
  limit: "200mb",
  inflate: true
}));

const PORT = process.env.PORT || 80;

const IMPORT_TOKEN = process.env.IMPORT_TOKEN;
const EVOLUTION_URL = process.env.EVOLUTION_URL;
const EVOLUTION_APIKEY = process.env.EVOLUTION_APIKEY;
const INSTANCE_NAME = process.env.INSTANCE_NAME;
const EVOLUTION_INSTANCE_ID = process.env.EVOLUTION_INSTANCE_ID;
const POSTGRES_URI = process.env.POSTGRES_URI;
const SESSION_DIR = process.env.SESSION_DIR || "/app/data/sessions";

const pool = POSTGRES_URI
  ? new Pool({ connectionString: POSTGRES_URI })
  : null;

function auth(req, res, next) {
  const token = req.header("token");

  if (!IMPORT_TOKEN || token !== IMPORT_TOKEN) {
    return res.status(401).json({
      error: "Token inválido"
    });
  }

  next();
}

function createJobId() {
  return crypto.randomUUID();
}

function sha256Json(payload) {
  return crypto
    .createHash("sha256")
    .update(JSON.stringify(payload))
    .digest("hex");
}

async function getEvolutionState() {
  const encodedInstance = encodeURIComponent(INSTANCE_NAME);

  const response = await fetch(
    `${EVOLUTION_URL}/instance/connectionState/${encodedInstance}`,
    {
      method: "GET",
      headers: {
        apikey: EVOLUTION_APIKEY
      }
    }
  );

  const data = await response.json().catch(() => ({}));

  if (!response.ok) {
    throw new Error(JSON.stringify(data));
  }

  return data?.instance?.state || "close";
}

async function getInstanceFromDb() {
  if (!pool) {
    throw new Error("POSTGRES_URI não configurada");
  }

  const result = await pool.query(
    `
    SELECT 
      id,
      name,
      "connectionStatus",
      "ownerJid",
      number,
      "clientName",
      "createdAt",
      "updatedAt"
    FROM "Instance"
    WHERE id = $1
    LIMIT 1
    `,
    [EVOLUTION_INSTANCE_ID]
  );

  return result.rows[0] || null;
}

async function getSessionFromDb() {
  if (!pool) {
    throw new Error("POSTGRES_URI não configurada");
  }

  const result = await pool.query(
    `
    SELECT 
      "sessionId",
      LENGTH(creds) AS tamanho_creds,
      LEFT(creds, 120) AS inicio_creds,
      "createdAt"
    FROM "Session"
    WHERE "sessionId" = $1
    LIMIT 1
    `,
    [EVOLUTION_INSTANCE_ID]
  );

  return result.rows[0] || null;
}

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "evolution-session-gateway",
    routes: [
      "/health",
      "/instance/status",
      "/debug/evolution-db"
    ]
  });
});

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "evolution-session-gateway"
  });
});

app.get("/debug/evolution-db", auth, async (req, res) => {
  try {
    const instance = await getInstanceFromDb();
    const session = await getSessionFromDb();

    return res.json({
      ok: true,
      databaseConnected: true,
      evolutionInstanceId: EVOLUTION_INSTANCE_ID,
      instanceFound: Boolean(instance),
      sessionFound: Boolean(session),
      instance,
      session
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      databaseConnected: false,
      error: String(error.message || error)
    });
  }
});

app.get("/instance/status", auth, async (req, res) => {
  try {
    const state = await getEvolutionState();

    const isConnected = ["open", "connected"].includes(
      String(state).toLowerCase()
    );

    if (isConnected) {
      return res.json({
        status: {
          connected: true,
          loggedIn: true
        },
        instance: {
          status: "connected",
          evolutionState: state
        }
      });
    }

    return res.json({
      status: {
        connected: false,
        loggedIn: false
      },
      instance: {
        status: "disconnected",
        evolutionState: state
      }
    });
  } catch (error) {
    return res.json({
      status: {
        connected: false,
        loggedIn: false
      },
      instance: {
        status: "disconnected",
        warning: "Não foi possível consultar a Evolution",
        detail: String(error.message || error)
      }
    });
  }
});

app.post("/instance/import-web-session/start", auth, async (req, res) => {
  const jobId = createJobId();
  const jobPath = path.join(SESSION_DIR, jobId);

  await fs.mkdir(jobPath, { recursive: true });

  await fs.writeFile(
    path.join(jobPath, "start.json"),
    JSON.stringify(req.body, null, 2)
  );

  res.json({
    jobId
  });
});

app.post("/instance/import-web-session/chunk", auth, async (req, res) => {
  const { jobId, section, seq, sha256, payload } = req.body;

  if (!jobId || !section || seq === undefined) {
    return res.status(400).json({
      error: "jobId, section e seq são obrigatórios"
    });
  }

  const calculatedSha = sha256Json(payload);

  if (sha256 && calculatedSha !== sha256) {
    return res.status(400).json({
      error: "SHA256 inválido",
      expected: sha256,
      received: calculatedSha
    });
  }

  const jobPath = path.join(SESSION_DIR, jobId);
  await fs.mkdir(jobPath, { recursive: true });

  const filename = `${String(seq).padStart(5, "0")}-${section}.json`;

  await fs.writeFile(
    path.join(jobPath, filename),
    JSON.stringify(req.body, null, 2)
  );

  res.json({
    ok: true
  });
});

app.post("/instance/import-web-session/finish", auth, async (req, res) => {
  const { jobId } = req.body;

  if (!jobId) {
    return res.status(400).json({
      error: "jobId é obrigatório"
    });
  }

  const jobPath = path.join(SESSION_DIR, jobId);

  await fs.writeFile(
    path.join(jobPath, "finish.json"),
    JSON.stringify(
      {
        finishedAt: new Date().toISOString(),
        instanceName: INSTANCE_NAME,
        evolutionInstanceId: EVOLUTION_INSTANCE_ID,
        evolutionUrl: EVOLUTION_URL
      },
      null,
      2
    )
  );

  return res.status(501).json({
    error: "Sessão recebida pelo gateway, mas a importação real para a Evolution ainda precisa ser implementada."
  });
});

app.post("/instance/import-web-session/history", auth, async (req, res) => {
  const filename = `history-${Date.now}.json`;

  await fs.mkdir(SESSION_DIR, { recursive: true });

  await fs.writeFile(
    path.join(SESSION_DIR, filename),
    JSON.stringify(req.body, null, 2)
  );

  res.json({
    ok: true
  });
});

app.listen(PORT, () => {
  console.log(`Gateway rodando na porta ${PORT}`);
});
