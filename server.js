import express from "express";
import crypto from "crypto";
import fs from "fs/promises";
import path from "path";

const app = express();

app.use(express.json({
  limit: "200mb",
  inflate: true
}));

const PORT = process.env.PORT || 3000;

const IMPORT_TOKEN = process.env.IMPORT_TOKEN;
const EVOLUTION_URL = process.env.EVOLUTION_URL;
const EVOLUTION_APIKEY = process.env.EVOLUTION_APIKEY;
const INSTANCE_NAME = process.env.INSTANCE_NAME;
const SESSION_DIR = process.env.SESSION_DIR || "/app/data/sessions";

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

app.get("/health", (req, res) => {
  res.json({
    ok: true,
    service: "evolution-session-gateway"
  });
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
