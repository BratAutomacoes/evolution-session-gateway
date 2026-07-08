import express from "express";
import crypto from "crypto";
import fs from "fs/promises";
import path from "path";
import pg from "pg";

const { Pool } = pg;

const app = express();

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);

  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, token, authorization, apikey");
  res.setHeader("Access-Control-Max-Age", "86400");

  if (req.method === "OPTIONS") {
    return res.sendStatus(204);
  }

  next();
});

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
const BACKUP_DIR = process.env.BACKUP_DIR || "/app/data/backups";

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

function asBufferObject(value) {
  if (!value) return value;

  if (value.type === "Buffer" && value.data) {
    return value;
  }

  if (typeof value === "string") {
    return {
      type: "Buffer",
      data: value
    };
  }

  return value;
}

function keyPair(pair) {
  if (!pair) return pair;

  return {
    private: asBufferObject(pair.private || pair.privKey),
    public: asBufferObject(pair.public || pair.pubKey)
  };
}

function signedPreKey(input) {
  if (!input) return input;

  return {
    keyId: input.keyId,
    keyPair: keyPair(input.keyPair),
    signature: asBufferObject(input.signature)
  };
}

function accountObject(account) {
  if (!account) return account;

  return {
    details: asBufferObject(account.details),
    accountSignatureKey: asBufferObject(account.accountSignatureKey),
    accountSignature: asBufferObject(account.accountSignature),
    deviceSignature: asBufferObject(account.deviceSignature)
  };
}

function safeParseCreds(raw) {
  if (!raw) return {};

  let value = raw;

  for (let i = 0; i < 3; i++) {
    if (typeof value !== "string") break;

    try {
      value = JSON.parse(value);
    } catch {
      break;
    }
  }

  if (value && typeof value === "object") {
    return value;
  }

  return {};
}

function isDoubleEncoded(raw) {
  if (!raw || typeof raw !== "string") return false;

  try {
    const parsed = JSON.parse(raw);
    return typeof parsed === "string";
  } catch {
    return false;
  }
}

function encodeCredsForStorage(creds, previousRaw) {
  const json = JSON.stringify(creds);

  const forceDoubleEncode =
    process.env.CREDS_DOUBLE_ENCODE === undefined
      ? true
      : process.env.CREDS_DOUBLE_ENCODE === "true";

  if (previousRaw) {
    return isDoubleEncoded(previousRaw) ? JSON.stringify(json) : json;
  }

  return forceDoubleEncode ? JSON.stringify(json) : json;
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

  return data?.instance?.state || data?.instance?.connectionStatus || "close";
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

async function getPreviousSessionRaw() {
  if (!pool) {
    throw new Error("POSTGRES_URI não configurada");
  }

  const result = await pool.query(
    `
    SELECT *
    FROM "Session"
    WHERE "sessionId" = $1
    LIMIT 1
    `,
    [EVOLUTION_INSTANCE_ID]
  );

  return result.rows[0] || null;
}

async function backupCurrentSession() {
  await fs.mkdir(BACKUP_DIR, { recursive: true });

  const current = await getPreviousSessionRaw();

  const filename = `session-${EVOLUTION_INSTANCE_ID}-${Date.now()}.json`;
  const backupPath = path.join(BACKUP_DIR, filename);

  await fs.writeFile(
    backupPath,
    JSON.stringify(current || null, null, 2)
  );

  return {
    backupPath,
    hadSession: Boolean(current)
  };
}

async function listLatestJob() {
  const jobs = await fs.readdir(SESSION_DIR).catch(() => []);

  const mapped = [];

  for (const name of jobs) {
    const full = path.join(SESSION_DIR, name);
    const stat = await fs.stat(full).catch(() => null);

    if (stat?.isDirectory()) {
      mapped.push({
        name,
        path: full,
        time: stat.mtimeMs
      });
    }
  }

  mapped.sort((a, b) => b.time - a.time);

  return mapped[0] || null;
}

async function importSessionToEvolution(jobId) {
  if (!pool) {
    throw new Error("POSTGRES_URI não configurada");
  }

  if (!EVOLUTION_INSTANCE_ID) {
    throw new Error("EVOLUTION_INSTANCE_ID não configurado");
  }

  const jobPath = path.join(SESSION_DIR, jobId);
  const startPath = path.join(jobPath, "start.json");

  const startRaw = await fs.readFile(startPath, "utf8");
  const start = JSON.parse(startRaw);

  const device = start.device;

  if (!device) {
    throw new Error("start.json não possui device");
  }

  const previousSession = await getPreviousSessionRaw();
  const previousRaw = previousSession?.creds || null;
  const previousCreds = safeParseCreds(previousRaw);

  const ownerJid = device.meJid || previousCreds.me?.id || null;
  const number = ownerJid ? ownerJid.split("@")[0].replace(/\D/g, "") : null;

  const importedCreds = {
    ...previousCreds,

    noiseKey: keyPair(device.noiseKey),

    signedIdentityKey: keyPair(
      device.signedIdentityKey || device.identityKey
    ),

    signedPreKey: signedPreKey(device.signedPreKey),

    registrationId: device.registrationId,

    advSecretKey: device.advSecretKey,

    account: accountObject(device.account),

    platform: device.platform || previousCreds.platform || "web",

    me: {
      ...(previousCreds.me || {}),
      id: ownerJid || previousCreds.me?.id,
      lid: device.meLid || previousCreds.me?.lid,
      name: INSTANCE_NAME
    },

    registered: true
  };

  if (!importedCreds.signalIdentities) {
    importedCreds.signalIdentities = [];
  }

  const credsText = encodeCredsForStorage(importedCreds, previousRaw);

  let backup = null;

  try {
    backup = await backupCurrentSession();

    await pool.query("BEGIN");

    await pool.query(
      `
      INSERT INTO "Session" (id, "sessionId", creds, "createdAt")
      VALUES ($1, $1, $2, NOW())
      ON CONFLICT ("sessionId")
      DO UPDATE SET creds = EXCLUDED.creds
      `,
      [EVOLUTION_INSTANCE_ID, credsText]
    );

    await pool.query(
      `
      UPDATE "Instance"
      SET "connectionStatus" = 'close',
          "ownerJid" = COALESCE($2, "ownerJid"),
          number = COALESCE($3, number),
          "updatedAt" = NOW()
      WHERE id = $1
      `,
      [EVOLUTION_INSTANCE_ID, ownerJid, number]
    );

    await pool.query("COMMIT");

    return {
      jobPath,
      backup,
      ownerJid,
      number,
      credsLength: credsText.length,
      importedKeys: Object.keys(importedCreds)
    };
  } catch (error) {
    try {
      await pool.query("ROLLBACK");
    } catch {}

    throw error;
  }
}

app.get("/", (req, res) => {
  res.json({
    ok: true,
    service: "evolution-session-gateway",
    routes: [
      "/health",
      "/instance/status",
      "/debug/evolution-db",
      "/debug/latest-job"
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

app.get("/debug/latest-job", auth, async (req, res) => {
  try {
    const latest = await listLatestJob();

    if (!latest) {
      return res.json({
        ok: true,
        jobFound: false
      });
    }

    const files = await fs.readdir(latest.path);

    return res.json({
      ok: true,
      jobFound: true,
      latest,
      files: files.sort()
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
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
  try {
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
  } catch (error) {
    res.status(500).json({
      ok: false,
      error: String(error.message || error)
    });
  }
});

app.post("/instance/import-web-session/chunk", auth, async (req, res) => {
  try {
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
  } catch (error) {
    res.status(500).json({
      ok: false,
      error: String(error.message || error)
    });
  }
});

app.post("/instance/import-web-session/finish", auth, async (req, res) => {
  const { jobId } = req.body;

  if (!jobId) {
    return res.status(400).json({
      error: "jobId é obrigatório"
    });
  }

  try {
    const jobPath = path.join(SESSION_DIR, jobId);
    await fs.mkdir(jobPath, { recursive: true });

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

    const result = await importSessionToEvolution(jobId);

    return res.json({
      ok: true,
      message: "Sessão recebida e importação experimental gravada na Evolution.",
      result
    });
  } catch (error) {
    return res.status(500).json({
      ok: false,
      error: "Falha ao importar sessão para a Evolution",
      detail: String(error.message || error)
    });
  }
});

app.post("/instance/import-web-session/history", auth, async (req, res) => {
  try {
    const filename = `history-${Date.now()}.json`;

    await fs.mkdir(SESSION_DIR, { recursive: true });

    await fs.writeFile(
      path.join(SESSION_DIR, filename),
      JSON.stringify(req.body, null, 2)
    );

    res.json({
      ok: true
    });
  } catch (error) {
    res.status(500).json({
      ok: false,
      error: String(error.message || error)
    });
  }
});

app.listen(PORT, () => {
  console.log(`Gateway rodando na porta ${PORT}`);
});
