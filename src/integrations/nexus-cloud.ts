export type SystemsApiToolRegistrationRequest = {
  id: string;
  name: string;
  description: string;
  upstreamUrl?: string;
  mode?: "standalone" | "orchestrated";
  exposed?: boolean;
  health?: "healthy" | "degraded" | "offline";
  capabilities?: readonly string[];
};

export function buildNexusVaultSystemsApiRegistrationPayload(port: number): SystemsApiToolRegistrationRequest {
  const upstreamUrl = resolveUpstreamUrl(port);
  return {
    id: toolId(),
    name: toolName(),
    description: "Secrets, key lifecycle, and audit chain service",
    upstreamUrl,
    mode: process.env.SYSTEMS_API_MODE === "orchestrated" ? "orchestrated" : "standalone",
    exposed: true,
    health: "healthy",
    capabilities: [
      "secrets-management",
      "key-rotation",
      "audit-log",
      "systems-api",
    ],
  };
}

function cloudBaseUrl(): string {
  return (process.env.NEXUS_CLOUD_URL ?? "").trim().replace(/\/$/, "");
}

function cloudHeaders(): Record<string, string> {
  return {
    "content-type": "application/json",
    accept: "application/json",
    ...(process.env.NEXUS_CLOUD_API_KEY ? { "x-api-key": process.env.NEXUS_CLOUD_API_KEY } : {}),
  };
}

function toolId(): string {
  return (process.env.NEXUS_VAULT_TOOL_ID ?? "nexus-vault").trim();
}

function toolName(): string {
  return (process.env.NEXUS_VAULT_TOOL_NAME ?? "Nexus Vault").trim();
}

function heartbeatIntervalMs(): number {
  const raw = Number(process.env.NEXUS_CLOUD_HEARTBEAT_INTERVAL_MS ?? "30000");
  return Number.isFinite(raw) ? Math.max(5000, raw) : 30000;
}

function resolveUpstreamUrl(port: number): string {
  const configured = (process.env.NEXUS_VAULT_PUBLIC_URL ?? "").trim();
  return configured || `http://localhost:${port}`;
}

export function hasVaultCloudSystemsApiIntegration(): boolean {
  return cloudBaseUrl().length > 0;
}

export async function registerNexusVaultWithCloud(payload: SystemsApiToolRegistrationRequest): Promise<void> {
  const response = await fetch(`${cloudBaseUrl()}/api/v1/tools`, {
    method: "POST",
    headers: cloudHeaders(),
    body: JSON.stringify(payload),
  });

  if (!response.ok) {
    throw new Error(`Cloud tool registration failed with status ${response.status}`);
  }
}

export async function heartbeatNexusVaultWithCloud(targetToolId: string, upstreamUrl?: string): Promise<void> {
  const response = await fetch(`${cloudBaseUrl()}/api/v1/tools/${encodeURIComponent(targetToolId)}/heartbeat`, {
    method: "POST",
    headers: cloudHeaders(),
    body: JSON.stringify({ health: "healthy", ...(upstreamUrl ? { upstreamUrl } : {}) }),
  });

  if (!response.ok) {
    throw new Error(`Cloud heartbeat failed with status ${response.status}`);
  }
}

export function startNexusVaultCloudRegistrationHeartbeat(port: number): () => void {
  const registrationPayload = buildNexusVaultSystemsApiRegistrationPayload(port);
  const upstreamUrl = registrationPayload.upstreamUrl;
  const id = registrationPayload.id;

  registerNexusVaultWithCloud(registrationPayload)
    .then(() => {
      console.log(`[nexus-vault] Registered with Nexus Cloud as ${id}`);
    })
    .catch((error) => {
      console.warn(`[nexus-vault] Cloud registration failed: ${(error as Error).message}`);
    });

  const timer = setInterval(() => {
    heartbeatNexusVaultWithCloud(id, upstreamUrl).catch((error) => {
      console.warn(`[nexus-vault] Cloud heartbeat failed: ${(error as Error).message}`);
    });
  }, heartbeatIntervalMs());

  timer.unref();
  return () => clearInterval(timer);
}
