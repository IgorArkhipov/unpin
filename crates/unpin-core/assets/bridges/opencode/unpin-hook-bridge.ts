import { createConnection } from "node:net"

type BridgeResponse = {
  decision?: "allow" | "deny"
  arguments?: Record<string, unknown>
  result?: unknown
}

async function dispatch(
  event: string,
  payload: unknown,
  enforcing: boolean,
): Promise<BridgeResponse | undefined> {
  const socketPath = process.env.UNPIN_BRIDGE_SOCKET
  const sessionId = process.env.UNPIN_SESSION_ID
  if (!socketPath || !sessionId) {
    if (enforcing) throw new Error("Unpin enforcing bridge is unavailable")
    return undefined
  }

  return await new Promise((resolve, reject) => {
    const socket = createConnection(socketPath)
    let response = ""
    socket.setEncoding("utf8")
    socket.setTimeout(10_000, () => socket.destroy(new Error("Unpin bridge timed out")))
    socket.on("connect", () => {
      socket.end(`${JSON.stringify({ version: 1, sessionId, event, payload })}\n`)
    })
    socket.on("data", (chunk) => {
      response += chunk
      if (response.length > 1024 * 1024) socket.destroy(new Error("bridge response too large"))
    })
    socket.on("end", () => {
      try {
        resolve(JSON.parse(response) as BridgeResponse)
      } catch (error) {
        if (enforcing) reject(error)
        else resolve(undefined)
      }
    })
    socket.on("error", (error) => {
      if (enforcing) reject(error)
      else resolve(undefined)
    })
  })
}

export const UnpinHookBridge = async () => ({
  "tool.execute.before": async (input: unknown, output: { args: Record<string, unknown> }) => {
    const response = await dispatch("tool.execute.before", { input, output }, true)
    if (response?.decision === "deny") throw new Error("Unpin hook policy denied tool call")
    if (response?.arguments) output.args = response.arguments
  },
  "tool.execute.after": async (input: unknown, output: { result?: unknown }) => {
    const response = await dispatch("tool.execute.after", { input, output }, false)
    if (response && Object.prototype.hasOwnProperty.call(response, "result")) output.result = response.result
  },
})
