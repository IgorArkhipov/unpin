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

export default function unpinHookBridge(pi: {
  on: (event: string, handler: (payload: any) => Promise<any>) => void
}) {
  pi.on("tool_call", async (event) => {
    const response = await dispatch("tool_call", event, true)
    if (response?.decision === "deny") {
      return { block: true, reason: "Unpin hook policy denied tool call" }
    }
    if (response?.arguments) event.input = response.arguments
  })

  pi.on("tool_result", async (event) => {
    const response = await dispatch("tool_result", event, false)
    if (response && Object.prototype.hasOwnProperty.call(response, "result")) return response.result
  })
}
