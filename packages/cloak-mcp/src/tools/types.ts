export interface ToolResult {
  content: Array<{ type: "text"; text: string }>;
  structuredContent?: Record<string, unknown>;
  isError?: boolean;
}

export interface CloakTool {
  name: string;
  description: string;
  // JSON Schema (Draft 2020-12). Hand-written, no zod-to-json-schema dep.
  inputSchema: object;
  outputSchema: object;
  handler: (args: unknown) => Promise<ToolResult>;
}

export function jsonToolResult(structuredContent: Record<string, unknown>): ToolResult {
  return {
    content: [{ type: "text", text: JSON.stringify(structuredContent) }],
    structuredContent,
  };
}
