export interface ToolResult {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
}

export interface CloakTool {
  name: string;
  description: string;
  // JSON Schema (Draft 2020-12). Hand-written, no zod-to-json-schema dep.
  inputSchema: object;
  handler: (args: unknown) => Promise<ToolResult>;
}
