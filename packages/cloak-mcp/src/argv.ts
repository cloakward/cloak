export function argValue(argv: string[], names: string[]): string | null {
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (!arg) continue;
    for (const name of names) {
      if (arg === name) {
        const value = argv[i + 1];
        if (value && !value.startsWith("--")) return value;
      }
      const prefix = `${name}=`;
      if (arg.startsWith(prefix)) {
        const value = arg.slice(prefix.length);
        if (value.length > 0) return value;
      }
    }
  }
  return null;
}
