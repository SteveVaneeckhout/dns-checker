/** Message of a caught value, which may not be an `Error` at all. */
export function errorMessage(e: unknown): string {
  return Error.isError(e) ? e.message : String(e);
}
