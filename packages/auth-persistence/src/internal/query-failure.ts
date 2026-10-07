/** Native query failures stay in E until the owning workflow reports and redacts
 * them. Drivers may carry a more specific tag; the cause remains available to
 * the application's constraint classifier and is never public telemetry. */
export interface QueryFailure {
  readonly _tag: string;
  readonly cause: unknown;
}
