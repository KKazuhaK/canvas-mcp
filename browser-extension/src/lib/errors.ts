// An error whose message is safe to show to the user as-is.
export class UserError extends Error {
  code: string;
  constructor(code: string, message: string) {
    super(message);
    this.code = code;
  }
}
