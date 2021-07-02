import type { Context } from 'aws-lambda';

export class Logger {
  logFormat: string;

  constructor(awsRequestId: string) {
    this.logFormat = `{ "awsRequestId": "${awsRequestId}", "message": "%s" }`;
  }

  public debug(msg: string): void {
    console.debug(this.logFormat, msg);
  }

  public info(msg: string): void {
    console.info(this.logFormat, msg);
  }

  public warn(msg: string): void {
    console.warn(this.logFormat, msg);
  }

  public error(msg: string): void {
    console.error(this.logFormat, msg);
  }
}

export const createLogger = (context: Context): Logger => new Logger(context.awsRequestId);
