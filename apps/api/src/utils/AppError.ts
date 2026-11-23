/**
 * @description used to throw the  error in structurte of Error class 
 * but according to our message and codes
 */

export class AppError extends Error {
      public readonly statusCode: number;
      public readonly isOperational: boolean;

      constructor(message: string, statusCode = 500, isOperational = true) {
          super(message);
          this.statusCode = statusCode;
          this.isOperational = isOperational;

          Object.setPrototypeOf(this, new.target.prototype);
          Error.captureStackTrace(this, this.constructor);
      }
}