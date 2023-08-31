import { Decoder } from 'io-ts';
import { isLeft } from 'fp-ts/lib/Either';

export class SchemaValidator {
  public validateJsonAgainstSchema(schema: Decoder<unknown, unknown>, json: unknown): boolean {
    const validated = schema.decode(json);

    // If validation errors, isLeft will return true
    return !isLeft(validated);
  }
}
