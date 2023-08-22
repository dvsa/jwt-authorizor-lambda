import { Decoder } from 'io-ts';
import { isLeft } from 'fp-ts/lib/Either';

export class SchemaValidator {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  public validateJsonAgainstSchema(schema: Decoder<any, any>, json: any): boolean {
    const validated = schema.decode(json);

    // If validation errors, isLeft will return true
    return !isLeft(validated);
  }
}
