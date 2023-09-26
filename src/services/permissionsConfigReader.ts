import * as fs from 'fs';
import { PERMISSIONS_FILE_SCHEMA } from '../resources/permissionsConfigFileSchema';
import { PermissionsConfig } from '../types/configuration';
import { Logger } from '../util/logger';
import { SchemaValidator } from './schemaValidator';

export class PermissionsConfigReader {
  validator: SchemaValidator;

  logger: Logger;

  constructor(validator: SchemaValidator, logger: Logger) {
    this.validator = validator;
    this.logger = logger;
  }

  public readConfigFile(filePath: string): PermissionsConfig {
    try {
      // eslint-disable-next-line security/detect-non-literal-fs-filename
      const fileContents = fs.readFileSync(filePath, 'utf-8');

      const permissionsConfig: unknown = JSON.parse(fileContents);

      const isValidJson = this.validator.validateJsonAgainstSchema(PERMISSIONS_FILE_SCHEMA, permissionsConfig);

      if (!isValidJson) {
        throw new Error('Permissions configuration file does not match valid schema');
      }

      return permissionsConfig as PermissionsConfig;
    } catch (error) {
      const { message } = error as Error;
      this.logger.info(message);

      throw new Error('Could not read permissions configuration file');
    }
  }
}
