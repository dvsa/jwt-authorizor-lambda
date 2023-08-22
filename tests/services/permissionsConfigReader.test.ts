import * as fs from 'fs';
import { PermissionsConfigReader } from '../../src/services/permissionsConfigReader';
import { SchemaValidator } from '../../src/services/schemaValidator';
import { Logger } from '../../src/util/logger';
import { PermissionsConfig } from '../../src/types/configuration';

jest.mock('fs');
jest.mock('../../src/services/schemaValidator');
jest.mock('../../src/util/logger');

describe('PermissionsConfigReader', () => {
  let permissionsConfigReader: PermissionsConfigReader;

  const FILE_PATH = '/path/to/file';
  const FILE_JSON: PermissionsConfig = [{
    role: 'Role',
    authorisedEndpoints: [{
      httpVerb: 'GET',
      url: '/endpoint/one',
    }],
  }];
  const FILE_BUFFER = Buffer.from(JSON.stringify(FILE_JSON));

  beforeAll(() => {
    permissionsConfigReader = new PermissionsConfigReader(new SchemaValidator(), new Logger(''));
  });

  beforeEach(() => {
    jest.spyOn(fs, 'readFileSync').mockImplementation(() => FILE_BUFFER);
    (SchemaValidator.prototype as jest.Mocked<SchemaValidator>).validateJsonAgainstSchema.mockReturnValue(true);
  });

  afterEach(() => {
    jest.resetAllMocks();
  });

  describe('readConfigFile', () => {
    test('log and throw an error if reading file fails', () => {
      jest.spyOn(fs, 'readFileSync').mockImplementation(() => { throw new Error('Error reading config file'); });

      expect(() => permissionsConfigReader.readConfigFile(FILE_PATH)).toThrow(/Could not read permissions configuration file/);

      expect(Logger.prototype.info).toHaveBeenCalledWith('Error reading config file');
    });

    test('log and throw an error if schema validation returns false', () => {
      (SchemaValidator.prototype as jest.Mocked<SchemaValidator>).validateJsonAgainstSchema.mockReturnValue(false);

      expect(() => permissionsConfigReader.readConfigFile(FILE_PATH)).toThrow(/Could not read permissions configuration file/);

      expect(Logger.prototype.info).toHaveBeenCalledWith('Permissions configuration file does not match valid schema');
    });

    test('return a valid configuration read from the config file', () => {
      const permissionsConfig = permissionsConfigReader.readConfigFile(FILE_PATH);

      expect(permissionsConfig).toStrictEqual(FILE_JSON);
      expect(SchemaValidator.prototype.validateJsonAgainstSchema).toHaveBeenCalled();
    });
  });
});
