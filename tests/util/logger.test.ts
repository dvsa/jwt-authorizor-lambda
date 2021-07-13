import { Logger } from '../../src/util/logger';

describe('Test logger', () => {
  test('logger.debug() calls console.debug() with expected parameters', () => {
    const logger: Logger = new Logger('');
    console.debug = jest.fn();

    logger.debug('hello');

    expect(console.debug).toHaveBeenCalledWith(logger.logFormat, 'hello');
  });

  test('logger.info() calls console.info() with expected parameters', () => {
    const logger: Logger = new Logger('');
    console.info = jest.fn();

    logger.info('hello');

    expect(console.info).toHaveBeenCalledWith(logger.logFormat, 'hello');
  });

  test('logger.warn() calls console.warn() with expected parameters', () => {
    const logger: Logger = new Logger('');
    console.warn = jest.fn();

    logger.warn('hello');

    expect(console.warn).toHaveBeenCalledWith(logger.logFormat, 'hello');
  });

  test('logger.error() calls console.error() with expected parameters', () => {
    const logger: Logger = new Logger('');
    console.error = jest.fn();

    logger.error('hello');

    expect(console.error).toHaveBeenCalledWith(logger.logFormat, 'hello');
  });
});
