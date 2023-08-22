import { array, string, type } from 'io-ts';

export const PERMISSIONS_FILE_SCHEMA = array(
  type({
    role: string,
    authorisedEndpoints: array(
      type({
        httpVerb: string,
        url: string,
      }),
    ),
  }),
);
