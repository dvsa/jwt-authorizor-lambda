# JWT Authorizor Lambda

Lambda to act as an authorizer for API Gateway using JWT from multiple sources. Currently only supports Cognito and Azure.

## Custom permissions from configuration file

The lambda supports reading permissions for specified endpoints from a configuration file and building authorised policies based on this config.

For a given token, authorised endpoints listed in the config file for the token's role will be added to the returned authorised policy.

The application repository making use of the authoriser should store the configuration file in a location suitable to their repository structure. The application CI Build Job should be updated to produce a zip archive containing the configuration file. This should be uploaded to an S3 archive store. A [Lambda Layer](https://docs.aws.amazon.com/lambda/latest/dg/chapter-layers.html) should be created from this location in S3 to enable the authoriser to access the configuration file.

An example configuration file in the required format can be found [here](/configuration.example.json).

Example policy statements returned for this example are:

```
{
  Effect: 'Allow',
  Action: 'execute-api:Invoke',
  Resource: 'arn:aws:execute-api:eu-west-2:123456789012:/*/GET/api/endpoint/one/*',
},
{
  Effect: 'Allow',
  Action: 'execute-api:Invoke',
  Resource: 'arn:aws:execute-api:eu-west-2:123456789012:/*/POST/api/endpoint/two',
}
```

This functionality is toggled on and off using the `ENABLE_CONFIGURATION_FILE` environment variable. If this is disabled, permissions will be granted/denied to every endpoint hosted by the API.

### Error Scenarios

The lambda will error building custom permissions in the following scenarios:

- `ENABLE_CONFIGURATION_FILE` is set to `true` but `CONFIGURATION_FILE_PATH` is not set
- Permissions configuration file cannot be read from `CONFIGURATION_FILE_PATH` location
- Permissions configuration file is not of the required format

## Environment variables
The following environment variables need to be set for the lambda to function.

- `COGNITO_POOL_ID `
- `COGNITO_REGION`
- `AZURE_TENANT_ID`
- `AZURE_CLIENT_ID(_[0-9]+)?` - Allows either single client id or multiple
- `COGNITO_CLIENT_ID(_[0-9]+)?` - Allows either single client id or multiple

The following are optional environment variables which can be set.

- `IS_MOCK` - WARNING: Setting this to `true` will always return an authorised policy for any token (the token will not be verified).
- `ENABLE_CONFIGURATION_FILE` - Setting this to `true` will turn on functionality to build an authorised policy based on a permissions configuration file.
- `CONFIGURATION_FILE_PATH` - Location of permissions configuration file, read when `ENABLE_CONFIGURATION_FILE` is `true`.

## Development

### Requirements

- node v18.15.0
- [SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html)


### Build

- `npm i`
- `npm run build:dev`

### Watch

To watch for changes and automatically trigger a new build:
- `npm run watch:dev`


### Run Lambdas Locally

- Build the files first
- Create `env.json` file containing:
```json
{
  "ApiGatewayTokenAuthorizerEvent": {
    "COGNITO_POOL_ID": "",
    "COGNITO_REGION": "",
    "COGNITO_CLIENT_ID": "",
    "AZURE_TENANT_ID": "",
    "AZURE_CLIENT_ID": ""
  }
}
```
- If reading custom permissions from a config file, create the config `configuration.json` file at the root of the project and include the following env vars also:
```
  "ENABLE_CONFIGURATION_FILE": "true",
  "CONFIGURATION_FILE_PATH": "configuration.json",
```
- Create event file. An example for this is:
```json
{
  "authorizationToken": "Bearer {replace with real token}",
  "methodArn": "arn:aws:execute-api:eu-west-2:123456789012:/prod/POST/{proxy+}"
}
```
- Invoke the event: `npm run invoke -- --env-vars env.json -e event/file/path.json`


### Tests

- The [Jest](https://jestjs.io/) framework is used to run tests and collect code coverage
- To run the tests, run the following command within the root directory of the project: `npm test`
- Coverage results will be displayed on terminal and stored in the `coverage` directory
    - The coverage requirements can be set in `jest.config.js`


### Logging

By using a utility wrapper (`src/utility/logger`) surrounding `console.log`, the `awsRequestId` is output with every debug/info/warn/error message.
