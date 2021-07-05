# JWT Authorizor Lambda

Lambda to act as an authorizer for API Gateway using JWT from multiple sources. Currently only supports Cognito and Azure.

## Environment variables
The following environment variables need to be set for the lambda to function.

- `COGNITO_POOL_ID `
- `COGNITO_REGION`
- `COGNITO_CLIENT_ID`
- `AZURE_TENANT_ID`
- `AZURE_CLIENT_ID`


## Development

### Requirements

- node v12.18.3
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
