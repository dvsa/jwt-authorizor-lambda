const CopyPlugin = require('copy-webpack-plugin');
const { merge } = require('webpack-merge');
const common = require('./webpack.common.js');

module.exports = merge(common, {
  mode: 'development',
  devtool: 'source-map',
  plugins: [
    new CopyPlugin({
      patterns: [{ from: './configuration.json', to: `.aws-sam/build/ApiGatewayTokenAuthorizerEvent/`, noErrorOnMissing: true }],
    }),
  ],
});
