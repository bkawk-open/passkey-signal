#!/usr/bin/env node
import 'source-map-support/register';
import * as cdk from 'aws-cdk-lib';
import { PasskeySignalStack } from '../lib/passkey-signal-stack';
import { PasskeySignalEnclaveStack } from '../lib/passkey-signal-enclave-stack';

const app = new cdk.App();

const env = {
  account: '238576302016',
  region: 'us-east-1',
};

const mainStack = new PasskeySignalStack(app, 'PasskeySignalStack', { env });

new PasskeySignalEnclaveStack(app, 'PasskeySignalEnclaveStack', {
  env,
  vpc: mainStack.vpc,
  lambdaSecurityGroup: mainStack.lambdaSecurityGroup,
});
