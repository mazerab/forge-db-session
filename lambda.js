const getForgeSecrets = async () => {
	'use strict';
	let AWS = require('aws-sdk'),
    	endpoint = "https://secretsmanager.us-east-1.amazonaws.com",
    	region = "us-east-1",
    	secretName = "<your secret store name goes here>",
    	secret,
		binarySecretData;
	let FORGE_CLIENT_ID, FORGE_CLIENT_SECRET;
	console.info('Creating a Secrets Manager client ...');
	const client = new AWS.SecretsManager({ endpoint: endpoint, region: region });
	return new Promise((resolve, reject) => {
		client.getSecretValue({SecretId: secretName}, (err, data) => {
			if(err) {
				if(err.code === 'ResourceNotFoundException') {
					console.error(`The requested secret ${secretName} was not found`);
				} else if(err.code === 'InvalidRequestException') {
					console.error(`The request was invalid due to: ${err.message}`);
				} else if(err.code === 'InvalidParameterException') {
					console.error(`The request had invalid params: ${err.message}`);
				}
				reject(err);
			} else {
				// Decrypted secret using the associated KMS CMK
				// Depending on whether the secret was a string or binary, one of these fields will be populated
				if(data.SecretString !== "") {
					secret = data.SecretString;
					const secret_json = JSON.parse(secret);
					if (Object.keys(secret_json).length === 1) {
						FORGE_CLIENT_ID = Object.keys(secret_json)[0];
						FORGE_CLIENT_SECRET = Object.values(secret_json)[0];
						const appSecrets = { 
							ForgeClientID: FORGE_CLIENT_ID,
							ForgeClientSecret: FORGE_CLIENT_SECRET
						};
						console.info('Successfully retrieved the app secrets!');
						resolve(appSecrets);
					}
				} else {
					binarySecretData = data.SecretBinary;
					console.error('Unexpected binary data in secrets!');
					reject(Error('Unexpected binary data in secrets!'));
				}
			}
		});
	});
};

const getForgeToken = async (secrets) => {
	'use strict';
	const forgeSDK = require('forge-apis');
	return new Promise((resolve, reject) => {
		// Initialize the 2-legged oAuth2 Forge client
		const oAuth2TwoLegged = new forgeSDK.AuthClientTwoLegged(secrets['ForgeClientID'], secrets['ForgeClientSecret'], ['data:read', 'bucket:read'], true);
		oAuth2TwoLegged.authenticate()
			.then(function(credentials){
				console.info('Successfully authenticated to the Forge app!');
				resolve(credentials);
			}, function(err) {
				console.error(`Error retrieving credentials: ${JSON.stringify(err)}.`);
				reject(JSON.stringify(err));
		});
	});
};

const setForgeTokenInDb = async (credentials) => {
	'use strict';
	const AWS = require('aws-sdk');
	AWS.config.update({ region: 'us-east-1' });
	const ddb = new AWS.DynamoDB({ apiVersion: '2012-10-08' });
	const params = {
		TableName: 'ForgeAuthSession',
		Item: {
			'AccessToken': { S: credentials.access_token },
			'ExpiresAt': { S: credentials.expires_at.toString() }
		}
	}
	return new Promise((resolve, reject) => {
		ddb.putItem(params, function(err, data) {
			if(err) {
				console.error(JSON.stringify(err));
				reject(err);
			} else {
				console.info(`Successfully inserted ${JSON.stringify(params.Item)} in database!`);
				resolve('success');
			}
		});
	});
};

exports.handler = async (event, context, callback) => {
	'use strict';
	const secrets = await getForgeSecrets();
	const credentials = await getForgeToken(secrets);
	const dbInfo = await setForgeTokenInDb(credentials);
	if(dbInfo === 'success') {
		callback(null, 'Successfully stored Forge credentials in database!');
	} else {
		callback('Failed to store Forge auth credentials in database!');
	}
}


