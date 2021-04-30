var express = require("express");
var bodyParser = require('body-parser');
var cons = require('consolidate');
var base64url = require('base64url');
var cors = require('cors');
var jose = require('jsrsasign');

const NodeRSA = require('node-rsa'); //per cifratura token
private_k = '-----BEGIN RSA PRIVATE KEY-----\n' +
'MIICXAIBAAKBgQCvhNH7mlRbScBZZGYl38tTfm/xgG6EY5lOqhsWCT2vR3jY/Iad\n' +
'TLDuXkgnWXhuLKsy8wgLPnR/32KH9EkWDEIwgiWm1PjhcegBYd8caP+qxGio75wL\n' +
'/nDaK5gZDyjerA3L1JiyeXGj+mZ2Z22adyHoxaV18UZSKS97GkjNRry0LwIDAQAB\n' +
'AoGAdGKNXtoyL6pS6rPBbEHesIm5rxkrr4vfv6LafR05kv3Aq5mfpbSR6i4IiFcy\n' +
'nVPvXcR7xADw/U3iJyacRAty41+qBongyh+gdkt74qKVvMW6K03Y1e29K4MX4wQP\n' +
'oFs5BcZyerXKgflgfU0vTKOUegBSNXp0l+ZTZ4aVd/k9bMkCQQDkwCDNl2p7XY89\n' +
'wpCxhnJqcP1csztFS/S/g8pfzJJZ4Ryn4uYtScECcWrdnvoUxzq/2PW0FHEfvNYf\n' +
'ajRGQ+IDAkEAxG1c9Us1fUYJGF6zHLTDVpAYuFJUBYxbMm9JFUTcm3LwXcMTPWFU\n' +
'eAcyX3dBBfkF8fsNRku7Zook4H7/Rm+DZQJBAM5euvlf0jPr60+nmYxfJBf9ScZ4\n' +
'+E8DQJILHuegkqQ9n/GilVBkSpmeou+//hQCzXDJFpnZG1mrrm13DiQaF+sCQC8L\n' +
'Qkg9SwJF08fSZnNpl58Tw9fhX940T2M04/wEEhHo5UiPf/wjY2eb0aSrmxcjHRln\n' +
'VzaOzMMyMsLRp7Hm40ECQEWKpQEcCQj8aYjNxfVmTeB9oOk5/I6Ft4QyY92WmzfP\n' +
'2ZmRi/BLcWQitNB+eP6jS5AfEEyoOB5/mp7rHKVvIrU=\n' +
'-----END RSA PRIVATE KEY-----\n';

var privateKeyDec = new NodeRSA(private_k);
console.log('chiave decifratura: '+privateKeyDec);

var app = express();

app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for bearer tokens)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/protectedResource');
app.set('json spaces', 4);

app.use('/', express.static('files/protectedResource'));
app.use(cors());

var resource = {
	"name": "Protected Resource",
	"description": "This data has been protected by OAuth 2.0"
};

var protectedResources = {
		"resource_id": "protected-resource-1",
		"resource_secret": "protected-resource-secret-1"
};

var authServer = {
	introspectionEndpoint: 'http://localhost:9001/introspect'
};

var rsaKey = {
  "alg": "RS256",
  "e": "AQAB",
  "n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
  "kty": "RSA",
  "kid": "authserver"
};


var getAccessToken = function(req, res, next) {
	// check the auth header first
	var auth = req.headers['authorization'];
	var inToken = null;
	if (auth && auth.toLowerCase().indexOf('bearer') == 0) {
		inToken = auth.slice('bearer '.length);
	} else if (req.body && req.body.access_token) {
		// not in the header, check in the form body
		inToken = req.body.access_token;
	} else if (req.query && req.query.access_token) {
		inToken = req.query.access_token
	}
	
	console.log('Incoming token: %s', inToken);

	inToken = privateKeyDec.decrypt(inToken,'utf8');
	
	var tokenParts = inToken.split('.');
	var header = JSON.parse(base64url.decode(tokenParts[0]));
	var payload = JSON.parse(base64url.decode(tokenParts[1]));
	console.log('Payload', payload);

	var publicKey = jose.KEYUTIL.getKey(rsaKey);

	if (jose.jws.JWS.verify(inToken, 
			publicKey, 
			[header.alg])) {
	
		console.log('Signature validated');

		if (payload.iss == 'http://localhost:9001/') {
			console.log('issuer OK');
			if ((Array.isArray(payload.aud) && __.contains(payload.aud, 'http://localhost:9002/')) || 
				payload.aud == 'http://localhost:9002/') {
				console.log('Audience OK');
			
				var now = Math.floor(Date.now() / 1000);
			
				if (payload.iat <= now) {
					console.log('issued-at OK');
					if (payload.exp >= now) {
						console.log('expiration OK');
					
						console.log('Token valid!');
	
						req.access_token = payload;
					
					}
				}
			}
		}
	}
			
	next();
	return;
	
};

var requireAccessToken = function(req, res, next) {
	if (req.access_token) {
		next();
	} else {
		res.status(401).end();
	}
};


var savedWords = [];

app.options('/resource', cors());

app.post("/resource", cors(), getAccessToken, function(req, res){

	if (req.access_token) {
		res.json(resource);
	} else {
		res.status(401).end();
	}
	
});

var server = app.listen(9002, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('OAuth Resource Server is listening at http://%s:%s', host, port);
});

