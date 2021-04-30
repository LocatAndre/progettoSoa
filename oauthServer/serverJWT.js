var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var cons = require('consolidate');
var nosql = require('nosql').load('database.nosql');
var sqlite3 = require('sqlite3').verbose();
var querystring = require('querystring');
var __ = require('underscore');
__.string = require('underscore.string');


var jose = require('jsrsasign'); //per la firma del token
const NodeRSA = require('node-rsa'); //per cifratura token

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'authorizationServer');
app.set('json spaces', 4);

// authorization server info
var authServer = {
	authorizationEndpoint: 'http://localhost:9001/authorize',
	tokenEndpoint: 'http://localhost:9001/token'
};

//qui devo generare io la chiave
//As an added exercise, generate your own JWK using a JOSE library and replace the one in the code here.
//sono chiavi a 2048 bit (la dimensione consigliata più piccola)
// d = k privata / e = parametro per la cifratura (potenza) /n = k pubblica
var rsaKey = {
	"alg": "RS256",
	"d": "ZXFizvaQ0RzWRbMExStaS_-yVnjtSQ9YslYQF1kkuIoTwFuiEQ2OywBfuyXhTvVQxIiJqPNnUyZR6kXAhyj__wS_Px1EH8zv7BHVt1N5TjJGlubt1dhAFCZQmgz0D-PfmATdf6KLL4HIijGrE8iYOPYIPF_FL8ddaxx5rsziRRnkRMX_fIHxuSQVCe401hSS3QBZOgwVdWEb1JuODT7KUk7xPpMTw5RYCeUoCYTRQ_KO8_NQMURi3GLvbgQGQgk7fmDcug3MwutmWbpe58GoSCkmExUS0U-KEkHtFiC8L6fN2jXh1whPeRCa9eoIK8nsIY05gnLKxXTn5-aPQzSy6Q",
	"e": "AQAB",
	"n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
	"kty": "RSA", //tipo di chiave
	"kid": "authserver" //id chiave
};
//converto la chiave rsa in un formato che la libreria (jose) può usare per le operazioni di cifratura
var privateKeyFirma = jose.KEYUTIL.getKey(rsaKey);


//chiave per cifratura token
//const key = new NodeRSA({b: 1024}) //chiave rsa 1024 bit
//dal file creato alla riga precedente facciamo l'export della coppia di chiavi, per usarle separatamente
//var publicKeyEnc = key.exportKey('public');

//const key = new NodeRSA({b: 1024});

//var publicKeyEnc = key.exportKey('public');
//var publicKeyEnc = key.exportKey('private');


public_k = '-----BEGIN PUBLIC KEY-----\n' +
	'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCvhNH7mlRbScBZZGYl38tTfm/x\n' +
	'gG6EY5lOqhsWCT2vR3jY/IadTLDuXkgnWXhuLKsy8wgLPnR/32KH9EkWDEIwgiWm\n' +
	'1PjhcegBYd8caP+qxGio75wL/nDaK5gZDyjerA3L1JiyeXGj+mZ2Z22adyHoxaV1\n' +
	'8UZSKS97GkjNRry0LwIDAQAB\n' +
	'-----END PUBLIC KEY-----\n';


var publicKeyEnc = new NodeRSA(public_k);
console.log('chiave privata: ' + publicKeyEnc);


var newdb = new sqlite3.Database('myNewDb.db');

newdb.get("PRAGMA foreign_keys = ON")

newdb.run(
	'CREATE TABLE IF NOT EXISTS ClientInformation(clientId string PRIMARY KEY,clientSecret string NOT NULL,redirectUri string NOT NULL,scope string)'
);

newdb.run(
	'CREATE TABLE IF NOT EXISTS UserInformation(username string PRIMARY KEY,password string NOT NULL)'
);

newdb.run(
	'CREATE TABLE IF NOT EXISTS Request(reqId string PRIMARY KEY,clientId string,responseType string NOT NULL,redirectUri string NOT NULL,scope string, state string NOT NULL, FOREIGN KEY (clientId) REFERENCES ClientInformation (clientId))'
);


newdb.run(
	'CREATE TABLE IF NOT EXISTS Code(authCode string PRIMARY KEY, clientId string, scope string, FOREIGN KEY (clientId) REFERENCES ClientInformation (clientId))'
);


newdb.run(
	'CREATE TABLE IF NOT EXISTS Token(clientId string, accessToken string, PRIMARY KEY(clientId, accessToken), FOREIGN KEY (clientId) REFERENCES ClientInformation (clientId))'
);

newdb.run(
	'CREATE TABLE IF NOT EXISTS RefreshToken(clientId string, refreshToken string, PRIMARY KEY(clientId, refreshToken), FOREIGN KEY (clientId) REFERENCES ClientInformation (clientId))'
);

/*
var clientToDelete = 'oauth-client-1';

newdb.run('DELETE FROM ClientInformation WHERE clientId=?', [clientToDelete], (err) =>{
	if(err){
		console.log('tupla non cancellata');
	}

	console.log('tupla cancellata con successo');
});*/

newdb.run('INSERT INTO clientInformation(clientId,clientSecret,redirectUri,scope) VALUES(?,?,?,?)', ['oauth-client-1', 'oauth-client-secret-1', 'http://localhost:9000/callback', 'foo bar'], (err) => {
	if (err) {
		return console.log('tupla non inserita');
	}
	console.log('tupla inserita con successo');
});


app.post("/clientRegistration", function (req, res) {

	var clientId = randomstring.generate(8);
	var clientSecret = randomstring.generate(8);

	var redirectUri = req.redirect_uri;
	var scope = req.scope;

	newdb.run('INSERT INTO ClientInformation(clientId,clientSecret,redirectUri,scope) VALUES(?,?,?,?)', [clientId, clientSecret, redirectUri, scope], (err) => {
		if (err) {
			return console.log('tupla non inserita');
		}

		console.log('le informazioni del client sono state inserite');
	});

	res.render('clientInfo', { clientId: clientId, clientSecret: clientSecret }); //qua devo capire che pagina renderizzare

	return;
});


app.post("/userRegistration", function (req, res) {

	var email = req.body.email;
	var password = req.body.password1;

	console.log(email, password)

	var newdb = new sqlite3.Database('myNewDb.db');

	newdb.run('INSERT INTO UserInformation(username,password) VALUES(?,?)', [email, password], (err) => {
		if (err) {
			return console.log('tupla non inserita');
		}

		console.log('le informazioni dell\'utente sono state inserite');
	});

	return res.render('login');

});

app.get("/login", function (req, res) {

	return res.render('login.html')

});

app.post("/authorize", function (req, res) {

	var newdb = new sqlite3.Database('myNewDb.db');
	/*dobbiamo capire chi è il client che fa richiesta,
	quindi consideriamo il parametro client_id che dovrà essere presente
	nella richiesta stessa. client_id lo consideriamo pubblico dato che viene
	passato dal browser nella richiesta*/

	var reqclient = req.query.client_id;
	var requri = req.query.redirect_uri;
	var reqscope = req.query.scope;

	console.log('il client id della richiesta è: ' + reqclient);
	console.log('il redirect uri della richiesta è: ' + requri);
	console.log('lo scope nella richiesta è: ' + reqscope);


	newdb.get('SELECT clientId, redirectUri, scope FROM ClientInformation WHERE clientId=?', [reqclient], (err, row) => {

		if (err) {
			return console.log('errore nella query');
		}

		if (row.clientId != reqclient) {
			console.log('il client in tabella è: %s', row.clientId)
			console.log('client %s sconosciuto', reqclient);
			res.render('error', { error: 'client sconosciuto' });
			return;
		}

		if (row.redirectUri != requri) {
			console.log('\'uri in tabella è: %s', row.redirectUri)
			console.log('uri %s sconosciuto', requri);
			res.render('error', { error: 'client sconosciuto' });
			return;
		}

		var rscope = reqscope ? reqscope.split(' ') : undefined; // array di scope a cui è stato richiesto l'accesso
		var cscope = row.scope ? row.scope.split(' ') : undefined; //array di scope associati al client 

		if (__.difference(rscope, cscope).length > 0) {

			console.log('super mannaggia scope cannato');

			var urlParsed = buildUrl(req.query.redirect_uri, {
				error: 'scope non valido'
			});

			res.redirect(urlParsed);
			return;
		}

		var reqid = randomstring.generate(8);

		var responseType = req.query.response_type;
		var stato = req.query.state;


		newdb.run('INSERT INTO Request(reqId,clientId,responseType,redirectUri,scope,state) VALUES(?,?,?,?,?,?)', [reqid, reqclient, responseType, requri, reqscope, stato], (err) => {
			if (err) {
				return console.log('tupla non inserita');
			}

			console.log('la richiesta è stata inserita');

		});

		res.render('approve', { client: reqclient, reqid: reqid, scope: rscope });

		return;
	});
});



app.post('/approve', function (req, res) {

	var newdb = new sqlite3.Database('myNewDb.db');

	var reqIdCheck = req.body.reqid;

	/*qui controlliamo che il reqid che si trova nel corpo della post del client sia uguale a quello
	che avevamo memorizzato*/

	newdb.get('SELECT reqId, clientId, responseType, redirectUri, scope, state FROM Request WHERE reqId=?', [reqIdCheck], (err, row) => {

		if (err) {
			return console.log('errore nella query di inserimento richiesta');
		}

		else if (row.reqId != reqIdCheck) {
			console.log('Il request id è: ' + row.reqId);
			console.log('Il request id della richiesta è: ' + reqIdCheck);
			res.render('error', { error: 'non è stata trovata alcuna richiesta di autorizzazione corrispondente' });
			return;
		}

		else {
			console.log('Il request id è: ' + row.reqId);
			console.log('richiesta riconosciuta');

			var requestToDelete = row.reqId

			newdb.run('DELETE FROM Request WHERE clientId=?', [requestToDelete], (err) => {
				if (err) {
					console.log('tupla non cancellata');
				}

				console.log('tupla cancellata con successo da Request');
			});

		}

		//qui se l'utente clicca "approve"
		if (req.body.approve) {
			/*dobbiamo controllare se il response type è di tipo code perché stiamo
			implementando il protocollo con il flusso authorization code, quindi il tipo
			code è l'unico che supportiamo. Qui sotto generiamo l'authorization code,
			che poi il client dovrà inviare al token endpoint dell'authorization server
			per ricevere l'access token*/

			if (row.responseType == 'code') {

				console.log('il responseType è di tipo code');

				var bodyScope = getScopesFromForm(req.body);
				//var quasiRscope = JSON.stringify(bodyScope);
				//var stringa = JSON.parse(quasiRscope);
				console.log('l\'rscope nel body è: ' + bodyScope);

				var rscopeS = bodyScope.toString().replace(",", " ");

				//var cscopeS = row.scope.toString();
				cscopeS = row.scope;

				//converto in array perché __.difference confronta gli array
				var rscope = Array.from(rscopeS);
				var cscope = Array.from(cscopeS);

				console.log('l\'rscope è: ' + rscope);
				console.log('il cscope è: ' + cscope);


				// VEDI underscore.js (libreria) per funzione __.difference()
				if (__.difference(rscope, cscope).length > 0) {
					console.log('la differenza di lunghezza è:' + __.difference(rscope, cscope).length);

					var urlParsed = buildUrl(row.redirectUri, {
						error: 'scope non valido'
					});

					res.redirect(urlParsed);
					return;
				}

				/*memorizziamo l'authorization code in codes, così potremo recuperarlo
				quando il client chiederà il token di accesso presentanto l'authorization code
				che gli stiamo mandando. Se il codice presentato dal client per ottenere il token
				è uguale a quello che abbiamo memorizzato allora tutto a posto*/

				var code = randomstring.generate(8);

				newdb.run('INSERT INTO Code(authCode,clientId,scope) VALUES(?,?,?)', [code, row.clientId, cscopeS], (err) => {
					if (err) {
						return console.log('tupla non inserita');
					}

					console.log('il codice è stato inserito');

				});


				console.log("lo stato salvato è: " + row.state);
				var stateS = row.state.toString();

				var urlParsed = buildUrl(row.redirectUri, {
					code: code,
					/*mandiamo al client anche lo stato perché se il client lo invia
					nella sua richiesta allora il server è obbligato a rinviarlo
					-----------------

					NON SO SE SIA GIUSTO MANDARE LO STATO DELLA RICHIESTA SALVATA, perché prima era
					come sotto*/
					//state: req.query.state 
					state: stateS
				});

				res.redirect(urlParsed);
				return;

			}

			else {
				console.log('il responseType è:' + row.responseType);

				var urlParsed = buildUrl(row.redirectUri, {
					error: 'response_type non supportato'
				});

				res.redirect(urlParsed);
				return;
			}
		}

		//qui se l'utente clicca "deny"
		else { /*il client viene rediretto verso il redirect_uri indicato nella primissima richiesta
				e viene mostrato il messaggio d'errore*/
			var urlParsed = buildUrl(row.redirectUri, {
				error: 'accesso negato'
			});
			res.redirect(urlParsed);
			return;
		}
	})

});

// -------------------- FINO A QUI TUTTO BENE

//token endpoint che si aspetta una post dal client (contenente l'authorization code)

app.post("/token", function (req, res) {
	console.log('sono al tokenEndpoint');
	/*qui autentichiamo il client per vedere se la richiesta del token è legittima.
		Quindi controlliamo che il client_id e il client_secret siano validi.
		Tali parametri sono accettati sia che vengano passati tramite HTTP basic authentication
		che tramite form (vedi pagina 83).
		Si controlla prima l'authorization header, dato che è il metodo preferito dalla specifica di
		OAuth per il passaggio di questi parametri. L'authorization header in HTTP è una stringa in 
		base64, composta dalla concatenzazione di username e password (separati da :). OAuth usa il
		client_id come username e il client_secret come password.*/
	var newdb = new sqlite3.Database('myNewDb.db');

	var auth = req.headers['authorization'];
	if (auth) {
		var clientCredentials = decodeClientCredentials(auth);
		var client = clientCredentials.id;
		var clientSecret = clientCredentials.secret;
	}

	/*Se il client ha inviato client_id e client_secret nell'authorization header, il body 
	della richiesta va comunque controllato. Infatti, se le informazioni fossero presenti
	anche qui, questo porterebbe ad un errore e ad un possibile security breach (non capisco
	bene il perché)*/
	if (req.body.client_id) {
		if (client) {
			console.log('il client ha tentato di autenticarsi con metodi multipli');
			res.status(401).json({ error: 'client non valido' });
			return;
		}
	}


	//qui controllo che il client che richiede l'access token sia un client valido
	newdb.get('SELECT clientId, clientSecret FROM ClientInformation WHERE clientId=?', [client], (err, row) => {

		if (err) {
			return console.log('errore nella query al token endpoint');
		}

		if (!row.clientId) {
			console.log('client %s sconosciuto', clientId);
			res.status(401).json({ error: 'client non valido' });
			return;
		}

		if (row.clientSecret != clientSecret) {
			console.log('Atteso client secret %s, ottenuto client secret %s', row.clientSecret, clientSecret);
			res.status(401).json({ error: 'client non valido' });
			return;
		}
	});


	if (req.body.grant_type == 'authorization_code') {

		/* recuperiamo l'authCode in base al clientId che ha fatto la richiesta per il token, per vedere se quel client ha effettivamente
		ottenuto un authorization code dal server precedentemente*/
		var clientCredentials = decodeClientCredentials(auth);
		var clientCred = clientCredentials.id;

		console.log('il client di clientCredentials è: ' + clientCred);

		var newdb = new sqlite3.Database('myNewDb.db');

		newdb.get('SELECT authCode, clientId, scope FROM Code WHERE clientId=?', [clientCred], (err, row) => {

			if (err) {
				return console.log('errore nella seconda query del tokenEndpoint');
			}

			console.log(row.authCode);

			if (row.authCode) {

				/*possiamo controllare che l'authorization code inviato tramite la post al token endpoint sia stato
			generato proprio per il client che lo ha inviato. Se così fosse allora possiamo generare
			l'authorization token*/
				if (row.clientId == clientCred) {
					/*IMPORTANTE + DATABASE vedere pagina 85 capitolo 11 per la memorizzazione del token.
				Non ci sta memorizzarlo in chiaro.
				Inoltre, dovremmo aggiungere un expiration_date al token (che quindi il 
				resource server dovrà controllare. Il parametro expires_in dovrà essere inviato
				al client insieme al token ovviamente). L'expiration_date si riferisce solo
				all'access_token, non al refresh_token, che di norma dura di più (quando scade
				il client deve fare il procedimento da capo ottenendo l'authorization code). 
				I token possono anche essere revocati, per ciclo vitale token vedi capitolo 11

				Nel nostro caso il token è una stringa casuale senza alcuna struttura interna. 
				Poi però dovrò trasformarlo in un token JWT (vedo capitolo 11)*/

					//var access_token = randomstring.generate();

					//creo token JWT
					var header = { 'typ': 'JWT', 'alg': rsaKey.alg, 'kid': rsaKey.kid }; //kid è l'id della chiave

					var payload = {
						iss: 'http://localhost:9001/', //token issuer
						sub: clientCred, //utente a cui si riferisce il token
						aud: 'http://localhost:9002/', //token audience, cioè chi dovrebbe processare il token
						iat: Math.floor(Date.now() / 1000), //momento di emissione del token
						exp: Math.floor(Date.now() / 1000) + (5 * 60), //scadenza del token (scade in 5 minuti)
						jti: randomstring.generate(8) //identificativo del token 
					};

					//la parte del token dopo l'ultimo punto sarà la firma del token (fatta con la k privata dell'auth server)
					var access_token = jose.jws.JWS.sign(header.alg, JSON.stringify(header), JSON.stringify(payload), privateKeyFirma);

					console.log('access token non cifrato: ' + access_token);

					access_token = publicKeyEnc.encrypt(access_token, 'base64'); //access_token cifrato codifica base64
					console.log('l\'access token JWT cifrato emesso è il seguente: ' + access_token);


					/*creiamo anche un refresh token, che sarà utile al client per ottenere un nuovo
					access token senza dover rifare tutto il procedimento coinvolgengo l'utente*/
					var refresh_token = randomstring.generate();
					refresh_token = publicKeyEnc.encrypt(refresh_token, 'base64'); //cifro il refresh_token

					newdb.run('INSERT INTO Token(clientId,accessToken) VALUES(?,?)', [client, access_token], (err) => {
						if (err) {
							return console.log('tupla non inserita');
						}

						console.log('l\'access token è stato inserito');
						console.log('emesso access token %s con successo', access_token);

					});

					newdb.run('INSERT INTO RefreshToken(clientId,refreshToken) VALUES(?,?)', [client, refresh_token], (err) => {
						if (err) {
							return console.log('tupla non inserita');
						}

						console.log('il refresh token è stato inserito');
						console.log('emesso refresh token %s con successo', refresh_token);

					});
					/*quando inviamo il token al client gli indichiamo la tipologia, 
				così che lui sappia come utilizzarlo per presentarlo al
				resource server. 
				Il nostro token è di tipo bearer e viene inviato al client in formato JSON*/

					var token_response = { access_token: access_token, token_type: 'Bearer', refresh_token: refresh_token, scope: row.scope };

					res.status(200).json(token_response);
					console.log('emessi access token e refresh token per code %s', row.authCode);

					newdb.run('DELETE FROM Code WHERE clientId=? and authCode=?', [row.clientId, row.authCode], (err) => {
						if (err) {
							console.log('tupla non cancellata');
						}

						console.log('tupla cancellata con successo da Code');
					});

					return;
				}

				else {
					console.log('Atteso client_id %s, ottenuto client_id %s', row.clientId, client);
					res.status(400).json({ error: 'invalid_grant' });
					return;
				}
			}

			else {
				console.log('code %s sconosciuto', row.authCode);
				res.status(400).json({ error: 'invalid_grant' });
				return;
			}

		});

	}

	else if (req.body.grant_type == 'refresh_token') {

		var clientCredentials = decodeClientCredentials(auth);
		var clientCred = clientCredentials.id;

		newdb.get('SELECT clientId, refreshToken FROM RefreshToken WHERE clientId=?', [clientCred], (err, row) => {

			if (err) {
				return console.log('errore nella query del refreshToken');
			}

			/*confrontiamo il refreshToken memorizzato con quello presente nella richiesta. 
			Inoltre, controlliamo che i clientId combacino, perché se fossero diversi si 
			potrebbe assumere che il refresh token sia stato compromesso e sia utilizzato
			da un client malevolo*/

			if (row.refreshToken != req.body.refresh_token || row.clientId != req.query.clientId) {

				newdb.run('DELETE FROM RefreshToken WHERE clientId=? and refreshToken=?', [row.clientId, row.refreshToken], (err) => {
					if (err) {
						console.log('tupla non cancellata');
					}

					console.log('tupla cancellata con successo da RefreshToken');
				});

				res.status(400).json({ error: 'invalid_grant' });
				return;
			}
			/*se il refresh_token va bene (è valido e inviato dal giusto client) allora
		generiamo un nuovo access_token e lo inviamo al client. Rinviamo anche il
		refresh_token, così il client potrà riutilizzarlo finché non sarà scaduto*/
			else {
				//qui delete access token prima di crearne uno nuovo
				newdb.get('SELECT accessToken FROM Token WHERE clientId=?', [clientCred], (err, row) => {

					if (err) {
						return console.log('errore nella query prima della cancellazione dell\'access token');
					}

					newdb.run('DELETE FROM Token WHERE clientId=? and accessToken=?', [clientCred, row.accessToken], (err) => {
						if (err) {
							console.log('tupla non cancellata');
						}

						console.log('tupla cancellata con successo da Token');
					});
				});


				//creo un altro access token JWT
				var header = { 'typ': 'JWT', 'alg': rsaKey.alg, 'kid': rsaKey.kid }; //kid è l'id della chiave

				var payload = {
					iss: 'http://localhost:9001/', //token issuer
					sub: clientCred, //utente a cui si riferisce il token
					aud: 'http://localhost:9002/', //token audience, cioè chi dovrebbe processare il token
					iat: Math.floor(Date.now() / 1000), //momento di emissione del token
					exp: Math.floor(Date.now() / 1000) + (5 * 60), //scadenza del token (scade in 5 minuti)
					jti: randomstring.generate(8) //identificativo del token 
				};


				//la parte del token dopo l'ultimo punto sarà la firma del token (fatta con la k privata dell'auth server)
				var new_access_token = jose.jws.JWS.sign(header.alg, JSON.stringify(header), JSON.stringify(payload), privateKeyFirma);
				new_access_token = publicKeyEnc.encrypt(new_access_token, 'base64');

				newdb.run('INSERT INTO Token(clientId,accessToken) VALUES(?,?)', [clientCred, new_access_token], (err) => {
					if (err) {
						return console.log('tupla non inserita');
					}

					console.log('l\'access token è stato inserito');
					console.log('emesso con successo un nuovo access token %s', new_access_token);

				});

				var token_response = { access_token: new_access_token, token_type: 'Bearer', refresh_token: row.refreshToken };
				res.status(200).json(token_response);

				return;
			}


		});


	}

	else {
		console.log('grant type %s sconosciuto', req.body.grant_type);
		res.status(400).json({ error: 'grant_type non supportato' });
	}

});


var buildUrl = function (base, options, hash) {
	var newUrl = url.parse(base, true);
	delete newUrl.search;
	if (!newUrl.query) {
		newUrl.query = {};
	}
	__.each(options, function (value, key, list) {
		newUrl.query[key] = value;
	});
	if (hash) {
		newUrl.hash = hash;
	}

	return url.format(newUrl);
};

var decodeClientCredentials = function (auth) {
	var clientCredentials = Buffer.from(auth.slice('basic '.length), 'base64').toString().split(':');
	var clientId = querystring.unescape(clientCredentials[0]);
	var clientSecret = querystring.unescape(clientCredentials[1]);
	return { id: clientId, secret: clientSecret };
};

var getScopesFromForm = function (body) {
	return __.filter(__.keys(body), function (s) { return __.string.startsWith(s, 'scope_'); })
		.map(function (s) { return s.slice('scope_'.length); });
};

app.use('/', express.static('authorizationServer'));


var server = app.listen(9001, 'localhost', function () {
	var host = server.address().address;
	var port = server.address().port;

	console.log('OAuth Authorization Server is listening at http://%s:%s', host, port);
});


newdb.close();
