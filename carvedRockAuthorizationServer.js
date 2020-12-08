var express = require("express");
var url = require("url");
var bodyParser = require('body-parser');
var randomstring = require("randomstring");
var cons = require('consolidate');
var querystring = require('querystring');
var jose = require('jsrsasign');
var __ = require('underscore');
__.string = require('underscore.string');

var app = express();

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for the token endpoint)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/authorizationServer');
app.set('json spaces', 4);

// authorization server information
var authServer = {
	authorizationEndpoint: 'http://localhost:9003/authorize',
	tokenEndpoint: 'http://localhost:9003/token'
};

// client information
var clients = [
	{
		"client_id": "globomantics-client-1",
		"client_secret": "globomantics-client-secret-1",
        "redirect_uris": ["http://localhost:9000/callback"],
        "scope": "visits membershipTime averageWorkoutLength"
	}
];

var rsaKey = {
    "alg": "RS256",
    "d": "ZXFizvaQ0RzWRbMExStaS_-yVnjtSQ9YslYQF1kkuIoTwFuiEQ2OywBfuyXhTvVQxIiJqPNnUyZR6kXAhyj__wS_Px1EH8zv7BHVt1N5TjJGlubt1dhAFCZQmgz0D-PfmATdf6KLL4HIijGrE8iYOPYIPF_FL8ddaxx5rsziRRnkRMX_fIHxuSQVCe401hSS3QBZOgwVdWEb1JuODT7KUk7xPpMTw5RYCeUoCYTRQ_KO8_NQMURi3GLvbgQGQgk7fmDcug3MwutmWbpe58GoSCkmExUS0U-KEkHtFiC8L6fN2jXh1whPeRCa9eoIK8nsIY05gnLKxXTn5-aPQzSy6Q",
    "e": "AQAB",
    "n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
    "kty": "RSA",
    "kid": "authserver"
  };

var refreshTokens = {};

var accessTokens = [];

var codes = {};

var requests = {};

var getClient = function(clientId) {
	return __.find(clients, function(client) { return client.client_id == clientId; });
};

app.get('/', function(req, res) {
	res.render('index', {clients: clients, authServer: authServer});
});

app.get("/authorize", function(req, res){
	
    var client = getClient(req.query.client_id);
    
	if (!client) {
		res.render('error', {error: 'Unknown client'});
		return;
	} else if (!__.contains(client.redirect_uris, req.query.redirect_uri)) {
		res.render('error', {error: 'Invalid redirect URI'});
		return;
	} else {
        var rscope = req.query.scope ? req.query.scope.split(' ') : undefined;
        var cscope = client.scope ? client.scope.split(' ') : undefined;
        if (__.difference(rscope, cscope).length > 0) {
            var urlParsed = buildUrl(req.query.redirect_uri, {
                error: 'invalid_scope'
            });
            res.redirect(urlParsed);
            return;
        }
        
        // this could be the user session as well
	    var reqid = randomstring.generate(8);
	    requests[reqid] = req.query;

        res.render('approve', {client: client, reqid: reqid, scope: rscope});
        return;
    } 
	
});

app.post('/approve', function(req, res) {

	var reqid = req.body.reqid;
	var query = requests[reqid];
	delete requests[reqid];

	if (!query) {
		res.render('error', {error: 'No matching authorization request'});
		return;
	}

	if (req.body.approve) {

		if (query.response_type == 'code') {
            
            // user approved access
            var rscope = getScopesFromForm(req.body);
            var client = getClient(query.client_id);
            var cscope = client.scope ? client.scope.split(' ') : undefined;
            if (__.difference(rscope, cscope).length > 0) {
                var urlParsed = buildUrl(query.redirect_uri, {
                    error: 'invalid_scope'
                });
                res.redirect(urlParsed);
                return;
            }

			var code = randomstring.generate(8);

			codes[code] = { request: query, scope: rscope };

			var urlParsed = buildUrl(query.redirect_uri, {
				code: code,
				state: query.state
			});
			res.redirect(urlParsed);
			return;
			
		} else {
			var urlParsed = buildUrl(query.redirect_uri, {
				error: 'unsupported_response_type'
			});
			res.redirect(urlParsed);
		}

	} else {
		var urlParsed = buildUrl(query.redirect_uri, {
			error: 'access_denied'
		});
		res.redirect(urlParsed);
		return;
	}
	
});

app.post("/token", function(req, res){
	
	var auth = req.headers['authorization'];
	if (auth) {
		// check the auth header
		var clientCredentials = decodeClientCredentials(auth);
		var clientId = clientCredentials.id;
		var clientSecret = clientCredentials.secret;
	}
	
	// otherwise, check the post body
	if (req.body.client_id) {
		if (clientId) {
			// if we've already seen the client's credentials in the authorization header, this is an error
			console.log('Client attempted to authenticate with multiple methods');
			res.status(401).json({error: 'invalid_client'});
			return;
		}
		
		var clientId = req.body.client_id;
		var clientSecret = req.body.client_secret;
	}
	
	var client = getClient(clientId);
	if (!client) {
		console.log('Unknown client %s', clientId);
		res.status(401).json({error: 'invalid_client'});
		return;
	}
	
	if (client.client_secret != clientSecret) {
		console.log('Mismatched client secret, expected %s got %s', client.client_secret, clientSecret);
		res.status(401).json({error: 'invalid_client'});
		return;
	}
	
	if (req.body.grant_type == 'authorization_code') {
		
		var code = codes[req.body.code];
		
		if (code) {
			delete codes[req.body.code]; // burn our code, it's been used
			if (code.request.client_id == clientId) {
				
				var header = { 'typ': 'JWT', 'alg': rsaKey.alg, 'kid': rsaKey.kid };
				var payload = {
					iss: 'http://localhost:9003/',
					sub: "Carved Rock Member",
					aud: 'http://localhost:9002/',
					iat: Math.floor(Date.now() / 1000),
					exp: Math.floor(Date.now() / 1000) + (5 * 60),
                    jti: randomstring.generate(8),
                    scope: code.scope
				};
				
				var privateKey = jose.KEYUTIL.getKey(rsaKey);
				var access_token = jose.jws.JWS.sign(header.alg,
					JSON.stringify(header),
					JSON.stringify(payload),
                    privateKey);
                
                // save this to a database in production
                accessTokens.push({ access_token: access_token, client_id: clientId, scope: code.scope });

                var refreshToken = randomstring.generate();

                refreshTokens[refreshToken] = { clientId: clientId };

				console.log('Issuing access token %s', access_token);

				var token_response = { access_token: access_token, token_type: 'Bearer',  scope: code.scope.join(' '), refresh_token: refreshToken };

				res.status(200).json(token_response);
				console.log('Issued tokens for code %s', req.body.code);
				
				return;
			} else {
				console.log('Client mismatch, expected %s got %s', code.request.client_id, clientId);
				res.status(400).json({error: 'invalid_grant'});
				return;
			}
		

		} else {
			console.log('Unknown code, %s', req.body.code);
			res.status(400).json({error: 'invalid_grant'});
			return;
		}
	} else if (req.body.grant_type == 'refresh_token') {

        var token = refreshTokens[req.body.refresh_token];

			if (token) {
				console.log("We found a matching refresh token: %s", req.body.refresh_token);
				if (token.client_id != clientId) {
                    // token may have been compromised, remove it
                    delete refreshTokens[token];
					res.status(400).json({error: 'invalid_grant'});
					return;
                }

                var header = { 'typ': 'JWT', 'alg': rsaKey.alg, 'kid': rsaKey.kid };
				var payload = {
					iss: 'http://localhost:9003/',
					sub: "Carved Rock Member",
					aud: 'http://localhost:9002/',
					iat: Math.floor(Date.now() / 1000),
					exp: Math.floor(Date.now() / 1000) + (5 * 60),
                    jti: randomstring.generate(8),
                    scope: code.scope
				};
                
                var refreshToken = randomstring.generate();

				var privateKey = jose.KEYUTIL.getKey(rsaKey);
				var access_token = jose.jws.JWS.sign(header.alg,
					JSON.stringify(header),
					JSON.stringify(payload),
                    privateKey);
                
                // save this to a database in production
                accessTokens.push({ access_token: access_token, client_id: clientId, scope: code.scope});

                var token_response = { access_token: access_token, client_id: clientId, scope: code.scope, refresh_token: refreshToken };
                
				res.status(200).json(token_response);
				return;
			} else {
				console.log('No matching token was found.');
				res.status(400).json({error: 'invalid_grant'});
				return;
			}
	} else {
		console.log('Unknown grant type %s', req.body.grant_type);
		res.status(400).json({error: 'unsupported_grant_type'});
	}
});

var buildUrl = function(base, options, hash) {
	var newUrl = url.parse(base, true);
	delete newUrl.search;
	if (!newUrl.query) {
		newUrl.query = {};
	}
	__.each(options, function(value, key, list) {
		newUrl.query[key] = value;
	});
	if (hash) {
		newUrl.hash = hash;
	}
	
	return url.format(newUrl);
};

var decodeClientCredentials = function(auth) {
	var clientCredentials = Buffer.from(auth.slice('basic '.length), 'base64').toString().split(':');
	var clientId = querystring.unescape(clientCredentials[0]);
	var clientSecret = querystring.unescape(clientCredentials[1]);	
	return { id: clientId, secret: clientSecret };
};

var getScopesFromForm = function(body) {
	return __.filter(__.keys(body), function(s) { return __.string.startsWith(s, 'scope_'); })
				.map(function(s) { return s.slice('scope_'.length); });
};

app.use('/', express.static('files/authorizationServer'));

var server = app.listen(9003, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('Carved Rock Authorization Server is listening at http://%s:%s', host, port);
});
 
