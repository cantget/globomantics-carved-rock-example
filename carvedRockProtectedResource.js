var express = require("express");
var bodyParser = require('body-parser');
var cons = require('consolidate');
var __ = require('underscore');
var cors = require('cors');
var jose = require('jsrsasign');
var base64url = require('base64url');

var app = express();

app.use(bodyParser.urlencoded({ extended: true })); // support form-encoded bodies (for bearer tokens)

app.engine('html', cons.underscore);
app.set('view engine', 'html');
app.set('views', 'files/protectedResource');
app.set('json spaces', 4);

app.use('/', express.static('files/protectedResource'));
app.use(cors());

var resource = {
    "name" : "Carved Rock Fitness",
    "description" : "Carved Rock Fitness Workout API"
}

var rsaKey = {
    "alg": "RS256",
    "e": "AQAB",
    "n": "p8eP5gL1H_H9UNzCuQS-vNRVz3NWxZTHYk1tG9VpkfFjWNKG3MFTNZJ1l5g_COMm2_2i_YhQNH8MJ_nQ4exKMXrWJB4tyVZohovUxfw-eLgu1XQ8oYcVYW8ym6Um-BkqwwWL6CXZ70X81YyIMrnsGTyTV6M8gBPun8g2L8KbDbXR1lDfOOWiZ2ss1CRLrmNM-GRp3Gj-ECG7_3Nx9n_s5to2ZtwJ1GS1maGjrSZ9GRAYLrHhndrL_8ie_9DS2T-ML7QNQtNkg2RvLv4f0dpjRYI23djxVtAylYK4oiT_uEMgSkc4dxwKwGuBxSO0g9JOobgfy0--FUHHYtRi0dOFZw",
    "kty": "RSA",
    "kid": "authserver"
  };

var getAccessToken = function(req, res, next) {
    var inToken = null;
    var auth = req.headers['authorization'];
    if (auth && auth.toLowerCase().indexOf('bearer') == 0) {
        inToken = auth.slice('bearer '.length);
    } else if (req.body && req.body.access_token) {
        inToken = req.body.access_token;
    } else if (req.query && req.query.access_token) {
        inToken = req.query.access_token;
    }

    console.log('Incoming token: %s', inToken);

	var pubKey = jose.KEYUTIL.getKey(rsaKey);
	var signatureValid = jose.jws.JWS.verify(inToken, pubKey, ['RS256']);
	if (signatureValid) {
		console.log('Signature validated.');
		var tokenParts = inToken.split('.');
		var payload = JSON.parse(base64url.decode(tokenParts[1]));
		console.log('Payload', payload);
		if (payload.iss == 'http://localhost:9003/') {
			console.log('issuer OK');
			if ((Array.isArray(payload.aud) && _.contains(payload.aud, 'http://localhost:9002/')) || 
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

app.options('/gymStats', cors());

var requireAccessToken = function(req, res, next) {
    if (req.access_token) {
        next();
    } else {
        res.status(401).end();
    }
}


app.get("/gymStats", getAccessToken, requireAccessToken, cors(), function(req, res){

    console.log("hit the gymStats API");

    var gymStats = {};
    if (__.contains(req.access_token.scope, 'visits')) {
        gymStats.visits = 120;
    }

    if (__.contains(req.access_token.scope, 'membershipTime')) {
        gymStats.membershipTime = 2;
    }

    if (__.contains(req.access_token.scope, 'averageWorkoutLength')) {
        gymStats.averageWorkoutLength = 1.5;
    }

    console.log('Sending gymStats: ', gymStats);

    res.json(gymStats);	
});

var server = app.listen(9002, 'localhost', function () {
  var host = server.address().address;
  var port = server.address().port;

  console.log('Carved Rock Resource Server is listening at http://%s:%s', host, port);
});