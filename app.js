var express = require('express');
var bodyParser = require('body-parser');
var app = express();
var exec = require('child_process').exec;

const crypto = require('crypto');

const ACCEPTED_HASH = ['sha1', 'sha256'];
const SECRET = require('./secrets').whSecret;

/**
 * 
 * @param {Request} req 
 * @param {Response} res 
 * @param {()=>void} next 
 */
function verifyAndParse(req, res, next) {
	if (!req.headers['x-hub-signature']) {
		res.sendStatus(401);
		return;
	}
	const [hashMethod, theirSigHash] = req.headers['x-hub-signature'].toLowerCase().split('=');
	if(!theirSigHash || !ACCEPTED_HASH.includes(hashMethod)) {
		res.sendStatus(401);
		return;
	}
	const hmac = crypto.createHmac(hashMethod, SECRET);
	hmac.update(req.body);
	const ourSigHash = hmac.digest('hex');
	if(ourSigHash.toLowerCase() !== theirSigHash) {
		res.sendStatus(401);
		return;
	}
	req.body = JSON.parse(req.body.toString())
	next()
}

app.use(bodyParser.raw({type: '*/*'}))

app.get('/payload', function (req, res) {
    res.sendStatus(405);
	console.log('get /payload');
});

app.post('/payload',
	verifyAndParse,
	function (req, res) {
		let branch;
		const repository = req.body.repository.full_name;
		try {
			console.log(req.body.pusher.name + ' just pushed to ' + req.body.repository.full_name);
			[,branch] = req.body.ref.match(/^refs\/heads\/(.+)$/);
		} catch (err) {
			console.error(err);
			res.sendStatus(400);
		}
		const cBranch = branch.replace(/\//g, '');
		exec(`./scripts/${repository}/${cBranch}.sh`, (err, stdout, stderr)=>execCallback(req,res,{err,stdout,stderr}));
	}
);

const PORT = process.env.PORT || 5001;

app.listen(PORT, function () {
	console.log(`listening on port ${PORT}`);
});

function execCallback(req, res, {err, stdout, stderr}) {
	if(stdout) console.log(stdout);
	if(stderr) console.log(stderr);
	if(err) {
		console.error(err);
		res.sendStatus(500);
		return;
	}
	res.sendStatus(200);
}