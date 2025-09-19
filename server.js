const port = process.env.PORT || 443;
const express = require('express');
const https = require('https');
const app = express();
const fs = require('fs');
const crypto = require('crypto')
const cookieSession = require('cookie-session');

const httpsOptions = {
    key: fs.readFileSync('./ssl/privatekey.pem'),
    cert: fs.readFileSync('./ssl/fullchain.pem')
}

// Functions
function loadWebpage(filename, req, data) {
    let webpage = fs.readFileSync(filename).toString();

    // Insert data
    for (key in data) {
        webpage = webpage.replaceAll(key, data[key]);
    }

    // Return final webpage
    return webpage;
}

function calculateSha256(inputString) {
    const hash = crypto.createHash('sha256'); // Initialize a SHA256 hash object
    hash.update(inputString); // Feed the input string into the hash object
    return hash.digest('hex'); // Compute the hash digest and encode it in hexadecimal format
}

async function getLoggedInUser(req) {
    let session = req.session.sessionId;
    if (session) {
        let user = await client.get(`sessions:${session}`);
        return (user != null) ? user : undefined;
    } else {
        return undefined;
    }
}

function saltGen(len,characters) {
	if (len == null) {
		len = 16
	}
	if (characters == null) {
		characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
	}
	let res = '';
	let counter = 0;
	let charactersLength = characters.length;
    while (counter < len) {
        res += characters.charAt(Math.floor(Math.random() * charactersLength));
        counter += 1;
    }
    return res;
}

// Configure middleware
app.use(cookieSession({
    name: 'session',
    keys: [process.env.SESSION_KEY_1, process.env.SESSION_KEY_2],
    maxAge: 14 * 24 * 60 * 60 * 1000 // 14 days in ms
}));

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Primary endpoints
app.get('/', (req, res) => {
    loadWebpage('index.html', req, {});
})

const server = https.createServer(httpsOptions, app);

server.listen(port, () => {
    console.log(`Mensajeador corriendo en puerto ${port}`);
})