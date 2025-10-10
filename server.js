require('dotenv').config();
const port = process.env.PORT || 443;
const express = require('express');
const https = require('https');
const app = express();
const fs = require('fs');
const crypto = require('crypto');
const cookieSession = require('cookie-session');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

const httpsOptions = {
    key: fs.readFileSync('./ssl/privatekey.pem'),
    cert: fs.readFileSync('./ssl/fullchain.pem')
};

// Load users
let users = [
    {
        "uname": "pineapple",
        "password": "passwd123", // Hashed and salted
        "salt": "afc3dFxCRNdisPIL", // Random 16 digit salt
        "email": "pineapple_cherry@mymailservice.pn",
        "public_key": "abc", // Each user has a public key
        "private_key": "abc", // Users can (optionally) store the
        // password-protected private keys here
        "2fa_key": "abc", // Encrypt with server key
        "lang": "es",
        "display_name": "Mx. Pinapple"
    }
];
users = fs.existsSync('./data/users.json') ?
    fs.readFileSync('./data/users.json') : [];
sesiones = fs.existsSync('./data/sesiones.json') ?
    fs.readFileSync('./data/sesiones.json') : {};

// Load locale files
let loc_global = {};
function refreshLangFiles() {
    loc_global['es'] = JSON.parse(fs.readFileSync(`locale/es.json`)
        .toString());
}
refreshLangFiles();

// Functions
function loadWebpage(filename, req, data) {
    let webpage = fs.readFileSync(filename).toString();

    // Insert data
    for (key in data) {
        webpage = webpage.replaceAll(key, data[key]);
    }

    // Get correct locale
    locale = 'es';

    // Localise
    webpage = translate(webpage, locale);

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

function translate(text, locale) {
    // Ge the locale file
    let loc = loc_global['es'];
    // Insert data
    for (key in loc) {
        text = text.replaceAll('\\!!' + key + '!!\\', loc[key]);
    }
    // Return translated text
    return text;
}

function generateUser(uname, passwd, email, pubkey, lang, display_name) {
    let salt = saltGen(16);
    passwd = calculateSha256(passwd + salt);
    return {
        "uname": uname,
        "password": passwd, // Hashed and salted
        "salt": salt, // Random 16 digit salt
        "email": email,
        "public_key": pubkey, // Each user has a public key
        "private_key": undefined, // Users can (optionally) store the
        // password-protected private keys here
        "2fa_key": undefined, // Encrypt with server key
        "lang": (lang !== undefined) ? lang : 'es',
        "display_name": display_name
    }
}

function getUserByUsername(uname) {
    for (user in users) {
        if (users[user]['uname'] === uname) {
            return user;
        }
    }
}

function gen2FAKey() {
    // Generate a secret key
    const secretKey = speakeasy.generateSecret({ length: 20 });

    return secretKey['base32'];
}

function verifyOTP(otp) {
    const verified = speakeasy.totp.verify({
      secret: key,
      encoding: "base32",
      token: otp,
    });
    return verified;
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
    if (getLoggedInUser(req) === undefined) {
        res.send(loadWebpage('index.html', req, {}));
        return;
    }
    if (users[getLoggedInUser(req)]['2fa_key'] === undefined) {
        res.send(loadWebpage('2fa.html', req, {}));
        return;
    }
    if (users[getLoggedInUser(req)]['public_key'] === undefined) {
        res.send(loadWebpage('createUserKeypair.html', req, {}));
        return;
    }
    res.send(loadWebpage('chat.html', req, {}));
});

app.get('/login', (req, res) => {
    res.send(loadWebpage('login.html', req, {}));
});

app.post('/login', (req, res) => {
    res.send('/');
});

app.get('/registrar', (req, res) => {
    res.send(loadWebpage('registrar.html', req, {}));
});

app.post('/registrar', (req, res) => {
    let uname = req.body.uname;
    if (uname == undefined || uname.length == 0) {
        res.send(translate('\\!!registro.err.nombre_vacío!!\\','es'));
        return;
    }
    let passwd = req.body.passwd;
    if (passwd == undefined || passwd.length == 0) {
        res.send(translate('\\!!registro.err.contraseña_vacía!!\\','es'));
        return;
    }
    let correo = req.body.correo;
    if (correo == undefined || correo.length == 0 || !correo.includes('@')) {
        res.send(translate('\\!!registro.err.correo_inválido!!\\','es'));
        return;
    }
    let clavepublica = req.body.clavepublica;
    if (clavepublica == undefined || clavepublica.length == 0) {
        res.send(translate('\\!!registro.err.clave_pública_vacía!!\\','es'));
        return;
    }
    let display_name = req.body.display_name;
    if (clavepublica == undefined || clavepublica.length == 0) {
        display_name = uname;
    }
    let user = generateUser(uname, passwd, correo, clavepublica, 'es',
        display_name);
    users.push(user);
    let sid = saltGen();
    let i = 0;
    while (sid in sesiones) {
        i++;
        if (i >= 100) {
            res.send(translate('\\!!registro.err.sin_sid_disponible!!\\', 'es'));
            return;
        }
        sid = saltGen();
    }
    req.session.sessionId = sid;
    sesiones[sid] = getUserByUsername(uname);
    res.redirect('/configurarA2F');
    passwd = undefined;
});

app.get('/style.css', (req, res) => {
    res.sendFile(__dirname + '/style.css');
});

app.get('/assets/fonts/linjalipamanka-normal.woff', (req, res) => {
    res.sendFile(__dirname + '/assets/fonts/linjalipamanka-normal.woff');
});

app.get("/qrgen/:contents", async (req, res) => {
    try {
        const contents = req.params.contents;
        
        // Generate QR code as PNG buffer
        const qrBuffer = await QRCode.toBuffer(contents, {
            type: "png",
            margin: 1,
            width: 300
        });
        
        // Establece el tipo de contenido como image/png para poderlo cargar
        res.setHeader("Content-Type", "image/png");
        res.send(qrBuffer);
    } catch (err) {
        res.status(500).send("Error generando código QR");
    }
});

app.get("/otpqrgen/:label", async (req, res) => {
    try {
        const label = req.params.label;           // e.g. "miusuario"
        const issuer = req.query.issuer || "Mensajeador";
        const secret = req.query.secret;          // REQUERIDO

        if (!secret) {
            return res.status(400).send("Falta ?secret=BASE32SECRET");
        }

        // Haz el URL otpauth the speakeasy
        const otpauthUrl = speakeasy.otpauthURL({
            secret,
            label,
            issuer,
            encoding: "base32"
        });

        // Convierte el código QR a un buffer PNG
        const qrBuffer = await QRCode.toBuffer(otpauthUrl, {
            type: "png",
            margin: 1,
            width: 300
        });

        res.setHeader("Content-Type", "image/png");
        res.send(qrBuffer);
    } catch (err) {
        console.error(err);
        res.status(500).send("Error generando el código QR");
    }
});

// Endpoints administrativos
app.get('/admin/refreshLangFiles', (req, res) => {
    refreshLangFiles();
    res.redirect('/');
});

const server = https.createServer(httpsOptions, app);

server.listen(port, () => {
    console.log(`Mensajeador corriendo en puerto ${port}`);
});