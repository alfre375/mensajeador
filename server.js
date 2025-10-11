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
const CryptoJS = require('crypto-js');
const twoWeeks = 1000 * 60 * 60 * 24 * 14;

const httpsOptions = {
    key: fs.readFileSync('./ssl/privatekey.pem'),
    cert: fs.readFileSync('./ssl/fullchain.pem')
};

// Load users
var users = [
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
    JSON.parse(fs.readFileSync('./data/users.json').toString()) : [];
var sesiones = fs.existsSync('./data/sesiones.json') ?
    JSON.parse(fs.readFileSync('./data/sesiones.json').toString()) : {};

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
        webpage = webpage.replaceAll('<!--'+key+'-->', data[key]);
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

function getLoggedInUser(req) {
    let session = req.session.sessionId;
    if (session) {
        if (sesiones[session]['expiry'] > new Date().getTime()) {
            delete sesiones[session];
            return undefined;
        }
        let user = sesiones[session]['user'];
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

function verifyOTP(otp, key) {
    const verified = speakeasy.totp.verify({
      secret: key,
      encoding: "base32",
      token: otp,
    });
    return verified;
}

function encryptAES(data, key) {
    return CryptoJS.AES.encrypt(data, key).toString();
}

function decryptAES(encryptedData, key) {
    const bytes = CryptoJS.AES.decrypt(encryptedData, key);
    return bytes.toString(CryptoJS.enc.Utf8);
}

// Configure middleware
app.use(cookieSession({
    name: 'session',
    keys: [process.env.SESSION_KEY_1 || 'sk1', process.env.SESSION_KEY_2 || 'sk2'],
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
        res.send(translate('\\!!general.debes_configurar_a2f!!\\','es'));
        return;
    }
    if (users[getLoggedInUser(req)]['public_key'] === undefined) {
        res.send(loadWebpage('createUserKeypair.html', req, {}));
        return;
    }
    res.send(loadWebpage('chat.html', req, {}));
});

app.get('/configurarA2F', (req, res) => {
    let mfa_key = gen2FAKey();
    users[getLoggedInUser(req)]['2fa_key'] = encryptAES(mfa_key, process.env.SERVER_AES_KEY);
    res.send(loadWebpage('2fa.html', req, {'CÓDIGO_A2F':mfa_key}));
    delete mfa_key;
})

app.get('/login', (req, res) => {
    res.send(loadWebpage('login.html', req, {}));
});

app.post('/login', (req, res) => {
    let uname = req.body.uname;
    let passwd = req.body.password;
    let mfa_code = req.body.mfa;
    let uid = getUserByUsername(uname);
    if (uid === undefined) {
        res.statusCode = 400;
        res.send(translate('\\!!iniciar_sesión.usuario_no_existe!!\\', 'es'));
        return;
    }
    let salt = users[uid]['salt'];
    passwd = calculateSha256(passwd + salt);
    if (passwd !== users[uid]['password']) {
        res.statusCode = 400;
        res.send(translate('\\!!iniciar_sesión.contraseña_incorrecta!!\\', 'es'));
        return;
    }
    if (!verifyOTP(mfa_code, decryptAES(users[uid]['2fa_key'], process.env.SERVER_AES_KEY))) {
        res.statusCode = 400;
        res.send(translate('\\!!iniciar_sesión.código_a2f_incorrecto!!\\', 'es'));
        return;
    }
    let sid = saltGen();
    let i = 0;
    while (sid in sesiones) {
        i++;
        if (i >= 100) {
            res.statusCode = 500;
            res.send(translate('\\!!registro.err.sin_sid_disponible!!\\', 'es'));
            return;
        }
        sid = saltGen();
    }
    req.session.sessionId = sid;
    let twoWeeksTime = new Date(new Date().getTime() + twoWeeks);
    sesiones[sid] = {'user':uid,'expiry':twoWeeksTime.getTime()};
    res.statusCode = 200;
    res.redirect('/');
});

app.get('/registrar', (req, res) => {
    res.send(loadWebpage('registrar.html', req, {}));
});

app.post('/registrar', (req, res) => {
    let uname = req.body.uname;
    if (uname == undefined || uname.length == 0) {
        res.statusCode = 400;
        res.send(translate('\\!!registro.err.nombre_vacío!!\\','es'));
        return;
    }
    let passwd = req.body.passwd;
    if (passwd == undefined || passwd.length == 0) {
        res.statusCode = 400;
        res.send(translate('\\!!registro.err.contraseña_vacía!!\\','es'));
        return;
    }
    let correo = req.body.correo;
    if (correo == undefined || correo.length == 0 || !correo.includes('@')) {
        res.statusCode = 400;
        res.send(translate('\\!!registro.err.correo_inválido!!\\','es'));
        return;
    }
    let clavepublica = req.body.clavepublica;
    if (clavepublica == undefined || clavepublica.length == 0) {
        res.statusCode = 400;
        res.send(translate('\\!!registro.err.clave_pública_vacía!!\\','es'));
        return;
    }
    let display_name = req.body.display_name;
    if (display_name == undefined || display_name.length == 0) {
        display_name = uname;
    }
    if (getUserByUsername(uname)) {
        res.statusCode = 400;
        res.send(translate('\\!!registro.err.usuario_ya_existe!!\\', 'es'));
        return;
    }
    let user = generateUser(uname, passwd, correo, clavepublica, 'es',
        display_name);
    users.push(user);
    let sid = saltGen();
    let i = 0;
    while (sid in sesiones) {
        i++;
        if (i >= 100) {
            res.statusCode = 500;
            res.send(translate('\\!!registro.err.sin_sid_disponible!!\\', 'es'));
            return;
        }
        sid = saltGen();
    }
    req.session.sessionId = sid;
    let twoWeeksTime = new Date(new Date(). getTime() + twoWeeks);
    sesiones[sid] = {'user':getUserByUsername(uname),'expiry':twoWeeksTime.getTime()};
    res.statusCode = 200;
    res.redirect('/');
    passwd = undefined;
});

app.get('/style.css', (req, res) => {
    res.sendFile(__dirname + '/style.css');
});

app.get('/client.js', (req, res) => {
    res.sendFile(__dirname + '/client.js');
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
        const issuer = req.query.issuer;// || "Mensajeador";
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

// Save data when terminating
function saveData() {
    fs.writeFileSync('./data/users.json', JSON.stringify(users));
}
process.on('SIGINT', () => {
    saveData();
    process.exit(0);
});
process.on('SIGTERM', () => {
    saveData();
    process.exit(0);
})

const server = https.createServer(httpsOptions, app);

server.listen(port, () => {
    console.log(`Mensajeador corriendo en puerto ${port}`);
});