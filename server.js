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
const webpush = require('web-push');
const cors = require('cors');
const multer = require('multer');
const path = require('path');
const sharp = require('sharp');
const { Client } = require('pg');
const twoWeeks = 1000 * 60 * 60 * 24 * 14;
const thirtyDays = 1000 * 60 * 60 * 24 * 30;

const httpsOptions = {
    key: fs.readFileSync('./ssl/privatekey.pem'),
    cert: fs.readFileSync('./ssl/fullchain.pem')
};

const server = https.createServer(httpsOptions, app);
const { Server } = require("socket.io");
const io = new Server(server);

const github_oauth_enabled = process.env.SSO_GITHUB_CLIENT_ID && process.env.SSO_GITHUB_CLIENT_SECRET;

const githubAuth = github_oauth_enabled
    ? {
        clientId: process.env.SSO_GITHUB_CLIENT_ID,
        clientSecret: process.env.SSO_GITHUB_CLIENT_SECRET,
        redirectUri: process.env.FULL_DOMAIN + '/oauth/github/callback',
    }
    : null;

// Carga postgres
const client = new Client({
  user: process.env.POSTGRES_USER,
  host: process.env.POSTGRES_HOST || 'localhost',
  database: process.env.POSTGRES_DB || 'mensajeador_db',
  password: process.env.POSTGRES_PASSWD,
  port: process.env.POSTGRES_PORT || 5432,
});

client.connect();

// Carga los archivos de localización
let loc_global = {};
function refreshLangFiles() {
    loc_global['es'] = JSON.parse(fs.readFileSync(`locale/es.json`).toString());
    loc_global['en'] = JSON.parse(fs.readFileSync(`locale/en.json`).toString());
    loc_global['zh'] = JSON.parse(fs.readFileSync(`locale/zh.json`).toString());
    loc_global['tok-sp'] = JSON.parse(fs.readFileSync(`locale/tok-sp.json`).toString());
}
refreshLangFiles();

// Crear directorio de /data/pfp
let pfp_dir = path.join(__dirname, 'data/pfp');

if (!fs.existsSync(pfp_dir)) {
    fs.mkdirSync(pfp_dir);
}

// Configuración de webpush
const publicVapidKey = process.env.VAPID_PUBLIC_KEY;
const privateVapidKey = process.env.VAPID_PRIVATE_KEY;
if (!publicVapidKey || !privateVapidKey) {
    console.error("Faltan VAPID keys en .env");
    process.exit(1);
}
webpush.setVapidDetails(
    "mailto:example@yourdomain.org",
    publicVapidKey,
    privateVapidKey
);

/**
 * Agrega una subscripción de webpush
*/
async function agregarSubscripcion(req, subscripcion) {
    let liu = await getLoggedInUser(req);
    if (liu === undefined) { return false; }
    
    await client.query(`
    INSERT INTO web_notification_subscriptions
    (user_id, endpoint, expiration_time, p256dh, auth)
    VALUES ($1, $2, $3, $4, $5)
    ON CONFLICT (user_id, endpoint) DO NOTHING
    `, [
        liu,
        subscripcion.endpoint,
        subscripcion.expirationTime,
        subscripcion.keys.p256dh,
        subscripcion.keys.auth
    ]);
    return true;
}

/**
 * Quita una subscripción de webpush
 */
async function quitarSubscripcion(subscripcion) {
    await client.query(
        `DELETE FROM web_notification_subscriptions WHERE endpoint = $1`,
        [
            subscripcion.endpoint
        ]
    );
}

async function enviarNotificacion(subscripcion, payload) {
    if (typeof payload !== 'string') {
        payload = JSON.stringify(payload);
    }
    try {
        let resultado = await webpush.sendNotification(subscripcion, payload);
        return { 'success': true };
    } catch (err) {
        if (err.statusCode === 404 || err.statusCode === 410) {
            await quitarSubscripcion(subscripcion);
            return { 'success': false, 'quitado': true }
        }
        return { 'success': false, 'quitado': false, 'err': err }
    }
}

// Multer
const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 5 * 1024 * 1024 // 5 MB to B
    },
    fileFilter: (req, file, cb) => {
        const allowed = ['image/png', 'image/jpeg', 'image/webp'];
        if (!allowed.includes(file.mimetype)) {
            return cb(new Error('Only png, jpeg, and webp allowed'), false);
        }
        cb(null, true);
    }
});

// Functions
function getUserLocales(req) {
    let locale = [];
    
    // Browser (priority 1)
    let browser_locale = req.headers['accept-language'];
    let appropriate_browser_locale_found = false;
    browser_locale.replaceAll(' ','');
    browser_locale = browser_locale.split(',');
    let locale_list = []
    if (req.session.lang) {
        locale_list = [...req.session.lang, ...browser_locale, 'es'];
    } else {
        locale_list = [...browser_locale, 'es'];
    }
    for (let lang of locale_list) {
        lang = lang.split(';')[0];
        switch (lang) {
            // Spanish
            case "es":
                locale.push('es');
                appropriate_browser_locale_found = true;
                break;
            case "es-ES":
                locale.push('es');
                appropriate_browser_locale_found = true;
                break;
            case "es-MX":
                locale.push('es');
                appropriate_browser_locale_found = true;
                break;
            case "es-US":
                locale.push('es');
                appropriate_browser_locale_found = true;
                break;
            case "es-419":
                locale.push('es');
                appropriate_browser_locale_found = true;
                break;
                
            // English
            case "en":
                locale.push('en');
                appropriate_browser_locale_found = true;
                break;
            case "en-GB":
                locale.push('en');
                appropriate_browser_locale_found = true;
                break;
            case "en-CA":
                locale.push('en');
                appropriate_browser_locale_found = true;
                break;
            case "en-AU":
                locale.push('en');
                appropriate_browser_locale_found = true;
                break;
            case "en-US":
                locale.push('en');
                appropriate_browser_locale_found = true;
                break;
                
            // Chinese (simplified)
            case "zh":
                locale.push('zh');
                appropriate_browser_locale_found = true;
                break;
            case "zh-Hans":
                locale.push('zh');
                appropriate_browser_locale_found = true;
                break;
            case "zh-CN":
                locale.push('zh');
                appropriate_browser_locale_found = true;
                break;
            case "zh-SG":
                locale.push('zh');
                appropriate_browser_locale_found = true;
                break;
            
            // toki pona
            case "tok":
                locale.push('tok-sp');
                appropriate_browser_locale_found = true;
                break;
            case "tok-sp":
                locale.push('tok-sp');
                appropriate_browser_locale_found = true;
                break;
        }
    }
    
    return locale;
}

function loadWebpage(filename, req, data) {
    let webpage = fs.readFileSync(filename).toString();

    // Insert data
    for (let key of Object.keys(data)) {
        webpage = webpage.replaceAll('<!--'+key+'-->', data[key]);
    }

    // Get correct locale
    locale = getUserLocales(req);

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

/**
 * 
 * @param {express.Request} req The request from expressjs or socket.io
 * @param {string} sigreq The string to check against for the API key verification (not including timestamp nor the // immediately following the timestamp). Leave blank if the endpoint is not meant for use by API.
 * @returns If the user is logged in and authentication is successful, their local userid is returned; if not, undefined is returned
 */
async function getLoggedInUser(req, sigreq) {
    let session = req.session.sessionId;
    let sourcetype = req.body?.sourcetype || req.query?.sourcetype || 'sourcetype.web';
    if (sourcetype === 'sourcetype.web' && session) {
        const result = await client.query(
            `SELECT user_id, expiry FROM sessions_web WHERE id = $1`,
            [req.session.sessionId]
        );

        const session = result.rows[0];

        if (!session) return undefined;
        
        if (session.expiry < Date.now()) {
            await client.query(`DELETE FROM sessions_web WHERE id = $1`, [sessionId]);
            return undefined;
        }
        
        return session.user_id;
    } else if (sourcetype == 'sourcetype.api') {
        const pubkey = req.header('X-Ident');
        const timestamp = req.header('X-Timestamp');
        const signature = req.header('X-Signature');

        if (!pubkey || !timestamp || !signature) return undefined;

        if (parseInt(timestamp) > Date.now() + 5000) return undefined;

        const res = await client.query(`
            SELECT user_id
            FROM llaves_api
            WHERE pub_rsa_pss_key = $1
        `, [pubkey]);

        const user_id = res.rows[0]?.user_id;
        if (!user_id) return undefined;

        if (!verificarFirma(pubkey, timestamp + '//' + sigreq)) return undefined;

        return user_id;
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

function translate_simple(key, langlist) {
    for (let language of langlist) {
        loc = loc_global[language];
        val = loc[key];
        if (val) {
            return val;
        } 
    }
    return '\\!!' + key + '!!\\';
}

function translate(text, langlist) {
    const loc_default = Object.keys(loc_global['es']);
    
    // Insert data
    for (let key of loc_default) {
        text = text.replaceAll('\\!!' + key + '!!\\', translate_simple(key, langlist));
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
        "display_name": display_name,
        "conversations": []
    }
}

async function getUserByUsername(uname) {
    const res = await client.query(`
        SELECT user_id
        FROM users
        WHERE uname = $1
    `, [uname]);

    return res.rows[0]?.user_id;
}

async function getUserByGithubId(github_id) {
    const res = await client.query(`
    SELECT user_id
    FROM users
    WHERE oauth->>'github_id' = $1
    `, [github_id]);

    return res.rows[0]?.user_id;
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

function verificarFirma(publicKeyPem, payload, signatureBase64) {
    return crypto.verify(
        'sha256',
        Buffer.from(payload),
        {
            key: publicKeyPem,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN
        },
        Buffer.from(signatureBase64, 'base64')
    );
}

function firmar(privatePem, payload) {
    const signature = crypto.sign(
        'sha256', // hash
        Buffer.from(payload, 'utf-8'),
        {
            key: privatePem,
            padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
            saltLength: crypto.constants.RSA_PSS_SALTLEN_MAX_SIGN
        }
    );

    return signature.toString('base64');
}

const INSTANCE_ID = process.env.INSTANCE_ID;
function idGlobalDeIdLocal(id_local, id_instancia) {
    id_instancia = id_instancia || INSTANCE_ID;
    return id_local + ':' + id_instancia;
}

function idGlobal(id, id_instancia) {
    if (id.includes(':')) {
        return id;
    }
    return id + ':' + (id_instancia || INSTANCE_ID);
}

// Configure middleware
const sessionMiddleware = cookieSession({
    name: 'session',
    keys: [process.env.SESSION_KEY_1 || 'sk1', process.env.SESSION_KEY_2 || 'sk2'],
    maxAge: 14 * 24 * 60 * 60 * 1000 // 14 days in ms
});
app.use(sessionMiddleware);

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Primary endpoints
app.get('/', async (req, res) => {
    let liu = await getLoggedInUser(req)
    if (liu === undefined) {
        res.send(loadWebpage('index.html', req, {}));
        return;
    }
    const result = await client.query(`
        SELECT display_name, uname, twofa_key, public_key
        FROM users
        WHERE user_id = $1
    `, [liu]);

    const user = result.rows[0];
    if (user['twofa_key'] === null) {
        res.send(translate('\\!!general.debes_configurar_a2f!!\\',getUserLocales(req)));
        return;
    }
    if (user['public_key'] === null) {
        res.send(loadWebpage('createUserKeypair.html', req, {}));
        return;
    }

    res.send(loadWebpage('chat.html', req, {
        'UID-DE-USUARIO': liu,
        'NOMBRE_DE_PERFIL': user?.display_name,
        'NOMBRE_DE_USUARIO': user?.uname
    }));
});

app.get('/configurarA2F', async (req, res) => {
    let mfa_key = gen2FAKey();
    const userId = await getLoggedInUser(req);

    await client.query(`
        UPDATE users
        SET twofa_key = $1
        WHERE user_id = $2
    `, [
        encryptAES(mfa_key, process.env.SERVER_AES_KEY),
        userId
    ]);
    res.send(loadWebpage('2fa.html', req, {'CÓDIGO_A2F':mfa_key}));
    mfa_key = undefined;
});

app.get('/login', (req, res) => {
    res.send(loadWebpage('login.html', req, {
        'ALL_SSO_DISABLED': (github_oauth_enabled) ? '' : 'hidden',
        'GITHUB_SSO_DISABLED': github_oauth_enabled ? '' : 'hidden'
    }));
});

app.post('/login', async (req, res) => {
    let sourcetype = req.body.sourcetype || 'sourcetype.web';
    const acceptable_sourcetypes_at_endpoint = [
        'sourcetype.web',
        //'sourcetype.app' // Planned for future
    ]
    if (!(acceptable_sourcetypes_at_endpoint.includes(sourcetype))) {
        res.json({
            'success': false,
            'error': 'INVALID_SOURCETYPE',
            'request_completion': 0x00, // no significant portion was completed
            'error_localised': translate('\\!!iniciar_sesión.sourcetype_inválido!!\\', getUserLocales(req)),
            'fault': 'client',
            'fault_fix': 'Set sourcetype to a valid option (or none if visiting from the web)',
            'acceptable_sourcetypes_at_endpoint': acceptable_sourcetypes_at_endpoint,
            'sourcetype': sourcetype
        });
        return;
    }
    
    let uname = req.body.uname;
    let passwd = req.body.password;
    let mfa_code = req.body.mfa;
    
    const result = await client.query(`
        SELECT user_id, password, salt, twofa_key
        FROM users
        WHERE uname = $1
    `, [uname]);

    const user = result.rows[0];
    
    if (!user) {
        if (sourcetype === 'web') {
            res.status(401).send(translate('\\!!iniciar_sesión.credenciales_inválidas!!\\', getUserLocales(req)));
        } else {
            res.status(401).json({
                'success': false,
                'error': 'INCORRECT_LOGIN_CREDENTIALS',
                'request_completion': 0x00,
                'error_localised': translate('\\!!iniciar_sesión.credenciales_inválidas!!\\', getUserLocales(req)),
                'fault': 'client',
                'fault_fix': 'Check the username, password, and TOTP fields and try again with revised credentials',
                'sourcetype': sourcetype
            });
        }        
        return;
    }
    let salt = user.salt;
    passwd = calculateSha256(passwd + salt);
    if (passwd !== user.password) {
        if (sourcetype === 'web') {
            res.status(401).send(translate('\\!!iniciar_sesión.credenciales_inválidas!!\\', getUserLocales(req)));
        } else {
            res.status(401).json({
                'success': false,
                'error': 'INCORRECT_LOGIN_CREDENTIALS',
                'request_completion': 0x00,
                'error_localised': translate('\\!!iniciar_sesión.credenciales_inválidas!!\\', getUserLocales(req)),
                'fault': 'client',
                'fault_fix': 'Check the username, password, and TOTP fields and try again with revised credentials',
                'sourcetype': sourcetype
            });
        }
        return;
    }
    if (!verifyOTP(mfa_code, decryptAES(user.twofa_key, process.env.SERVER_AES_KEY))) {
        if (sourcetype === 'web') {
            res.status(401).send(translate('\\!!iniciar_sesión.credenciales_inválidas!!\\', getUserLocales(req)));
        } else {
            res.status(401).json({
                'success': false,
                'error': 'INCORRECT_LOGIN_CREDENTIALS',
                'request_completion': 0x00,
                'error_localised': translate('\\!!iniciar_sesión.credenciales_inválidas!!\\', getUserLocales(req)),
                'fault': 'client',
                'fault_fix': 'Check the username, password, and TOTP fields and try again with revised credentials',
                'sourcetype': sourcetype
            });
        }
        return;
    }
    
    // Generate a sessionid
    let sid = saltGen(sourcetype === 'sourcetype.web' ? 16 : 64);
    let i = 0;
    while ((await client.query(`SELECT * FROM sessions_web WHERE id = $1`, [sid])).rowCount !== 0) {
        i++;
        if (i >= 100) {
            res.statusCode = 500;
            res.send(translate('\\!!registro.err.sin_sid_disponible!!\\', getUserLocales(req)));
            return;
        }
        sid = saltGen(sourcetype === 'sourcetype.web' ? 16 : 64);
    }
    
    // Expiry of sessionid
    let expiryTime = new Date(new Date().getTime() + (sourcetype === 'sourcetype.web' ? twoWeeks : thirtyDays));
    
    // Register sessionid
    if (sourcetype === 'sourcetype.web') {
        await client.query(
            `INSERT INTO sessions_web (id, user_id, expiry) VALUES ($1, $2, $3)`,
            [sid, user.user_id, expiryTime]
        );
    } else {
        // sourcetype.app support planned
    }
    
    // Send response
    res.statusCode = 200;
    if (sourcetype === 'sourcetype.web') {
        req.session.sessionId = sid;
        res.redirect('/');
    } else {
        res.json({
            'success': 'true',
            'sourcetype': sourcetype,
            'token': sid,
            'expiry': thirtyDays,
        });
    }
});

app.get('/oauth/github', (req, res) => {
    if (!github_oauth_enabled) {
        res.status(400).send(translate('\\!!iniciar_sesión.sso.github.deshabilitado_en_servidor!!\\', getUserLocales(req)));
        return;
    }
    const state = crypto.randomBytes(16).toString('hex');
    req.session.state = state;
    req.session.oauth_intent = 'login';
    
    const url = new URL('https://github.com/login/oauth/authorize');
    url.searchParams.set('client_id', githubAuth.clientId);
    url.searchParams.set('redirect_uri', githubAuth.redirectUri);
    url.searchParams.set('state', state);
    url.searchParams.set('scope', '');

    return res.redirect(url.toString());
});

app.get('/oauth/github/configure', async (req, res) => {
    if (!github_oauth_enabled) {
        res.status(400).send(translate('\\!!iniciar_sesión.sso.github.deshabilitado_en_servidor!!\\', getUserLocales(req)));
        return;
    }
    
    if (await getLoggedInUser(req) === undefined) {
        res.status(200).redirect('/');
        return;
    }
    
    const state = crypto.randomBytes(16).toString('hex');
    req.session.state = state;
    req.session.oauth_intent = 'configure';
    
    const url = new URL('https://github.com/login/oauth/authorize');
    url.searchParams.set('client_id', githubAuth.clientId);
    url.searchParams.set('redirect_uri', githubAuth.redirectUri);
    url.searchParams.set('state', state);
    url.searchParams.set('scope', '');

    return res.redirect(url.toString());
});

app.get('/oauth/github/callback', async (req, res) => {
    if (!github_oauth_enabled) {
        res.status(400).send(translate('\\!!iniciar_sesión.sso.github.deshabilitado_en_servidor!!\\', getUserLocales(req)));
        return;
    }
    try {
        // CSRF protection
        if (req.query.state !== req.session.state) {
            return res.status(400).send('Estado inválido');
        }
        req.session.state = undefined;
        
        const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
            method: 'POST',
            headers: {
                Accept: 'application/json',
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                client_id: githubAuth.clientId,
                client_secret: githubAuth.clientSecret,
                code: req.query.code,
                redirect_uri: githubAuth.redirectUri,
                state: req.query.state,
            }),
        });

        const tokenData = await tokenRes.json();
        if (!tokenData.access_token) {
            return res.status(401).send('No se pudo obtener el token');
        }

        const userInfo = await fetch('https://api.github.com/user', {
            headers: {
                Authorization: `Bearer ${tokenData.access_token}`,
                Accept: 'application/vnd.github+json',
            },
        }).then(r => r.json());

        let userGithubId = userInfo.id;
        
        let oauth_intent = req.session.oauth_intent;
        req.session.oauth_intent = undefined;
        if (oauth_intent === 'login') {
            // Identify the user
            let uid = await getUserByGithubId(userGithubId);
            // Log the user in
            let sid = saltGen();
            let i = 0;
            while ((await client.query(`SELECT * FROM sessions_web WHERE id = $1`, [sid])).rowCount !== 0) {
                i++;
                if (i >= 100) {
                    res.statusCode = 500;
                    res.send(translate('\\!!registro.err.sin_sid_disponible!!\\', getUserLocales(req)));
                    return;
                }
                sid = saltGen();
            }
            req.session.sessionId = sid;
            let twoWeeksTime = new Date(new Date().getTime() + twoWeeks);
            await client.query(
                `INSERT INTO sessions_web (id, user_id, expiry) VALUES ($1, $2, $3)`,
                [sid, user.user_id, twoWeeksTime]
            );
            res.statusCode = 200;
            res.redirect('/');
        } else if (oauth_intent === 'configure') {
            let liu = await getLoggedInUser(req);
            if (liu === undefined) res.redirect('/login');
            await client.query(`
                UPDATE users
                SET oauth = jsonb_set(
                    COALESCE(oauth, '{}'::jsonb),
                    '{github_id}',
                    to_jsonb($1::text),
                    true
                )
                WHERE user_id = $2
                `, [
                    userGithubId,
                    liu
                ]
            );
            res.status(200).redirect('/configurarCuenta');
        }
    } catch (err) {
        console.error(err);
        res.status(500).send('Ha fallado la autenticación con GitHub');
    }
});

app.get('/registrar', (req, res) => {
    res.send(loadWebpage('registrar.html', req, {}));
});

app.post('/registrar', async (req, res) => {
    let uname = req.body.uname;
    if (uname == undefined || uname.length == 0) {
        res.statusCode = 400;
        res.send(translate('\\!!registro.err.nombre_vacío!!\\',getUserLocales(req)));
        return;
    }
    let passwd = req.body.passwd;
    if (passwd == undefined || passwd.length == 0) {
        res.statusCode = 400;
        res.send(translate('\\!!registro.err.contraseña_vacía!!\\',getUserLocales(req)));
        return;
    }
    let correo = req.body.correo;
    if (correo == undefined || correo.length == 0 || !correo.includes('@')) {
        correo = null
    }
    let clavepublica = req.body.clavepublica;
    if (clavepublica == undefined || clavepublica.length == 0) {
        res.statusCode = 400;
        res.send(translate('\\!!registro.err.clave_pública_vacía!!\\',getUserLocales(req)));
        return;
    }
    let display_name = req.body.display_name;
    if (display_name == undefined || display_name.length == 0) {
        display_name = uname;
    }
    if (await getUserByUsername(uname)) {
        res.statusCode = 400;
        res.send(translate('\\!!registro.err.usuario_ya_existe!!\\', getUserLocales(req)));
        return;
    }
    let uid = crypto.randomUUID();
    let salt = saltGen();
    passwd = calculateSha256(passwd + salt)
    await client.query(`
        INSERT INTO users (
            user_id,
            uname,
            password,
            salt,
            email,
            public_key,
            display_name
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7)
        `, [
            uid,
            uname,
            passwd,
            salt,
            email,
            clavepublica,
            display_name
        ]
    );
    let sid = saltGen();
    let i = 0;
    while ((await client.query(`SELECT * FROM sessions_web WHERE id = $1`, [sid])).rowCount !== 0) {
        i++;
        if (i >= 100) {
            res.statusCode = 500;
            res.send(translate('\\!!registro.err.sin_sid_disponible!!\\', getUserLocales(req)));
            return;
        }
        sid = saltGen();
    }
    req.session.sessionId = sid;
    let twoWeeksTime = new Date(new Date().getTime() + twoWeeks);
    await client.query(`INSERT INTO sessions_web (id, user_id, expiry) VALUES ($1, $2, $3)`, [sid, uid, twoWeeksTime]);
    res.statusCode = 200;
    res.redirect('/');
    passwd = undefined;
});

app.get('/logout', async (req, res) => {
    await client.query(`DELETE FROM sessions_web WHERE id = $1`, [req.session.sessionId]);
    req.session.sessionId = undefined;
    res.status(200).redirect('/');
});

app.get('/logout_all', async (req, res) => {
    let uid = getLoggedInUser(req);
    await client.query(`DELETE FROM sessions_web WHERE user_id = $1`, [uid]);
    req.session.sessionId = undefined;
    res.status(200).redirect('/');
});

app.get('/configurarCuenta', async (req, res) => {
    let liu = await getLoggedInUser(req);
    if (liu === undefined) { res.redirect('/login'); return; }
    res.send(loadWebpage('configurarCuenta.html', req, {
        'UID': liu,
        // 'ALL_SSO_DISABLED': (github_oauth_enabled) ? '' : 'hidden',
        'GITHUB_SSO_DISABLED': github_oauth_enabled ? '' : 'hidden',
    }));
});

app.post('/subscribe', async (req, res) => {
    let subscripcion = req.body.subscripcion;
    if (!subscripcion) {
        return res.status(400).json({ error: 'Falta subscripción' });
    }
    await agregarSubscripcion(req, subscripcion);
    res.status(201).json({ success: true });
});

app.post('/unsubscribe', async (req, res) => {
    let subscripcion = req.body.subscripcion;
    if (!subscripcion) {
        return res.status(400).json({ success: false, error: 'Falta subscripción' });
    }
    await quitarSubscripcion(subscripcion);
    res.status(200).json({ success: true });
});

app.get('/vapidPublicKey', (req, res) => {
    res.json({ publicKey: publicVapidKey });
});

app.get('/comenzarConversacion/md', async (req, res) => {
    if (await getLoggedInUser(req) === undefined) {
        res.statusCode = 200;
        res.redirect('/login');
        return;
    }
    res.statusCode = 200;
    res.send(loadWebpage('comenzarMD.html', req, {}));
});

app.get('/enviarClavePrivada', async (req, res) => {
    if (!await getLoggedInUser(req)) {
        res.redirect('/login');
        return;
    }
    res.send(loadWebpage('enviarClavePrivada.html', req, {}));
});

app.get('/recibirClavePrivada', async (req, res) => {
    if (!await getLoggedInUser(req)) {
        res.redirect('/login');
        return;
    }
    res.send(loadWebpage('recibirClavePrivada.html', req, {}));
});

app.post('/establecerFotoDePerfil', upload.single('pfp'), async (req, res) => {
    try {
        let uid = await getLoggedInUser(req);
        if (uid === undefined) {
            res.redirect('/login');
            return;
        }
        
        if (!req.file) {
            res.status(400).json({
                'success': false,
                'error_localised': translate('\\!!establecer_fdp.sin_archivo!!\\', getUserLocales(req))
            });
            return;
        }
        
        let outputPath = path.join(pfp_dir, `usuario_${uid}.webp`);
        let tempPath = path.join(pfp_dir, `usuario_${uid}_tmp.webp`);
        
        await sharp(req.file.buffer)
            .rotate()
            .resize({
                width: 512,
                height: 512,
                fit: 'inside',
                withoutEnlargement: true
            })
            .webp({
                lossless: true
            })
            .toFile(tempPath);
        fs.renameSync(tempPath, outputPath);
        
        await client.query(
            `UPDATE users
            SET profile_picture = $1
            WHERE user_id = $2`,
            [outputPath.toString(), uid]
        );
        
        res.status(200).redirect('/configurarCuenta');
    } catch (err) {
        console.error(err);
        res.status(400).json({ 'success': false });
    }
});

app.delete('/desestablecerFotoDePerfil', async (req, res) => {
    let uid = await getLoggedInUser(req);
    if (uid === undefined) {
        res.redirect('/login');
        return;
    }
    
    if (!/[0-9]+/.test(uid)) {
        res.status(400).send(translate('\\!!desestablecer_fdp.uid_inválido!!\\', getUserLocales(req)));
        return;
    }
    
    let filePath = path.join(pfp_dir, `usuario_${uid}.webp`);
    
    if (fs.existsSync(filePath)) {
        fs.rmSync(filePath);
    }
    
    await client.query(
        `UPDATE users
        SET profile_picture = NULL
        WHERE user_id = $1`,
        [uid]
    );
    
    res.status(204).end();
});

available_languages = ['es', 'en', 'zh', 'zh-Hans', 'tok-sp'];
app.get('/setlang/es', (req, res) => {
    req.session.lang = ['es'];
    res.redirect('/');
});

app.get('/setlang/en', (req, res) => {
    req.session.lang = ['en'];
    res.redirect('/');
});

app.get('/setlang/zh', (req, res) => {
    req.session.lang = ['zh'];
    res.redirect('/');
});

app.get('/setlang/zh-Hans', (req, res) => {
    req.session.lang = ['zh-Hans'];
    res.redirect('/');
});

app.get('/setlang/tok-sp', (req, res) => {
    req.session.lang = ['tok-sp'];
    res.redirect('/');
});

app.get('/setlang/clear', (req, res) => {
    req.session.lang = [];
    res.redirect('/');
});

app.get('/setlang/:languages', (req, res) => {
    let languages = [];
    for (let language of req.params.languages.split(',')) {
        if (available_languages.includes(language)) {
            languages.push(language);
        }
    }
    req.session.lang = languages;
    res.redirect('/');
});

app.get('/app/getUIDByUsername', async (req, res) => {
    let username = req.query.username;
    let uid = await getUserByUsername(username);
    if (uid === undefined) {
        res.statusCode = 400;
        res.send(translate('\\!!app.usuario_no_existe!!\\', getUserLocales(req)));
        return;
    }
    res.statusCode = 200;
    res.send(uid);
})

app.get('/app/getUserPublicKey', async (req, res) => {
    let uid = req.query.user;
    let user_instance = INSTANCE_ID;
    let is_local = true;
    if (uid.includes(':')) {
        let usplit = uid.split(':');
        uid = usplit[0];
        user_instance = usplit[1];
        is_local = user_instance === INSTANCE_ID;
    }
    
    if (!is_local) {
        // Federación aún no implementada
        res.statusCode = 501;
        res.send('Funcionalidad de federación aún no implementada');
        return;
    }
    
    let result = await client.query(`SELECT public_key FROM users WHERE user_id = $1`, [uid]);
    
    if (result.rowCount === 0) {
        res.statusCode = 400;
        res.send(translate('\\!!app.usuario_no_existe!!\\', getUserLocales(req)));
        return;
    }
    let key = result.rows[0]?.public_key;
    res.send(key);
});

app.get('/app/getLoggedInUser', async (req, res) => {
    let liu = await getLoggedInUser(req);
    res.statusCode = 200;
    res.send(liu);
})

app.get('/app/converesDeUsuario', async (req, res) => {
    let liu = await getLoggedInUser(req);
    if (liu === undefined) {
        res.json([]);
        return;
    }
    
    const result = await client.query(
        `SELECT conver_global_id
        FROM user_conversations
        WHERE user_id = $1`,
        [liu]
    );

    const converesDeUsuario = result.rows.map(r => r.conver_global_id);

    res.json(converesDeUsuario);
});

app.get('/app/nombreDeConver', async (req, res) => {
    let conver = req.query.conver;
    let conver_instance = INSTANCE_ID;
    if (conver.includes(':')) {
        let csplit = conver.split(':');
        conver = csplit[0];
        conver_instance = csplit[1];
    }
    
    // Federación aún no implementada
    if (conver_instance !== INSTANCE_ID) {
        res.statusCode = 501;
        res.send('Funcionalidad de federación aún no implementada');
        return;
    }
    
    // Identifica el usuario
    let liu = await getLoggedInUser(req);
    if (liu === undefined) {
        res.statusCode = 401;
        res.send('Debes iniciar sesión primero');
        return;
    }
    
    // Identifica la conversación y confirma que exista
    let queryRes = await client.query(`SELECT * FROM conversations WHERE conver_id = $1`, [conver]);
    if (queryRes.rowCount === 0) {
        res.statusCode = 400;
        res.send('No existe la conversación');
        return;
    }
    
    // Confirma que el usuario está en la conversación
    let queryRes2 = await client.query(
        `SELECT * FROM conversation_participants WHERE conver_id = $1 AND user_global_id = $2`,
        [
            conver,
            idGlobalDeIdLocal(liu, INSTANCE_ID)
        ]
    );
    if (queryRes2.rowCount === 0) {
        res.statusCode = 403;
        res.send('No estás en esta conversación');
        return;
    }
    
    // Devuelve el nombre de la conversación
    res.statusCode = 200;
    res.send(queryRes.rows[0]['conver_name']);
});

app.get('/app/llaveAESDeConver', async (req, res) => {
    let conver = req.query.conver;
    let conver_instance = INSTANCE_ID;
    if (conver.includes(':')) {
        let csplit = conver.split(':');
        conver = csplit[0];
        conver_instance = csplit[1];
    }
    
    // Federación aún no implementada
    if (conver_instance !== INSTANCE_ID) {
        res.statusCode = 501;
        res.send('Funcionalidad de federación aún no implementada');
        return;
    }
    
    // Identificar el usuario
    let liu = await getLoggedInUser(req, 'llaveAESDeConver//' + conver);
    if (liu === undefined) {
        res.statusCode = 401;
        res.send('Debes iniciar sesión primero');
        return;
    }
    
    
    // Identifica la conversación y confirma que exista
    let queryRes = await client.query(`SELECT * FROM conversations WHERE conver_id = $1`, [conver]);
    if (queryRes.rowCount === 0) {
        res.statusCode = 400;
        res.send('No existe la conversación');
        return;
    }
    
    // Confirma que el usuario está en la conversación
    let queryRes2 = await client.query(
        `SELECT * FROM conversation_participants WHERE conver_id = $1 AND user_global_id = $2`,
        [
            conver,
            idGlobalDeIdLocal(liu, INSTANCE_ID)
        ]
    );
    if (queryRes2.rowCount === 0) {
        res.statusCode = 403;
        res.send('No estás en esta conversación');
        return;
    }
    
    // Regresar la llave de conversación
    res.statusCode = 200;
    res.send(queryRes2.rows[0]['encrypted_key']);
});

app.get('/app/converModoMensajesAutenticados', async (req, res) => {
    let conver_id = req.query.conver_id;
    
    // Federación aún no implementada
    
    let queryRes = await client.query(`SELECT settings->>'unverified_message_sender' AS ums WHERE conver_id = $1`, [conver_id]);
    
    res.statusCode = 200;
    res.send(queryRes.rows[0]?.ums == false);
});

app.post('/app/comenzarConversacion/md', async (req, res) => {
    let usersToAdd = req.body.users;
    let nombreConver = req.body.nombreConver;
    
    if (nombreConver.includes('"')) {
        res.statusCode = 400;
        res.send(translate('\\!!app.doble_comillas_inválido_en_nombre_de_conver!!\\', getUserLocales(req)));
        return;
    }
    
    let uuid = crypto.randomUUID();
    let i = 0;
    while ((await client.query(`SELECT * FROM conversations WHERE conver_id = $1`, [uuid])).rowCount !== 0) {
        i++
        if (i > 500) {
            res.statusCode = 500;
            res.send(translate('\\!!app.no_se_encontró_uuid_abierto!!\\', getUserLocales(req)));
            return;
        }
        uuid = crypto.randomUUID();
    }
    
    await client.query(
        `INSERT INTO conversations (conver_id, conver_name, conver_type, crypt-type, settings)
        VALUES ($1, $2, 0, 'AES-GCM', $3)`,
        [
            uuid,
            nombreConver,
            JSON.stringify({
                'font': undefined, // cuando es undefined: usa fuentes predeterminados
                'require-consent-to-add': false, // requiere que todos los usuarios acepten para agregar más usuarios
            })
        ]
    );
    
    
    // Agregar usuarios
    for (user of Object.keys(usersToAdd)) {
        let user_id_local = user;
        let user_instance = INSTANCE_ID;
        let is_local = true;
        if (user_id_local.includes(':')) {
            let usplit = user_id_local.split(':');
            user_id_local = usplit[0];
            user_instance = usplit[1];
            is_local = user_instance === INSTANCE_ID;
        }
        
        // Ver si el usuario es local (de esta instancia) o externo (de otra instancia)
        if (is_local) {
            if ((await client.query(`SELECT * FROM users WHERE user_id = $1`, [user_id_local])).rowCount !== 0) {
                // El usuario existe
                // Agregar conversación a lista de conversaciones del usuario
                await client.query(
                    `INSERT INTO user_conversations (conver_global_id, user_id, encrypted_key) VALUES ($1, $2, $3)`,
                    [
                        idGlobalDeIdLocal(uuid, INSTANCE_ID),
                        user_id_local,
                        usersToAdd[user]
                    ]
                );
                
                // Agregar usuario a lista de usuarios de conversación
                await client.query(
                    `INSERT INTO conversation_participants (conver_id, user_global_id, encrypted_key) VALUES ($1, $2, $3)`,
                    [
                        uuid,
                        idGlobalDeIdLocal(user_id_local, user_instance),
                        usersToAdd[user]
                    ]
                );
            } else {
                // El usuario no existe
                usersToAdd[user] = undefined;
            }
        } else {
            // Federación aún no implementada
            if (user_instance !== INSTANCE_ID) {
                res.statusCode = 501;
                res.send('Funcionalidad de federación aún no implementada');
                return;
            }
        }
    }
    
    res.statusCode = 200;
    res.send(uuid);
});

app.get('/app/fotoDePerfil', async (req, res) => {
    let uid = req.query.user;
    let user_instance = INSTANCE_ID;
    let is_local = true;
    if (uid.includes(':')) {
        let usplit = uid.split(':');
        uid = usplit[0];
        user_instance = usplit[1];
        is_local = user_instance === INSTANCE_ID;
    }
    
    if (is_local) {
        if ((uid === undefined) || (await client.query(`SELECT * FROM users WHERE user_id = $1`, [uid])).rowCount === 0) {
            res.sendFile(__dirname + '/assets/imgs/FDP_predeterminado.svg');
            return;
        }
        let pfp_location = (await client.query(
                `SELECT profile_picture FROM users WHERE user_id = $1`,
                [uid]
            )).rows[0]['profile_picture']
        if (pfp_location !== null) {
            //res.set('Content-Type', users[uid]['profile-picture']['type']); // images/png images/svg images/jpeg
            res.sendFile(pfp_location);
            return;
        }
    } // Federación aún no implementada
    
    res.sendFile(__dirname + '/assets/imgs/FDP_predeterminado.svg');
});

app.get('/app/mensajesNuevos', async (req, res) => {
    let desde = parseInt(req.query.desde); // Mensaje más viejo
    let hasta = parseInt(req.query.hasta); // Mensaje más nuevo
    let conver = req.query.conver;
    let conver_instance = INSTANCE_ID;
    let is_local = true;
    if (conver.includes(':')) {
        let csplit = conver.split(':');
        conver = csplit[0];
        conver_instance = csplit[1];
        is_local = conver_instance == INSTANCE_ID;
    }
    
    if (!is_local) {
        // Federación aún no implementada
        if (conver_instance !== INSTANCE_ID) {
            res.statusCode = 501;
            res.send('Funcionalidad de federación aún no implementada');
            return;
        }
    }
    
    if ((await client.query(`SELECT * FROM conversations WHERE conver_id = $1`, [conver])).rowCount === 0) {
        res.statusCode = 400;
        res.send('La conversación solicitada no existe');
        return;
    }
    if (!Number.isInteger(desde) || !Number.isInteger(hasta)) {
        res.statusCode = 400;
        res.send('Los numeros ingresados no son válidos');
        return;
    }

    if (desde < 0) {
        desde = 0;
    }
    
    if (hasta < 0) {
        hasta = 0;
    }
    
    let mensajesDeConver = await client.query(`SELECT * FROM messages WHERE conver_id = $1 ORDER BY id ASC`, [conver]);
    let n = mensajesDeConver.rowCount;
    
    // convertir índices reversos a índices reales
    let i0 = n - 1 - desde;
    let i1 = n - 1 - hasta;
    
    if (i0 < 0) {
        i0 = 0;
    }
    
    if (i1 < 0) {
        i1 = 0;
    }

    // ordenar para obtener segmento [min..max] inclusive
    let desde_verificado = Math.min(i0, i1);
    let hasta_verificado = Math.max(i0, i1);

    // slice toma (start, endExclusive) -> por eso end + 1
    let mensajesParaDevolver = mensajesDeConver.rows.slice(desde_verificado, hasta_verificado + 1);
    
    res.send(mensajesParaDevolver);
});

app.get('/app/nombreParaMostrarPorUID', async (req, res) => {
    let uid = req.query.uid;
    let user_instance = INSTANCE_ID;
    let is_local = true;
    if (uid.includes(':')) {
        let usplit = uid.split(':');
        uid = usplit[0];
        user_instance = usplit[1];
        is_local = user_instance === INSTANCE_ID;
    }
    try {
        let queryRes = (await client.query(`SELECT display_name FROM users WHERE user_id = $1`, [uid]));
        if (queryRes.rowCount !== 0) {
            res.statusCode = 200;
            res.send(queryRes.rows[0]['display_name']);
            return;
        }
    } catch {}
    
    res.statusCode = 400;
    res.send('El usuario especificado no se ha encontrado');
});

app.get('/style.css', (req, res) => {
    res.sendFile(__dirname + '/style.css');
});

app.get('/client.js', (req, res) => {
    res.sendFile(__dirname + '/client.js');
});

app.get('/chat.js', (req, res) => {
    res.sendFile(__dirname + '/chat.js');
});

app.get('/enviarClavePrivada.js', (req, res) => {
    res.sendFile(__dirname + '/enviarClavePrivada.js');
});

app.get('/recibirClavePrivada.js', (req, res) => {
    res.sendFile(__dirname + '/recibirClavePrivada.js');
});

app.get('/service-worker.js', (req, res) => {
    res.sendFile(__dirname + '/service-worker.js');
});

app.get('/socket.io/socket.io.js', (req, res) => {
    res.sendFile(__dirname + '/node_modules/socket.io/client-dist/socket.io.js');
});

app.get('/assets/fonts/linjalipamanka-normal.woff', (req, res) => {
    res.sendFile(__dirname + '/assets/fonts/linjalipamanka-normal.woff');
});

app.get('/assets/imgs/GitHub_Invertocat_Black.svg', (req, res) => {
    res.sendFile(__dirname + '/assets/imgs/GitHub_Invertocat_Black.svg');
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

// Endpoints para API
app.post('/api/register_api_key', async (req, res) => {
    let username = req.body.username;
    let passwd = req.body.password;
    let totp = req.body.totp;
    let pubkey = req.body.pubkey;
    let sample = req.body.sample;
    
    // Revisar uid
    let uid = await getUserByUsername(username);
    if (uid === undefined) {
        res.status(401).json({
            'success': false,
            'error': 'INCORRECT_CREDENTIALS'
        });
        return;
    }
    
    let queryRes = await client.query('SELECT salt, password, twofa_key FROM users WHERE user_id = $1', [uid]);
    
    // Revisar contraseña
    let salt = queryRes.rows[0].salt
    if (calculateSha256(queryRes.rows[0].password + salt) !== calculateSha256(passwd + salt)) {
        res.status(401).json({
            'success': false,
            'error': 'INCORRECT_CREDENTIALS'
        });
        return;
    }
    
    // Revisar código de A2F
    if (!verifyOTP(totp, decryptAES(queryRes.rows[0].twofa_key, process.env.SERVER_AES_KEY))) {
        res.status(401).json({
            'success': false,
            'error': 'INCORRECT_CREDENTIALS'
        });
        return;
    }
    
    // Revisar muestra
    if (!verificarFirma(pubkey, 'sample', sample)) {
        res.status(400).json({
            'success': false,
            'error': 'PUBLICKEY_DOES_NOT_MATCH_SAMPLE'
        });
        return;
    }
    
    await client.query(`INSERT INTO llaves_api (pub_rsa_pss_key, user_id) VALUES ($1, $2)`, [pubkey, uid]);
    
    res.statusCode = 200;
    res.json({
        'success': true
    });
});

app.get('/api/verify_api_key', async (req, res) => {
    let apipubkey = req.query.apipubkey;
    let uid_query = await client.query(`SELECT user_id FROM llaves_api WHERE pub_rsa_pss_key = $1`, [apipubkey]);
    res.status(200).json((uid_query.rowCount !== 0) ? {
        'uid': uid_query.rows[0],
        'verification_OK': true
    } : {
        'verification_OK': false
    });
});

app.post('/api/enviar_mensaje', async (req, res) => {
    let datosDeMensaje = req.body.datosDeMensaje;
    let conver = req.body.conver;
    let notificar = req.body.notificar; // Función no soportada
    let usuario_encriptado = req.body.usuario_encriptado;
    let rts = { datosDeMensaje, conver, notificar, usuario_encriptado };
    let sigreq = `enviar_mensaje//${JSON.stringify(rts)}`;
    let uid = await getLoggedInUser(req, sigreq);
    if (uid === undefined) {
        res.status(401).json({
            'success': false,
            'error': 'INVALID_CREDENTIALS',
        });
        return;
    }
    let conver_instance = INSTANCE_ID;
    let is_local = true;
    if (conver.includes(':')) {
        let csplit = conver.split(':');
        conver = csplit[0];
        conver_instance = csplit[1];
        is_local = conver_instance === INSTANCE_ID;
    }
    
    if ((process.env.ISOLATED === 1 || true) && (is_local)) { // Federación aún no soportada
        res.status(401).json({
            'success': false,
            'error': 'ISOLATED_INSTANCE_CANNOT_SEND_EXTERNALLY'
        });
        return;
    }
    
    // Verificar que esté en la conversación y que sea conversación valida
    let converQuery = await client.query(`SELECT conver_name FROM conversations WHERE conver_id = $1`, [conver]);
    
    let miembrosParaEmitir = (await client.query(
        `SELECT user_global_id FROM conversation_participants WHERE conver_id = $1`,
        [conver]
    )).rows.map(r => r['user_global_id']);
    
    if (((converQuery.rowCount === 0) || (miembrosParaEmitir.includes(idGlobalDeIdLocal(uid, INSTANCE_ID))))) {
        res.status(403).json({
            'success': false,
            'error': 'NOT_IN_CONVERSATION_OR_CONVERSATION_DOES_NOT_EXIST'
        });
        return;
    }
    
    // Empujar mensaje a servidor
    await client.query(
        `INSERT INTO messages (conver_id, sender_global_id, ciphertext, iv) VALUES ($1, $2, $3, $4)`,
        [
            conver,
            idGlobalDeIdLocal(uid, INSTANCE_ID),
            datosDeMensaje.ciphertext,
            datosDeMensaje.iv
        ]
    );
    
    // Enviar mensaje a usuarios activos
    let socketsParaEmitir = [];
    let miembrosEnLinea = [];
    //console.log(miembrosParaEmitir);
    for (let miembro_global of miembrosParaEmitir) {
        let msplit = miembro_global.split(':');
        let miembro = msplit[0];
        let miembro_instancia = msplit[1];
        if (miembro_instancia === INSTANCE_ID) {
            if (miembro in socketIds) {
                miembrosEnLinea.push(miembro);
                for (id of socketIds[miembro]) {
                    socketsParaEmitir.push(id);
                }
            }
        } // Federación aún no implementada
    }
    for (let socketId of socketsParaEmitir) {
        io.to(socketId).emit('recibirMensaje', rts);
    }
    
    // Notifica a los usuarios listados
    let subscripcionesDeNotificaciones = (await client.query(`SELECT * FROM web_notification_subscriptions`)).rows;
    let nombreDeConver = (converQuery.rows[0]['conver_name']);
    for (let miembro of rts['notificar']) {
        if (miembro === undefined) { continue; }
        let miembro_instancia = INSTANCE_ID;
        let is_local = true;
        if (miembro.includes(':')) {
            let msplit = miembro.split(':');
            miembro = msplit[0];
            miembro_instancia = msplit[1];
            is_local = miembro_instancia === INSTANCE_ID;
        }
        let miembro_global = idGlobalDeIdLocal(miembro, miembro_instancia);
        
        if (!is_local) continue; // Federación aún no implementada
        
        if (!miembrosParaEmitir.includes(miembro)) { continue; }
        if (!miembrosEnLinea.includes(miembro)) {
            if (subscripcionesDeNotificaciones.map(r => r['user_id']).includes(miembro)) {
                for (let subscripcion of subscripcionesDeNotificaciones.filter(r => r['user_id'] == miembro)[0]) {
                    enviarNotificacion(subscripcion, {
                        title: 'Nuevo mensaje',
                        body: 'Alguien te ha mandado un mensaje en ' + nombreDeConver,
                        url: '/'
                    });
                }
            }
        }
    }
});

app.get('/api/lista_converes', async (req, res) => {
    let uid = await getLoggedInUser(req, 'api//lista_converes');
    if (uid === undefined) {
        res.status(401).json({
            'success': false,
            'error': 'INVALID_CREDENTIALS',
        });
        return;
    }
    res.status(200).json((
        await client.query(`SELECT conver_global_id FROM user_conversations WHERE user_id = $1`, [uid])
    ).rows.map(r => r['conver_global_id']));
});

// Endpoints administrativos
app.get('/admin/refreshLangFiles', (req, res) => {
    refreshLangFiles();
    res.redirect('/');
});

// Endpoints de uso general
app.get('/usos_del_servidor/mensajeador', (req, res) => {
    res.status(200).send(Buffer.from([0xF3, 0xD4]));
});

// Endpoints de federación
app.get('/federacion/id_instancia', (req, res) => {
    res.statusCode = 200;
    res.send(INSTANCE_ID);
});

const PUB_RSA_PSS_KEY_B64 = fs.existsSync('./federation/pubkey_rsa_pss.pem') ?
    fs.readFileSync('./federation/pubkey_rsa_pss.pem') :
    process.env.PUB_RSA_PSS_KEY;
const PRI_RSA_PSS_KEY_B64 = fs.existsSync('./federation/privatekey_rsa_pss.pem') ?
    fs.readFileSync('./federation/privatekey_rsa_pss.pem') :
    process.env.PRI_RSA_PSS_KEY;
const PUB_RSA_PSS_KEY = Buffer.from(PUB_RSA_PSS_KEY_B64, 'base64').toString('utf-8');
const PRI_RSA_PSS_KEY = Buffer.from(PRI_RSA_PSS_KEY_B64, 'base64').toString('utf-8');

app.get('/federacion/reconocer_instancia/:ubicacion', async (req, res) => {
    let loc = new URL('https://' + req.body.ubicacion + '/federacion/reconocer_instancia');
    let query = {
        'pub_rsa_pss_key': PUB_RSA_PSS_KEY_B64,
        'sample': firmar(PRI_RSA_PSS_KEY, 'sample'), // firma 'sample' con la llave
        'primary_address': process.env.IP,
        'primary_port': process.env.PORT,
        'instance_id': INSTANCE_ID,
        'name_full': process.env.INSTANCE_NAME,
        'code': process.env.INSTANCE_CODE,
        'display_name': process.env.INSTANCE_DISPLAY_NAME,
        'request_return': true
    };
    
    let response = await fetch(loc, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(query)
    });
    
    res.statusCode = response.status;
    res.send(await response.json());
});

app.post('/federacion/reconocer_instancia', async (req, res) => {
    let pub_rsa_pss_key = req.body.pub_rsa_pss_key;
    let sample = req.body.sample;
    let primary_address = req.body.primary_address;
    let primary_port = req.body.primary_port;
    let instance_id = req.body.instance_id;
    let name_full = req.body.name_full;
    let code = req.body.code;
    let display_name = req.body.display_name;
    let request_return = req.body.request_return;
    
    if (!(pub_rsa_pss_key && sample && primary_address && primary_port && instance_id && code)) {
        res.statusCode = 400;
        res.json({
            'success': false,
            'error': 'MISSING_REQUIRED_INFORMATION'
        });
        return;
    }
    
    if (!(display_name || name_full)) { name_full = display_name = code; }
    else if (!display_name) { display_name = name_full; }
    else if (!name_full) { name_full = display_name; }
    
    if (!verificarFirma(Buffer.from(pub_rsa_pss_key, 'base64').toString('utf-8'), 'sample', sample)) {
        res.statusCode = 401;
        res.json({
            'success': false,
            'error': 'PROVIDED_SAMPLE_INVALID'
        });
        return;
    }
    
    let alreadyExistsQuery = await client.query(`SELECT * FROM instances WHERE instance_id = $1 OR code = $2`);
    
    if (alreadyExistsQuery.rowCount !== 0) {
        res.statusCode = 500;
        res.send({
            'success': false,
            'error': 'INSTANCE_ID_OR_CODE_ALREADY_EXISTS'
        });
        return;
    }
    
    await client.query(
        `INSERT INTO instances
        (instance_id, name_full, display_name, address, port, rsa_pss_public_key, code)
        VALUES ($1, $2, $3, $4, $5, $6, $7)`,
        [
            instance_id,
            name_full,
            display_name,
            primary_address,
            primary_port,
            pub_rsa_pss_key,
            code
        ]
    );
    
    if (request_return) {
        let loc = new URL('https://' + primary_address + ':' + primary_port + '/federacion/reconocer_instancia');
        let query = {
            'pub_rsa_pss_key': PUB_RSA_PSS_KEY_B64,
            'sample': firmar(PRI_RSA_PSS_KEY, 'sample'), // firma 'sample' con la llave
            'primary_address': process.env.IP,
            'primary_port': process.env.PORT,
            'instance_id': INSTANCE_ID,
            'name_full': process.env.INSTANCE_NAME,
            'code': process.env.INSTANCE_CODE,
            'display_name': process.env.INSTANCE_DISPLAY_NAME,
            'request_return': true
        };
        
        let response = await fetch(loc, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify(query)
        });
        
        res.statusCode = response.status;
        res.send(await response.json());
        return;
    }
    
    res.statusCode = 200;
    res.send({
        'success': true
    });
});

// Socket.io
io.use((socket, next) => {
    sessionMiddleware(socket.request, socket.request.res || {}, next);
});

var socketIds = {} // key: user UUID, value: array of socketIds
var intencionesDeEnviarClavePrivada = {} // key: id de intención, valor: {socketId, userId, IP}

io.on('connection', async (socket) => {
    let liu = await getLoggedInUser(socket.request);
    if (liu === undefined) {
        socket.disconnect(true);
    }
    let liu_global = idGlobalDeIdLocal(liu, INSTANCE_ID);
    if (socketIds[liu] === undefined) {
        socketIds[liu] = [];
    }
    socketIds[liu].push(socket.id);
    //console.log(socketIds);
    socket.on('disconnect', async () => {
        //console.log('user disconnected');
        if (liu !== undefined) socketIds[liu].splice(socketIds[liu].indexOf(socket.id), 1);
    });
    
    // Sistema de mensajes
    socket.on('enviarMsg', async (msg) => {
        //console.log('message: ' + JSON.stringify(msg));
        // Agregar mensaje a conversación
        let datosDeMensaje = msg['datosDeMensaje'];
        let conver = msg['conver'];
        let conver_instance = INSTANCE_ID;
        let is_local = true;
        if (conver.includes(':')) {
            let csplit = conver.split(':');
            conver = csplit[0];
            conver_instance = csplit[1];
            is_local = conver_instance === INSTANCE_ID;
        }
        
        if (!is_local) return; // Federación aún no implementada
        
        let converQuery = await client.query(`SELECT * FROM conversations WHERE conver_id = $1`, [conver]);
        let converParticipantsQuery = await client.query(
            `SELECT * FROM conversation_participants WHERE conver_id = $1`, [conver]
        );
        let conversationParticipants = converParticipantsQuery.rows.map(r => r['user_global_id']);
        if ((converQuery.rowCount !== 0) && (conversationParticipants.includes(liu_global))) {
            await client.query(
                `INSERT INTO messages (conver_id, sender_global_id, ciphertext, iv) VALUES ($1, $2, $3, $4)`,
                [
                    conver,
                    liu_global,
                    datosDeMensaje.ciphertext,
                    datosDeMensaje.iv
                ]
            );
            
            // Emitir a miembros en linea
            let socketsParaEmitir = [];
            let miembrosEnLinea = [];
            for (miembro of conversationParticipants) {
                let msplit = miembro.split(':');
                if (msplit[1] !== INSTANCE_ID) continue; // Federación aún no implementada
                if (msplit[0] in socketIds) {
                    miembrosEnLinea.push(msplit[0]);
                    for (id of socketIds[msplit[0]]) {
                        socketsParaEmitir.push(id);
                    }
                }
            }
            for (let socketId of socketsParaEmitir) {
                io.to(socketId).emit('recibirMensaje', msg);
            }
            
            // Notificar a miembros listados para notificación
            let subscripcionesDeNotificaciones = (await client.query(`SELECT * FROM web_notification_subscriptions`)).rows;
            for (let miembro of msg['notificar']) {
                let uidMiembro = await getUserByUsername(miembro);
                if (uidMiembro === undefined) { continue; }
                let miembro_instancia = INSTANCE_ID;
                let is_local = true;
                if (uidMiembro.includes(':')) {
                    let msplit = uidMiembro.split(':');
                    uidMiembro = msplit[0];
                    miembro_instancia = msplit[1];
                    is_local = miembro_instancia === INSTANCE_ID;
                }
                // let miembro_global = idGlobalDeIdLocal(uidMiembro, miembro_instancia);
                
                if (!is_local) continue; // Federación aún no implementada
                
                if (uidMiembro === undefined) { continue; }
                if (!conversationParticipants.includes(uidMiembro)) { continue; }
                if (!miembrosEnLinea.includes(uidMiembro)) {
                    if (subscripcionesDeNotificaciones.map(r => r['user_id']).includes(uidMiembro)) { // AQUÍ
                        for (subscripcion of subscripcionesDeNotificaciones.filter(r => r['user_id'] == uidMiembro)) {
                            enviarNotificacion(subscripcion, {
                                title: 'Nuevo mensaje',
                                body: 'Alguien te ha mandado un mensaje en ' + converQuery.rows[0].conver_name,
                                url: '/'
                            });
                        }
                    }
                }
            }
        }
    });
    
    // Envio de clave privada de un dispositivo a otro
    socket.on('intencionEnviarClavePrivada', async (datos) => { // Paso 1 (emitido por cliente enviador)
        let idDeIntencion = datos['id'];
        if (!(Object.keys(intencionesDeEnviarClavePrivada).includes(idDeIntencion))) {
            intencionesDeEnviarClavePrivada[idDeIntencion] = {
                'socketId': socket.id,
                'userid': await getLoggedInUser(socket.request),
                'ip': socket.handshake.address
            };
        } else {
            socket.to(socket.id).emit('idIECPExistente', idDeIntencion);
        }
    });
    socket.on('intencionRecibirClavePrivada', async (datos) => { // Paso 2 (emitido por cliente recibidor)
        let idDeIntencion = datos['id'];
        if (Object.keys(intencionesDeEnviarClavePrivada).includes(idDeIntencion)) {
            let intencionDeEnviar = intencionesDeEnviarClavePrivada[idDeIntencion];
            let clavePublicaDeEnvio = datos['clave-publica'];
            let ipDeRecibidor = socket.handshake.address;
            let usuarioRecibidor = await getLoggedInUser(socket.request);
            
            // Verificar identidad del usuario (recuerda que el ciente mandador también debe revisar esto)
            if (ipDeRecibidor === intencionDeEnviar['ip']) {
                if (usuarioRecibidor === intencionDeEnviar['userid']) {
                    io.to(intencionDeEnviar['socketId']).emit('resIntEnvClavePrivada', {
                        clavePublicaDeEnvio,
                        //ipDeRecibidor,
                        //usuarioRecibidor,
                        'socketDeRecibidor': socket.id
                    });
                }
            }
        }
    });
    socket.on('enviarClavePrivada', (datos) => {
        let usuarioRecibidor = datos['usuario-recibidor'];
        let claveEncriptada = datos['clave-encriptada'];
        io.to(usuarioRecibidor).emit('recibirClavePrivada', claveEncriptada);
    });
});

// Save data when terminating
function saveData() {
    // fs.writeFileSync('./data/users.json', JSON.stringify(users));
    // fs.writeFileSync('./data/sesiones.json', JSON.stringify(sesiones));
    // fs.writeFileSync('./data/conversaciones.json', JSON.stringify(converes));
    // fs.writeFileSync('./data/subscripciones.json', JSON.stringify(subscripciones));
    // fs.writeFileSync('./data/apipubkeys.json', JSON.stringify(apipubkeys));
}
process.on('SIGINT', () => {
    saveData();
    process.exit(0);
});
process.on('SIGTERM', () => {
    saveData();
    process.exit(0);
});

server.listen(port, () => {
    console.log(`Mensajeador corriendo en puerto ${port}`);
});