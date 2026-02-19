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
const twoWeeks = 1000 * 60 * 60 * 24 * 14;

const httpsOptions = {
    key: fs.readFileSync('./ssl/privatekey.pem'),
    cert: fs.readFileSync('./ssl/fullchain.pem')
};

const server = https.createServer(httpsOptions, app);
const { Server } = require("socket.io");
const io = new Server(server);

// Carga los usuarios
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
        "display_name": "Mx. Pinapple",
        "conversations": []
    }
];
users = fs.existsSync('./data/users.json') ?
    JSON.parse(fs.readFileSync('./data/users.json').toString()) : [];
var sesiones = fs.existsSync('./data/sesiones.json') ?
    JSON.parse(fs.readFileSync('./data/sesiones.json').toString()) : {};

// Carga las conversaciónes
var converes = {
    'a8d3d493-434f-448c-bf88-2d69b9c211fa': {
        'conversation-type': 0, // Usuario a usuario, estilo mensaje directo
        'conversation-name': 'Clase de Mx. Pineapple',
        'creation-date': new Date().getTime(),
        'conversation-users': {
            0: 'abcabcabc', // Key: uid del usuario; val: llave de conversación encriptada con llave pública del usuario
            1: 'cbacba'
        },
        'conversation-settings': {
            'font': undefined, // cuando es undefined: usa fuentes predeterminados
            'require-consent-to-add': false, // requiere que todos los usuarios acepten para agregar más usuarios
        },
        'messages': [
            { // En realidad, cada mensaje está encriptado
                'sent-by': 0,
                'type': 0, // 0 es un mensaje de texto estándard
                'content': 'This message was sent today',
                'sent-at': new Date().getTime()
            }
        ]
    }
}
converes = fs.existsSync('./data/conversaciones.json') ?
    JSON.parse(fs.readFileSync('./data/conversaciones.json').toString()) : {};

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
var subscripciones = fs.existsSync('./data/subscripciones.json') ?
    JSON.parse(fs.readFileSync('./data/subscripciones.json').toString()) : {};

function agregarSubscripcion(req, subscripcion) {
    let liu = getLoggedInUser(req);
    if (liu === undefined) { return false; }
    if (!Object.keys(subscripciones).includes(liu)) {
        subscripciones[liu] = [];
    }
    subscripciones[liu].push(subscripcion);
    return true;
}
function quitarSubscripcion(subscripcion) {
    for (user of subscripciones) {
        for (subscripcion_subses in subscripciones[user]) {
            if (subscripciones[user][subscripcion_subses] == subscripcion) {
                subscripciones[user][subscripcion_subses] = undefined;
            }
        }
    }
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
            quitarSubscripcion(subscripcion);
            return { 'success': false, 'quitado': true }
        }
        return { 'success': false, 'err': err }
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

function getLoggedInUser(req) {
    let session = req.session.sessionId;
    if (session && sesiones[session]) {
        if (sesiones[session]['expiry'] < new Date().getTime()) {
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
app.get('/', (req, res) => {
    let liu = getLoggedInUser(req)
    if (liu === undefined) {
        res.send(loadWebpage('index.html', req, {}));
        return;
    }
    if (users[liu]['2fa_key'] === undefined) {
        res.send(translate('\\!!general.debes_configurar_a2f!!\\',getUserLocales(req)));
        return;
    }
    if (users[liu]['public_key'] === undefined) {
        res.send(loadWebpage('createUserKeypair.html', req, {}));
        return;
    }
    res.send(loadWebpage('chat.html', req, {
        'UID-DE-USUARIO': liu,
        'NOMBRE_DE_PERFIL': users[liu]['display_name'],
        'NOMBRE_DE_USUARIO': users[liu]['uname']
    }));
});

app.get('/configurarA2F', (req, res) => {
    let mfa_key = gen2FAKey();
    users[getLoggedInUser(req)]['2fa_key'] = encryptAES(mfa_key, process.env.SERVER_AES_KEY);
    res.send(loadWebpage('2fa.html', req, {'CÓDIGO_A2F':mfa_key}));
    mfa_key = undefined;
});

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
        res.send(translate('\\!!iniciar_sesión.usuario_no_existe!!\\', getUserLocales(req)));
        return;
    }
    let salt = users[uid]['salt'];
    passwd = calculateSha256(passwd + salt);
    if (passwd !== users[uid]['password']) {
        res.statusCode = 400;
        res.send(translate('\\!!iniciar_sesión.contraseña_incorrecta!!\\', getUserLocales(req)));
        return;
    }
    if (!verifyOTP(mfa_code, decryptAES(users[uid]['2fa_key'], process.env.SERVER_AES_KEY))) {
        res.statusCode = 400;
        res.send(translate('\\!!iniciar_sesión.código_a2f_incorrecto!!\\', getUserLocales(req)));
        return;
    }
    let sid = saltGen();
    let i = 0;
    while (sid in sesiones) {
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
        res.statusCode = 400;
        res.send(translate('\\!!registro.err.correo_inválido!!\\',getUserLocales(req)));
        return;
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
    if (getUserByUsername(uname)) {
        res.statusCode = 400;
        res.send(translate('\\!!registro.err.usuario_ya_existe!!\\', getUserLocales(req)));
        return;
    }
    let user = generateUser(uname, passwd, correo, clavepublica, getUserLocales(req),
        display_name);
    users.push(user);
    let sid = saltGen();
    let i = 0;
    while (sid in sesiones) {
        i++;
        if (i >= 100) {
            res.statusCode = 500;
            res.send(translate('\\!!registro.err.sin_sid_disponible!!\\', getUserLocales(req)));
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

app.get('/configurarCuenta', (req, res) => {
    let liu = getLoggedInUser(req);
    if (liu === undefined) { res.redirect('/login'); }
    res.send(loadWebpage('configurarCuenta.html', req, {
        'UID': liu
    }));
});

app.post('/subscribe', (req, res) => {
    let subscripcion = req.body.subscripcion;
    if (!subscripcion) {
        return res.status(400).json({ error: 'Falta subscripción' });
    }
    agregarSubscripcion(req, subscripcion);
    res.status(201).json({ success: true });
});

app.post('/unsubscribe', (req, res) => {
    let subscripcion = req.body.subscripcion;
    if (!subscripcion) {
        return res.status(400).json({ success: false, error: 'Falta subscripción' });
    }
    quitarSubscripcion(subscripcion);
    res.status(200).json({ success: true });
});

app.get('/vapidPublicKey', (req, res) => {
    res.json({ publicKey: publicVapidKey });
});

app.get('/comenzarConversacion/md', (req, res) => {
    if (getLoggedInUser(req) === undefined) {
        res.statusCode = 200;
        res.redirect('/login');
        return;
    }
    res.statusCode = 200;
    res.send(loadWebpage('comenzarMD.html', req, {}));
});

app.get('/enviarClavePrivada', (req, res) => {
    if (!getLoggedInUser(req)) {
        res.redirect('/login');
        return;
    }
    res.send(loadWebpage('enviarClavePrivada.html', req, {}));
});

app.get('/recibirClavePrivada', (req, res) => {
    if (!getLoggedInUser(req)) {
        res.redirect('/login');
        return;
    }
    res.send(loadWebpage('recibirClavePrivada.html', req, {}));
});

app.post('/establecerFotoDePerfil', upload.single('pfp'), async (req, res) => {
    try {
        let uid = getLoggedInUser(req);
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
        
        users[uid]['profile-picture'] = outputPath.toString();
        
        res.status(200).redirect('/configurarCuenta');
    } catch (err) {
        console.error(err);
        res.status(400).json({ 'success': false });
    }
});

app.delete('/desestablecerFotoDePerfil', (req, res) => {
    let uid = getLoggedInUser(req);
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
    
    users[uid]['profile-picture'] = undefined;
    
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
        if (language in available_languages) {
            languages.push(language);
        }
    }
    res.redirect('/');
});

app.get('/app/getUIDByUsername', (req, res) => {
    let username = req.query.username;
    let uid = getUserByUsername(username);
    if (uid === undefined) {
        res.statusCode = 400;
        res.send(translate('\\!!app.usuario_no_existe!!\\', getUserLocales(req)));
        return;
    }
    res.statusCode = 200;
    res.send(uid);
})

app.get('/app/getUserPublicKey', (req, res) => {
    let uid = req.query.user;
    if (typeof uid == 'string') {
        uid = parseInt(uid);
        if (uid === NaN) {
            res.statusCode = 400;
            res.send(translate('\\!!app.uid_no_válido!!\\', getUserLocales(req)));
            return;
        }
    }
    if (users[uid] === undefined) {
        res.statusCode = 400;
        res.send(translate('\\!!app.usuario_no_existe!!\\', getUserLocales(req)));
        return;
    }
    let key = users[uid]['public_key'];
    res.send(key);
});

app.get('/app/getLoggedInUser', (req, res) => {
    let liu = getLoggedInUser(req);
    res.statusCode = 200;
    res.send(liu);
})

app.get('/app/converesDeUsuario', (req, res) => {
    let liu = getLoggedInUser(req);
    if (liu === undefined) {
        res.json([]);
        return;
    }
    let converesDeUsuario = users[liu]['conversations'];
    res.json(converesDeUsuario);
});

app.get('/app/nombreDeConver', (req, res) => {
    let conver = req.query.conver;
    let liu = getLoggedInUser(req);
    if (liu === undefined) {
        res.statusCode = 401;
        res.send('Debes iniciar sesión primero');
        return;
    }
    if (!(conver in converes)) {
        res.statusCode = 400;
        res.send('No existe la conversación');
        return;
    }
    if (converes[conver]['conversation-users'][liu] === undefined) {
        res.statusCode = 403;
        res.send('No estás en esta conversación');
        return;
    }
    res.statusCode = 200;
    res.send(converes[conver]['conversation-name']);
});

app.get('/app/llaveAESDeConver', (req, res) => {
    let conver = req.query.conver;
    let liu = getLoggedInUser(req);
    if (liu === undefined) {
        res.statusCode = 401;
        res.send('Debes iniciar sesión primero');
        return;
    }
    if (!conver in converes) {
        res.statusCode = 400;
        res.send('No existe la conversación');
        return;
    }
    if (converes[conver]['conversation-users'][liu] === undefined) {
        res.statusCode = 403;
        res.send('No estás en esta conversación');
        return;
    }
    res.statusCode = 200;
    res.send(converes[conver]['conversation-users'][liu]);
});

app.post('/app/comenzarConversacion/md', (req, res) => {
    let usersToAdd = req.body.users;
    let nombreConver = req.body.nombreConver;
    
    if (nombreConver.includes('"')) {
        res.statusCode = 400;
        res.send(translate('\\!!app.doble_comillas_inválido_en_nombre_de_conver!!\\', getUserLocales(req)));
        return;
    }
    
    let date = new Date().getTime();
    let uuid = crypto.randomUUID();
    let i = 0;
    while (uuid in converes) {
        i++
        if (i > 500) {
            res.statusCode = 500;
            res.send(translate('\\!!app.no_se_encontró_uuid_abierto!!\\', getUserLocales(req)));
            return;
        }
        uuid = crypto.randomUUID();
    }
    
    for (user of Object.keys(usersToAdd)) {
        if (user in users) {
            users[user]['conversations'].push(uuid);
        } else {
            usersToAdd[user] = undefined;
        }
    }
    
    let conver = {
        'conversation-type': 0, // Usuario a usuario, estilo mensaje directo
        'conversation-name': nombreConver,
        'creation-date': date,
        'conversation-users': usersToAdd,
        'conversation-settings': {
            'font': undefined, // cuando es undefined: usa fuentes predeterminados
            'require-consent-to-add': false, // requiere que todos los usuarios acepten para agregar más usuarios
        },
        'messages': []
    }
    
    converes[uuid] = conver;
    res.statusCode = 200;
    res.send(uuid);
});

app.get('/app/fotoDePerfil', (req, res) => {
    let uid = req.query.user;
    uid = parseInt(uid);
    if ((uid == NaN) || !(uid in users)) {
        res.sendFile(__dirname + '/assets/imgs/FDP_predeterminado.svg');
        return;
    }
    if (users[uid]['profile-picture'] !== undefined) {
        //res.set('Content-Type', users[uid]['profile-picture']['type']); // images/png images/svg images/jpeg
        res.sendFile(users[uid]['profile-picture']);
        return;
    }
    res.sendFile(__dirname + '/assets/imgs/FDP_predeterminado.svg');
});

app.get('/app/mensajesNuevos', (req, res) => {
    let desde = parseInt(req.query.desde); // Mensaje más viejo
    let hasta = parseInt(req.query.hasta); // Mensaje más nuevo
    let conver = req.query.conver;
    if (!(conver in converes)) {
        res.statusCode = 400;
        res.send('La conversación solicitada no existe');
        return;
    }
    let mensajesDeConver = converes[conver]['messages'];
    let n = mensajesDeConver.length;
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
    let mensajesParaDevolver = mensajesDeConver.slice(desde_verificado, hasta_verificado + 1);
    
    res.send(mensajesParaDevolver);
});

app.get('/app/nombreParaMostrarPorUID', (req, res) => {
    let uid = req.query.uid;
    if (uid in users) {
        res.send(users[uid]['display_name']);
        return;
    }
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

// Socket.io
io.use((socket, next) => {
    sessionMiddleware(socket.request, socket.request.res || {}, next);
});

var socketIds = {} // key: user UUID, value: array of socketIds
var intencionesDeEnviarClavePrivada = {} // key: id de intención, valor: {socketId, userId, IP}

io.on('connection', (socket) => {
    if (getLoggedInUser(socket.request) === undefined) {
        socket.disconnect(true);
    }
    if (socketIds[getLoggedInUser(socket.request)] === undefined) {
        socketIds[getLoggedInUser(socket.request)] = [];
    }
    socketIds[getLoggedInUser(socket.request)].push(socket.id);
    //console.log(socketIds);
    socket.on('disconnect', () => {
        //console.log('user disconnected');
        let liu = getLoggedInUser(socket.request);
        socketIds[liu].splice(socketIds[liu].indexOf(socket.id), 1)
    });
    
    // Sistema de mensajes
    socket.on('enviarMsg', (msg) => {
        //console.log('message: ' + JSON.stringify(msg));
        // Agregar mensaje a conversación
        let datosDeMensaje = msg['datosDeMensaje'];
        let conver = msg['conver'];
        if ((conver in converes) && (getLoggedInUser(socket.request) in converes[conver]['conversation-users'])) {
            converes[conver]['messages'].push(datosDeMensaje);
            
            // Emitir a miembros en linea
            let miembrosParaEmitir = Object.keys(converes[conver]['conversation-users']);
            let socketsParaEmitir = [];
            let miembrosEnLinea = [];
            //console.log(miembrosParaEmitir);
            for (miembro of miembrosParaEmitir) {
                if (miembro in socketIds) {
                    miembrosEnLinea.push(miembro);
                    for (id of socketIds[miembro]) {
                        socketsParaEmitir.push(id);
                    }
                }
            }
            for (socketId of socketsParaEmitir) {
                io.to(socketId).emit('recibirMensaje', msg);
            }
            
            // Notificar a miembros listados para notificación
            for (miembro of msg['notificar']) {
                let uidMiembro = getUserByUsername(miembro);
                if (uidMiembro === undefined) { continue; }
                if (!Object.keys(converes[conver]['conversation-users']).includes(uidMiembro)) { continue; }
                if (!miembrosEnLinea.includes(uidMiembro)) {
                    if (Object.keys(subscripciones).includes(uidMiembro)) {
                        for (subscripcion of subscripciones[uidMiembro]) {
                            enviarNotificacion(subscripcion, {
                                title: 'Nuevo mensaje',
                                body: 'Alguien te ha mandado un mensaje en ' + converes[conver]['conversation-name'],
                                url: '/'
                            });
                        }
                    }
                }
            }
        }
    });
    
    // Envio de clave privada de un dispositivo a otro
    socket.on('intencionEnviarClavePrivada', (datos) => { // Paso 1 (emitido por cliente enviador)
        let idDeIntencion = datos['id'];
        if (!(idDeIntencion in Object.keys(intencionesDeEnviarClavePrivada))) {
            intencionesDeEnviarClavePrivada[idDeIntencion] = {
                'socketId': socket.id,
                'userid': getLoggedInUser(socket.request),
                'ip': socket.handshake.address
            };
        } else {
            socket.to(socket.id).emit('idIECPExistente', idDeIntencion);
        }
    });
    socket.on('intencionRecibirClavePrivada', (datos) => { // Paso 2 (emitido por cliente recibidor)
        let idDeIntencion = datos['id'];
        if (Object.keys(intencionesDeEnviarClavePrivada).includes(idDeIntencion)) {
            let intencionDeEnviar = intencionesDeEnviarClavePrivada[idDeIntencion];
            let clavePublicaDeEnvio = datos['clave-publica'];
            let ipDeRecibidor = socket.handshake.address;
            let usuarioRecibidor = getLoggedInUser(socket.request);
            
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
    fs.writeFileSync('./data/users.json', JSON.stringify(users));
    fs.writeFileSync('./data/sesiones.json', JSON.stringify(sesiones));
    fs.writeFileSync('./data/conversaciones.json', JSON.stringify(converes));
    fs.writeFileSync('./data/subscripciones.json', JSON.stringify(subscripciones));
}
process.on('SIGINT', () => {
    saveData();
    process.exit(0);
});
process.on('SIGTERM', () => {
    saveData();
    process.exit(0);
})

server.listen(port, () => {
    console.log(`Mensajeador corriendo en puerto ${port}`);
});