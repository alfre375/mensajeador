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
    JSON.parse(fs.readFileSync('./data/conversaciones.json').toString()) : {}

// Carga los archivos de localización
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

app.get('/comenzarConversacion/md', (req, res) => {
    if (getLoggedInUser(req) === undefined) {
        res.statusCode = 200;
        res.redirect('/login');
        return;
    }
    res.statusCode = 200;
    res.send(loadWebpage('comenzarMD.html', req, {}));
});

app.get('/app/getUIDByUsername', (req, res) => {
    let username = req.query.username;
    let uid = getUserByUsername(username);
    if (uid === undefined) {
        res.statusCode = 400;
        res.send(translate('\\!!app.usuario_no_existe!!\\', 'es'));
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
            res.send(translate('\\!!app.uid_no_válido!!\\'));
            return;
        }
    }
    if (users[uid] === undefined) {
        res.statusCode = 400;
        res.send(translate('\\!!app.usuario_no_existe!!\\', 'es'));
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
        res.send(translate('\\!!app.doble_comillas_inválido_en_nombre_de_conver!!\\'));
        return;
    }
    
    let date = new Date().getTime();
    let uuid = crypto.randomUUID();
    let i = 0;
    while (uuid in converes) {
        i++
        if (i > 500) {
            res.statusCode = 500;
            res.send(translate('\\!!app.no_se_encontró_uuid_abierto!!\\', 'es'));
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
        res.send(users[uid]['profile-picture']);
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
            //console.log(miembrosParaEmitir);
            for (miembro of miembrosParaEmitir) {
                if (miembro in socketIds) {
                    for (id of socketIds[miembro]) {
                        socketsParaEmitir.push(id);
                    }
                }
            }
            for (socketId of socketsParaEmitir) {
                io.to(socketId).emit('recibirMensaje', msg);
            }
            
            // Notificar a miembros listados para notificación
        }
    });
});

// Save data when terminating
function saveData() {
    fs.writeFileSync('./data/users.json', JSON.stringify(users));
    fs.writeFileSync('./data/sesiones.json', JSON.stringify(sesiones));
    fs.writeFileSync('./data/conversaciones.json', JSON.stringify(converes));
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