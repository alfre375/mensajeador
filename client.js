async function generateKeyPair() {
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048, // Tamaño de la llave (e.g., 2048 o 4096 bits)
            publicExponent: new Uint8Array([1, 0, 1]), // 65537
            hash: "SHA-256",
        },
        true, // extraíble
        ["encrypt", "decrypt", "wrapKey", "unwrapKey"] // usos
    );
    return keyPair;
}

async function generateAesKey() {
    const key = await crypto.subtle.generateKey(
        {
            name: "AES-GCM", // Or "AES-CBC", "AES-CTR", "AES-KW"
            length: 256, // For AES-256; can also be 128 or 192
        },
        true, // extractable: true if you want to export the key later
        ["encrypt", "decrypt"] // keyUsages: define what the key can be used for
    );
    return key;
}

async function encryptDataAsymmetric(publicKey, data) {
    const encodedData = new TextEncoder().encode(data);
    const encryptedData = await window.crypto.subtle.encrypt(
        { name: "RSA-OAEP", },
        publicKey,
        encodedData
    );
    return encryptedData;
}

async function decryptDataAsymmetric(privateKey, encryptedData) {
    const decryptedData = await window.crypto.subtle.decrypt(
        { name: "RSA-OAEP", },
        privateKey,
        encryptedData
    );
    return new TextDecoder().decode(decryptedData);
}

// Encrypt -> devuelve objetos serializables (Base64)
async function encryptDataAES(key, plaintext) {
    // IV de 12 bytes (96 bits) recomendado para AES-GCM
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encoded = new TextEncoder().encode(plaintext);
    const ciphertextBuf = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv: iv,
        },
        key,
        encoded
    );
    return {
        ciphertext: arrayBufferToBase64(ciphertextBuf),
        iv: arrayBufferToBase64(iv.buffer) // usa tu función existente
    };
}

// Decrypt <- acepta ciphertext e iv en Base64 (por ejemplo, resultado de JSON.parse)
async function decryptDataAES(key, encryptedData) {
    const ciphertextBase64 = encryptedData['ciphertext']
    const ivBase64 = encryptedData['iv'];
    const ciphertextBuf = base64ToArrayBuffer(ciphertextBase64);
    const ivBuf = base64ToArrayBuffer(ivBase64);
    const ivView = new Uint8Array(ivBuf);
    const decrypted = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: ivView,
        },
        key,
        ciphertextBuf
    );
    return new TextDecoder().decode(decrypted);
}

function arrayBufferToBase64(buf) {
    const bytes = new Uint8Array(buf);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
}

function base64ToArrayBuffer(b64) {
    const binary = atob(b64);
    const len = binary.length;
    const bytes = new Uint8Array(len);
    for (let i = 0; i < len; i++) bytes[i] = binary.charCodeAt(i);
    return bytes.buffer;
}

// Wrap AES key with RSA public key -> base64 string
async function wrapAesKeyWithPublicKey(publicKey, aesKey) {
    // 'raw' format wraps the AES key bytes
    const wrapped = await crypto.subtle.wrapKey(
        'raw',          // format of the key to wrap (raw bytes)
        aesKey,         // CryptoKey (AES)
        publicKey,      // RSA public CryptoKey (RSA-OAEP)
        { name: 'RSA-OAEP' }
    );
    return arrayBufferToBase64(wrapped);
}

// Unwrap (decrypt) wrapped AES key with RSA private key -> returns CryptoKey (AES)
async function unwrapAesKeyWithPrivateKey(privateKey, wrappedBase64) {
    const wrappedBuf = base64ToArrayBuffer(wrappedBase64);
    const aesKey = await crypto.subtle.unwrapKey(
        'raw',                       // format of wrapped key
        wrappedBuf,                  // wrapped key ArrayBuffer
        privateKey,                  // RSA private CryptoKey (RSA-OAEP)
        { name: 'RSA-OAEP' },        // unwrapping algorithm
        { name: 'AES-GCM', length: 256 }, // algorithm of the resulting key
        true,                        // extractable (true if you want to export later)
        ['encrypt', 'decrypt']       // usages
    );
    return aesKey;
}

async function exportPublicKeyForJSON(publicKey) {
    // Regresa un objeto JWK seguro para JSON.stringify();
    return await crypto.subtle.exportKey('jwk', publicKey);
}

async function importPublicKeyFromJSON(jwk) {
    // Acepta un objeto JWK (o un string JSON conteniendo el JWK) y devuelve un CryptoKey para la encripción
    const parsed = (typeof jwk === 'string') ? JSON.parse(jwk) : jwk;
    return await crypto.subtle.importKey(
        'jwk',
        parsed,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        true,
        ['encrypt', 'wrapKey']
    );
}

async function exportPrivateKeyForLocalStorage(privateKey) {
    // Exporta las claves privadas como JWK y regresa un string bueno para localStorage.setItem();
    const jwk = await crypto.subtle.exportKey('jwk', privateKey);
    return JSON.stringify(jwk);
}

async function importPrivateKeyFromLocalStorage(storedString) {
    // Toma el string producido por exportPrivateKeyForLocalStorage() y regresa un CryptoKey para decripción.
    const jwk = JSON.parse(storedString);
    return await crypto.subtle.importKey(
        'jwk',
        jwk,
        { name: 'RSA-OAEP', hash: 'SHA-256' },
        true,
        ['decrypt', 'unwrapKey']
    );
}

async function makeRequest(url, method, body) {
    try {
        const response = await fetch(url, { // Replace with your URL
            method: method,
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify(body)
        });
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        const result = await response;
        return result;
    } catch (error) {
        console.error('Error posting data:', error);
    }
}

function formatearTiempo(timestamp) {
    const date = new Date(timestamp);
    
    const hours = String(date.getHours()).padStart(2, '0');
    const minutes = String(date.getMinutes()).padStart(2, '0');
    const day = String(date.getDate()).padStart(2, '0');
    const month = String(date.getMonth() + 1).padStart(2, '0'); // Month is 0-indexed
    const year = date.getFullYear();
    
    return `${hours}h${minutes} ${day}/${month}/${year}`;
}

async function registrarse() {
    let uname = document.getElementById('uname').value;
    let password = document.getElementById('password').value;
    let email = document.getElementById('email').value;
    let display_name = document.getElementById('displayname').value;
    let accountKeyPair = await generateKeyPair();
    let private_key = await exportPrivateKeyForLocalStorage(accountKeyPair.privateKey);
    let public_key = await exportPublicKeyForJSON(accountKeyPair.publicKey);
    localStorage.setItem('account_private_key', private_key);
    let res = await makeRequest('./registrar', 'POST', {
        'uname': uname,
        'passwd': password,
        'correo': email,
        'clavepublica': public_key,
        'display_name': display_name
    });
    //console.log(res);
    
    if (!res) {
        alert('Error en la petición del servidor');
        return;
    }
    
    if (res.redirected) {
        window.location.href = res.url;
        return;
    }
    
    try {
        const contentType = res.headers.get('content-type') || '';
        
        if (contentType.includes('application/json')) {
            const json = await res.json();
            if (json && typeof json.message === 'string') {
                alert(json.message);
            } else {
                alert(JSON.stringify(message));
            }
        } else {
            // Suponemos texto pleno (str)
            const text = await res.text();
            alert(text);
        }
    } catch (err) {
        console.error('Error leyendo la respuesta:', err);
        alert('Respuesta inesperada del servidor');
    }
}

async function comenzarMD() {
    let users = document.getElementById('uname').value.split(',');
    let convoName = document.getElementById('convoName').value;
    let convoKey = await generateAesKey();
    let uts = {} // Users to submit
    for (user of users) {
        let uid = await (await makeRequest('/app/getUIDByUsername?username='+user, 'GET')).text();
        let pubKey = await (await makeRequest('/app/getUserPublicKey?user='+uid, 'GET')).text();
        pubKey = await importPublicKeyFromJSON(pubKey);
        let encryptedConvoKey = await wrapAesKeyWithPublicKey(pubKey, convoKey);
        uts[uid] = encryptedConvoKey;
    }
    let liu = await (await makeRequest('/app/getLoggedInUser', 'GET')).text();
    let pubKey = await (await makeRequest('/app/getUserPublicKey?user='+liu, 'GET')).text();
    pubKey = await importPublicKeyFromJSON(pubKey);
    let encryptedConvoKey = await wrapAesKeyWithPublicKey(pubKey, convoKey);
    uts[liu] = encryptedConvoKey;
    let res = await makeRequest('/app/comenzarConversacion/md', 'POST', { 'users': uts, 'nombreConver': convoName});
    if (res.status === 200) {
        window.location.href = '../';
    }
}