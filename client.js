async function generateKeyPair() {
    const keyPair = await window.crypto.subtle.generateKey(
        {
            name: "RSA-OAEP",
            modulusLength: 2048, // Tamaño de la llave (e.g., 2048 o 4096 bits)
            publicExponent: new Uint8Array([1, 0, 1]), // 65537
            hash: "SHA-256",
        },
        true, // extraíble
        ["encrypt", "decrypt"] // usos
    );
    return keyPair;
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
        ['encrypt']
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
        ['decrypt']
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