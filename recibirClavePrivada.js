const baseUrl = `${window.location.protocol}//${window.location.host}`;
var socket = io(baseUrl, {
    withCredentials: true
});

var clavePrivadaDeEnvio = null;

async function intencionDeRecibir() {
    let id = prompt('Ingresa el código de 6 dígitos:');
    let idRegEx = /^[0-9]{6}$/;
    if (!idRegEx.test(id)) {
        alert('Id inválido!');
        return;
    }
    let parClaves = await generateKeyPair();
    clavePrivadaDeEnvio = parClaves.privateKey;
    let clavePublicaDeEnvio = parClaves.publicKey;
    socket.emit('intencionRecibirClavePrivada', {'id': id, 'clave-publica': await exportPublicKeyForJSON(clavePublicaDeEnvio)});
}

socket.on('recibirClavePrivada', async (claveEncriptada) => {
    // Decriptar Clave
    //let claveDecriptada = await unwrapPrivateKeyWithPrivateKey(clavePrivadaDeEnvio, claveEncriptada);
    let claveDecriptada = await decryptPrivateKeyHybrid(clavePrivadaDeEnvio, claveEncriptada);
    
    // Revisar si hay clave existente
    if (localStorage.getItem('account_private_key')) {
        let ok = prompt('Estas segure de que quieres sobreescribir la clave existente? NO SE PUEDE RECUPERAR! (Escribe AVXC)');
        if (ok !== 'AVXC') {
            alert('No has escrito AVXC, cancelando');
            return;
        }
    }
    
    // Escribir clave privada a localStorage
    localStorage.setItem('account_private_key', claveDecriptada);
});

async function insertarConTexto() {
    let full_code = prompt('Inserta el código: ');
    let code_hash = await sha256(full_code);
    let [salt, iv, ciphertext] = full_code.split(';');
    
    let passwd = prompt('Inserta la contraseña: ');
    passwd = await sha256(passwd + salt);
    
    let pkey_dec = await decryptDataAES(await importAESKeyFromHex(passwd), { iv, ciphertext });
    
    let pkey_original = localStorage.getItem('account_private_key');
    let confirmation;
    if (pkey_original) {
        confirmation = confirm('¿Quieres reponer la clave existente con la de hash: ' + code_hash + '?');
    } else {
        confirmation = confirm('¿Quieres agregar la clave con hash: ' + code_hash + '?');
    }
    
    if (confirmation) {
        localStorage.setItem('account_private_key', pkey_dec);
    }
}