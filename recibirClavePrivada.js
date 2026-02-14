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