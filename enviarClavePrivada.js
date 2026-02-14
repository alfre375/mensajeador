const baseUrl = `${window.location.protocol}//${window.location.host}`;
var socket = io(baseUrl, {
    withCredentials: true
});

function intencionDeEnviar(id) {
    let elementoId = document.getElementById('idDeEnvio');
    elementoId.innerHTML = id || '000000';
    socket.emit('intencionEnviarClavePrivada', {'id': id || '000000'});
}

socket.on('idIECPExistente', (id) => {
    intencionDeEnviar(id + 1);
});

socket.on('resIntEnvClavePrivada', async (datos) => {
    // Verificar
    let confirmar = confirm(`Enviando clave privada a dispositivo de ${datos['usuarioRecibidor']}`);
    if (!(confirmar === true)) {
        alert('Se ha cancelado el envio');
        return;
    }
    
    // Encriptar clave
    let clavePublicaDeEnvio = await importPublicKeyFromJSON(datos['clavePublicaDeEnvio']);
    //let clavePrivadaDeUsuario = await importPrivateKeyFromLocalStorage(localStorage.getItem('account_private_key'));
    //let clavePrivadaDeUsuarioEncriptado = await wrapPrivateKeyWithPublicKey(clavePublicaDeEnvio, clavePrivadaDeUsuario);
    let clavePrivadaDeUsuarioEncriptado = await encryptPrivateKeyHybrid(
        clavePublicaDeEnvio,
        localStorage.getItem('account_private_key')
    );
    
    // Enviar clave
    socket.emit('enviarClavePrivada', {
        'usuario-recibidor': datos['socketDeRecibidor'],
        'clave-encriptada': clavePrivadaDeUsuarioEncriptado
    });
});