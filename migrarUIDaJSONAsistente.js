async function migrar(conver_id, mapaUUID, modo_ultra_privado, desde, hasta) {
    let comandos = [];
    converAbierto = conver_id;
    if (converAbierto) {
        llaveAesDeConver = await (await makeRequest('/app/llaveAESDeConver?conver='+converAbierto,'GET')).text();
        llaveAesDeConver = await unwrapAesKeyWithPrivateKey(userPrivateKey, llaveAesDeConver);
        let mensajesParaPoblar = await cargarMensajes(desde, hasta);
        
        for (let mensaje of mensajesParaPoblar) {
            console.log(mensaje);
            let mensajeDecriptado = JSON.parse(await decryptDataAES(llaveAesDeConver, mensaje));
            let uidDeEnviador = mensajeDecriptado['sent-by'];
            if (Object.keys(mapaUUID).includes(uidDeEnviador)) {
                mensajeDecriptado['sent-by'] = mapaUUID[uidDeEnviador];
                let uuid_de_enviador = mensajeDecriptado['sent-by'];
                let mensajeActualizado = await encryptDataAES(llaveAesDeConver,JSON.stringify(mensajeDecriptado));
                let uuid_enviador_a_empujar = modo_ultra_privado ? null : uuid_de_enviador;
                comandos.push(
                    `UPDATE messages SET ciphertext = '${mensajeActualizado['ciphertext']}', iv = '${mensajeActualizado['iv']}', sender_global_id = '${uuid_enviador_a_empujar}' WHERE id = ${mensaje['id']}`
                );
            }
        }
    }
    
    return comandos.join('; ');
}