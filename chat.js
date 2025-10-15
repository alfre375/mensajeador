const baseUrl = `${window.location.protocol}//${window.location.host}`;
var socket = io(baseUrl, {
    withCredentials: true
});

let uid = null;
let converes = [];
let converAbierto = null;
let llaveAesDeConver = null;
let userPrivateKey = null;
const mensajeDeMuestra = `<div class="mensaje" id="muestra_de_mensaje"> <!--Mensaje de muestra-->
        <img src="/app/fotoDePerfil?user=uid" width="36.8px" height="36.8px" class="fotoDePerfilMensaje">
        <div class="mensajeMedio">
            <div> <!--Información de mensaje-->
                <span>de_quien_es</span>
                <span>cuando_se_ha_mandado</span>
                editado_en
            </div>
            <div>
                <span>texto_de_mensaje</span>
            </div>
        </div>
    </div>`

async function abrirConver(converParaAbrir) {
    converAbierto = converParaAbrir || converes[0];
    if (converAbierto && converes.includes(converAbierto)) {
        llaveAesDeConver = await (await makeRequest('/app/llaveAESDeConver?conver='+converAbierto,'GET')).text();
        llaveAesDeConver = await unwrapAesKeyWithPrivateKey(userPrivateKey, llaveAesDeConver);
        let mensajesParaPoblar = await cargarMensajes();
        resetearAreaDeMensajes();
        await poblarMensajesViejos(mensajesParaPoblar);
        let objetoConver = document.getElementById(converAbierto);
        if (objetoConver.classList.contains('converConNuevoMensaje')) {
            objetoConver.classList.remove('converConNuevoMensaje');
        }
        let divMensajes = document.getElementById('mensajes');
        divMensajes.scrollTop = divMensajes.scrollHeight;
    }
}
async function start() {
    uid = await (await makeRequest('/app/getLoggedInUser', 'GET')).text();
    converes = await (await makeRequest('/app/converesDeUsuario', 'GET')).json();
    userPrivateKey = await importPrivateKeyFromLocalStorage(localStorage.getItem('account_private_key'));
    abrirConver();
    popularListaDeConveres();
}

start();

function isValidUUID(uuidString) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuidString);
}

async function popularListaDeConveres() {
    for (conver of converes) {
        let placeholder = document.getElementById('uuid_de_conver');
        let pohtml = placeholder.outerHTML; // pohtml: Placeholder Outer HTML
        if (!isValidUUID(conver)) {
            continue;
        }
        let nombreConver = await (await makeRequest('/app/nombreDeConver?conver='+conver,'GET')).text();
        placeholder.outerHTML = pohtml.replaceAll('uuid_de_conver',conver).replace('NOMBRE_CONVER',nombreConver) + pohtml;
    }
    if (converes.length === 0) {
        document.getElementById('areaConverPrincipal').innerHTML = 'No tines ninguna conversación para cargar. Crea una nueva.';
    }
    //document.getElementById('uuid_de_conver').outerHTML = '';
}

async function enviarMensaje() {
    let msg = document.getElementById('msg');
    let contenidoMsg = msg.value;
    if (contenidoMsg.trim() === '') { return; }
    let notificar = [];
    for (n of contenidoMsg.split(' ')) {
        if (n.startsWith('@')) {
            notificar.push(n.slice(1));
        }
    }
    let timestamp = new Date().getTime();
    let msgJSON = {
        'sent-by': uid,
        'type': 0,
        'content': contenidoMsg,
        'sent-at': timestamp
    };
    let encryptedMsg = await encryptDataAES(llaveAesDeConver,JSON.stringify(msgJSON));
    let contentToEmit = {
        'datosDeMensaje': encryptedMsg,
        'conver': converAbierto,
        'notificar': notificar
    };
    socket.emit('enviarMsg', contentToEmit);
    msg.value = '';
}

async function cargarMensajes(desde, hasta) {
    if (desde === undefined) {
        desde = 25;
    }
    if (hasta === undefined) {
        hasta = 0;
    }
    let mensajesCargados = await makeRequest(`/app/mensajesNuevos?conver=${converAbierto}&desde=${desde}&hasta=${hasta}`, 'GET');
    if (mensajesCargados.status !== 200) {
        console.error(mensajesCargados.status + await mensajesCargados.text());
        return {};
    }
    return await mensajesCargados.json();
}

async function poblarMensajesViejos(mensajesParaPoblar) {
    mensajesParaPoblar = mensajesParaPoblar.reverse();
    for (mensaje of mensajesParaPoblar) {
        let mensajeDecriptado = JSON.parse(await decryptDataAES(llaveAesDeConver, mensaje));
        let uidDeEnviador = mensajeDecriptado['sent-by']
        let enviadoPor = await makeRequest('/app/nombreParaMostrarPorUID?uid='+uidDeEnviador,'GET');
        if (enviadoPor.status === 400) {
            enviadoPor = '[USUARIO BORRADO]';
        } else if  (enviadoPor.status === 200) {
            enviadoPor = await enviadoPor.text();
        } else {
            enviadoPor = '[ERR '+enviadoPor.status+']';
        }
        let contenidoParaIngresar = mensajeDeMuestra.replaceAll('de_quien_es', sanetizar(enviadoPor))
        contenidoParaIngresar = contenidoParaIngresar.replaceAll('uid', sanetizar(uidDeEnviador));
        let enviadoALas = formatearTiempo(mensajeDecriptado['sent-at']);
        contenidoParaIngresar = contenidoParaIngresar.replaceAll('cuando_se_ha_mandado', enviadoALas);
        contenidoParaIngresar = contenidoParaIngresar.replaceAll('editado_en', ''); // Aún no se pueden editar mensajes
        contenidoParaIngresar = contenidoParaIngresar.replaceAll('texto_de_mensaje', sanetizar(mensajeDecriptado['content']));
        let epma = document.getElementById('espacioParaMensajeAntes');
        let epmaHTML = epma.outerHTML;
        epma.outerHTML = epmaHTML + contenidoParaIngresar;
    }
}

function resetearAreaDeMensajes() {
    let mensajes = document.getElementById('mensajes');
    mensajes.innerHTML = '<div class="noMostrar" id="espacioParaMensajeAntes"></div><div class="noMostrar" id="espacioParaMensajeDespues"></div>';
}

socket.on('recibirMensaje', async (msg) => {
    let converDeMensaje = msg['conver'];
    //console.log(converDeMensaje);
    if (converDeMensaje === converAbierto) {
        // Averiguar y desencriptar mensaje
        let mensaje = msg['datosDeMensaje'];
        mensaje = JSON.parse(await decryptDataAES(llaveAesDeConver, mensaje));
        
        // Averiguar si está el usuario hasta abajo de la lista de mensajes
        let divMensajes = document.getElementById('mensajes');
        let estaHastaAbajo = divMensajes.scrollHeight - divMensajes.scrollTop <= divMensajes.clientHeight + 0.25;
        
        // Agregar mensaje a lista de mensajes
        let uidDeEnviador = mensaje['sent-by']
        let enviadoPor = await makeRequest('/app/nombreParaMostrarPorUID?uid='+uidDeEnviador,'GET');
        if (enviadoPor.status === 400) {
            enviadoPor = '[USUARIO BORRADO]';
        } else if  (enviadoPor.status === 200) {
            enviadoPor = await enviadoPor.text();
        } else {
            enviadoPor = '[ERR '+enviadoPor.status+']';
        }
        let contenidoParaIngresar = mensajeDeMuestra.replaceAll('de_quien_es', sanetizar(enviadoPor))
        contenidoParaIngresar = contenidoParaIngresar.replaceAll('uid', sanetizar(uidDeEnviador));
        let enviadoALas = formatearTiempo(mensaje['sent-at']);
        contenidoParaIngresar = contenidoParaIngresar.replaceAll('cuando_se_ha_mandado', enviadoALas);
        contenidoParaIngresar = contenidoParaIngresar.replaceAll('editado_en', ''); // Aún no se pueden editar mensajes
        contenidoParaIngresar = contenidoParaIngresar.replaceAll('texto_de_mensaje', sanetizar(mensaje['content']));
        let epmd = document.getElementById('espacioParaMensajeDespues');
        let epmdHTML = epmd.outerHTML;
        epmd.outerHTML = contenidoParaIngresar + epmdHTML;
        
        // Si el usuario estaba hasta abajo antes de agregar el mensaje, bajalos hasta abajo de nuevo
        if (estaHastaAbajo) { divMensajes.scrollTop = divMensajes.scrollHeight; }
    } else if (converes.includes(converDeMensaje)) {
        let objetoConver = document.getElementById(converDeMensaje);
        if (!objetoConver.classList.contains('converConNuevoMensaje')) {
            objetoConver.classList.add('converConNuevoMensaje');
        }
    }
})

function sanetizar(content) {
    content = content.replaceAll('<', '&lt;');
    content = content.replaceAll('>', '&gt;');
    return content;
}