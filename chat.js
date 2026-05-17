const baseUrl = `${window.location.protocol}//${window.location.host}`;
var socket = io(baseUrl, {
    withCredentials: true
});

let uid = null;
let converes = [];
let converAbierto = null;
let llaveAesDeConver = null;
let userPrivateKey = null;

let ctx_menu_msg_id = undefined;
let ctx_menu_msg_div = undefined;

const mensajeDeMuestra = `<div class="mensaje" id="muestra_de_mensaje" data-message-id="id_mensaje"> <!--Mensaje de muestra-->
        <div class="respondiendoDiv noRespondiendo" id="respondiendo_div_msg_id_mensaje" onclick="scrollToMsg(id_msg_resp)">
            ╭&nbsp;<img height="17.6px" height="17.6px" id="respondiendo_img_msg_id_mensaje" class="respItm" src="fdp_respondiendo">&nsbp;
            <span class="respItm" id="respondiendo_usuario_msg_id_mensaje">usuario_respondiendo</span>
            <span class="respItm" id="respondiendo_txt_msg_id_mensaje">texto_respondiendo</span>
        </div>
        <div class="mensajePrincipal">
            <img src="/app/fotoDePerfil?user=uid" width="36.8px" height="36.8px" class="fotoDePerfilMensaje" id="fdp_msg_id_mensaje">
            <div class="mensajeMedio">
                <div> <!--Información de mensaje-->
                    <span id="enviador_msg_id_mensaje">de_quien_es</span>
                    <span>cuando_se_ha_mandado</span>
                    editado_en
                </div>
                <div>
                    <span id="texto_msg_id_mensaje">texto_de_mensaje</span>
                </div>
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
        let mensajesParaPoblarActualizado = [];
        for (msg of mensajesParaPoblar) {
            if (idsDeMensajes.includes(msg.id)) continue;
            idsDeMensajes.push(msg.id);
            mensajesParaPoblarActualizado.push(msg);
        }
        await poblarMensajesViejos(mensajesParaPoblarActualizado);
        let objetoConver = document.getElementById(converAbierto);
        if (objetoConver.classList.contains('converConNuevoMensaje')) {
            objetoConver.classList.remove('converConNuevoMensaje');
        }
        espacioDeMensajes.scrollTop = espacioDeMensajes.scrollHeight;
        await delay(2000);
        pausarCargarMensajes = false;
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

function isValidGlobalUUID(uuidString) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}:[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuidString);
}

async function popularListaDeConveres() {
    for (let conver of converes) {
        let placeholder = document.getElementById('uuid_de_conver');
        let pohtml = placeholder.outerHTML; // pohtml: Placeholder Outer HTML
        if (!isValidGlobalUUID(conver)) {
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
        'sent-at': timestamp,
        'replying-to': currentlyReplyingTo
    };
    let encryptedMsg = await encryptDataAES(llaveAesDeConver,JSON.stringify(msgJSON));
    // let msgAutenticado = (
    //     await ((await makeRequest('/app/converModoMensajesAutenticados?conver_id=' + converAbierto, 'GET')).text())
    // ) === 'true';
    let contentToEmit = {
        'datosDeMensaje': encryptedMsg,
        'conver': converAbierto,
        'notificar': notificar
    };
    socket.emit('enviarMsg', contentToEmit);
    
    msg.value = '';
    closeReplyMessage();
}

async function cargarMensajes(desde, hasta) {
    if (desde === undefined) {
        desde = 24;
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
        contenidoParaIngresar = contenidoParaIngresar.replaceAll('id_mensaje', mensaje.id);
        contenidoParaIngresar = contenidoParaIngresar.replaceAll('muestra_de_mensaje', 'msg_'+mensaje.id);
        
        if (mensajeDecriptado['replying-to']) {
            let res_msg = await makeRequest(`/app/mensaje?conver=${converAbierto}&id=${mensajeDecriptado['replying-to']}`);
            
            if (res_msg.status !== 200) {
                console.error(res_msg.status + await res_msg.text());
            } else {
                let res_msg_json =  await res_msg.json();
                let res_dec = JSON.parse(await decryptDataAES(llaveAesDeConver, res_msg_json));
                let res_displayname = await (await makeRequest(`/app/nombreParaMostrarPorUID?uid=${res_dec['sent-by']}`)).text();
                contenidoParaIngresar = contenidoParaIngresar.replaceAll(' noRespondiendo', '');
                contenidoParaIngresar = contenidoParaIngresar.replaceAll('fdp_respondiendo','/app/fotoDePerfil?user=' + res_dec['sent-by']);
                contenidoParaIngresar = contenidoParaIngresar.replaceAll('usuario_respondiendo', sanetizar(res_displayname));
                contenidoParaIngresar = contenidoParaIngresar.replaceAll('texto_respondiendo', sanetizar(res_dec['content']));
                contenidoParaIngresar = contenidoParaIngresar.replaceAll('id_msg_resp', res_msg_json['id']);
            }
        }
        
        let epma = document.getElementById('espacioParaMensajeAntes');
        let epmaHTML = epma.outerHTML;
        epma.outerHTML = epmaHTML + contenidoParaIngresar;
        
        let div_msg = document.getElementById('msg_'+mensaje.id);
        div_msg.addEventListener('contextmenu', (e) => {
            e.preventDefault();
            e.stopPropagation();
            let ctx_menu = document.getElementById('msg_context_menu');
            ctx_menu.style.display = 'block';
            ctx_menu.style.left = (e.pageX - document.documentElement.clientWidth * 0.2) + 'px';
            ctx_menu.style.top = (e.pageY - 0) + 'px';
            ctx_menu.dataset.msgId = mensaje.id;
            if (ctx_menu_msg_div) {
                ctx_menu_msg_div.classList.remove('menu_ctx_abierto');
            }
            ctx_menu_msg_div = div_msg;
            ctx_menu_msg_id = div_msg.getAttribute('data-message-id');
            div_msg.classList.add('menu_ctx_abierto');
        }, false);
    }
}

function closeCtxMenu(menuElement, type) {
    menuElement.style.display = 'none';
    menuElement.style.left = undefined;
    menuElement.style.top = undefined;
    
    if (type == 'msg') {
        ctx_menu_msg_div.classList.remove('menu_ctx_abierto');
    }
}

document.body.addEventListener('contextmenu', (e) => {
    closeCtxMenu(document.getElementById('msg_context_menu'), 'msg');
});

var currentlyReplyingTo = undefined;

function setReplyMessage() {
    closeCtxMenu(document.getElementById('msg_context_menu'), 'msg'); // Cerrar el menú de contexto
    
    msgARespDiv = document.getElementById('msgAResp');
    msgARespDiv.style.display = 'block';
    
    msgARespText = document.getElementById('msgARespTxt');
    msgARespText.innerHTML = document.getElementById('texto_msg_' + ctx_menu_msg_id).innerHTML;
    
    msgARespImg = document.getElementById('msgARespImg');
    msgARespImg.src = document.getElementById('fdp_msg_' + ctx_menu_msg_id).src;
    
    document.documentElement.style.setProperty(
        '--main-text-box-height',
        document.getElementById('enviarMensajes').offsetHeight + 'px'
    );
    
    currentlyReplyingTo = ctx_menu_msg_id;
}

function closeReplyMessage() {
    msgARespDiv = document.getElementById('msgAResp');
    msgARespDiv.style.display = 'none';
    
    document.documentElement.style.setProperty(
        '--main-text-box-height',
        document.getElementById('enviarMensajes').offsetHeight + 'px'
    );
    
    currentlyReplyingTo = undefined;
}

const espacioDeMensajes = document.getElementById('mensajes');
var idsDeMensajes = [];
const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));

var pausarCargarMensajes = true;
espacioDeMensajes.addEventListener('scroll', async (e) => {
    if (pausarCargarMensajes) return;
    if (espacioDeMensajes.scrollTop <= 3) {
        // Cargar mensajes adicionales
        pausarCargarMensajes = true;
        let oldMBHeight = espacioDeMensajes.scrollHeight;
        let oldScrollHeight = espacioDeMensajes.scrollTop;
        let mensajesParaPoblar = await cargarMensajes(idsDeMensajes.length + 24, idsDeMensajes.length);
        let mensajesParaPoblarActualizado = [];
        for (msg of mensajesParaPoblar) {
            if (idsDeMensajes.includes(msg.id)) continue;
            idsDeMensajes.push(msg.id);
            mensajesParaPoblarActualizado.push(msg);
        }
        poblarMensajesViejos(mensajesParaPoblarActualizado);
        let scrollHeightDiff = espacioDeMensajes.scrollHeight - oldMBHeight;
        espacioDeMensajes.scrollTop = oldScrollHeight + scrollHeightDiff;
        
        await delay(2000);
        pausarCargarMensajes = false;
    }
});

async function scrollToMsg(msg) {
    console.log('Scrolling!')
    if (!idsDeMensajes.includes(msg.toString())) return;
    
    let msg_div = document.getElementById('msg_' + msg);
    msg_div.scrollIntoView({ behavior: 'smooth' });
    await delay(500);
    
    msg_div.style.backgroundColor = '#666';
    await delay(500);
    
    msg_div.style.backgroundColor = '#fff';
    await delay(500);
    
    msg_div.style.backgroundColor = undefined;
}

function resetearAreaDeMensajes() {
    espacioDeMensajes.innerHTML = '<div class="noMostrar" id="espacioParaMensajeAntes"></div><div class="noMostrar" id="espacioParaMensajeDespues"></div>';
}

socket.on('recibirMensaje', async (msg) => {
    let converDeMensaje = msg['conver'];
    //console.log(converDeMensaje);
    if (converDeMensaje === converAbierto) {
        idsDeMensajes.push(msg['id'])
        // Averiguar y desencriptar mensaje
        let mensaje_enc = msg['datosDeMensaje'];
        let mensaje = JSON.parse(await decryptDataAES(llaveAesDeConver, mensaje_enc));
        
        // Averiguar si está el usuario hasta abajo de la lista de mensajes
        let divMensajes = espacioDeMensajes;
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
        
        if (mensaje['replying-to']) {
            let res_msg = await makeRequest(`/app/mensaje?conver=${converAbierto}&id=${mensaje['replying-to']}`);
            
            if (res_msg.status !== 200) {
                console.error(res_msg.status + await res_msg.text());
            } else {
                let res_msg_json =  await res_msg.json();
                let res_dec = JSON.parse(await decryptDataAES(llaveAesDeConver, res_msg_json));
                let res_displayname = await (await makeRequest(`/app/nombreParaMostrarPorUID?uid=${res_dec['sent-by']}`)).text();
                contenidoParaIngresar = contenidoParaIngresar.replaceAll(' noRespondiendo', '');
                contenidoParaIngresar = contenidoParaIngresar.replaceAll('fdp_respondiendo','/app/fotoDePerfil?user=' + res_dec['sent-by']);
                contenidoParaIngresar = contenidoParaIngresar.replaceAll('usuario_respondiendo', sanetizar(res_displayname));
                contenidoParaIngresar = contenidoParaIngresar.replaceAll('texto_respondiendo', sanetizar(res_dec['content']));
                contenidoParaIngresar = contenidoParaIngresar.replaceAll('id_msg_resp', res_msg_json['id']);
            }
        }
        
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