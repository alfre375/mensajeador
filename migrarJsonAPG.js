// Archivo generado por ChatGPT

require('dotenv').config()
const fs = require('fs');
const { Client } = require('pg');
const crypto = require('crypto')

// =====================
// CONFIG
// =====================
const INSTANCE_ID = process.env.INSTANCE_ID;

if (!INSTANCE_ID) {
    throw new Error("Falta INSTANCE_ID en variables de entorno");
}

// validación básica de UUID
if (!/^[0-9a-fA-F-]{36}$/.test(INSTANCE_ID)) {
    throw new Error("INSTANCE_ID no parece ser un UUID válido");
}

// conexión (tu versión)
const client = new Client({
    user: process.env.POSTGRES_USER,
    host: process.env.POSTGRES_HOST || 'localhost',
    database: process.env.POSTGRES_DB || 'mensajeador_db',
    password: process.env.POSTGRES_PASSWD,
    port: process.env.POSTGRES_PORT || 5432,
});

// mapa de userId a su nuevo ID (por UUIDv4)
const userIdMap = {};

// formato global
function makeGlobalId(localId) {
    return `${localId}:${INSTANCE_ID}`;
}

async function main() {
    await client.connect();
    console.log("✔ PostgreSQL conectado");

    const users = JSON.parse(fs.readFileSync('./data/users.json', 'utf8'));
    const conversaciones = JSON.parse(fs.readFileSync('./data/conversaciones.json', 'utf8'));

    // =====================
    // USERS
    // =====================
    for (let i = 0; i < users.length; i++) {
        const u = users[i];
        const newId = crypto.randomUUID();

        userIdMap[i.toString()] = newId;

        await client.query(`
        INSERT INTO users (
            user_id, uname, password, salt, email,
            public_key, twofa_key, lang,
            display_name, profile_picture, oauth
        )
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
        `, [
            newId,
            u.uname,
            u.password,
            u.salt,
            u.email,
            u.public_key ? Buffer.from(JSON.stringify(u.public_key)) : null,
            u["2fa_key"],
            u.lang,
            u.display_name,
            u["profile-picture"],
            u.oauth ? JSON.stringify(u.oauth) : null
        ]);
        
        // =====================
        // SUBSCRIPCIONES WEB
        // =====================
        const subscripciones = JSON.parse(
            fs.readFileSync('./data/subscripciones.json', 'utf8')
        );

        for (const [userIndex, subs] of Object.entries(subscripciones)) {
            const userUUID = userIdMap[userIndex];

            if (!userUUID) {
                console.warn(`⚠ Usuario no encontrado para subscripción: ${userIndex}`);
                continue;
            }

            for (const sub of subs) {
                await client.query(`
                INSERT INTO web_notification_subscriptions (
                    user_id, endpoint, expiration_time, p256dh, auth
                )
                VALUES ($1,$2,$3,$4,$5)
                `, [
                    userUUID,
                    sub.endpoint,
                    sub.expirationTime ? new Date(sub.expirationTime) : null,
                    sub.keys.p256dh,
                    sub.keys.auth
                ]);
            }
        }

        console.log("✔ Subscripciones web migradas");
    }

    console.log("✔ Users migrados");

    // =====================
    // CONVERSACIONES
    // =====================
    for (const [oldId, conv] of Object.entries(conversaciones)) {
        await client.query(`
        INSERT INTO conversations (
            conver_id, conver_name, conver_type, crypt_type, settings, creation_date
        )
        VALUES ($1,$2,$3,$4,$5,$6)
        `, [
            oldId,
            conv["conversation-name"],
            conv["conversation-type"],
            conv["crypt-type"],
            JSON.stringify(conv["conversation-settings"]),
            new Date(conv['creation-date'])
        ]);

        // =====================
        // PARTICIPANTES
        // =====================
        for (const [userIndex, encryptedKey] of Object.entries(conv["conversation-users"])) {
            const userUUID = userIdMap[userIndex];

            await client.query(`
            INSERT INTO conversation_participants (
                conver_id, user_global_id, encrypted_key
            )
            VALUES ($1,$2,$3)
            `, [
                oldId,
                makeGlobalId(userUUID),
                encryptedKey
            ]);
        }

        // =====================
        // MENSAJES
        // =====================
        for (const msg of conv.messages) {
            await client.query(`
            INSERT INTO messages (
                conver_id, sender_global_id, ciphertext, iv
            )
            VALUES ($1,$2,$3,$4)
            `, [
                oldId,
                null, // no hay sender en JSON
                msg.ciphertext,
                msg.iv
            ]);
        }
    }

    console.log("✔ Conversaciones y mensajes migrados");

    // =====================
    // USER_CONVERSATIONS
    // =====================
    for (let i = 0; i < users.length; i++) {
        const u = users[i];
        const userUUID = userIdMap[i.toString()];

        for (const convId of u.conversations) {
            await client.query(`
            INSERT INTO user_conversations (
                conver_global_id, user_id, encrypted_key
            )
            VALUES ($1,$2,$3)
            `, [
                makeGlobalId(convId),
                userUUID,
                conversaciones[convId]['conversation-users'][i]
            ]);
        }
    }

    console.log("✔ Relaciones usuario-conversación migradas");

    await client.end();
}

main().catch(err => {
    console.error("❌ Error en migración:", err);
    process.exit(1);
});