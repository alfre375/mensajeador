# Setting up a Mensajeador instance
## Configuring PostgreSQL
1. Install [PostgreSQL 18](https://www.postgresql.org/), either locally or on another device.
2. Create a database, then make sure that you can access the database from the device(s) where you run the Mensajeador instance.
3. Run the following SQL commands to create the required tables:
```sql
CREATE TABLE instances (
    instance_id UUID PRIMARY KEY,
    
    name_full TEXT,
    display_name TEXT,
    
    address TEXT NOT NULL,
    port INTEGER NOT NULL CHECK (port > 0 AND port <= 65535),
    
    public_key BYTEA NOT NULL,
    
    first_recognised TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE conversations (
    conver_id UUID PRIMARY KEY,
    conver_name TEXT NOT NULL,
    conver_type INT DEFAULT 0,
    crypt_type TEXT DEFAULT 'AES-GCM',
    settings JSONB,
    creation_date TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE users (
    user_id UUID PRIMARY KEY,
    uname TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    salt TEXT NOT NULL,
    email TEXT,
    public_key BYTEA,
    twofa_key TEXT,
    lang TEXT,
    display_name TEXT,
    profile_picture TEXT,
    oauth JSONB,
    agree_tos_privacy_policy TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE conversation_participants (
    conver_id UUID REFERENCES conversations(conver_id) ON DELETE CASCADE,
    user_global_id TEXT NOT NULL,
    encrypted_key TEXT NOT NULL,
    PRIMARY KEY (conver_id, user_global_id)
);

CREATE TABLE user_conversations (
    conver_global_id TEXT NOT NULL,
    user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
    encrypted_key TEXT NOT NULL,
    PRIMARY KEY (user_id, conver_global_id)
);

CREATE TABLE messages (
    id BIGSERIAL PRIMARY KEY,
    conver_id UUID REFERENCES conversations(conver_id) ON DELETE CASCADE,
    
    sender_global_id TEXT,
    
    ciphertext TEXT NOT NULL,
    iv TEXT NOT NULL
);

CREATE TABLE sessions_web (
    id TEXT PRIMARY KEY,
    user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
    expiry TIMESTAMPTZ NOT NULL
);

CREATE TABLE llaves_api (
    pub_rsa_pss_key BYTEA PRIMARY KEY,
    user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,
    time_added TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE web_notification_subscriptions (
    id BIGSERIAL PRIMARY KEY,

    user_id UUID REFERENCES users(user_id) ON DELETE CASCADE,

    endpoint TEXT UNIQUE NOT NULL,
    expiration_time TIMESTAMPTZ,

    p256dh TEXT NOT NULL,
    auth TEXT NOT NULL
);
```

## Preparing the server
1. Ensure npm and nodejs are installed and updated
2. Install all required dependencies by running `npm i`
3. Create a .env file
4. Specify the PORT variable by adding a line with `PORT=[the port you want to use]` to the .env file. The default port for HTTPS is 443, so it is recommended that you use that if you want others to use the client. The port you use does not affect your ability to use federation, as the port is sent when prompting another server for recognition. At this time, it is recommended that you do not change your PORT once you set it up; however, this will likely change in the future.
5. Generate a 256-bit hexadecimal AES key. This can be done with `openssl rand -hex 32`. Then, add the key to the SERVER_AES_KEY environment variable.
6. Generate a VAPID keypair with [this website](https://vapidkeys.com/). Put the private key in the VAPID_PRIVATE_KEY environment variable and the public key in the VAPID_PUBLIC_KEY environment variable.
7. If you would like to enable GitHub SSO, go to [the GitHub developer settings](https://github.com/settings/developers) and create a new OAuth App. Set the Homepage URL to be your instance's address at the / endpoint, and the Authorisation Callback URL to your instance's address at the /oauth/github/callback endpoint. The name does not affect the functionality of the SSO, but it is a required field. When you are done creating the OAuth App, put the client ID into the SSO_GITHUB_CLIENT_ID environment variable. Then, generate a new client secret for your OAuth App, and put it into the SSO_GITHUB_CLIENT_SECRET environment variable. If you would not like to enable GitHub SSO, you can skip this step.
8. Put the full domain into the FULL_DOMAIN environment variable. It should include the protocol (`https://`) and the port, but should not end in a `/`.
9. Put the primary IP into the IP environment variable. This can be an IPv4 address, but it can also be a domain name, localhost, or something else of the sort. Do not include the port, protocol, nor end in `/`.
10. Put either 0 (if you want to enable federation) or 1 (if you do not want to enable federation). This can be changed at any time. As of version 1.0.0, federation is not supported.
11. Specify the instance ID in the INSTANCE_ID environment variable. Avoid using the same ID as another instance. It must be in the form of a UUID. It should be in hexadecimal and with the hyphens in the appropriate places. It is required even if you do not plan to federate in the present nor the future. You can get a random UUID with the `uuidgen -r` command. If you want a UUID based on something like your domain name, you can use the `uuidgen -N [whatever you want here] -n @dns -s`. In any case, it is strongly recommended to check if the official Mensajeador instance already has a server with your instance ID. **YOU SHOULD NEVER CHANGE YOUR INSTANCE ID.**
12. Specify the INSTANCE_NAME, INSTANCE_CODE, and INSTANCE_DISPLAY_NAME environment variables. The INSTANCE_CODE required in order to get other instances to recognise your instances. If neither the INSTANCE_NAME nor the INSTANCE_DISPLAY_NAME are specified, the INSTANCE_CODE will be used for both. If only one of either the INSTANCE_NAME and INSTANCE_DISPLAY_NAME are specified, the other will be the value of the one which is specified. Neither INSTANCE_CODE nor INSTANCE_NAME nor INSTANCE_DISPLAY_NAME should contain newline nor the carriage return character. INSTANCE_CODE should not contain spaces (` `) nor colons (`:`). Additionally, in most cases, it is recommended that the INSTANCE_CODE contains only the latin letters used in English (ideally only lowercase), numbers used in English (0123456789), underscores (_), and hyphens (-), though this would depend on your primary target audience. It is used in global usernames (which is `[local username]:[instance code]`), which are used when pinging another user (currently not working as of v1.0.0), or when adding another user to a conversation. However, if for example, your target audience (note that this includes anyone who interacts with your users on the platform, not just your users themselves) predominantly communicates on the platform in the Russian language, it is advised that you choose something that is easy to type in the Russian keyboard for your INSTANCE_CODE, and the same goes for other languages. It is safe to change all 3 of these values in the future.
13. Set the POSTGRES_HOST, POSTGRES_PORT, and POSTGRES_DB variables to your PostgreSQL server's IP (domain name and localhost are OK when applicable), port, and database name respectively. Set the POSTGRES_USER and POSTGRES_PASSWD environment variables to your PostgreSQL user's username and password respectively.
14. Create the `ssl` folder directly in the mensajeador directory, and inside, put your TLS private key under `privatekey.pem` and your TLS public key under `fullchain.pem`. It is recommended that you have your keys signed by a widely trusted Certificate Authority.
15. Create a `data` folder directly in the mensajeador directory, and inside, make a folder named `pfp`.
16. Create an RSA-PSS keypair with the following commands:
```bash
mkdir federation

openssl genpkey -algorithm rsa-pss \
    -pkeyopt rsa_keygen_bits:2048 \
    -pkeyopt rsa_pss_keygen_md:sha256 \
    -pkeyopt rsa_pss_keygen_mgf1_md:sha256 \
    -pkeyopt rsa_pss_keygen_saltlen:32 \
    -out federation/privatekey_rsa_pss.pem
    
openssl pkey -in federation/privatekey_rsa_pss.pem -pubout -out federation/pubkey_rsa_pss.pem
```
Make sure never to share your private key. Encode your private key as base 64 and put the result into the PRI_RSA_PSS_KEY environment variable, then encode your public key as base 64 and put the result of that into the PUB_RSA_PSS_KEY environment variable. Alternatively, you can directly put the keys into federation/privatekey_rsa_pss.pem and federation/pubkey_rsa_pss.pem, with the federation directory directly in the mensajeador directory, for the private and public keys respectively.

# Environment variable options
## PORT
This is the port of the server. It is optional, and defaults to 443.

## SERVER_AES_KEY
This is the AES key of the server. It is required, and should be a randomly generated 256-bit hexadecimal key. It should be kept secret. If it is leaked, immediately reset all 2FA keys and notify your users that they must immediately reenable 2FA to maintain the security of their accounts.

## VAPID_PRIVATE_KEY
This is the vapid private key for the server. It is used for web push notificaitons; however, as of version 1.0.2, push notifications do not work. The key is required to enable push notifications, but is otherwise not required.

## VAPID_PUBLIC_KEY
This is the vapid public key for the server. It is used for web push notifications; however, as of version 1.0.2, push notifications do not work. The key is required to enable push notifications, but is otherwise not required. It must be of the same pair as the VAPID_PRIVATE_KEY.

## SSO_GITHUB_CLIENT_ID
This is the client ID for your GitHub OAuth App for this instance. It is required if and only if you want to enable GitHub SSO.

## SSO_GITHUB_CLIENT_SECRET
This is the client secret for your GitHub OAuth App for this instance. It is required if and only if you want to enable GitHub SSO. It must be of the same OAuth App as the SSO_GITHUB_CLIENT_ID.

## FULL_DOMAIN
This is the full domain of the instance. If you have multiple, it should be your primary domain, or the one that is least likely to change (though it can be changed). It should include the protocol, the domain name, and the port, but should not include the / at the end. If you do not have a domain, you can also use an IP address. If you are on a local instance and do not need it to be accessed by the internet, you can also use localhost or a private IP address or a domain name from a custom DNS; however, if you want something that is visible to the public or interacts with an instance on the internet, you should use the public IP address.

## IP
This is the IP at which the instance is located. It can be an IP address, a domain name, or another such identifier. It should be one by which anyone who uses your instance would be able to access.

## ISOLATED
This is an option to disable federation; however, as of version 1.0.2, federation is not implemented yet. The value can either be a 0, in which case federation would (once implemented) be enabled, or a 1, in which case federation would be disabled, even after it is implemented. The default value is 0.

## INSTANCE_ID
This is the ID of your instance. It is very important that this does not change, even if ISOLATED is set to 1 and you never intend to set it to 0. It is highly reccomended that you choose a unique INSTANCE_ID value; otherwise, federation would break once implemented. It should be a UUID. If you run multiple servers for one instance, they should have the same INSTANCE_ID, since they are still the same instance.

## INSTANCE_NAME
This is the full name of your instance. This is required for federation, but can default to other values. This can be changed at any time.

## INSTANCE_CODE
This is the code for your instance. It is used as part of the username for the users on your instance. It can change at any time, but keep in mind that others will need to know it in order to mention users of your instance as well as to add your instance's users to conversations. It should be easily typable by as many of those who interact with your users as possible, whether or not they themselves are your users. For example, if your users are interacted with primarily by Russian speakers, it is reccomended that you choose something that can be easily typed with the russian keyboard. If there is no language that is very common among those who interact with your users, it is reccomended that you choose something that can be easily typed with the English keyboard. Symbols should also be avoided to make typing this code easier. It is especially important that this code does not contain spaces ( ), colons (:), nor at symbols (@). 

## INSTANCE_DISPLAY_NAME
This is the display name of your instance. This can also be changed at any time, and there are effectively no limits to what it can be, though generally it is as short as or shorter than the full name of the instance. For example, you may choose to use an abbreviated form of your INSTANCE_NAME.

## POSTGRES_USER
This is the user of the postgres server. This user should have permissions to read, add, change, and delete rows on the database specified on POSTGRES_DB. It is required.

## POSTGRES_HOST
This is the address of the postgres server as it is known by the server running the instance. Setting it to localhost, a private IP, or an internal hostname is acceptable, and may be the best option depending on the specific setup. It does not need to be (and probably should not be) accessible to the general public, but should be accessible to the servers of this instance. It is required.

## POSTGRES_DB
This is the name of the database on Postgres that is used for Mensajeador. It is required.

## POSTGRES_PASSWD
This is the password for the user specified under POSTGRES_USER. It is required if a password is required for access to the postgres server specified in POSTGRES_HOST.

## POSTGRES_PORT
This is the port of the Postgres server. It is required.

## DEV_SKIP_TOTP
This is an option to disable TOTP validation. If enabled, the server will allow a user to log in even if the TOTP is blank, invalid, or incorrect. It is not reccomended for production environments, and is intended for test environments only. It defaults to disabled. To enable it, set the value to `SKIP`.