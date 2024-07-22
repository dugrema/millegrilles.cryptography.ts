import stringify from 'json-stable-stringify'
import { digest } from './digest';
import { MessageSigningKey, verifyMessageSignature } from './ed25519';
import { CertificateWrapper } from './certificates';
import { getMgs4CipherWithSecret } from './encryption.mgs4';
import { secretFromEd25519, secretFromEd25519PrivateX25519Peer } from './x25519';
import { encodeBase64Nopad } from './multiencoding';
import { DomainSignature } from './keymaster';

export enum MessageKind {
    Document = 0,
    Request = 1,
    Command = 2,
    Transaction = 3,
    Response = 4,
    Event = 5,
    EncryptedResponse = 6,
    MigratedTransaction = 7,
    EncryptedCommand = 8,
}

export type Routage = {domaine?: string, action?: string, partition?: string};

export type PreMigration = {};

export type MessageDecryption = {
    cle_id?: string,
    cles?: Object,
    format: string,
    hachage?: string,
    header?: string,
    nonce?: string,
    signature?: DomainSignature,
    verification?: string,
};

export class MilleGrillesMessage {
    estampille: number;  // Timestamp in epoch (seconds)
    kind: MessageKind;  // Message kind
    contenu: string;  // Content of the message. Encoding depends on the kind of message.
    pubkey?: string;  // Public key of the certificate used for signing the message.
    id?: string;  // Unique message identifier. Hex value of the blake2s-256 digest for this message kind.
    routage?: Routage;  // Routing information
    pre_migration?: PreMigration;  // Transaction migration information
    origine?: string;  // System of origin (IDMG)
    dechiffrage?: MessageDecryption;  // Decryption information.
    signature: string;  // Message signature
    certificate?: string[];  // PEM certificat chain (excluding the CA/root)
    millegrille?: string;  // PEM certificate of the system (CA/root)
    attachements?: {}  // Attachments to this message

    constructor(estampille: number, kind: MessageKind, contenu: string) {
        this.estampille = estampille;
        this.kind = kind;
        this.contenu = contenu;
    }

    async sign(signingKey: MessageSigningKey) {
        this.pubkey = signingKey.publicKey;
        verifyForKind(this);
        if(!this.id) this.id = await generateMessageId(this);
        this.signature = await(signMessage(this, signingKey));
    }

    async verify() {
        let messageId = await generateMessageId(this);
        if(this.id !== messageId) throw new Error("Message digest is invalid");
        return await verifyMessage(this);
    }

    async getContent(decryptionKey?: MessageSigningKey): Promise<Object> {
        if(![MessageKind.EncryptedResponse, MessageKind.EncryptedCommand].includes(this.kind)) {
            // This is not an encrypted message. The content is a JSON string.
            return JSON.parse(this.contenu);
        }

        // This is an encrytped message.
        if(!decryptionKey) throw new Error("The message is encrypted. The decryption key must be provided.");
        if(!this.dechiffrage) throw new Error("The message is encrypted but is missing the decryption information.");

        return await decryptMessageContent(decryptionKey, this.kind, this.dechiffrage, this.contenu);
    }
};

/**
 * Verifies a message by kind to find any missing or empty elements.
 * @param message Message to check
 */
function verifyForKind(message: MilleGrillesMessage) {
    const kind = message.kind;
    if(typeof(kind) !== 'number') throw new Error("Kind missing");
    if(!message.pubkey) throw new Error("pubkey missing");
    if(!message.estampille) throw new Error("estampille missing");
    if(!message.contenu) throw new Error("contenu missing");
    if([1,2,3,5,7,8].includes(kind) && !message.routage) throw new Error("routage missing");
    if([6,8].includes(kind) && !message.dechiffrage) throw new Error("dechiffrage missing");
    if(kind === 7 && !message.pre_migration) throw new Error("pre_migration missing");
    if(kind === 8 && !message.origine) throw new Error("origine missing");
}

async function generateMessageId(message: MilleGrillesMessage): Promise<string> {
    const kind = message.kind;
    if(typeof(kind) !== 'number') throw new Error("Kind missing");

    // The digest is done on an array of elements. The array depends on the kind of message.

    let content: any[] = [message.pubkey, message.kind, message.estampille, message.contenu];
    if([0,4].includes(kind)) {
        // Nothing to add
    } else if([1,2,3,5].includes(kind)) {
        content.push(message.routage)
    } else if(kind === 6) {
        content.push(message.dechiffrage)
    } else if(kind === 7) {
        content.push(message.routage)
        content.push(message.pre_migration)
    } else if(kind === 8) {
        content.push(message.routage)
        content.push(message.origine)
        content.push(message.dechiffrage)
    } else {
        throw new Error('Unsupported kind of message');
    }

    // Convert to JSON (properly ordered for dict elements)
    let output: any = stringify(content);
    // Convert to bytes
    output = new TextEncoder().encode(output.normalize());
    
    // Digest with blake2s-256 to hex
    let digestBytes = await digest(output, {digestName: 'blake2s-256', encoding: 'bytes'})
    let digestString = Buffer.from(digestBytes).toString('hex');
    
    return digestString;
}

async function signMessage(message: MilleGrillesMessage, key: MessageSigningKey): Promise<string> {
    if(!message.id) throw new Error("Message id is missing");
    let messageId = Buffer.from(message.id, 'hex');
    let signature = await key.sign(messageId);
    message.certificate = key.certificate.pemChain;
    return signature
}

async function verifyMessage(message: MilleGrillesMessage): Promise<boolean> {
    if(!message.id) throw new Error("Message id is missing");
    let messageId = Buffer.from(message.id, 'hex');
    let signatureBytes = Buffer.from(message.signature, 'hex');
    let pubkey = Buffer.from(message.pubkey, 'hex');
    return await verifyMessageSignature(pubkey, messageId, signatureBytes);
}

export async function createRoutedMessage(
    signingKey: MessageSigningKey, kind: MessageKind, content: Object, routing: Routage, timestamp?: Date
): Promise<MilleGrillesMessage> {
    if(![1,2,3,5].includes(kind)) throw new Error("createStandardMessage Only supports kinds 1, 2, 3 and 5");
    
    if(!timestamp) timestamp = new Date();
    let timestampEpoch: number = Math.floor(timestamp.getTime() / 1000);
    let contentString = stringify(content);
    let message = new MilleGrillesMessage(timestampEpoch, kind, contentString);
    message.routage = routing;
    await message.sign(signingKey);

    return message
}

export async function createDocument(
    signingKey: MessageSigningKey, content: Object, timestamp?: Date
): Promise<MilleGrillesMessage> {
    return await createSimpleMessage(signingKey, MessageKind.Document, content, timestamp);
}

export async function createResponse(
    signingKey: MessageSigningKey, content: Object, timestamp?: Date
): Promise<MilleGrillesMessage> {
    return await createSimpleMessage(signingKey, MessageKind.Response, content, timestamp);
}

async function createSimpleMessage(
    signingKey: MessageSigningKey, kind: MessageKind, content: Object, timestamp?: Date
): Promise<MilleGrillesMessage> {
    if(!timestamp) timestamp = new Date();
    let timestampEpoch: number = Math.floor(timestamp.getTime() / 1000);
    let contentString = stringify(content);
    let message = new MilleGrillesMessage(timestampEpoch, MessageKind.Document, contentString);
    await message.sign(signingKey);

    return message
}

export async function createEncryptedResponse(
    signingKey: MessageSigningKey, encryptionKeys: CertificateWrapper[], content: Object, timestamp?: Date
): Promise<MilleGrillesMessage> {

    let millegrilleKeyHex = signingKey.certificate.getMillegrillePublicKey();
    let millegrilleKeyBytes = Buffer.from(millegrilleKeyHex, 'hex');
    let secret = await secretFromEd25519(millegrilleKeyBytes);
    let cipher = await getMgs4CipherWithSecret(secret.secret);

    // Convert content to binary
    let contentBytes = new TextEncoder().encode(stringify(content));

    // Encrypt content, serialize with base64nopad
    let outputBuffers = [];
    outputBuffers.push(await cipher.update(contentBytes));
    outputBuffers.push(await cipher.finalize());
    outputBuffers = outputBuffers.filter(item=>item)  // Remove null buffers
    let output = Buffer.concat(outputBuffers);
    let contentString = encodeBase64Nopad(output);

    let cles = {};
    for(let encryptionKey of encryptionKeys) {
        let publicKey = encryptionKey.getPublicKey();
        let publicKeyBytes = Buffer.from(publicKey, 'hex');
        let encryptedSecret = await secretFromEd25519PrivateX25519Peer(secret.secret, publicKeyBytes);
        cles[publicKey] = encodeBase64Nopad(encryptedSecret);
    }

    // Populate decryption information
    let decryption: MessageDecryption = {
        cles,
        format: 'mgs4',
        nonce: encodeBase64Nopad(cipher.header),
    }

    if(!timestamp) timestamp = new Date();
    let timestampEpoch: number = Math.floor(timestamp.getTime() / 1000);
    let message = new MilleGrillesMessage(timestampEpoch, MessageKind.EncryptedResponse, contentString);
    message.dechiffrage = decryption;
    await message.sign(signingKey);

    return message;
}

export async function createEncryptedCommand(
    signingKey: MessageSigningKey, encryptionKeys: CertificateWrapper[], content: Object, routing: Routage, timestamp?: Date
): Promise<MilleGrillesMessage> {
    throw new Error('not implemented')
}

async function decryptMessageContent(
    decryptionKey: MessageSigningKey, kind: MessageKind, decryption: MessageDecryption, content: string
): Promise<Object> {
    throw new Error('todo')
}
