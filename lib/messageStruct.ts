type MessageKind = 1 | 2 | 3 | 4 | 5 | 6 | 7 | 8;

type Routage = {};

type PreMigration = {};

type MessageDecryption = {};

type MilleGrillesMessage = {
    id: string,  // Unique message identifier. Hex value of the blake2s-256 digest for this message kind.
    pubkey: string,  // Public key of the certificate used for signing the message.
    estampille: number,  // Timestamp in epoch (seconds)
    kind: MessageKind,  // Message kind
    contenu: string,  // Content of the message. Encoding depends on the kind of message.
    routage?: Routage,  // Routing information
    pre_migration?: PreMigration,  // Transaction migration information
    origine?: string,  // System of origin (IDMG)
    dechiffrage?: MessageDecryption,  // Decryption information.
    signature: string,  // Message signature
    certificate?: [string],  // PEM certificat chain (excluding the CA/root)
    millegrille?: string,  // PEM certificate of the system (CA/root)
    attachements?: {}  // Attachments to this message
};

