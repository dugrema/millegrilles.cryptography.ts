import { BasicConstraintsExtension, X509Certificate } from "@peculiar/x509";

export async function verifyCertificate(certificatePems: string[], caCertPem: string, date?: Date | boolean): Promise<boolean> {
    // Load the CA certificate to get the publicKey. Ensure it has the CA extension flag.
    const caCert = new X509Certificate(caCertPem);
    const caExtensions: BasicConstraintsExtension = caCert.getExtension('2.5.29.19');
    if(caExtensions.ca !== true) throw new Error("Invalid CA certificate");

    // Determine the validation date (if any)
    let validationDate = null;  // Date is false, no check is done on the certificate dates
    if(date) {
        validationDate = date;
    } else if(date !== false) {
        validationDate = new Date();  // Use current date
    } else if(date != null) {
        throw new Error("Bad value for date. Must be a Date object, false or null.");
    }

    // Map the PEMs to certificate objects
    let certs = certificatePems.map(item=>new X509Certificate(item));

    // Add the CA cert (self-signed).
    certs.push(caCert);

    // Reverse to verify the certificate chain in order (CA/intermediary first).
    certs.reverse();
    
    let parentKey = caCert.publicKey.rawData;  // Initialise verification with the CA key (self-signed, checks itself)
    for(let cert of certs) {
        let result = await cert.verify({date: validationDate, publicKey: parentKey, signatureOnly: false});
        if(!result) throw new Error("Invalid certificate");
        
        const basicExtensions: BasicConstraintsExtension = caCert.getExtension('2.5.29.19');
        if(basicExtensions.ca === true) {
            // This is a CA cert (root, intermediary). Use current publicKey to check next certificate.
            parentKey = cert.publicKey.rawData;
        } else {
            // This is a leaf certificate. Ensure no other certificates are present (will crash if any).
            parentKey = null;
        }
    }

    return true;
}
