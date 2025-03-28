require("dotenv").config();
const jwt = require("jsonwebtoken");
const crypto = require("crypto");

const JWT_SECRET = process.env.JWT_SECRET || "your_jwt_secret";
let ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || "defaultencryptionkey"; // Must be 32 bytes

// Ensure the encryption key is exactly 32 bytes
ENCRYPTION_KEY = crypto.createHash("sha256").update(ENCRYPTION_KEY).digest("base64").substr(0, 32);

const IV_LENGTH = 16; // AES requires 16-byte IV

const encrypt = (payload) => {
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });

    let iv = crypto.randomBytes(IV_LENGTH);
    let cipher = crypto.createCipheriv("aes-256-cbc", Buffer.from(ENCRYPTION_KEY, "utf-8"), iv);
    let encrypted = Buffer.concat([cipher.update(token), cipher.final()]);

    return iv.toString("hex") + ":" + encrypted.toString("hex");
};

const decrypt = (token) => {
    try {
        let parts = token.split(":");
        let iv = Buffer.from(parts[0], "hex");
        let encryptedText = Buffer.from(parts[1], "hex");

        let decipher = crypto.createDecipheriv("aes-256-cbc", Buffer.from(ENCRYPTION_KEY, "utf-8"), iv);
        let decrypted = Buffer.concat([decipher.update(encryptedText), decipher.final()]);

        return jwt.verify(decrypted.toString(), JWT_SECRET);
    } catch (error) {
        return null;
    }
};

module.exports = {
    encrypt,
    decrypt
};