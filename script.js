const { encrypt, decrypt } = require("./encrypt");

const payload = { userId: 123, username: "testuser" };

console.log("🔐 Encrypting JWT...");
const encryptedToken = encrypt(payload);
console.log("Encrypted Token:", encryptedToken);

console.log("\n🔓 Decrypting JWT...");
const decryptedPayload = decrypt(encryptedToken);
console.log("Decrypted Payload:", decryptedPayload);

if (decryptedPayload) {
    console.log("\n✅ Success: JWT encryption and decryption working correctly!");
} else {
    console.log("\n❌ Error: JWT verification failed.");
}