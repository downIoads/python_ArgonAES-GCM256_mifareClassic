# python_ArgonAES-GCM256_mifareClassic
Python script to encrypt data safely

# What is happening?
Master password is hashed using argon2 to make rainbow table attacks slower.
A static salt is used for argon2 because otherwise I would have to store the salt somewhere. Instead the idea is store the encrypted data on an NFC tag with a UID that can't be changed and the UID will be the argon2 salt of the encrypted data it holds. Then argon2 gives a 32byte password which is used for AES-GCM-256 encryption (static nonce which is equal to the salt used in argon2. Let me know if this can be problematic security-wise, I don't really care right now because this was just for learning). The algorithm spits outs two values: 1. encrypted message 2. tag
The encryped message will be written to a Mifare Classic 1k tag which has the UID that was used as salt/nonce. The tag itself will physically be written on the tag along with a description of which data the tag contains, so that I don't have to remember it. If your master password is strong, you should be able to give someone your tag, explain what you did, show your source code, answer any questions (except for revealing master password) and still be sure that the data won't be decryped any time soon (that was the goal anyways, maybe next week someone breaks argon2 or AES GCM). The reason for this project is that I have a bunch of Mifare Classic 1k cards which broken encryption, so the only way to safely store data is to encrypt it before it is written on the card. The card is not temperproof which is why AES-GCM was chosen. The tag written on the NFC chip is there to authenticate the authenticity of the encrypted data. It's a pretty cool feature of the GCM mode.

# Important advice
Using custom salts in argon2 and non-random nonces in AES becomes problematic as soon as you encrypt multiple pieces of data with these values. and the same password That's why per NFC tag (so per UID which is the salt/nonce) you should only encrypt data exactly once, then never re-use that salt/tag in combination with your master password ever again. This can be relevant because 4 byte UID is prone to collisions so you might accidently have bought chinese cards with the same UID.


