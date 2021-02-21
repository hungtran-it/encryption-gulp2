const crypto = require('crypto');
const through = require('through2');
const aes = require('browserify-aes')

const ENCODING = 'base64';
const SimpleAes = {
  randomBytes(size) {
    return crypto.randomBytes(size);
  },
  sha256(input) {
    return crypto.createHash('sha256')
      .update(input)
      .digest()
  },
  encrypt(secret, text) {
    return SimpleAes.encryptRaw(SimpleAes.sha256(secret), text)
  },
  decrypt(secret, crypted) {
    return SimpleAes.decryptRaw(SimpleAes.sha256(secret), crypted)
  },
  encryptRaw(hashedSecret, text) {
    // const iv = SimpleAes.randomBytes(16);
    const iv = Buffer.from((text.toString('utf8', 0, 16) + "fr1o4m4the7AESimplementation").substr(0, 16));
    const cipher = aes.createCipheriv('aes-256-ctr', hashedSecret, iv)
    return Buffer.concat([iv, cipher.update(text), cipher.final()])
  },
  decryptRaw(hashedSecret, crypted) {
    const iv = crypted.slice(0, 16)
    crypted = crypted.slice(16)
    const decipher = aes.createCipheriv('aes-256-ctr', hashedSecret, iv)
    return Buffer.concat([decipher.update(crypted), decipher.final()])
  }
}

function encrypt(plain, password) {
  const encrypted = SimpleAes.encrypt(password, plain);

  return encrypted.toString(ENCODING);
}

function descrypt(encryptedText, password) {
  const decrypted = SimpleAes.decrypt(password, Buffer.from(encryptedText, ENCODING)).toString('utf8');

  return decrypted;
}

module.exports = function ({ password = 'password', decrypt = false } = {}) {
  if (decrypt) {
    return through.obj((vinylFile, encoding, callback) => {
      callback(null, encryptor(vinylFile, password, decrypt));
    });
  }

  return through.obj((vinylFile, encoding, callback) => {
    callback(null, encryptor(vinylFile, password, decrypt));
  });
};

function encryptor(vinylFile, password, decrypt) {
  if (vinylFile._contents) {

    if (decrypt) {
      const decryptedText = vinylFile._contents.toString('utf8');
      const decrypted = descrypt(decryptedText, password);
      vinylFile._contents = Buffer.from(decrypted, 'utf8');
    } else {
      const encrypted = encrypt(vinylFile._contents, password);
      vinylFile._contents = Buffer.from(encrypted, 'utf8');
    }

    return vinylFile;
  }

  return vinylFile;
}
