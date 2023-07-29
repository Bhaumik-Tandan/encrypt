const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');

const app = express();
const port = 3000;

app.use(bodyParser.json());

// Encrypt data using AES-256
function encryptData(data, key) {
    try {
      // Ensure the key is a valid 32-byte buffer
      const validatedKey = crypto.createHash('sha256').update(key).digest('base64').slice(0, 32);
  
      const iv = crypto.randomBytes(16);
      const cipher = crypto.createCipheriv('aes-256-cbc', validatedKey, iv);
      let encryptedData = cipher.update(data, 'utf8', 'hex');
      encryptedData += cipher.final('hex');
      return iv.toString('hex') + ':' + encryptedData;
    } catch (error) {
      throw new Error('Encryption failed. Invalid key or data.');
    }
  }

// Decrypt data using AES-256
function decryptData(encryptedData, key) {
    try {
      // Ensure the key is a valid 32-byte buffer
      const validatedKey = crypto.createHash('sha256').update(key).digest('base64').slice(0, 32);
  
      const [iv, data] = encryptedData.split(':');
      const decipher = crypto.createDecipheriv('aes-256-cbc', validatedKey, Buffer.from(iv, 'hex'));
      let decryptedData = decipher.update(data, 'hex', 'utf8');
      decryptedData += decipher.final('utf8');
      return decryptedData;
    } catch (error) {
      throw new Error('Decryption failed. Invalid key or encrypted data.');
    }
  }

// Endpoint to encrypt data
app.post('/encrypt', (req, res) => {
  const { data, key } = req.body;
  if (!data || !key) {
    return res.status(400).json({ error: 'Both data and key are required' });
  }

  try {
    const encryptedData = encryptData(data, key);
    res.json({ encrypted_data: encryptedData });
  } catch (error) {
    res.status(500).json({ error: 'Encryption failed. Invalid key or data.' });
  }
});

// Endpoint to decrypt data
app.post('/decrypt', (req, res) => {
  const { encrypted_data, key } = req.body;
  if (!encrypted_data || !key) {
    return res.status(400).json({ error: 'Both encrypted_data and key are required' });
  }

  try {
    const decryptedData = decryptData(encrypted_data, key);
    res.json({ decrypted_data: decryptedData });
  } catch (error) {
    res.status(500).json({ error: 'Decryption failed. Invalid key or encrypted data.' });
  }
});

// Start the server
app.listen(port, () => {
  console.log(`Server is running on http://localhost:${port}`);
});
