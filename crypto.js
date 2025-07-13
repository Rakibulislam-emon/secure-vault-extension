// Encryption/decryption utilities using Web Crypto API

// Generate encryption key from PIN
async function deriveKeyFromPin(pin, salt) {
  const encoder = new TextEncoder();
  const pinData = encoder.encode(pin);
  
  // Convert salt from hex string to Uint8Array if needed
  const saltArray = typeof salt === 'string' 
    ? new Uint8Array(salt.match(/.{1,2}/g).map(byte => parseInt(byte, 16)))
    : salt;
  
  // Use PBKDF2 to derive a key from the PIN
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    pinData,
    { name: 'PBKDF2' },
    false,
    ['deriveBits', 'deriveKey']
  );
  
  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: saltArray,
      iterations: 100000,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

// Encrypt data
async function encryptData(data, key) {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  
  // Generate a random IV
  const iv = crypto.getRandomValues(new Uint8Array(12));
  
  const encryptedBuffer = await crypto.subtle.encrypt(
    {
      name: 'AES-GCM',
      iv: iv
    },
    key,
    dataBuffer
  );
  
  // Combine IV and encrypted data
  const result = {
    iv: Array.from(iv).map(b => b.toString(16).padStart(2, '0')).join(''),
    data: Array.from(new Uint8Array(encryptedBuffer))
      .map(b => b.toString(16).padStart(2, '0')).join('')
  };
  
  return JSON.stringify(result);
}

// Decrypt data with better error handling
async function decryptData(encryptedString, key) {
  try {
    // Check if the input is valid JSON
    let encryptedObj;
    try {
      encryptedObj = JSON.parse(encryptedString);
    } catch (parseError) {
      console.error('Invalid encrypted data format:', parseError);
      throw new Error('Invalid encrypted data format');
    }
    
    // Validate the encrypted object structure
    if (!encryptedObj.iv || !encryptedObj.data) {
      console.error('Missing required encryption fields');
      throw new Error('Missing required encryption fields');
    }
    
    // Convert hex strings back to Uint8Arrays
    const iv = new Uint8Array(encryptedObj.iv.match(/.{1,2}/g)
      .map(byte => parseInt(byte, 16)));
    const encryptedData = new Uint8Array(encryptedObj.data.match(/.{1,2}/g)
      .map(byte => parseInt(byte, 16)));
    
    // Decrypt the data
    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: iv
      },
      key,
      encryptedData
    );
    
    // Convert the decrypted buffer to a string
    const decoder = new TextDecoder();
    return decoder.decode(decryptedBuffer);
  } catch (error) {
    console.error('Decryption error details:', error);
    throw error; // Re-throw to be handled by the caller
  }
}
