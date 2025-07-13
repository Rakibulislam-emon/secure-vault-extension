// Crypto functions directly included
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
    // Check if the input is valid
    if (!encryptedString || typeof encryptedString !== 'string') {
      console.error('Invalid encrypted data: not a string or undefined', encryptedString);
      throw new Error('Invalid encrypted data format');
    }
    
    // Check if the input is valid JSON
    let encryptedObj;
    try {
      encryptedObj = JSON.parse(encryptedString);
    } catch (parseError) {
      console.error('Invalid encrypted data format:', parseError);
      console.error('Raw data:', encryptedString);
      throw new Error('Invalid encrypted data format');
    }
    
    // Validate the encrypted object structure
    if (!encryptedObj.iv || !encryptedObj.data) {
      console.error('Missing required encryption fields');
      console.error('Parsed object:', encryptedObj);
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

// Initialize storage with encryption
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.get(['credentials', 'pinHash', 'salt'], function(result) {
    if (!result.credentials) {
      chrome.storage.local.set({ credentials: [] });
    }
    if (!result.pinHash) {
      // First-time setup will prompt user to create PIN
      chrome.tabs.create({ url: 'setup.html' });
    }
  });
});

// Handle messages from content script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'saveCredentials') {
    console.log('Received credentials from content script');
    // Use Promise handling for async operations
    saveEncryptedCredentials(message.data)
      .then(() => {
        sendResponse({status: 'received'});
      })
      .catch(error => {
        console.error('Error saving credentials:', error);
        sendResponse({status: 'error', message: error.message});
      });
    
    return true; // Keep the message channel open for async response
  }
});

// Encrypt and save credentials
async function saveEncryptedCredentials(data) {
  // Validate input data
  if (!data.password || !data.email || !data.url) {
    console.error('Missing required credential data');
    throw new Error('Missing required credential data');
  }
  
  console.log('Processing credential for:', data.email);
  
  return new Promise((resolve, reject) => {
    chrome.storage.local.get(['salt', 'pin'], async function(result) {
      try {
        const salt = result.salt;
        const pin = result.pin;
        
        if (!salt || !pin) {
          console.error('Missing salt or PIN for encryption');
          reject(new Error('Missing salt or PIN for encryption'));
          return;
        }
        
        // Get encryption key
        const encryptionKey = await deriveKeyFromPin(pin, salt);
        
        // Encrypt the password
        const encryptedPassword = await encryptData(data.password, encryptionKey);
        
        console.log('Password encrypted successfully');
        
        // Store the encrypted data
        chrome.storage.local.get('credentials', function(result) {
          const credentials = result.credentials || [];
          
          // Check if this site already exists
          const existingIndex = credentials.findIndex(cred => 
            cred.email === data.email && cred.url === data.url);
          
          if (existingIndex >= 0) {
            credentials[existingIndex] = {
              email: data.email,
              password: encryptedPassword,
              url: data.url,
              timestamp: data.timestamp
            };
          } else {
            credentials.push({
              email: data.email,
              password: encryptedPassword,
              url: data.url,
              timestamp: data.timestamp
            });
          }
          
          chrome.storage.local.set({ credentials }, function() {
            console.log('Credentials saved successfully');
            resolve();
          });
        });
      } catch (error) {
        console.error('Error during encryption:', error);
        reject(error);
      }
    });
  });
}

