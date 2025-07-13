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
    
    // Check if the string is empty
    if (encryptedString.trim() === '') {
      console.error('Empty encrypted data string');
      throw new Error('Empty encrypted data');
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
    if (!encryptedObj || typeof encryptedObj !== 'object') {
      console.error('Parsed data is not an object:', encryptedObj);
      throw new Error('Invalid encrypted data structure');
    }
    
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

document.addEventListener('DOMContentLoaded', async function() {
  try {
    // Fix any corrupted credentials
    fixCorruptedCredentials();
    
    const pinScreen = document.getElementById('pinScreen');
    const credentialsScreen = document.getElementById('credentialsScreen');
    const pinInput = document.getElementById('pinInput');
    const verifyPinButton = document.getElementById('verifyPin');
    const pinError = document.getElementById('pinError');
    const credentialsList = document.getElementById('credentialsList');
    const lockButton = document.getElementById('lockButton');
    
    // Setup extra buttons
    setupExtraButtons();
    
    // Verify PIN button click
    verifyPinButton.addEventListener('click', async function() {
      const pin = pinInput.value;
      
      if (!pin) {
        pinError.textContent = 'Please enter your PIN';
        return;
      }
      
      try {
        const isValid = await verifyPin(pin);
        
        if (isValid) {
          pinScreen.classList.remove('active');
          credentialsScreen.classList.add('active');
          loadCredentials();
        } else {
          pinError.textContent = 'Invalid PIN. Please try again.';
          pinInput.value = '';
        }
      } catch (error) {
        console.error('PIN verification error:', error);
        pinError.textContent = 'Error verifying PIN. Please try again.';
      }
    });
    
    // Lock button click
    lockButton.addEventListener('click', function() {
      // Clear the PIN from storage
      chrome.storage.local.remove('pin', function() {
        credentialsScreen.classList.remove('active');
        pinScreen.classList.add('active');
        pinInput.value = '';
        pinError.textContent = '';
      });
    });
    
    // Load and display credentials
    async function loadCredentials() {
      try {
        debugCredentials();
        chrome.storage.local.get(['credentials', 'salt', 'pin'], async function(result) {
          console.log('Retrieved from storage:', {
            hasCredentials: !!result.credentials,
            credentialsCount: result.credentials ? result.credentials.length : 0,
            hasSalt: !!result.salt,
            hasPin: !!result.pin
          });
          
          const credentials = result.credentials || [];
          const salt = result.salt;
          const pin = result.pin;
          
          if (credentials.length === 0) {
            credentialsList.innerHTML = '<p>No saved credentials yet.</p>';
            return;
          }
          
          if (!pin) {
            credentialsList.innerHTML = '<p>Error: PIN not available for decryption.</p>';
            return;
          }
          
          try {
            // Get encryption key for decryption
            const encryptionKey = await getEncryptionKey(salt);
            
            let html = '';
            for (const cred of credentials) {
              try {
                // Check if credential has all required fields
                if (!cred || !cred.email || !cred.url) {
                  console.error('Invalid credential object:', cred);
                  continue;
                }
                
                // Check if password is undefined or not a valid string
                if (!cred.password || typeof cred.password !== 'string') {
                  console.error('Invalid password data for:', cred.email);
                  
                  // Add a reset button for corrupted credentials
                  html += `
                    <div class="credential-item">
                      <div class="site">${new URL(cred.url).hostname}</div>
                      <div class="email">${cred.email}</div>
                      <div class="password-field">
                        <input type="password" value="[Invalid Password Data]" readonly>
                        <button disabled>Show</button>
                        <button disabled>Copy</button>
                      </div>
                      <button class="reset-credential" data-email="${cred.email}" data-url="${cred.url}">Reset</button>
                      <button class="delete-credential" data-email="${cred.email}" data-url="${cred.url}">Delete</button>
                    </div>
                  `;
                  continue;
                }
                
                // Try to parse the password to see if it's valid JSON
                try {
                  JSON.parse(cred.password);
                } catch (parseError) {
                  console.error('Password is not valid JSON for:', cred.email);
                  
                  // Add a reset button for corrupted credentials
                  html += `
                    <div class="credential-item">
                      <div class="site">${new URL(cred.url).hostname}</div>
                      <div class="email">${cred.email}</div>
                      <div class="password-field">
                        <input type="password" value="[Invalid Password Format]" readonly>
                        <button disabled>Show</button>
                        <button disabled>Copy</button>
                      </div>
                      <button class="reset-credential" data-email="${cred.email}" data-url="${cred.url}">Reset</button>
                      <button class="delete-credential" data-email="${cred.email}" data-url="${cred.url}">Delete</button>
                    </div>
                  `;
                  continue;
                }
                
                const decryptedPassword = await decryptData(cred.password, encryptionKey);
                const domain = new URL(cred.url).hostname;
                
                html += `
                  <div class="credential-item">
                    <div class="site">${domain}</div>
                    <div class="email">${cred.email}</div>
                    <div class="password-field">
                      <input type="password" value="${decryptedPassword}" readonly>
                      <button class="show-password">Show</button>
                      <button class="copy-password">Copy</button>
                    </div>
                    <button class="delete-credential" data-email="${cred.email}" data-url="${cred.url}">Delete</button>
                  </div>
                `;
              } catch (credError) {
                console.error('Error decrypting credential:', credError);
                console.error('Problematic credential:', cred);
                
                // Add a reset button for corrupted credentials
                html += `
                  <div class="credential-item">
                    <div class="site">${new URL(cred.url).hostname}</div>
                    <div class="email">${cred.email}</div>
                    <div class="password-field">
                      <input type="password" value="[Decryption Error]" readonly>
                      <button disabled>Show</button>
                      <button disabled>Copy</button>
                    </div>
                    <button class="reset-credential" data-email="${cred.email}" data-url="${cred.url}">Reset</button>
                    <button class="delete-credential" data-email="${cred.email}" data-url="${cred.url}">Delete</button>
                  </div>
                `;
              }
            }
            
            credentialsList.innerHTML = html;
            
            // Add event listeners for buttons
            setupCredentialButtons();
          } catch (keyError) {
            console.error('Error getting encryption key:', keyError);
            credentialsList.innerHTML = '<p>Error decrypting credentials. Please try again.</p>';
          }
        });
      } catch (error) {
        console.error('Error loading credentials:', error);
        credentialsList.innerHTML = '<p>Error loading credentials.</p>';
      }
    }
    
    // Helper functions for PIN verification and decryption
    async function verifyPin(pin) {
      return new Promise((resolve, reject) => {
        try {
          chrome.storage.local.get(['pinHash', 'salt'], async function(result) {
            if (!result.pinHash || !result.salt) {
              reject(new Error('PIN not set up'));
              return;
            }
            
            const salt = result.salt;
            // Convert salt from hex string to Uint8Array
            const saltArray = new Uint8Array(salt.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
            
            // Hash the entered PIN with the stored salt
            const encoder = new TextEncoder();
            const pinData = encoder.encode(pin);
            const hashBuffer = await crypto.subtle.digest('SHA-256', 
              new Uint8Array([...saltArray, ...pinData]));
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
            
            // Compare the hashes
            const isValid = hashHex === result.pinHash;
            
            if (isValid) {
              // Store the PIN temporarily for decryption
              chrome.storage.local.set({ pin: pin }, function() {
                // Test decryption after PIN is stored
                setTimeout(testDecryption, 500);
              });
            }
            
            resolve(isValid);
          });
        } catch (error) {
          reject(error);
        }
      });
    }
    
    async function getEncryptionKey(salt) {
      return new Promise((resolve, reject) => {
        try {
          chrome.storage.local.get('pin', async function(result) {
            if (!result.pin) {
              reject(new Error('PIN not found'));
              return;
            }
            
            const pin = result.pin;
            
            // Convert salt from hex string to Uint8Array if needed
            const saltArray = typeof salt === 'string' 
              ? new Uint8Array(salt.match(/.{1,2}/g).map(byte => parseInt(byte, 16)))
              : salt;
            
            // Use PBKDF2 to derive a key from the PIN
            const encoder = new TextEncoder();
            const pinData = encoder.encode(pin);
            
            const keyMaterial = await crypto.subtle.importKey(
              'raw',
              pinData,
              { name: 'PBKDF2' },
              false,
              ['deriveBits', 'deriveKey']
            );
            
            const key = await crypto.subtle.deriveKey(
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
            
            resolve(key);
          });
        } catch (error) {
          reject(error);
        }
      });
    }
    
    function setupCredentialButtons() {
      // Show/Hide password buttons
      const showButtons = document.querySelectorAll('.show-password');
      showButtons.forEach(button => {
        button.addEventListener('click', function() {
          const passwordInput = this.previousElementSibling;
          if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            this.textContent = 'Hide';
          } else {
            passwordInput.type = 'password';
            this.textContent = 'Show';
          }
        });
      });
      
      // Copy password buttons
      const copyButtons = document.querySelectorAll('.copy-password');
      copyButtons.forEach(button => {
        button.addEventListener('click', function() {
          const passwordInput = this.previousElementSibling.previousElementSibling;
          passwordInput.select();
          document.execCommand('copy');
          
          // Show feedback (optional)
          const originalText = this.textContent;
          this.textContent = 'Copied!';
          setTimeout(() => {
            this.textContent = originalText;
          }, 1500);
        });
      });
      
      // Delete credential buttons
      const deleteButtons = document.querySelectorAll('.delete-credential');
      deleteButtons.forEach(button => {
        button.addEventListener('click', function() {
          const email = this.getAttribute('data-email');
          const url = this.getAttribute('data-url');
          
          if (confirm(`Delete credential for ${email}?`)) {
            deleteCredential(email, url);
          }
        });
      });
      
      // Reset credential buttons
      const resetButtons = document.querySelectorAll('.reset-credential');
      resetButtons.forEach(button => {
        button.addEventListener('click', function() {
          const email = this.getAttribute('data-email');
          const url = this.getAttribute('data-url');
          
          if (confirm(`Reset credential for ${email}? This will remove it from storage.`)) {
            resetCredential(email, url);
          }
        });
      });
    }
    
    // Function to delete a credential
    function deleteCredential(email, url) {
      chrome.storage.local.get('credentials', function(result) {
        const credentials = result.credentials || [];
        const updatedCredentials = credentials.filter(cred => 
          !(cred.email === email && cred.url === url)
        );
        
        chrome.storage.local.set({ credentials: updatedCredentials }, function() {
          loadCredentials(); // Reload the credentials list
        });
      });
    }
    
    // Function to reset a credential
    function resetCredential(email, url) {
      chrome.storage.local.get('credentials', function(result) {
        const credentials = result.credentials || [];
        const updatedCredentials = credentials.filter(cred => 
          !(cred.email === email && cred.url === url)
        );
        
        chrome.storage.local.set({ credentials: updatedCredentials }, function() {
          alert(`The credential for ${email} at ${url} has been removed due to decryption issues. Please re-enter it on the website.`);
          loadCredentials(); // Reload the credentials list
        });
      });
    }

    // Function to test decryption
    function testDecryption() {
      chrome.storage.local.get(['credentials', 'salt', 'pin'], async function(result) {
        if (!result.credentials || result.credentials.length === 0) {
          console.log('No credentials to test');
          return;
        }
        
        try {
          const salt = result.salt;
          const pin = result.pin;
          
          if (!salt || !pin) {
            console.error('Missing salt or PIN for decryption test');
            return;
          }
          
          // Get encryption key
          const encryptionKey = await deriveKeyFromPin(pin, salt);
          
          // Try to decrypt the first credential
          const cred = result.credentials[0];
          console.log('Testing decryption for:', cred.email);
          
          try {
            const decrypted = await decryptData(cred.password, encryptionKey);
            console.log('Decryption successful:', decrypted);
          } catch (e) {
            console.error('Decryption test failed:', e);
          }
        } catch (error) {
          console.error('Test decryption error:', error);
        }
      });
    }

    // Function to clear all credentials
    function clearAllCredentials() {
      if (confirm('This will delete all stored credentials. Continue?')) {
        chrome.storage.local.set({ credentials: [] }, function() {
          alert('All credentials have been cleared. You will need to re-enter them on websites.');
          loadCredentials();
        });
      }
    }

    

    // Function to fix corrupted credentials
    function fixCorruptedCredentials() {
      chrome.storage.local.get('credentials', function(result) {
        const credentials = result.credentials || [];
        
        if (credentials.length === 0) {
          console.log('No credentials to fix');
          return;
        }
        
        console.log('Checking credentials for corruption...');
        
        // Filter out credentials with undefined or invalid passwords
        const validCredentials = credentials.filter(cred => {
          // Check if credential object is valid
          if (!cred || typeof cred !== 'object') {
            console.log('Found invalid credential object');
            return false;
          }
          
          // Check if required fields exist
          if (!cred.email || !cred.url) {
            console.log('Found credential missing required fields');
            return false;
          }
          
          // Check if password exists and is a string
          if (!cred.password || typeof cred.password !== 'string') {
            console.log('Found credential with invalid password:', cred.email);
            return false;
          }
          
          // Check if password is valid JSON
          try {
            const parsed = JSON.parse(cred.password);
            if (!parsed.iv || !parsed.data) {
              console.log('Found credential with invalid JSON structure:', cred.email);
              return false;
            }
            return true;
          } catch (e) {
            console.log('Found credential with invalid JSON:', cred.email);
            return false;
          }
        });
        
        if (validCredentials.length !== credentials.length) {
          console.log(`Fixing ${credentials.length - validCredentials.length} corrupted credential(s)`);
          chrome.storage.local.set({ credentials: validCredentials }, function() {
            console.log('Corrupted credentials fixed');
          });
        } else {
          console.log('No corrupted credentials found');
        }
      });
    }

    // Function to debug credentials
    function debugCredentials() {
      chrome.storage.local.get(['credentials', 'salt', 'pin', 'pinHash'], function(result) {
        console.log('Debug info:');
        console.log('Has salt:', !!result.salt);
        console.log('Has pin hash:', !!result.pinHash);
        console.log('Has temporary pin:', !!result.pin);
        
        if (result.credentials && result.credentials.length > 0) {
          console.log('Number of credentials:', result.credentials.length);
          console.log('First credential structure:', {
            url: result.credentials[0].url,
            email: result.credentials[0].email,
            hasPassword: !!result.credentials[0].password,
            passwordFormat: typeof result.credentials[0].password
          });
          
          // Try to parse the password to see if it's valid JSON
          try {
            const parsed = JSON.parse(result.credentials[0].password);
            console.log('Password JSON structure valid:', {
              hasIV: !!parsed.iv,
              hasData: !!parsed.data
            });
          } catch (e) {
            console.error('Password is not valid JSON:', e);
          }
        } else {
          console.log('No credentials stored');
        }
      });
    }

    // Setup extra buttons
    function setupExtraButtons() {
      const credentialsScreen = document.getElementById('credentialsScreen');
      
      
      
      // Add a "Clear All" button if it doesn't exist
      if (!document.getElementById('clearAllButton')) {
        const clearAllButton = document.createElement('button');
        clearAllButton.id = 'clearAllButton';
        clearAllButton.textContent = 'Clear All Credentials';
        clearAllButton.style.backgroundColor = '#ea4335';
        clearAllButton.style.marginTop = '10px';
        clearAllButton.style.width = '100%';
        
        clearAllButton.addEventListener('click', clearAllCredentials);
        
        // Add it before the lock button
        const lockButton = document.getElementById('lockButton');
        credentialsScreen.insertBefore(clearAllButton, lockButton);
      }
    }
  } catch (error) {
    console.error('Error initializing the app:', error);
    alert('An error occurred while initializing the app. Please try again.');
  }
});






