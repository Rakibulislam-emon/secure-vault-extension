document.getElementById('savePin').addEventListener('click', async function() {
  const pin = document.getElementById('pin').value;
  const confirmPin = document.getElementById('confirmPin').value;
  const errorMsg = document.getElementById('errorMsg');
  
  // Validate PIN
  if (pin.length < 4) {
    errorMsg.textContent = 'PIN must be at least 4 digits';
    return;
  }
  
  if (pin !== confirmPin) {
    errorMsg.textContent = 'PINs do not match';
    return;
  }
  
  try {
    // Generate a random salt
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const saltString = Array.from(salt).map(b => b.toString(16).padStart(2, '0')).join('');
    
    // Hash the PIN with the salt
    const encoder = new TextEncoder();
    const pinData = encoder.encode(pin);
    const hashBuffer = await crypto.subtle.digest('SHA-256', 
      new Uint8Array([...salt, ...pinData]));
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    // Save the hashed PIN and salt
    chrome.storage.local.set({ 
      pinHash: hashHex,
      salt: saltString
    }, function() {
      window.location.href = 'popup.html';
    });
  } catch (error) {
    errorMsg.textContent = 'Error creating PIN. Please try again.';
    console.error('PIN creation error:', error);
  }
});