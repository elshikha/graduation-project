// DOM Elements
const sign_in_btn = document.querySelector("#sign-in-btn");
const sign_up_btn = document.querySelector("#sign-up-btn");
const container = document.querySelector(".container");
const signInForm = document.getElementById("sign-in-form");
const signUpForm = document.getElementById("sign-up-form");

// API Base URL
const API_URL = 'http://localhost:5000/api';

// Toggle between sign in and sign up
sign_up_btn.addEventListener('click', () => {
    container.classList.add("sign-up-mode");
    clearMessages();
});

sign_in_btn.addEventListener('click', () => {
    container.classList.remove("sign-up-mode");
    clearMessages();
});

// Password toggle functionality
const toggleSignInPassword = document.getElementById('toggle-signin-password');
const toggleSignUpPassword = document.getElementById('toggle-signup-password');
const signinPasswordInput = document.getElementById('signin-password');
const signupPasswordInput = document.getElementById('signup-password');

toggleSignInPassword.addEventListener('click', () => {
    togglePasswordVisibility(signinPasswordInput, toggleSignInPassword);
});

toggleSignUpPassword.addEventListener('click', () => {
    togglePasswordVisibility(signupPasswordInput, toggleSignUpPassword);
});

// Password Strength Checker
function checkPasswordStrength(password) {
    let strength = 0;
    
    if (password.length > 6) {
        strength++;
    }
    if (password.length >= 10) {
        strength++;
    }
    if (/[A-Z]/.test(password)) {
        strength++;
    }
    if (/[0-9]/.test(password)) {
        strength++;
    }
    if (/[^A-Za-z0-9]/.test(password)) {
        strength++;
    }
    
    return strength;
}

// Password strength indicator
signupPasswordInput.addEventListener('keyup', function(e) {
    const password = e.target.value;
    const strength = checkPasswordStrength(password);
    
    // Remove all strength classes
    container.classList.remove('weak', 'moderate', 'strong');
    
    if (password.length === 0) {
        // No password entered
        return;
    }
    
    if (strength <= 2) {
        container.classList.add('weak');
    } else if (strength >= 3 && strength <= 4) {
        container.classList.add('moderate');
    } else {
        container.classList.add('strong');
    }
});

function togglePasswordVisibility(input, icon) {
    if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
    } else {
        input.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
    }
}

// Message display functions
function showMessage(formType, message, type) {
    const messageDiv = document.getElementById(`${formType}-message`);
    messageDiv.textContent = message;
    messageDiv.className = `message ${type}`;
    messageDiv.style.display = 'block';
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        messageDiv.style.display = 'none';
    }, 5000);
}

function clearMessages() {
    document.getElementById('signin-message').style.display = 'none';
    document.getElementById('signup-message').style.display = 'none';
}

// Loading state for buttons
function setButtonLoading(button, isLoading) {
    const btnText = button.querySelector('.btn-text');
    const btnLoader = button.querySelector('.btn-loader');
    
    if (isLoading) {
        btnText.style.display = 'none';
        btnLoader.style.display = 'inline';
        button.disabled = true;
    } else {
        btnText.style.display = 'inline';
        btnLoader.style.display = 'none';
        button.disabled = false;
    }
}

// Sign In Handler
signInForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearMessages();
    
    const identifier = document.getElementById('signin-identifier').value.trim();
    const password = document.getElementById('signin-password').value;
    const submitBtn = signInForm.querySelector('.btn');
    
    if (!identifier || !password) {
        showMessage('signin', 'Please fill in all fields', 'error');
        return;
    }
    
    setButtonLoading(submitBtn, true);
    
    try {
        const response = await fetch(`${API_URL}/signin`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                identifier: identifier,
                password: password
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            // Store token
            localStorage.setItem('token', data.token);
            localStorage.setItem('user', JSON.stringify(data.user));
            
            showMessage('signin', '✓ Login successful! Redirecting...', 'success');
            
            // Redirect to dashboard
            setTimeout(() => {
                window.location.href = 'frontend/html/dashboard.html';
            }, 1000);
        } else {
            // Generic error message - don't reveal which field is wrong
            showMessage('signin', '❌ Invalid credentials. Please try again.', 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        showMessage('signin', 'Unable to connect to server. Please make sure the backend is running.', 'error');
    } finally {
        setButtonLoading(submitBtn, false);
    }
});

// Sign Up Handler
signUpForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    clearMessages();
    
    const username = document.getElementById('signup-username').value.trim();
    const email = document.getElementById('signup-email').value.trim();
    const password = document.getElementById('signup-password').value;
    const submitBtn = signUpForm.querySelector('.btn');
    
    // Validation
    if (!username || !email || !password) {
        showMessage('signup', 'Please fill in all fields', 'error');
        return;
    }
    
    if (username.length < 3) {
        showMessage('signup', 'Invalid input. Please check your details.', 'error');
        return;
    }
    
    if (!isValidEmail(email)) {
        showMessage('signup', 'Invalid input. Please check your details.', 'error');
        return;
    }
    
    // Check password strength
    const strength = checkPasswordStrength(password);
    if (strength < 3) {
        showMessage('signup', 'Password is too weak. Use uppercase, numbers, and special characters.', 'error');
        return;
    }
    
    setButtonLoading(submitBtn, true);
    
    try {
        const response = await fetch(`${API_URL}/signup`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                username: username,
                email: email,
                password: password
            })
        });
        
        const data = await response.json();
        
        if (data.success) {
            // Store token
            localStorage.setItem('token', data.token);
            localStorage.setItem('user', JSON.stringify(data.user));
            
            showMessage('signup', '✓ Account created successfully! Redirecting...', 'success');
            
            // Clear form
            signUpForm.reset();
            container.classList.remove('weak', 'moderate', 'strong');
            
            // Redirect to dashboard
            setTimeout(() => {
                window.location.href = 'frontend/html/dashboard.html';
            }, 1000);
        } else {
            showMessage('signup', `❌ ${data.message}`, 'error');
        }
    } catch (error) {
        console.error('Error:', error);
        showMessage('signup', 'Unable to connect to server. Please make sure the backend is running.', 'error');
    } finally {
        setButtonLoading(submitBtn, false);
    }
});

// Social Login Handler
const socialIcons = document.querySelectorAll('.social-icon');
socialIcons.forEach(icon => {
    icon.addEventListener('click', async (e) => {
        e.preventDefault();
        const provider = icon.getAttribute('data-provider');
        handleSocialLogin(provider);
    });
});

function handleSocialLogin(provider) {
    // Show info message
    const formType = container.classList.contains('sign-up-mode') ? 'signup' : 'signin';
    showMessage(formType, `Redirecting to ${provider.charAt(0).toUpperCase() + provider.slice(1)} login...`, 'info');
    
    // OAuth URLs - You need to set these up with your OAuth credentials
    const oauthUrls = {
        google: 'https://accounts.google.com/o/oauth2/v2/auth?client_id=YOUR_GOOGLE_CLIENT_ID&redirect_uri=YOUR_REDIRECT_URI&response_type=code&scope=email profile',
        facebook: 'https://www.facebook.com/v12.0/dialog/oauth?client_id=YOUR_FACEBOOK_APP_ID&redirect_uri=YOUR_REDIRECT_URI&scope=email',
        twitter: 'https://twitter.com/i/oauth2/authorize?client_id=YOUR_TWITTER_CLIENT_ID&redirect_uri=YOUR_REDIRECT_URI&scope=tweet.read users.read&response_type=code',
        linkedin: 'https://www.linkedin.com/oauth/v2/authorization?client_id=YOUR_LINKEDIN_CLIENT_ID&redirect_uri=YOUR_REDIRECT_URI&response_type=code&scope=r_liteprofile r_emailaddress'
    };
    
    // For demo purposes - in production, this would redirect to OAuth
    setTimeout(() => {
        showMessage(formType, `Social login for ${provider} is not yet configured. Please add your OAuth credentials in app.js`, 'error');
    }, 1000);
    
    // Uncomment this in production with real OAuth credentials:
    // window.location.href = oauthUrls[provider];
}

// Helper function to validate email
function isValidEmail(email) {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
}

// Check if user is already logged in
function checkAuth() {
    const token = localStorage.getItem('token');
    if (token && window.location.pathname === '/index.html') {
        // Optional: Verify token with backend
        // If valid, redirect to dashboard
        // window.location.href = '/dashboard.html';
    }
}

// Run auth check on page load
checkAuth();

// Logout function (can be used in other pages)
function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = '/index.html';
}

// Make logout available globally
window.logout = logout;