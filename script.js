// Modal handling
function showModal(modalId) {
    document.getElementById(modalId).style.display = 'block';
}

function closeModal(modalId) {
    document.getElementById(modalId).style.display = 'none';
    // Clear form fields
    document.getElementById(modalId).querySelector('form').reset();
}

function showSignupForm() {
    showModal('signupModal');
}

function showLoginForm() {
    showModal('loginModal');
}

// Close modal when clicking outside
window.onclick = function(event) {
    if (event.target.className === 'modal') {
        event.target.style.display = 'none';
    }
}

// Show profile section after successful login
function showProfileSection() {
    document.getElementById('authSection').style.display = 'none';
    document.getElementById('profileSection').style.display = 'block';
}

// Profile form handling
function showProfileForm(type) {
    // Hide both forms first
    document.getElementById('recruiterForm').style.display = 'none';
    document.getElementById('developerForm').style.display = 'none';
    
    // Show the selected form
    if (type === 'recruiter') {
        document.getElementById('recruiterForm').style.display = 'block';
    } else if (type === 'developer') {
        document.getElementById('developerForm').style.display = 'block';
    }
}

// Form submissions
document.getElementById('signupForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const username = document.getElementById('signupUsername').value.trim();
    const email = document.getElementById('signupEmail').value.trim();
    const password = document.getElementById('signupPassword').value;

    console.log('Signup attempt:', { username, email });

    // Detailed client-side validation
    const errors = [];

    if (!username) errors.push('Username is required');
    if (!email) errors.push('Email is required');
    if (!password) errors.push('Password is required');

    // Email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (email && !emailRegex.test(email)) {
        errors.push('Invalid email format');
    }

    // Password strength check
    if (password && password.length < 8) {
        errors.push('Password must be at least 8 characters long');
    }

    // Display validation errors
    if (errors.length > 0) {
        alert(errors.join('\n'));
        return;
    }

    try {
        const response = await fetch('http://localhost:8000/signup', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                username,
                email,
                password,
                role: "seeker"  // Default role
            })
        });

        console.log('Response status:', response.status);
        
        const responseText = await response.text();
        console.log('Full response text:', responseText);

        let data;
        try {
            data = JSON.parse(responseText);
        } catch (parseError) {
            console.error('Error parsing response:', parseError);
            console.error('Unparseable response:', responseText);
            alert('Unexpected server response. Please check the console for details.');
            return;
        }
        
        // Handle different types of responses
        if (!response.ok) {
            const errorMessage = data.message || 'Signup failed';
            console.error('Signup error:', errorMessage);
            alert(errorMessage);
            return;
        }

        // Successful signup
        alert('Signup successful! Please login.');
        closeModal('signupModal');
        showLoginForm();
    } catch (error) {
        console.error('Network or unexpected error:', error);
        alert('An unexpected error occurred. Please try again later.');
    }
});

document.getElementById('loginForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const email = document.getElementById('loginEmail').value.trim();
    const password = document.getElementById('loginPassword').value;

    if (!email || !password) {
        alert('Email and password are required');
        return;
    }

    try {
        const response = await fetch('http://localhost:8000/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                email,
                password
            })
        });

        const data = await response.json();
        
        if (!response.ok) {
            throw new Error(data.error || 'Login failed');
        }

        // Store token and user info
        localStorage.setItem('token', data.data.token);
        localStorage.setItem('user', JSON.stringify(data.data.user));

        // Close login modal and redirect to profile selection
        closeModal('loginModal');
        window.location.href = 'profile-selection.html';
    } catch (error) {
        console.error('Login error:', error);
        alert(error.message || 'An error occurred during login');
    }
});

// Debugging function to log detailed request information
async function debugFetch(url, options) {
    console.log('Fetch Debug - URL:', url);
    console.log('Fetch Debug - Options:', JSON.stringify(options, null, 2));

    try {
        const response = await fetch(url, options);
        
        console.log('Fetch Debug - Response Status:', response.status);
        console.log('Fetch Debug - Response Headers:', Object.fromEntries(response.headers.entries()));
        
        const responseText = await response.text();
        console.log('Fetch Debug - Response Body:', responseText);
        
        return {
            response,
            responseText
        };
    } catch (error) {
        console.error('Fetch Debug - Error:', error);
        throw error;
    }
}

// Profile form submissions
document.getElementById('recruiterProfileForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const companyName = document.getElementById('companyName').value.trim();
    const position = document.getElementById('position').value.trim();
    const companyDescription = document.getElementById('companyDescription').value.trim();

    if (!companyName || !position || !companyDescription) {
        alert('All fields are required');
        return;
    }

    try {
        const token = localStorage.getItem('token');
        if (!token) {
            throw new Error('Not authenticated');
        }

        console.log('Submitting Recruiter Profile - Token:', token);

        const { response, responseText } = await debugFetch('http://localhost:8000/save-recruiter-profile', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                companyName,
                position,
                companyDescription
            })
        });
        
        if (!response.ok) {
            console.error('Server response:', responseText);
            throw new Error(responseText || 'Failed to save recruiter profile');
        }

        alert('Profile saved successfully!');
        document.getElementById('recruiterForm').style.display = 'none';
    } catch (error) {
        console.error('Error saving profile:', error);
        alert(error.message || 'An error occurred while saving your profile');
    }
});

document.getElementById('developerProfileForm').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const fullName = document.getElementById('fullName').value.trim();
    const title = document.getElementById('title').value.trim();
    const bio = document.getElementById('bio').value.trim();
    const skills = document.getElementById('skills').value.trim();

    if (!fullName || !title || !bio || !skills) {
        alert('All fields are required');
        return;
    }

    try {
        const token = localStorage.getItem('token');
        if (!token) {
            throw new Error('Not authenticated');
        }

        console.log('Submitting Developer Profile - Token:', token);

        const { response, responseText } = await debugFetch('http://localhost:8000/save-seeker-profile', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}`
            },
            body: JSON.stringify({
                fullName,
                title,
                bio,
                skills: skills.split(',').map(skill => skill.trim())
            })
        });
        
        if (!response.ok) {
            console.error('Server response:', responseText);
            throw new Error(responseText || 'Failed to save developer profile');
        }

        alert('Profile saved successfully!');
        document.getElementById('developerForm').style.display = 'none';
    } catch (error) {
        console.error('Error saving profile:', error);
        alert(error.message || 'An error occurred while saving your profile');
    }
});
