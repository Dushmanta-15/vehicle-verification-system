let stream = null;

document.addEventListener('DOMContentLoaded', function() {
    const videoElement = document.getElementById('videoElement');
    const canvasElement = document.getElementById('canvasElement');
    const capturedImage = document.getElementById('capturedImage');
    const startCamera = document.getElementById('startCamera');
    const captureButton = document.getElementById('captureButton');
    const registerForm = document.getElementById('registerForm');

    startCamera.addEventListener('click', initCamera);
    captureButton.addEventListener('click', captureFace);
    registerForm.addEventListener('submit', handleRegistration);
});

async function initCamera() {
    try {
        stream = await navigator.mediaDevices.getUserMedia({ 
            video: {
                width: { ideal: 640 },
                height: { ideal: 480 },
                facingMode: "user"
            }
        });
        const videoElement = document.getElementById('videoElement');
        const capturedImage = document.getElementById('capturedImage');
        
        videoElement.srcObject = stream;
        videoElement.style.display = 'block';
        capturedImage.style.display = 'none';
        
    } catch (err) {
        console.error('Camera access error:', err);
        alert('Could not access camera. Please ensure you have granted camera permissions.');
    }
}

function captureFace() {
    if (!stream) {
        alert('Please start the camera first');
        return;
    }

    const videoElement = document.getElementById('videoElement');
    const canvasElement = document.getElementById('canvasElement');
    const capturedImage = document.getElementById('capturedImage');

    canvasElement.width = videoElement.videoWidth;
    canvasElement.height = videoElement.videoHeight;
    canvasElement.getContext('2d').drawImage(videoElement, 0, 0);
    
    // Display captured image and hide video
    capturedImage.src = canvasElement.toDataURL('image/jpeg');
    videoElement.style.display = 'none';
    capturedImage.style.display = 'block';

    // Stop camera stream
    stream.getTracks().forEach(track => track.stop());
    stream = null;
}

async function handleRegistration(e) {
    e.preventDefault();
    
    console.log('Registration process started...');
    
    const capturedImage = document.getElementById('capturedImage');
    if (!capturedImage.src || capturedImage.src === '') {
        alert('Please capture your face image first');
        return;
    }

    // Validate form fields before proceeding
    const formValidation = validateFormFields();
    if (!formValidation.isValid) {
        alert(formValidation.message);
        return;
    }

    const formData = new FormData();
    
    // Add form fields and log them
    const fields = {
        'username': document.getElementById('username').value.trim(),
        'email': document.getElementById('email').value.trim(),
        'password': document.getElementById('password').value,
        'firstName': document.getElementById('firstName').value.trim(),
        'middleName': document.getElementById('middleName').value.trim(),
        'lastName': document.getElementById('lastName').value.trim(),
        'countryCode': document.getElementById('countryCode').value,
        'mobile': document.getElementById('mobile').value.trim(),
        'address': document.getElementById('address').value.trim(),
        'gender': document.getElementById('gender').value
    };

    // Log all field values before sending
    console.log('Form Data:', fields);

    // Append all fields to FormData
    Object.entries(fields).forEach(([key, value]) => {
        formData.append(key, value);
    });

    try {
        // Convert base64 to blob
        console.log('Converting captured image to blob...');
        const response = await fetch(capturedImage.src);
        const blob = await response.blob();
        formData.append('face_image', blob, 'face.jpg');
        console.log('Face image blob size:', blob.size, 'bytes');

        console.log('Sending registration request to /api/register...');
        
        // Show loading state
        const submitButton = document.querySelector('button[type="submit"]');
        const originalButtonText = submitButton.innerHTML;
        submitButton.innerHTML = '<span>Registering...</span>';
        submitButton.disabled = true;

        const registerResponse = await fetch('/api/register', {
            method: 'POST',
            body: formData
        });

        console.log('Response received:');
        console.log('- Status:', registerResponse.status);
        console.log('- Status Text:', registerResponse.statusText);
        console.log('- Headers:', Object.fromEntries(registerResponse.headers.entries()));
        console.log('- URL:', registerResponse.url);
        console.log('- OK:', registerResponse.ok);

        // Reset button state
        submitButton.innerHTML = originalButtonText;
        submitButton.disabled = false;

        // Handle different response statuses
        if (!registerResponse.ok) {
            let errorMessage = `Server error: ${registerResponse.status} ${registerResponse.statusText}`;
            
            try {
                const errorData = await registerResponse.json();
                if (errorData.error) {
                    errorMessage = errorData.error;
                }
                console.log('Server error response:', errorData);
            } catch (jsonError) {
                console.log('Could not parse error response as JSON');
                const errorText = await registerResponse.text();
                console.log('Error response text:', errorText);
                if (errorText) {
                    errorMessage = errorText;
                }
            }
            
            throw new Error(errorMessage);
        }

        // Parse successful response
        const data = await registerResponse.json();
        console.log('Server success response:', data);
        
        alert('Registration successful! Please login.');
        window.location.href = '/login';
        
    } catch (error) {
        // Reset button state in case of error
        const submitButton = document.querySelector('button[type="submit"]');
        if (submitButton.disabled) {
            submitButton.innerHTML = originalButtonText || '<span>Create Account</span>';
            submitButton.disabled = false;
        }

        console.error('Registration error details:');
        console.error('- Error object:', error);
        console.error('- Error name:', error.name);
        console.error('- Error message:', error.message);
        console.error('- Error stack:', error.stack);

        // Provide user-friendly error messages
        let userMessage = 'Registration failed. Please try again.';
        
        if (error.name === 'TypeError' && error.message.includes('Failed to fetch')) {
            userMessage = 'Connection failed. Please check your internet connection and server status.';
            console.error('Network error: Cannot reach the server at /api/register');
        } else if (error.message.includes('NetworkError')) {
            userMessage = 'Network error. Please check your connection and try again.';
        } else if (error.message.includes('CORS')) {
            userMessage = 'Server configuration error. Please contact support.';
        } else if (error.message) {
            userMessage = error.message;
        }

        alert(userMessage);
    }
}

function validateFormFields() {
    const fields = {
        firstName: document.getElementById('firstName').value.trim(),
        lastName: document.getElementById('lastName').value.trim(),
        username: document.getElementById('username').value.trim(),
        email: document.getElementById('email').value.trim(),
        password: document.getElementById('password').value,
        mobile: document.getElementById('mobile').value.trim(),
        address: document.getElementById('address').value.trim(),
        gender: document.getElementById('gender').value
    };

    // Check required fields
    const requiredFields = ['firstName', 'lastName', 'username', 'email', 'password', 'mobile', 'address', 'gender'];
    for (const field of requiredFields) {
        if (!fields[field]) {
            return {
                isValid: false,
                message: `${field.replace(/([A-Z])/g, ' $1').replace(/^./, str => str.toUpperCase())} is required`
            };
        }
    }

    // Validate name fields (only letters and spaces)
    const namePattern = /^[A-Za-z ]+$/;
    if (!namePattern.test(fields.firstName)) {
        return { isValid: false, message: 'First name should only contain letters and spaces' };
    }
    if (!namePattern.test(fields.lastName)) {
        return { isValid: false, message: 'Last name should only contain letters and spaces' };
    }

    // Validate middle name if provided
    const middleName = document.getElementById('middleName').value.trim();
    if (middleName && !namePattern.test(middleName)) {
        return { isValid: false, message: 'Middle name should only contain letters and spaces' };
    }

    // Validate mobile number (exactly 10 digits)
    if (!/^[0-9]{10}$/.test(fields.mobile)) {
        return { isValid: false, message: 'Mobile number must be exactly 10 digits' };
    }

    // Validate password (at least 8 characters, alphanumeric)
    if (!/^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/.test(fields.password)) {
        return { isValid: false, message: 'Password must be at least 8 characters long and contain both letters and numbers' };
    }

    // Validate email format
    const emailPattern = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    if (!emailPattern.test(fields.email)) {
        return { isValid: false, message: 'Invalid email format' };
    }

    return { isValid: true, message: 'All fields are valid' };
}