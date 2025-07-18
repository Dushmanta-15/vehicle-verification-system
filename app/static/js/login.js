let stream = null;

document.addEventListener('DOMContentLoaded', function() {
    const videoElement = document.getElementById('videoElement');
    const canvasElement = document.getElementById('canvasElement');
    const capturedImage = document.getElementById('capturedImage');
    const startCamera = document.getElementById('startCamera');
    const captureButton = document.getElementById('captureButton');
    const loginForm = document.getElementById('loginForm');

    startCamera.addEventListener('click', initCamera);
    captureButton.addEventListener('click', captureFace);
    loginForm.addEventListener('submit', handleLogin);
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
        console.error('Error:', err);
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

async function handleLogin(e) {
    e.preventDefault();
    
    const capturedImage = document.getElementById('capturedImage');
    if (!capturedImage.src) {
        alert('Please capture your face image first');
        return;
    }

    const formData = new FormData();
    formData.append('username', document.getElementById('username').value);
    formData.append('password', document.getElementById('password').value);

    try {
        // Convert base64 to blob
        const response = await fetch(capturedImage.src);
        const blob = await response.blob();
        formData.append('face_image', blob, 'face.jpg');

        console.log('Sending login request...');
        const loginResponse = await fetch('/api/login', {
            method: 'POST',
            body: formData
        });

        if (!loginResponse.ok) {
            const data = await loginResponse.json();
            throw new Error(data.error || 'Login failed');
        }

        const data = await loginResponse.json();
        console.log('Login successful:', data);

        // Store user info in session storage
        sessionStorage.setItem('username', data.username);

        // Redirect to dashboard
        window.location.href = '/dashboard';
        
    } catch (error) {
        console.error('Login error:', error);
        alert(error.message || 'Login failed. Please try again.');
    }
}