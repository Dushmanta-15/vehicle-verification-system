const api = axios.create({
    baseURL: '/api',
    headers: {
        'Content-Type': 'application/json'
    }
});

// Navigation handling
function updateNavigation() {
    const isLoggedIn = localStorage.getItem('userId');
    const navLinks = document.getElementById('navLinks');
    
    if (isLoggedIn) {
        navLinks.innerHTML = `
            <div class="space-x-4">
                <a href="/upload" class="hover:text-gray-200">Upload Vehicle</a>
                <a href="/verify" class="hover:text-gray-200">Verify</a>
                <button onclick="logout()" class="hover:text-gray-200">Logout</button>
            </div>
        `;
    } else {
        navLinks.innerHTML = `
            <div class="space-x-4">
                <a href="/register" class="hover:text-gray-200">Register</a>
                <a href="/login" class="hover:text-gray-200">Login</a>
            </div>
        `;
    }
}

// Face capture functionality
async function setupFaceCapture() {
    const video = document.getElementById('videoElement');
    const canvas = document.getElementById('canvasElement');
    const captureBtn = document.getElementById('captureBtn');
    
    try {
        const stream = await navigator.mediaDevices.getUserMedia({ video: true });
        video.srcObject = stream;
    } catch (err) {
        console.error('Error accessing camera:', err);
        alert('Unable to access camera');
    }
    
    return {
        captureFace: () => {
            canvas.width = video.videoWidth;
            canvas.height = video.videoHeight;
            canvas.getContext('2d').drawImage(video, 0, 0);
            return canvas.toDataURL('image/jpeg');
        }
    };
}

// Register functionality
if (document.getElementById('registerForm')) {
    const form = document.getElementById('registerForm');
    let faceCapture;
    
    setupFaceCapture().then(fc => faceCapture = fc);
    
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const formData = {
            username: form.username.value,
            email: form.email.value,
            password: form.password.value,
            face_image: faceCapture.captureFace()
        };
        
        try {
            await api.post('/register', formData);
            window.location.href = '/login';
        } catch (err) {
            console.error('Registration error:', err);
            alert('Registration failed');
        }
    });
}

// Login functionality
if (document.getElementById('loginForm')) {
    const form = document.getElementById('loginForm');
    let faceCapture;
    
    setupFaceCapture().then(fc => faceCapture = fc);
    
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const formData = {
            username: form.username.value,
            face_image: faceCapture.captureFace()
        };
        
        try {
            const response = await api.post('/login', formData);
            localStorage.setItem('userId', response.data.user_id);
            window.location.href = '/upload';
        } catch (err) {
            console.error('Login error:', err);
            alert('Login failed');
        }
    });
}

// Vehicle upload functionality
if (document.getElementById('vehicleForm')) {
    const form = document.getElementById('vehicleForm');
    
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const formData = {
            user_id: localStorage.getItem('userId'),
            vehicle_number: form.vehicleNumber.value,
            owner_details: form.ownerDetails.value,
            metadata: form.metadata.value
        };
        
        try {
            const response = await api.post('/vehicle', formData);
            document.getElementById('qrCodeDisplay').classList.remove('hidden');
            document.getElementById('qrCodeImage').src = response.data.qr_code;
        } catch (err) {
            console.error('Upload error:', err);
            alert('Upload failed');
        }
    });
}

// QR code scanning functionality
if (document.getElementById('qrScanner')) {
    let scanner = new QrScanner(
        document.getElementById('qrScanner'),
        async result => {
            try {
                const response = await api.post('/verify', { qr_data: result });
                displayVehicleDetails(response.data.vehicle_details);
            } catch (err) {
                console.error('Verification error:', err);
                alert('Verification failed');
            }
        }
    );
    
    scanner.start();
}

function displayVehicleDetails(details) {
    const container = document.getElementById('vehicleInfo');
    container.innerHTML = `
        <p><strong>Vehicle Number:</strong> ${details.number}</p>
        <p><strong>Owner Details:</strong> ${details.owner}</p>
        <p><strong>Additional Information:</strong> ${details.metadata}</p>
    `;
    document.getElementById('vehicleDetails').classList.remove('hidden');
}

// Logout functionality
function logout() {
    localStorage.removeItem('userId');
    window.location.href = '/login';
}

// Initialize navigation
updateNavigation();