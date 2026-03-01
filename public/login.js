// 1. Define your API endpoint here
const API_URL = 'https://campobrew.onrender.com/api';

document.getElementById('loginForm').addEventListener('submit', async (e) => {
    // 2. Stop the browser from refreshing the page or navigating away
    e.preventDefault();

    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    try {
        // 3. Send the POST request to the correct URL
        const response = await fetch(`${API_URL}/admin/login`, {
            method: 'POST',
            headers: { 
                'Content-Type': 'application/json' 
            },
            body: JSON.stringify({ email, password })
        });

        // 4. Parse the server's response
        const data = await response.json();

        if (response.ok) {
            // Success: Save the token and move to the dashboard
            localStorage.setItem('adminToken', data.token);
            window.location.href = 'admin-dashboard.html';
        } else {
            // Server-side error (e.g., wrong password)
            alert(data.error || 'Login failed');
        }
    } catch (err) {
        // Network-side error (e.g., server is down)
        console.error("Connection error:", err);
        alert('Could not connect to the server.');
    }
});