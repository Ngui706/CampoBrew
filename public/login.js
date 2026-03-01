const API_URL = 'https://campobrew.onrender.com/api';

document.getElementById('loginForm').addEventListener('submit', async (e) => {
    e.preventDefault();
    
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const submitBtn = document.getElementById('loginBtn');
    const errorDiv = document.getElementById('loginError');

    submitBtn.disabled = true;
    errorDiv.innerText = '';

    try {
        const response = await fetch(`${API_URL}/admin/login`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email, password })
        });

        const data = await response.json();

        if (response.ok) {
            localStorage.setItem('adminToken', data.token);
            window.location.href = 'admin-dashboard.html';
        } else {
            errorDiv.innerText = data.error || 'Login failed';
        }
    } catch (err) {
        errorDiv.innerText = 'Server connection error';
        console.error(err);
    } finally {
        submitBtn.disabled = false;
    }
});