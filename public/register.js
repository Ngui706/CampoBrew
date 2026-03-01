const API_URL = 'https://campobrew.onrender.com/api';

document.getElementById('registerForm').addEventListener('submit', async (e) => {
    e.preventDefault();

    const name = document.getElementById('name').value;
    const email = document.getElementById('regEmail').value;
    const password = document.getElementById('regPassword').value;
    const admin_secret = document.getElementById('adminSecret').value; // matches backend

    try {
        const response = await fetch(`${API_URL}/admin/register`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ name, email, password, adminSecret: admin_secret }) // key name in backend
        });

        const data = await response.json();

        if (response.ok) {
            alert('Registration successful! Please login.');
            window.location.href = 'admin-login.html';
        } else {
            alert(data.error || 'Registration failed');
        }
    } catch (err) {
        alert('Server connection error');
        console.error(err);
    }
});