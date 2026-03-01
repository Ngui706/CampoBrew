document.getElementById('loginForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            const email = document.getElementById('email').value;
            const password = document.getElementById('password').value;

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
                    alert(data.error || 'Login failed');
                }
            } catch (err) {
                alert('Server connection error');
            }
        });