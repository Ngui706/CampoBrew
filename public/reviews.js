 const API_URL = 'https://campobrew.onrender.com/api';

        // Load only approved reviews
        async function loadApprovedReviews() {
            try {
                const res = await fetch(`${API_URL}/reviews`);
                const reviews = await res.json();
                const container = document.getElementById('reviews-display');
                
                if (reviews.length === 0) {
                    container.innerHTML = `
                        <div class="col-span-full bg-white p-10 rounded-2xl text-center border-2 border-dashed">
                            <i class="fa-solid fa-comments text-gray-200 text-5xl mb-4"></i>
                            <p class="text-gray-500 font-medium">No reviews yet. Be the first to share your experience!</p>
                        </div>`;
                    return;
                }

                container.innerHTML = reviews.map(r => `
                    <div class="bg-white p-6 rounded-2xl shadow-sm border border-gray-100 flex flex-col justify-between hover:shadow-md transition">
                        <div>
                            <div class="flex justify-between items-start mb-4">
                                <div class="w-10 h-10 bg-coffee-light rounded-full flex items-center justify-center font-bold text-coffee-dark uppercase">
                                    ${r.user_name.charAt(0)}
                                </div>
                                <div class="text-xs font-bold text-orange-400">
                                    ${'★'.repeat(r.rating)}${'☆'.repeat(5 - r.rating)}
                                </div>
                            </div>
                            <p class="text-gray-700 italic text-sm leading-relaxed mb-4">"${r.comment}"</p>
                        </div>
                        <div class="border-t pt-3 mt-auto">
                            <p class="font-bold text-xs text-coffee-dark">${r.user_name}</p>
                            <p class="text-[10px] text-gray-400 uppercase tracking-tighter">${new Date(r.created_at).toLocaleDateString('en-KE', { day: 'numeric', month: 'short', year: 'numeric' })}</p>
                        </div>
                    </div>
                `).join('');
            } catch (err) {
                console.error("Failed to load reviews:", err);
            }
        }

        // Submit new review
        async function submitReview(e) {
            e.preventDefault();
            const btn = document.getElementById('submit-btn');
            btn.innerText = "Submitting...";
            btn.disabled = true;

            const payload = {
                user_name: document.getElementById('rev-name').value,
                rating: parseInt(document.getElementById('rev-rating').value),
                comment: document.getElementById('rev-comment').value
            };

            try {
                const res = await fetch(`${API_URL}/reviews`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });

                if (res.ok) {
                    alert("Asante! Your review has been sent for verification.");
                    e.target.reset();
                }
            } catch (err) {
                alert("Could not submit review. Please try again later.");
            } finally {
                btn.innerText = "Post Review";
                btn.disabled = false;
            }
        }

        document.addEventListener('DOMContentLoaded', () => {
            loadApprovedReviews();
            if (typeof updateGlobalCartCount === 'function') updateGlobalCartCount();
        });