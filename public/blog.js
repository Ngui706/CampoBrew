const API_URL = 'https://campobrew.onrender.com/api';

document.addEventListener('DOMContentLoaded', async () => {
    const grid = document.getElementById('blog-grid');

    try {
        const response = await fetch(`${API_URL}/api/blogs`);
        if (!response.ok) throw new Error("Failed to fetch blogs");

        const blogs = await response.json();

        if (!blogs.length) {
            grid.innerHTML = `
                <p class="text-center col-span-full text-gray-500">
                    No blog posts yet. Check back soon!
                </p>`;
            return;
        }

        // Render blogs
        grid.innerHTML = blogs
            .map((blog, index) => `
                <div class="bg-white rounded-xl shadow-sm overflow-hidden border border-gray-100 flex flex-col transition hover:shadow-md">
                    <div class="p-6 flex-grow">
                        <h2 class="text-xl font-serif font-bold mb-2 text-coffee-dark">${blog.title}</h2>
                        <p class="text-xs text-gray-400 mb-4 uppercase tracking-wider">
                            By ${blog.author || 'Admin'} • ${new Date(blog.created_at).toLocaleDateString()}
                        </p>

                        <div 
                            class="blog-content text-gray-600 text-sm line-clamp-4 whitespace-pre-wrap transition-all duration-300"
                            data-index="${index}"
                        >
                            ${blog.content}
                        </div>
                    </div>

                    <div class="p-6 pt-0 mt-auto border-t border-gray-50">
                        <button 
                            class="blog-toggle text-coffee-medium font-bold text-sm hover:text-coffee-dark mt-4 inline-block transition-colors"
                            data-index="${index}"
                        >
                            Read Article →
                        </button>
                    </div>
                </div>
            `)
            .join('');

    } catch (err) {
        grid.innerHTML = `
            <p class="text-center col-span-full text-red-500">
                Failed to load blogs.
            </p>`;
    }

    // Mobile menu toggle
    const navToggle = document.querySelector('.nav-toggle');
    const mobileMenu = document.getElementById('mobile-menu');
    if (navToggle && mobileMenu) {
        navToggle.addEventListener('click', () => {
            mobileMenu.classList.toggle('active');
        });
    }
});

// --- Blog Expand / Collapse (Event Delegation) ---
document.addEventListener('click', (e) => {
    if (!e.target.classList.contains('blog-toggle')) return;

    const index = e.target.getAttribute('data-index');
    const content = document.querySelector(`.blog-content[data-index="${index}"]`);

    if (!content) return;

    const isCollapsed = content.classList.contains('line-clamp-4');

    if (isCollapsed) {
        content.classList.remove('line-clamp-4');
        e.target.innerHTML = "← Read Less";
    } else {
        content.classList.add('line-clamp-4');
        e.target.innerHTML = "Read Article →";
    }
});