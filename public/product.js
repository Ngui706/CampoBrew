const API_URL = 'https://campobrew.onrender.com/api';
let allProducts = [];
let currentCategory = 'all';

document.addEventListener('DOMContentLoaded', () => {
    fetchProducts();
    updateCartBadge();

    const navToggle = document.querySelector('.nav-toggle');
    const mobileMenu = document.getElementById('mobile-menu');
    if (navToggle && mobileMenu) {
        navToggle.addEventListener('click', () => {
            mobileMenu.classList.toggle('active');
        });
    }
});

// 1. Fetch products from Express API
async function fetchProducts() {
    try {
        const response = await fetch(`${API_URL}/products`);
        allProducts = await response.json();
        renderProducts(allProducts);
    } catch (err) {
        console.error('Error fetching products:', err);
        document.getElementById('product-grid').innerHTML = `<p class="text-red-500">Could not load products. Is the server running?</p>`;
    }
}

// 2. Render Products into Grid
function renderProducts(products) {
    const grid = document.getElementById('product-grid');
    grid.innerHTML = products.map(product => `
        <div class="bg-white rounded-xl shadow-sm hover:shadow-md transition p-4 border border-gray-100 flex flex-col">
            <div class="h-56 overflow-hidden rounded-lg mb-4">
                <img src="${product.image_url}" alt="${product.name}" class="w-full h-full object-cover">
            </div>
            <span class="text-[10px] font-bold uppercase text-coffee-medium mb-1">${product.category}</span>
            <h3 class="text-lg font-bold mb-2">${product.name}</h3>
            <p class="text-gray-500 text-sm mb-4 line-clamp-2">${product.description}</p>
            <div class="mt-auto flex justify-between items-center">
                <span class="text-xl font-bold">KSh ${parseFloat(product.price).toFixed(2)}</span>
                <button onclick="addToCart(${product.id}, '${product.name}', ${product.price}, '${product.image_url}')" 
                        class="bg-coffee-dark text-white px-4 py-2 rounded-lg hover:bg-coffee-medium transition flex items-center gap-2">
                    <i class="fa-solid fa-cart-plus"></i> Add
                </button>
            </div>
        </div>
    `).join('');
}

// 3. Search & Category Filters
function applyFilters() {
    const searchTerm = document.getElementById('search-input').value.toLowerCase();
    
    let filtered = allProducts.filter(p => {
        const matchesSearch = p.name.toLowerCase().includes(searchTerm);
        const matchesCategory = currentCategory === 'all' || p.category === currentCategory;
        return matchesSearch && matchesCategory;
    });

    renderProducts(filtered);
}

function filterByCategory(cat) {
    currentCategory = cat;
    
    // Update button styles
    document.querySelectorAll('.cat-btn').forEach(btn => {
        btn.classList.remove('bg-coffee-dark', 'text-white');
        btn.classList.add('bg-white');
    });
    event.target.classList.add('bg-coffee-dark', 'text-white');

    applyFilters();
}

// 4. Cart Logic
function addToCart(id, name, price, img) {
    let cart = JSON.parse(localStorage.getItem('coffee_cart')) || [];
    
    const index = cart.findIndex(item => item.id === id);
    if (index > -1) {
        cart[index].quantity += 1;
    } else {
        cart.push({ id, name, price, img, quantity: 1 });
    }

    localStorage.setItem('coffee_cart', JSON.stringify(cart));
    updateCartBadge();
    
    // Toast notification (simple alert for now)
    console.log(`${name} added!`);
}

function updateCartBadge() {
    const cart = JSON.parse(localStorage.getItem('coffee_cart')) || [];
    const count = cart.reduce((sum, item) => sum + item.quantity, 0);
    document.getElementById('cart-count').innerText = count;
}