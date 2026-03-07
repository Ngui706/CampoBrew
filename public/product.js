
const API_URL = '/api'; 
let allProducts = [];
let currentCategory = 'all';

document.addEventListener('DOMContentLoaded', () => {
    fetchProducts();
    updateCartBadge();

    // 1. Real-time Search Listener
    const searchInput = document.getElementById('search-input');
    if (searchInput) {
        searchInput.addEventListener('input', applyFilters);
    }

    // 2. Mobile Menu Toggle
    const navToggle = document.querySelector('.nav-toggle');
    const mobileMenu = document.getElementById('mobile-menu');
    if (navToggle && mobileMenu) {
        navToggle.addEventListener('click', () => {
            mobileMenu.classList.toggle('active');
        });
    }
});

/**
 * Fetches products from the backend.
 * Uses the relative /api path to avoid CORS issues.
 */
async function fetchProducts() {
    try {
        const response = await fetch(`${API_URL}/products`);
        if (!response.ok) throw new Error('Failed to fetch products');
        
        allProducts = await response.json();
        renderProducts(allProducts);
    } catch (err) {
        console.error('Error fetching products:', err);
        const grid = document.getElementById('product-grid');
        if (grid) {
            grid.innerHTML = `
                <div class="col-span-full text-center py-10">
                    <p class="text-red-500 font-bold">Could not load products.</p>
                    <p class="text-gray-500 text-sm">Please check your database connection in Render.</p>
                </div>`;
        }
    }
}

/**
 * Renders the product cards into the grid.
 * Includes a "No Results" state.
 */
function renderProducts(products) {
    const grid = document.getElementById('product-grid');
    if (!grid) return;

    if (products.length === 0) {
        grid.innerHTML = `
            <div class="col-span-full text-center py-20">
                <i class="fa-solid fa-mug-hot text-4xl text-gray-200 mb-4"></i>
                <p class="text-gray-500">No coffees found matching your search.</p>
            </div>`;
        return;
    }

    grid.innerHTML = products.map(product => `
        <div class="bg-white rounded-xl shadow-sm hover:shadow-md transition p-4 border border-gray-100 flex flex-col">
            <div class="h-56 overflow-hidden rounded-lg mb-4">
                <img src="${product.image_url}" alt="${product.name}" class="w-full h-full object-cover hover:scale-105 transition duration-500">
            </div>
            <span class="text-[10px] font-bold uppercase text-coffee-medium mb-1">${product.category}</span>
            <h3 class="text-lg font-bold mb-2">${product.name}</h3>
            <p class="text-gray-500 text-sm mb-4 line-clamp-2">${product.description}</p>
            <div class="mt-auto flex justify-between items-center">
                <span class="text-xl font-bold">KSh ${parseFloat(product.price).toLocaleString()}</span>
                <button onclick="addToCart(${product.id}, '${product.name.replace(/'/g, "\\'")}', ${product.price}, '${product.image_url}')" 
                        class="bg-coffee-dark text-white px-4 py-2 rounded-lg hover:bg-coffee-medium transition flex items-center gap-2">
                    <i class="fa-solid fa-cart-plus"></i> Add
                </button>
            </div>
        </div>
    `).join('');
}

/**
 * Filters the master list based on search input and active category.
 */
function applyFilters() {
    const searchInput = document.getElementById('search-input');
    const searchTerm = searchInput ? searchInput.value.toLowerCase() : '';
    
    const filtered = allProducts.filter(p => {
        // Search matches Name OR Category
        const matchesSearch = 
            p.name.toLowerCase().includes(searchTerm) || 
            p.category.toLowerCase().includes(searchTerm);
        
        // Match active category button
        const matchesCategory = currentCategory === 'all' || p.category === currentCategory;
        
        return matchesSearch && matchesCategory;
    });

    renderProducts(filtered);
}

/**
 * Handles category button clicks.
 */
function filterByCategory(cat) {
    currentCategory = cat;
    
    // Update active UI state for category buttons
    document.querySelectorAll('.cat-btn').forEach(btn => {
        btn.classList.remove('bg-coffee-dark', 'text-white');
        btn.classList.add('bg-white', 'text-gray-600');
    });

    // Highlight the clicked button
    if (event && event.target) {
        event.target.classList.add('bg-coffee-dark', 'text-white');
        event.target.classList.remove('bg-white', 'text-gray-600');
    }

    applyFilters();
}

/**
 * Cart Logic: Save to LocalStorage
 */
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
    
    // Optional: Visual feedback
    showToast(`${name} added to cart!`);
}

function updateCartBadge() {
    const cart = JSON.parse(localStorage.getItem('coffee_cart')) || [];
    const count = cart.reduce((sum, item) => sum + item.quantity, 0);
    const badge = document.getElementById('cart-count');
    if (badge) badge.innerText = count;
}

function showToast(message) {
    console.log("Toast:", message);
    // You can implement a custom toast notification here later
}