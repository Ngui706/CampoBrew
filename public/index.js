const API_URL = 'https://campobrew.onrender.com/api';

document.addEventListener('DOMContentLoaded', () => {
    fetchFeaturedProducts();
    fetchActiveAds();
    updateCartUI();

    // mobile menu toggle
    const navToggle = document.querySelector('.nav-toggle');
    const mobileMenu = document.getElementById('mobile-menu');
    if (navToggle && mobileMenu) {
        navToggle.addEventListener('click', () => {
            mobileMenu.classList.toggle('active');
        });
    }
});

// --- 1. FETCH & RENDER PRODUCTS ---
async function fetchFeaturedProducts() {
    const productContainer = document.getElementById('featured-products');
    
    try {
        // We only want the first 4 products for the homepage
        const response = await fetch(`${API_URL}/products`);
        const products = await response.json();
        
        // Clear dummy static content
        productContainer.innerHTML = '';

        // Take only the top 4
        const featured = products.slice(0, 4);

        featured.forEach(product => {
            const productCard = `
                <div class="bg-white rounded-xl shadow-md overflow-hidden group hover:shadow-xl transition duration-300">
                    <div class="relative h-64 overflow-hidden">
                        <img src="${product.image_url}" alt="${product.name}" class="w-full h-full object-cover group-hover:scale-110 transition duration-500">
                        <div class="absolute top-2 right-2 bg-white text-xs font-bold px-2 py-1 rounded text-coffee-medium uppercase">
                            ${product.category}
                        </div>
                    </div>
                    <div class="p-5">
                        <h3 class="font-serif text-xl font-bold mb-2">${product.name}</h3>
                        <p class="text-gray-500 text-sm mb-4 line-clamp-2">${product.description}</p>
                        <div class="flex justify-between items-center">
                            <span class="text-lg font-bold text-coffee-dark">KSh ${parseFloat(product.price).toFixed(2)}</span>
                            <button onclick="addToCart(${product.id}, '${product.name}', ${product.price})" 
                                    class="bg-coffee-dark hover:bg-coffee-medium text-white p-2 rounded-full transition w-10 h-10 flex items-center justify-center">
                                <i class="fa-solid fa-plus"></i>
                            </button>
                        </div>
                    </div>
                </div>
            `;
            productContainer.innerHTML += productCard;
        });
    } catch (error) {
        console.error('Error fetching products:', error);
        productContainer.innerHTML = `<p class="text-center col-span-full text-red-500">Failed to load products. Please try again later.</p>`;
    }
}

// --- 2. FETCH & RENDER PROMOTIONS (ADS) ---
async function fetchActiveAds() {
    const banner = document.getElementById('promo-banner');
    try {
        const response = await fetch(`${API_URL}/ads`);
        const ads = await response.json();

        if (ads.length > 0) {
            // Display the first active ad
            banner.innerText = `${ads[0].title}: ${ads[0].description}`;
        }
    } catch (error) {
        console.log('No active ads found or error fetching ads.');
    }
}

// --- 3. SHOPPING CART LOGIC ---
let cart = JSON.parse(localStorage.getItem('coffee_cart')) || [];

function addToCart(id, name, price) {
    const existingItem = cart.find(item => item.id === id);
    
    if (existingItem) {
        existingItem.quantity += 1;
    } else {
        cart.push({ id, name, price, quantity: 1 });
    }

    // Save to local storage and update UI
    localStorage.setItem('coffee_cart', JSON.stringify(cart));
    updateCartUI();
    
    // Optional: Visual feedback
    alert(`${name} added to cart!`);
}

function updateCartUI() {
    const cartCount = document.getElementById('cart-count');
    const totalItems = cart.reduce((sum, item) => sum + item.quantity, 0);
    cartCount.innerText = totalItems;
}