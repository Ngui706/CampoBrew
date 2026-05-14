const API_URL = 'https://campo-brew.vercel.app/api';

let allProducts = [];
let currentCategory = 'all';

const state = {
    search: '',
    minPrice: '',
    maxPrice: '',
    inStockOnly: false,
    sort: 'featured',
};

document.addEventListener('DOMContentLoaded', () => {
    fetchProducts();
    updateCartBadge();
    bindControls();
    bindMobileMenu();
});

function bindControls() {
    const searchInput = document.getElementById('search-input');
    const searchBtn = document.getElementById('search-btn');
    const priceBtn = document.getElementById('price-btn');
    const stockOnly = document.getElementById('stock-only');
    const sortSelect = document.getElementById('sort-select');

    if (searchInput) {
        searchInput.addEventListener('input', () => {
            state.search = searchInput.value.trim().toLowerCase();
            applyFilters();
        });
    }

    if (searchBtn) searchBtn.addEventListener('click', applyFilters);
    if (priceBtn) priceBtn.addEventListener('click', () => {
        state.minPrice = document.getElementById('min-price').value;
        state.maxPrice = document.getElementById('max-price').value;
        applyFilters();
    });
    if (stockOnly) stockOnly.addEventListener('change', () => {
        state.inStockOnly = stockOnly.checked;
        applyFilters();
    });
    if (sortSelect) sortSelect.addEventListener('change', () => {
        state.sort = sortSelect.value;
        applyFilters();
    });
}

function bindMobileMenu() {
    const navToggle = document.querySelector('.nav-toggle');
    const mobileMenu = document.getElementById('mobile-menu');
    if (navToggle && mobileMenu) {
        navToggle.addEventListener('click', () => {
            mobileMenu.classList.toggle('active');
        });
    }
}

async function fetchProducts() {
    try {
        const response = await fetch(`${API_URL}/products`);
        if (!response.ok) throw new Error('Failed to fetch products');

        allProducts = await response.json();
        renderCategories(allProducts);
        renderFeaturedProducts(allProducts.filter((product) => product.featured));
        applyFilters();
    } catch (err) {
        console.error('Error fetching products:', err);
        showLoadError();
    }
}

function renderCategories(products) {
    const categoryList = document.getElementById('category-list');
    if (!categoryList) return;

    const categories = ['all', ...new Set(products.map((product) => product.category).filter(Boolean))];
    categoryList.innerHTML = categories.map((category) => {
        const count = category === 'all'
            ? products.length
            : products.filter((product) => product.category === category).length;

        return `
            <button class="cat-btn ${category === currentCategory ? 'active' : ''}" data-category="${escapeHtml(category)}">
                <span>${category === 'all' ? 'All Products' : escapeHtml(category)}</span>
                <span>${count}</span>
            </button>
        `;
    }).join('');

    categoryList.querySelectorAll('.cat-btn').forEach((button) => {
        button.addEventListener('click', () => {
            currentCategory = button.dataset.category;
            renderCategories(allProducts);
            applyFilters();
        });
    });
}

function renderFeaturedProducts(products) {
    const section = document.getElementById('featured-section');
    const grid = document.getElementById('featured-products-grid');
    if (!section || !grid) return;

    if (!products.length) {
        section.classList.add('hidden');
        return;
    }

    section.classList.remove('hidden');
    grid.innerHTML = products.slice(0, 4).map((product) => productCard(product, true)).join('');
}

function renderProducts(products) {
    const grid = document.getElementById('product-grid');
    const resultCount = document.getElementById('result-count');
    if (!grid) return;

    if (resultCount) {
        resultCount.textContent = `${products.length} product${products.length === 1 ? '' : 's'} found`;
    }

    if (!products.length) {
        grid.innerHTML = `
            <div class="col-span-full bg-white text-center py-20 px-4">
                <i class="fa-solid fa-magnifying-glass text-4xl text-gray-200 mb-4"></i>
                <p class="text-gray-600 font-semibold">No products match your filters.</p>
                <p class="text-gray-400 text-sm mt-1">Try a different category, search, or price range.</p>
            </div>`;
        return;
    }

    grid.innerHTML = products.map((product) => productCard(product)).join('');
}

function productCard(product, compact = false) {
    const stock = Number(product.stock) || 0;
    const price = Number(product.price) || 0;
    const safeName = escapeHtml(product.name || 'Coffee Product');
    const safeDescription = escapeHtml(product.description || '');
    const safeCategory = escapeHtml(product.category || 'TechSips');
    const safeImage = escapeAttribute(product.image_url || '');
    const cartPayload = [
        JSON.stringify(product.id),
        JSON.stringify(product.name || 'Coffee Product'),
        price,
        JSON.stringify(product.image_url || ''),
    ].join(', ');

    return `
        <article class="product-card bg-white group">
            <div class="relative product-image-wrap ${compact ? 'featured' : ''}">
                <img src="${safeImage}" alt="${safeName}" class="product-image" loading="lazy">
                ${product.featured ? '<span class="featured-badge">Featured</span>' : ''}
            </div>
            <div class="p-3 flex flex-col min-h-[176px]">
                <span class="text-[11px] uppercase text-gray-500 font-semibold truncate">${safeCategory}</span>
                <h3 class="product-title">${safeName}</h3>
                <p class="text-xs text-gray-500 line-clamp-2 mt-1">${safeDescription}</p>
                <div class="mt-auto pt-3">
                    <div class="flex items-end justify-between gap-2">
                        <div>
                            <p class="text-lg font-bold text-[#313133]">KSh ${price.toLocaleString()}</p>
                            <p class="text-xs ${stock > 0 ? 'text-green-600' : 'text-red-500'} font-semibold">
                                ${stock > 0 ? `${stock} in stock` : 'Out of stock'}
                            </p>
                        </div>
                        <button onclick='addToCart(${cartPayload})' ${stock <= 0 ? 'disabled' : ''} class="cart-action" aria-label="Add ${safeName} to cart">
                            <i class="fa-solid fa-cart-plus"></i>
                        </button>
                    </div>
                </div>
            </div>
        </article>
    `;
}

function applyFilters() {
    const min = state.minPrice === '' ? null : Number(state.minPrice);
    const max = state.maxPrice === '' ? null : Number(state.maxPrice);

    let filtered = allProducts.filter((product) => {
        const name = (product.name || '').toLowerCase();
        const category = (product.category || '').toLowerCase();
        const description = (product.description || '').toLowerCase();
        const price = Number(product.price) || 0;
        const stock = Number(product.stock) || 0;

        const matchesSearch = !state.search
            || name.includes(state.search)
            || category.includes(state.search)
            || description.includes(state.search);
        const matchesCategory = currentCategory === 'all' || product.category === currentCategory;
        const matchesMin = min === null || price >= min;
        const matchesMax = max === null || price <= max;
        const matchesStock = !state.inStockOnly || stock > 0;

        return matchesSearch && matchesCategory && matchesMin && matchesMax && matchesStock;
    });

    filtered = sortProducts(filtered);
    renderProducts(filtered);
}

function sortProducts(products) {
    return [...products].sort((a, b) => {
        if (state.sort === 'price-low') return (Number(a.price) || 0) - (Number(b.price) || 0);
        if (state.sort === 'price-high') return (Number(b.price) || 0) - (Number(a.price) || 0);
        if (state.sort === 'name') return (a.name || '').localeCompare(b.name || '');
        return Number(Boolean(b.featured)) - Number(Boolean(a.featured));
    });
}

function addToCart(id, name, price, img) {
    const cart = JSON.parse(localStorage.getItem('coffee_cart')) || [];
    const index = cart.findIndex((item) => String(item.id) === String(id));

    if (index > -1) {
        cart[index].quantity += 1;
    } else {
        cart.push({ id, name, price, img, quantity: 1 });
    }

    localStorage.setItem('coffee_cart', JSON.stringify(cart));
    updateCartBadge();
}

function updateCartBadge() {
    const cart = JSON.parse(localStorage.getItem('coffee_cart')) || [];
    const count = cart.reduce((sum, item) => sum + item.quantity, 0);
    const badge = document.getElementById('cart-count');
    if (badge) badge.innerText = count;
}

function showLoadError() {
    const grid = document.getElementById('product-grid');
    const resultCount = document.getElementById('result-count');
    if (resultCount) resultCount.textContent = 'Products could not be loaded';
    if (grid) {
        grid.innerHTML = `
            <div class="col-span-full bg-white text-center py-12 px-4">
                <p class="text-red-500 font-bold">Could not load products.</p>
                <p class="text-gray-500 text-sm">Please check the Supabase environment variables and products table.</p>
            </div>`;
    }
}

function escapeHtml(value) {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#039;');
}

function escapeAttribute(value) {
    return escapeHtml(value).replace(/`/g, '&#096;');
}
