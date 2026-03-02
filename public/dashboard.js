 const API_URL = 'https://campobrew.onrender.com/api';
const token = localStorage.getItem('adminToken');
let currentView = 'products';
let editingId = null;

// Security check
if (!token) window.location.href = 'admin-login.html';

document.addEventListener('DOMContentLoaded', () => switchSection('products'));

// 1. CORE NAVIGATION
async function switchSection(section) {
    currentView = section;
    let titleText = section;
    if (section === 'ads') titleText = 'Advertisements';
    document.getElementById('current-title').innerText = titleText;
    
    // UI Resets: Hide "Add New" button for Reviews, Orders, and Analytics
    const hideAddBtn = ['reviews', 'orders', 'dashboard'].includes(section);
    document.getElementById('add-btn').classList.toggle('hidden', hideAddBtn);
    
    // Reset KPIs if they exist when leaving dashboard
    const existingKpis = document.getElementById('kpi-container');
    if (section !== 'dashboard' && existingKpis) existingKpis.remove();

    if (section === 'dashboard') {
        loadAnalytics();
    } else {
        loadTable();
    }
}

// 2. DATA RENDERING (TABLES)
async function loadTable() {
    const tableHead = document.getElementById('table-head');
    const tableBody = document.getElementById('table-body');
    
    // Clear previous results
    tableBody.innerHTML = '<tr><td colspan="5" class="text-center py-4 text-gray-400 italic">Fetching data...</td></tr>';

    // Map view to endpoint
    const endpointMap = {
        products: 'products',
        blogs: 'blogs',
        ads: 'admin/ads',
        reviews: 'admin/reviews',
        orders: 'admin/orders'
    };

    try {
        const response = await fetch(`${API_URL}/${endpointMap[currentView]}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        if (!response.ok) {
            const errInfo = await response.json().catch(() => ({}));
            throw new Error(errInfo.error || `HTTP ${response.status}`);
        }
        const data = await response.json();

        // Header Configuration
        const headers = {
            products: ['Product', 'Price', 'Stock', 'Category', 'Actions'],
            blogs: ['Title', 'Author', 'Date', 'Actions'],
            ads: ['Title', 'Start', 'End', 'Active', 'Actions'],
            reviews: ['Customer', 'Rating', 'Status', 'Actions'],
            orders: ['Order ID', 'Total', 'Date', 'Status', 'Actions']
        };

        tableHead.innerHTML = `<tr>${headers[currentView].map(h => `<th class="px-6 py-4 text-sm font-bold text-gray-600 uppercase tracking-wider">${h}</th>`).join('')}</tr>`;
        tableBody.innerHTML = '';

        data.forEach(item => {
            let row = '';
            if (currentView === 'products') {
                row = `
                    <td class="px-6 py-4 font-medium text-gray-900">${item.name}</td>
                    <td class="px-6 py-4 text-gray-600">KSh ${item.price}</td>
                    <td class="px-6 py-4 text-gray-600">${item.stock}</td>
                    <td class="px-6 py-4"><span class="bg-blue-100 text-blue-800 text-xs font-bold px-2 py-1 rounded">${item.category}</span></td>
                    <td class="px-6 py-4 flex gap-3">
                        <button onclick="editItem(${item.id})" class="text-blue-600 hover:text-blue-800"><i class="fa-solid fa-pen-to-square"></i></button>
                        <button onclick="deleteItem(${item.id})" class="text-red-600 hover:text-red-800"><i class="fa-solid fa-trash"></i></button>
                    </td>`;
            } else if (currentView === 'blogs') {
                row = `
                    <td class="px-6 py-4 font-medium text-gray-900">${item.title}</td>
                    <td class="px-6 py-4 text-gray-600">${item.author}</td>
                    <td class="px-6 py-4 text-gray-500 text-sm">${new Date(item.created_at).toLocaleDateString()}</td>
                    <td class="px-6 py-4 flex gap-3">
                        <button onclick="editItem(${item.id})" class="text-blue-600 hover:text-blue-800"><i class="fa-solid fa-pen-to-square"></i></button>
                        <button onclick="deleteItem(${item.id})" class="text-red-600 hover:text-red-800"><i class="fa-solid fa-trash"></i></button>
                    </td>`;
            } else if (currentView === 'ads') {
                row = `
                    <td class="px-6 py-4 font-medium text-gray-900 flex items-center gap-2">
                        ${item.image_url ? `<img src="${item.image_url}" class="w-10 h-10 object-cover rounded">` : ''}
                        ${item.title}
                    </td>
                    <td class="px-6 py-4 text-gray-600 text-sm">${item.start_date ? new Date(item.start_date).toLocaleDateString() : '-'}</td>
                    <td class="px-6 py-4 text-gray-600 text-sm">${item.end_date ? new Date(item.end_date).toLocaleDateString() : 'N/A'}</td>
                    <td class="px-6 py-4 text-center">
                        ${item.active ? '<span class="text-green-600 font-bold">Yes</span>' : '<span class="text-red-500 font-bold">No</span>'}
                    </td>
                    <td class="px-6 py-4 flex gap-3">
                        <button onclick="editItem(${item.id})" class="text-blue-600 hover:text-blue-800"><i class="fa-solid fa-pen-to-square"></i></button>
                        <button onclick="deleteItem(${item.id})" class="text-red-600 hover:text-red-800"><i class="fa-solid fa-trash"></i></button>
                    </td>`;
            } else if (currentView === 'reviews') {
                row = `
                    <td class="px-6 py-4 font-medium text-gray-900">${item.user_name}</td>
                    <td class="px-6 py-4 text-orange-500">${'★'.repeat(item.rating)}</td>
                    <td class="px-6 py-4">${item.approved ? '<span class="text-green-600 font-bold">Approved</span>' : '<span class="text-orange-500 font-bold italic">Pending</span>'}</td>
                    <td class="px-6 py-4 flex gap-3">
                        ${!item.approved ? `<button onclick="approveReview(${item.id})" class="bg-green-600 text-white px-3 py-1 rounded text-xs font-bold">Approve</button>` : ''}
                        <button onclick="deleteItem(${item.id})" class="text-red-600 hover:text-red-800"><i class="fa-solid fa-trash"></i></button>
                    </td>`;
            } else if (currentView === 'orders') {
                const statusColor = item.status === 'Pending' ? 'text-orange-500 bg-orange-100' : 'text-green-600 bg-green-100';
                row = `
                    <td class="px-6 py-4 font-bold text-coffee-dark">#ORD-${item.id}<div class="text-[10px] font-normal text-gray-400">${item.customer_name || 'Guest'}</div></td>
                    <td class="px-6 py-4 text-green-700 font-bold">KSh ${parseFloat(item.total_price).toFixed(2)}</td>
                    <td class="px-6 py-4 text-gray-500 text-xs">${new Date(item.created_at).toLocaleString()}</td>
                    <td class="px-6 py-4"><span class="px-2 py-1 text-[10px] font-bold rounded ${statusColor}">${item.status || 'Pending'}</span></td>
                    <td class="px-6 py-4 flex gap-2">
                        <button onclick="viewOrderDetails(${item.id})" class="text-blue-600 hover:text-blue-800 text-xs font-bold underline">Details</button>
                        ${(item.status === 'Pending' || !item.status) ? `<button onclick="updateOrderStatus(${item.id}, 'Shipped')" class="bg-coffee-dark text-white px-2 py-1 rounded text-[10px]">Ship</button>` : ''}
                    </td>`;
            }
            tableBody.innerHTML += `<tr class="hover:bg-gray-50 transition border-b border-gray-100">${row}</tr>`;
        });
    } catch (err) {
        console.error(`Error loading ${currentView}:`, err);
        tableBody.innerHTML = `<tr><td colspan="5" class="text-center py-4 text-red-500 font-bold">Failed to load ${currentView}. Please check the console or ensure the server endpoint is available.</td></tr>`;
    }
}

// Add this logic to your existing loadTable() if currentView === 'reviews'
if (currentView === 'reviews') {
    row = `
        <td class="px-6 py-4 font-medium text-gray-900">${item.user_name}</td>
        <td class="px-6 py-4 text-orange-400">${'★'.repeat(item.rating)}</td>
        <td class="px-6 py-4">
            ${item.approved 
                ? '<span class="text-green-600 font-bold text-xs bg-green-50 px-2 py-1 rounded">Verified</span>' 
                : '<span class="text-orange-500 font-bold text-xs bg-orange-50 px-2 py-1 rounded">Pending</span>'}
        </td>
        <td class="px-6 py-4 flex gap-2">
            ${!item.approved ? `<button onclick="approveReview(${item.id})" class="bg-green-600 text-white px-3 py-1 rounded text-[10px] font-bold">Approve</button>` : ''}
            <button onclick="deleteItem(${item.id})" class="text-red-600"><i class="fa-solid fa-trash"></i></button>
        </td>
    `;
}

// Function to handle the approval click
async function approveReview(id) {
    const res = await fetch(`${API_URL}/admin/reviews/${id}/approve`, {
        method: 'PUT',
        headers: { 'Authorization': `Bearer ${token}` }
    });
    if (res.ok) {
        alert("Review is now live on the site!");
        loadTable();
    }
}

// 3. MODAL ACTIONS (ORDER DETAILS)
// Function to show Order Details in the Modal
async function viewOrderDetails(orderId) {
    editingId = orderId;
    const modal = document.getElementById('modal');
    const form = document.getElementById('modal-form');
    const saveBtn = document.getElementById('save-btn'); // The default "Save" button
    
    document.getElementById('modal-title').innerText = `Manage Order #ORD-${orderId}`;
    form.innerHTML = `<div class="col-span-2 text-center py-10"><i class="fa-solid fa-spinner animate-spin text-2xl"></i><p>Fetching Order Data...</p></div>`;
    modal.classList.remove('hidden');
    
    // Hide the standard "Product/Blog Save" button to avoid confusion
    if (saveBtn) saveBtn.classList.add('hidden');

    try {
        const response = await fetch(`${API_URL}/admin/orders/${orderId}`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });
        const order = await response.json();

        form.innerHTML = `
            <div class="col-span-2 space-y-6">
                <div class="grid grid-cols-1 md:grid-cols-2 gap-4 bg-gray-50 p-4 rounded-xl border border-gray-200">
                    <div>
                        <h4 class="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-2">Customer Info</h4>
                        <p class="text-sm font-bold text-coffee-dark">${order.customer_name}</p>
                        <p class="text-xs text-gray-600">${order.customer_email}</p>
                        <p class="text-xs text-gray-600 font-mono">${order.customer_phone || 'N/A'}</p>
                    </div>
                    <div>
                        <h4 class="text-[10px] font-bold text-gray-400 uppercase tracking-widest mb-2">Shipping To</h4>
                        <p class="text-xs text-gray-700 leading-relaxed">${order.shipping_address}</p>
                    </div>
                </div>

                <div class="bg-white p-4 rounded-xl border-2 border-dashed border-coffee-medium/30">
                    <label class="block text-xs font-bold text-gray-500 uppercase mb-2">Update Order Status</label>
                    <div class="flex gap-2">
                        <select id="update-status-select" class="flex-grow p-2 border rounded-lg text-sm bg-white outline-none focus:ring-2 focus:ring-coffee-medium">
                            <option value="Pending" ${order.status === 'Pending' ? 'selected' : ''}>⏳ Pending</option>
                            <option value="Processing" ${order.status === 'Processing' ? 'selected' : ''}>⚙️ Processing</option>
                            <option value="Shipped" ${order.status === 'Shipped' ? 'selected' : ''}>🚚 Shipped</option>
                            <option value="Delivered" ${order.status === 'Delivered' ? 'selected' : ''}>✅ Delivered</option>
                            <option value="Cancelled" ${order.status === 'Cancelled' ? 'selected' : ''}>❌ Cancelled</option>
                        </select>
                        <button onclick="submitStatusUpdate(${order.id})" class="bg-coffee-dark text-white px-4 py-2 rounded-lg text-sm font-bold hover:bg-coffee-medium transition shadow-md">
                            Save Changes
                        </button>
                    </div>
                </div>

                <div class="border-t pt-4">
                    <h4 class="font-bold text-xs uppercase text-gray-400 mb-3 tracking-widest text-center">Items Summary</h4>
                    <table class="w-full text-xs">
                        <thead>
                            <tr class="text-left text-gray-400 border-b border-gray-100">
                                <th class="pb-2">Product</th>
                                <th class="pb-2 text-center">Qty</th>
                                <th class="pb-2 text-right">Price</th>
                            </tr>
                        </thead>
                        <tbody>
                            ${order.items.map(item => `
                                <tr class="border-b border-gray-50">
                                    <td class="py-2 font-medium">${item.product_name || 'Coffee Product'}</td>
                                    <td class="py-2 text-center">${item.quantity}</td>
                                    <td class="py-2 text-right font-bold text-green-700">KSh ${parseFloat(item.price_at_purchase).toLocaleString()}</td>
                                </tr>`).join('')}
                        </tbody>
                    </table>
                </div>
            </div>`;
    } catch (err) {
        form.innerHTML = `<p class="col-span-2 text-red-500 text-center">Failed to load items. Verify endpoint /api/admin/orders/${orderId}</p>`;
    }
}

// Function to handle the actual saving of the status
async function submitStatusUpdate(orderId) {
    const newStatus = document.getElementById('update-status-select').value;
    
    try {
        const res = await fetch(`${API_URL}/admin/orders/${orderId}/status`, {
            method: 'PUT',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}` 
            },
            body: JSON.stringify({ status: newStatus })
        });

        if (res.ok) {
            alert(`Success! Order #ORD-${orderId} is now marked as ${newStatus}`);
            closeModal();
            loadTable(); // Refresh the main table to show the new status badge
        } else {
            alert("Error updating status.");
        }
    } catch (err) {
        console.error("Update failed:", err);
        alert("Server error. Check your connection.");
    }
}

// 4. CRUD ACTIONS
async function handleFormSubmit(e) {
    e.preventDefault();
    if (currentView === 'orders') return; // Orders are read-only

    let payload;
    if (currentView === 'products') {
        payload = {
            name: document.getElementById('f-name').value,
            description: document.getElementById('f-desc').value,
            price: document.getElementById('f-price').value,
            category: document.getElementById('f-cat').value,
            image_url: document.getElementById('f-img').value,
            stock: 10
        };
    } else if (currentView === 'blogs') {
        payload = {
            title: document.getElementById('f-title').value,
            author: document.getElementById('f-author').value,
            content: document.getElementById('f-content').value
        };
    } else if (currentView === 'ads') {
        payload = {
            title: document.getElementById('f-title').value,
            description: document.getElementById('f-desc').value,
            image_url: document.getElementById('f-img').value,
            start_date: document.getElementById('f-start').value,
            end_date: document.getElementById('f-end').value,
            active: document.getElementById('f-active').checked
        };
    }

    const method = editingId ? 'PUT' : 'POST';
    const url = editingId ? `${API_URL}/admin/${currentView}/${editingId}` : `${API_URL}/admin/${currentView}`;

    await fetch(url, {
        method: method,
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify(payload)
    });

    closeModal();
    loadTable();
}

async function editItem(id) {
    // use mapping to hit admin endpoints when necessary
    const endpoint = endpointMap[currentView] || currentView;
    const res = await fetch(`${API_URL}/${endpoint}/${id}`, {
        headers: { 'Authorization': `Bearer ${token}` }
    });
    const item = await res.json();
    editingId = id;
    document.getElementById('modal-title').innerText = `Edit ${currentView.slice(0, -1)}`;
    renderForm(item);
    document.getElementById('save-btn').classList.remove('hidden');
    document.getElementById('modal').classList.remove('hidden');
}

async function deleteItem(id) {
    if (!confirm('Are you sure?')) return;
    const endpoint = endpointMap[currentView] || currentView;
    await fetch(`${API_URL}/${endpoint}/${id}`, {
        method: 'DELETE',
        headers: { 'Authorization': `Bearer ${token}` }
    });
    loadTable();
}

async function updateOrderStatus(orderId, newStatus) {
    await fetch(`${API_URL}/admin/orders/${orderId}/status`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` },
        body: JSON.stringify({ status: newStatus })
    });
    loadTable();
}

// 5. ANALYTICS
async function loadAnalytics() {
    const tableHead = document.getElementById('table-head');
    const tableBody = document.getElementById('table-body');
    try {
        const response = await fetch(`${API_URL}/admin/analytics`, { headers: { 'Authorization': `Bearer ${token}` } });
        const stats = await response.json();

        const kpiHTML = `
            <div id="kpi-container" class="grid grid-cols-1 md:grid-cols-3 gap-6 mb-10">
                <div class="bg-white p-6 rounded-xl shadow-sm border-l-4 border-green-500">
                    <p class="text-gray-500 text-xs uppercase font-bold">Revenue</p>
                    <h3 class="text-2xl font-bold">KSh ${parseFloat(stats.totalRevenue).toFixed(2)}</h3>
                </div>
                <div class="bg-white p-6 rounded-xl shadow-sm border-l-4 border-blue-500">
                    <p class="text-gray-500 text-xs uppercase font-bold">Orders</p>
                    <h3 class="text-2xl font-bold">${stats.totalOrders}</h3>
                </div>
                <div class="bg-white p-6 rounded-xl shadow-sm border-l-4 border-orange-500">
                    <p class="text-gray-500 text-xs uppercase font-bold">Items Sold</p>
                    <h3 class="text-2xl font-bold">${stats.totalItemsSold}</h3>
                </div>
            </div>`;

        tableHead.parentElement.parentElement.insertAdjacentHTML('beforebegin', kpiHTML);
        tableHead.innerHTML = `<tr><th class="px-6 py-4">Top Selling Product</th><th class="px-6 py-4 text-center">Units Sold</th></tr>`;
        tableBody.innerHTML = stats.topProducts.map(p => `<tr><td class="px-6 py-4">${p.name}</td><td class="px-6 py-4 text-center font-bold">${p.units_sold}</td></tr>`).join('');
    } catch (err) { console.error(err); }
}

// UI UTILS
function openModal() {
    editingId = null;
    document.getElementById('save-btn').classList.remove('hidden');
    document.getElementById('modal-title').innerText = `Add New ${currentView.slice(0, -1)}`;
    renderForm();
    document.getElementById('modal').classList.remove('hidden');
}
function closeModal() { document.getElementById('modal').classList.add('hidden'); }
function logout() { localStorage.removeItem('adminToken'); window.location.href = 'admin-login.html'; }

function renderForm(data = null) {
    const form = document.getElementById('modal-form');
    if (currentView === 'products') {
        form.innerHTML = `
            <div class="col-span-2"><label class="text-xs font-bold">Product Name</label><input id="f-name" value="${data?.name || ''}" class="w-full border p-2 rounded"></div>
            <div class="col-span-2"><label class="text-xs font-bold">Description</label><textarea id="f-desc" class="w-full border p-2 rounded">${data?.description || ''}</textarea></div>
            <div><label class="text-xs font-bold">Price (KSh)</label><input id="f-price" type="number" step="0.01" value="${data?.price || ''}" class="w-full border p-2 rounded"></div>
            <div><label class="text-xs font-bold">Category</label><input id="f-cat" value="${data?.category || ''}" class="w-full border p-2 rounded"></div>
            <div class="col-span-2"><label class="text-xs font-bold">Image URL</label><input id="f-img" value="${data?.image_url || ''}" class="w-full border p-2 rounded"></div>`;
    } else if (currentView === 'blogs') {
        form.innerHTML = `
            <div class="col-span-2"><label class="text-xs font-bold">Blog Title</label><input id="f-title" value="${data?.title || ''}" class="w-full border p-2 rounded"></div>
            <div><label class="text-xs font-bold">Author</label><input id="f-author" value="${data?.author || ''}" class="w-full border p-2 rounded"></div>
            <div class="col-span-2"><label class="text-xs font-bold">Content</label><textarea id="f-content" rows="5" class="w-full border p-2 rounded">${data?.content || ''}</textarea></div>`;
    } else if (currentView === 'ads') {
        form.innerHTML = `
            <div class="col-span-2"><label class="text-xs font-bold">Ad Title</label><input id="f-title" value="${data?.title || ''}" class="w-full border p-2 rounded"></div>
            <div class="col-span-2"><label class="text-xs font-bold">Description</label><textarea id="f-desc" class="w-full border p-2 rounded">${data?.description || ''}</textarea></div>
            <div class="col-span-2" id="img-preview-container">
                <label class="text-xs font-bold">Image URL</label>
                <input id="f-img" value="${data?.image_url || ''}" class="w-full border p-2 rounded">
                ${data?.image_url ? `<img id="f-preview" src="${data.image_url}" class="mt-2 w-full h-32 object-cover rounded" />` : '<img id="f-preview" class="mt-2 w-full h-32 object-cover rounded hidden" />'}
            </div>
            <div><label class="text-xs font-bold">Start Date</label><input id="f-start" type="date" value="${data?.start_date ? data.start_date.slice(0,10) : ''}" class="w-full border p-2 rounded"></div>
            <div><label class="text-xs font-bold">End Date</label><input id="f-end" type="date" value="${data?.end_date ? data.end_date.slice(0,10) : ''}" class="w-full border p-2 rounded"></div>
            <div class="col-span-2 flex items-center gap-2"><input id="f-active" type="checkbox" ${data?.active ? 'checked' : ''}><label class="text-xs font-bold">Active</label></div>`;
        
        // add listener to update preview
        setTimeout(() => {
            const imgInput = document.getElementById('f-img');
            const preview = document.getElementById('f-preview');
            imgInput.addEventListener('input', () => {
                if (imgInput.value.trim()) {
                    preview.src = imgInput.value;
                    preview.classList.remove('hidden');
                } else {
                    preview.classList.add('hidden');
                }
            });
        }, 0);
    }
}

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

async function submitStatusUpdate(orderId) {
    const statusSelect = document.getElementById('update-status-select');
    const newStatus = statusSelect.value;
    const updateBtn = event.target; // The button clicked

    // Visual Feedback: Loading
    const originalText = updateBtn.innerText;
    updateBtn.innerText = "Updating...";
    updateBtn.disabled = true;

    try {
        const response = await fetch(`${API_URL}/admin/orders/${orderId}/status`, {
            method: 'PUT',
            headers: { 
                'Content-Type': 'application/json',
                'Authorization': `Bearer ${token}` 
            },
            body: JSON.stringify({ status: newStatus })
        });

        if (response.ok) {
            // Success notification
            alert(`Order #ORD-${orderId} successfully updated to: ${newStatus}`);
            
            // Refresh the background table to show the new status badge
            loadTable(); 
            
            // Close the modal
            closeModal();
        } else {
            const errorData = await response.json();
            alert(`Error: ${errorData.error || 'Failed to update status'}`);
        }
    } catch (err) {
        console.error("Status Update Error:", err);
        alert("Server error. Please check your connection.");
    } finally {
        // Reset button
        updateBtn.innerText = originalText;
        updateBtn.disabled = false;
    }
}