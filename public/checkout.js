const API_URL = 'https://campobrew.onrender.com/api';
const WHATSAPP_NUMBER = '254795846971';
 
        let cart = JSON.parse(localStorage.getItem('coffee_cart')) || [];

        document.addEventListener('DOMContentLoaded', renderOrderSummary);

        function buildWhatsAppMessage(orderData, orderId) {
            const itemsText = orderData.items.map((item, index) => {
                return `${index + 1}. Product ID: ${item.product_id}, Qty: ${item.quantity}, Price: KSh ${item.price}`;
            }).join('\n');

            return [
                `New TechSips Order${orderId ? ` #${orderId}` : ''}`,
                `Customer: ${orderData.customer_name}`,
                `Email: ${orderData.customer_email}`,
                `Phone: ${orderData.customer_phone}`,
                `Address: ${orderData.shipping_address}`,
                `Total: KSh ${orderData.total_price.toFixed(2)}`,
                'Items:',
                itemsText
            ].join('\n');
        }

        function sendOrderToWhatsApp(orderData, orderId) {
            const message = buildWhatsAppMessage(orderData, orderId);
            const whatsappUrl = `https://wa.me/${WHATSAPP_NUMBER}?text=${encodeURIComponent(message)}`;
            const whatsappLink = document.getElementById('whatsapp-link');

            if (whatsappLink) {
                whatsappLink.href = whatsappUrl;
                whatsappLink.classList.remove('hidden');
            }

            const newTab = window.open(whatsappUrl, '_blank');
            if (!newTab) {
                const whatsappStatus = document.getElementById('whatsapp-status');
                if (whatsappStatus) whatsappStatus.classList.remove('hidden');
            }
        }

        function renderOrderSummary() {
            const list = document.getElementById('cart-items-list');
            const subtotalEl = document.getElementById('subtotal');
            const totalEl = document.getElementById('total-price');
            const orderBtn = document.getElementById('place-order-btn');

            if (cart.length === 0) {
                list.innerHTML = `
                    <div class="text-center py-10">
                        <p class="text-gray-400 italic text-sm">Your cart is empty.</p>
                        <a href="products.html" class="text-coffee-medium text-xs underline mt-2 inline-block">Go add some coffee!</a>
                    </div>`;
                orderBtn.disabled = true;
                orderBtn.classList.add('opacity-50', 'cursor-not-allowed');
                return;
            }

            orderBtn.disabled = false;
            orderBtn.classList.remove('opacity-50', 'cursor-not-allowed');

            let total = 0;
            list.innerHTML = cart.map((item, index) => {
                const itemTotal = item.price * item.quantity;
                total += itemTotal;
                return `
                    <div class="flex items-center justify-between gap-4 bg-gray-50/50 p-3 rounded-xl border border-gray-100">
                        <div class="flex items-center gap-3">
                            <img src="${item.img || item.image_url}" class="w-12 h-12 rounded-lg object-cover shadow-sm">
                            <div>
                                <p class="font-bold text-xs text-coffee-dark leading-tight">${item.name}</p>
                                <p class="text-[10px] text-gray-500 font-bold mt-1">KSh ${item.price}</p>
                            </div>
                        </div>
                        
                        <div class="flex items-center gap-2 bg-white border border-gray-200 rounded-lg p-1">
                            <button onclick="updateQty(${index}, -1)" class="w-6 h-6 flex items-center justify-center text-coffee-medium hover:bg-coffee-light rounded transition">-</button>
                            <span class="text-xs font-bold w-4 text-center">${item.quantity}</span>
                            <button onclick="updateQty(${index}, 1)" class="w-6 h-6 flex items-center justify-center text-coffee-medium hover:bg-coffee-light rounded transition">+</button>
                        </div>
                    </div>
                `;
            }).join('');

            subtotalEl.innerText = `KSh ${total.toFixed(2)}`;
            totalEl.innerText = `KSh ${total.toFixed(2)}`;
        }

        function updateQty(index, change) {
            cart[index].quantity += change;
            if (cart[index].quantity <= 0) {
                if (confirm("Remove this item from your cart?")) {
                    cart.splice(index, 1);
                } else {
                    cart[index].quantity = 1;
                }
            }
            localStorage.setItem('coffee_cart', JSON.stringify(cart));
            renderOrderSummary();
        }

        async function submitOrder() {
            const name = document.getElementById('cust-name').value;
            const email = document.getElementById('cust-email').value;
            const phone = document.getElementById('cust-phone').value;
            const address = document.getElementById('cust-address').value;

            if (!name || !email || !phone || !address) {
                alert("Please fill in all shipping and contact details.");
                return;
            }

            const btn = document.getElementById('place-order-btn');
            const originalText = btn.innerText;
            btn.innerText = "Processing Order...";
            btn.disabled = true;

            const orderData = {
                customer_name: name,
                customer_email: email,
                customer_phone: phone,
                shipping_address: address,
                total_price: cart.reduce((sum,item)=>sum+item.price*item.quantity,0),
                items: cart.map(item=>({
                    product_id: item.id,
                    quantity: item.quantity,
                    price: item.price
                }))
            };

            try {
                const response = await fetch(`${API_URL}/orders`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(orderData)
                });
                const data = await response.json().catch(() => ({}));

                if (response.ok) {
                    localStorage.removeItem('coffee_cart');
                    document.getElementById('checkout-container').classList.add('hidden');
                    document.getElementById('success-screen').classList.remove('hidden');
                    window.scrollTo({ top: 0, behavior: 'smooth' });
                    sendOrderToWhatsApp(orderData, data.orderId);
                } else {
                    throw new Error("Order submission failed");
                }
            } catch (err) {
                alert("Error: Could not place order. Ensure your server is running.");
                btn.innerText = originalText;
                btn.disabled = false;
            }
        }
