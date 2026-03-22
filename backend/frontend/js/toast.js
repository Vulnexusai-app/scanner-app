// toast.js - Global Neon/Cyber Toast Notification System

function showToast(message, type = 'info') {
    let container = document.getElementById('toast-container');
    if (!container) {
        container = document.createElement('div');
        container.id = 'toast-container';
        container.style.cssText = `
            position: fixed; top: 20px; right: 20px; z-index: 9999;
            display: flex; flex-direction: column; gap: 10px; pointer-events: none;
        `;
        document.body.appendChild(container);

        if (!document.getElementById('toast-styles')) {
            const style = document.createElement('style');
            style.id = 'toast-styles';
            style.textContent = `
                .cyber-toast {
                    min-width: 280px; max-width: 380px;
                    padding: 14px 18px; border-radius: 10px;
                    background: rgba(10, 10, 20, 0.92);
                    backdrop-filter: blur(14px);
                    color: #e2e8f0; font-family: 'Inter', sans-serif;
                    font-size: 13.5px; font-weight: 500;
                    display: flex; align-items: center; gap: 12px;
                    box-shadow: 0 8px 32px rgba(0,0,0,0.4);
                    border: 1px solid rgba(255,255,255,0.08);
                    transform: translateX(120%); opacity: 0;
                    transition: all 0.38s cubic-bezier(0.68,-0.55,0.265,1.55);
                    pointer-events: auto; cursor: pointer;
                }
                .cyber-toast.show { transform: translateX(0); opacity: 1; }
                .cyber-toast.hide { transform: translateX(120%); opacity: 0; }
                .toast-success { border-left: 4px solid #00ffcc; box-shadow: 0 0 18px rgba(0,255,204,0.2); }
                .toast-error   { border-left: 4px solid #ff3366; box-shadow: 0 0 18px rgba(255,51,102,0.2); }
                .toast-info    { border-left: 4px solid #3b82f6; box-shadow: 0 0 18px rgba(59,130,246,0.2); }
                .toast-warning { border-left: 4px solid #f59e0b; box-shadow: 0 0 18px rgba(245,158,11,0.2); }
                .toast-icon { font-size: 17px; flex-shrink: 0; }
            `;
            document.head.appendChild(style);
        }
    }

    const icons = { success:'✅', error:'❌', warning:'⚠️', info:'ℹ️' };
    const toast = document.createElement('div');
    toast.className = `cyber-toast toast-${type}`;
    toast.innerHTML = `<span class="toast-icon">${icons[type]||icons.info}</span><span>${message}</span>`;
    toast.onclick = () => dismissToast(toast);
    container.appendChild(toast);

    requestAnimationFrame(() => toast.classList.add('show'));

    const timer = setTimeout(() => dismissToast(toast), 4200);
    toast._timer = timer;
}

function dismissToast(toast) {
    clearTimeout(toast._timer);
    toast.classList.remove('show');
    toast.classList.add('hide');
    setTimeout(() => toast.remove(), 400);
}

if (typeof window !== 'undefined') window.showToast = showToast;
if (typeof module !== 'undefined') module.exports = showToast;
