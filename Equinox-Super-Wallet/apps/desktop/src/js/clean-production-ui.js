// Equinox Production Clean-Slate UI Initializer
(function() {
    function sanitizePortal() {
        // Clear any pre-filled password or PIN fields on initial load
        document.querySelectorAll('input[type="password"], input[type="text"]').forEach(inp => {
            if (inp.value === "Equinox#Master2026" || inp.value === "482910" || inp.value === "My Sovereign Vault") {
                inp.value = "";
            }
        });

        // Remove hardcoded demo account rows in "4. Accounts" tab and dropdowns
        document.querySelectorAll('option, div, li, tr, p, span').forEach(el => {
            if (el.children.length === 0 || el.tagName === 'OPTION') {
                const txt = el.textContent || "";
                if (txt.includes("Ebt19oYi") || txt.includes("EHBT5KA643") || txt.includes("982,947.515") || txt.includes("250,000 EQX")) {
                    if (el.tagName === 'OPTION') {
                        el.textContent = "-- Create or Recover Your Own EQX Vault --";
                        el.value = "";
                    } else {
                        const row = el.closest('.account-row, .profile-item, li, tr') || el.parentElement;
                        if (row) row.style.display = "none";
                    }
                }
                if (txt.trim() === "Paste Genesis Seed" || txt.includes("Auto-Fill Word for Quick Test")) {
                    el.style.display = "none";
                }
            }
        });
    }

    window.addEventListener("DOMContentLoaded", () => {
        sanitizePortal();
        setTimeout(sanitizePortal, 300);
    });
    document.addEventListener("click", () => setTimeout(sanitizePortal, 50));
})();
