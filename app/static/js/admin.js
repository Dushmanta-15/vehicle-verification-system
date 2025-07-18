// static/js/admin.js

// Confirmation for delete actions
document.querySelectorAll('.delete-confirm').forEach(button => {
    button.addEventListener('click', function(e) {
        if (!confirm('Are you sure you want to delete this item? This action cannot be undone.')) {
            e.preventDefault();
        }
    });
});

// Search functionality
const searchInput = document.getElementById('search-input');
if (searchInput) {
    searchInput.addEventListener('input', debounce(function(e) {
        const searchTerm = e.target.value;
        if (searchTerm.length >= 2) {
            performSearch(searchTerm);
        }
    }, 500));
}

function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

function performSearch(term) {
    fetch(`/admin/search?q=${encodeURIComponent(term)}`)
        .then(response => response.json())
        .then(data => {
            updateSearchResults(data);
        })
        .catch(error => console.error('Search error:', error));
}

function updateSearchResults(data) {
    const resultsContainer = document.getElementById('search-results');
    if (!resultsContainer) return;

    resultsContainer.innerHTML = '';
    
    if (data.users?.length || data.vehicles?.length) {
        if (data.users?.length) {
            const usersList = createResultsList('Users', data.users, user => `
                <div class="search-result-item">
                    <div>${user.username}</div>
                    <div>${user.email}</div>
                </div>
            `);
            resultsContainer.appendChild(usersList);
        }
        
        if (data.vehicles?.length) {
            const vehiclesList = createResultsList('Vehicles', data.vehicles, vehicle => `
                <div class="search-result-item">
                    <div>${vehicle.vehicle_number}</div>
                    <div>${vehicle.owner_name}</div>
                </div>
            `);
            resultsContainer.appendChild(vehiclesList);
        }
    } else {
        resultsContainer.innerHTML = '<div class="no-results">No results found</div>';
    }
}

function createResultsList(title, items, itemTemplate) {
    const section = document.createElement('div');
    section.className = 'search-results-section';
    section.innerHTML = `
        <h3>${title}</h3>
        <div class="search-results-list">
            ${items.map(item => itemTemplate(item)).join('')}
        </div>
    `;
    return section;
}

// Dashboard Charts
function initDashboardCharts() {
    if (document.getElementById('usersChart')) {
        fetch('/admin/api/stats')
            .then(response => response.json())
            .then(data => {
                createLineChart('usersChart', 'Monthly User Registrations', data.monthly_users);
                createLineChart('vehiclesChart', 'Monthly Vehicle Registrations', data.monthly_vehicles);
            })
            .catch(error => console.error('Error loading charts:', error));
    }
}

function createLineChart(canvasId, label, data) {
    const ctx = document.getElementById(canvasId).getContext('2d');
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: data.map(item => item.month),
            datasets: [{
                label: label,
                data: data.map(item => item.count),
                borderColor: '#3498db',
                tension: 0.1,
                fill: false
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                }
            }
        }
    });
}

// Data Tables Enhancement
function initDataTables() {
    const tables = document.querySelectorAll('.data-table');
    tables.forEach(table => {
        new DataTable(table, {
            pageLength: 10,
            ordering: true,
            searching: true,
            responsive: true,
            language: {
                search: "Search in table:",
                paginate: {
                    first: "First",
                    last: "Last",
                    next: "Next",
                    previous: "Previous"
                }
            }
        });
    });
}

// Initialize all components
document.addEventListener('DOMContentLoaded', function() {
    initDashboardCharts();
    initDataTables();

    // Add active class to current sidebar link
    const currentPath = window.location.pathname;
    document.querySelectorAll('.sidebar-menu a').forEach(link => {
        if (link.getAttribute('href') === currentPath) {
            link.classList.add('active');
        }
    });
});

// Form validation
function validateForm(formId) {
    const form = document.getElementById(formId);
    if (!form) return true;

    let isValid = true;
    const requiredFields = form.querySelectorAll('[required]');
    
    requiredFields.forEach(field => {
        if (!field.value.trim()) {
            isValid = false;
            field.classList.add('invalid');
            
            const errorMessage = document.createElement('div');
            errorMessage.className = 'error-message';
            errorMessage.textContent = 'This field is required';
            
            if (!field.nextElementSibling?.classList.contains('error-message')) {
                field.parentNode.insertBefore(errorMessage, field.nextSibling);
            }
        } else {
            field.classList.remove('invalid');
            const nextSibling = field.nextElementSibling;
            if (nextSibling?.classList.contains('error-message')) {
                nextSibling.remove();
            }
        }
    });

    return isValid;
}