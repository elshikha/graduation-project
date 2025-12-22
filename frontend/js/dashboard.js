// DOM Elements
const sidebar = document.getElementById('sidebar');
const sidebarToggle = document.getElementById('sidebarToggle');
const modalOverlay = document.getElementById('modalOverlay');
const modalClose = document.getElementById('modalClose');
const btnCreateProject = document.getElementById('btnCreateProject');
const projectsContainer = document.getElementById('projectsContainer');
const viewBtns = document.querySelectorAll('.view-btn');
const analysisOptions = document.querySelectorAll('.analysis-option');

// Check if user is logged in
const token = localStorage.getItem('token');
const user = JSON.parse(localStorage.getItem('user') || '{}');

if (!token) {
    window.location.href = 'index.html';
}

// Display user name
if (user.username) {
    document.querySelector('.user-name').textContent = user.username;
}

// Sidebar Toggle
sidebarToggle.addEventListener('click', () => {
    sidebar.classList.toggle('collapsed');
});

// Sidebar Navigation
const sidebarItems = document.querySelectorAll('.sidebar-item');
sidebarItems.forEach(item => {
    item.addEventListener('click', (e) => {
        const page = item.dataset.page;
        const href = item.getAttribute('href');
        
        // If it's a valid link (not #), let it navigate naturally
        if (href && href !== '#') {
            // Don't prevent default, allow navigation
            return;
        }
        
        e.preventDefault();
        
        // Remove active class from all items
        sidebarItems.forEach(i => i.classList.remove('active'));
        
        // Add active class to clicked item
        item.classList.add('active');
        
        // Handle navigation for hash links only
        switch(page) {
            case 'dashboard':
                window.location.href = 'dashboard.html';
                break;
            case 'upload':
                window.location.href = 'static-analysis.html';
                break;
            case 'settings':
                console.log('Navigate to settings page');
                break;
        }
    });
});

// Create Project Modal
btnCreateProject.addEventListener('click', () => {
    modalOverlay.classList.add('active');
});

modalClose.addEventListener('click', () => {
    modalOverlay.classList.remove('active');
});

modalOverlay.addEventListener('click', (e) => {
    if (e.target === modalOverlay) {
        modalOverlay.classList.remove('active');
    }
});

// View Toggle (Grid/List)
viewBtns.forEach(btn => {
    btn.addEventListener('click', () => {
        const view = btn.dataset.view;
        
        // Remove active class from all buttons
        viewBtns.forEach(b => b.classList.remove('active'));
        
        // Add active class to clicked button
        btn.classList.add('active');
        
        // Toggle view
        if (view === 'list') {
            projectsContainer.classList.add('list-view');
        } else {
            projectsContainer.classList.remove('list-view');
        }
    });
});

// Analysis Type Selection
analysisOptions.forEach(option => {
    option.addEventListener('click', () => {
        const type = option.dataset.type;
        
        switch(type) {
            case 'static':
                // Navigate to static analysis upload page
                window.location.href = 'static-analysis.html';
                break;
            case 'dynamic':
                // Show coming soon message
                showNotification('Dynamic Analysis will be available later', 'info');
                break;
            case 'both':
                // Navigate to static analysis with flag for both
                localStorage.setItem('analysisMode', 'both');
                window.location.href = 'static-analysis.html';
                break;
        }
    });
});

// User Profile Click
const userProfile = document.querySelector('.user-profile');
userProfile.addEventListener('click', () => {
    // Show dropdown menu or navigate to settings
    const dropdown = document.createElement('div');
    dropdown.className = 'user-dropdown';
    dropdown.innerHTML = `
        <div class="dropdown-item" onclick="navigateToSettings()">
            <i class="fas fa-cog"></i> Settings
        </div>
        <div class="dropdown-item" onclick="logout()">
            <i class="fas fa-sign-out-alt"></i> Logout
        </div>
    `;
    
    // Check if dropdown already exists
    const existingDropdown = document.querySelector('.user-dropdown');
    if (existingDropdown) {
        existingDropdown.remove();
    } else {
        userProfile.appendChild(dropdown);
        
        // Close dropdown when clicking outside
        setTimeout(() => {
            document.addEventListener('click', function closeDropdown(e) {
                if (!userProfile.contains(e.target)) {
                    dropdown.remove();
                    document.removeEventListener('click', closeDropdown);
                }
            });
        }, 0);
    }
});

// Logout function
function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    localStorage.removeItem('analysisMode');
    window.location.href = '../../index.html';
}

// Navigate to settings
function navigateToSettings() {
    console.log('Navigate to settings page');
    // Will implement settings page navigation
}

// Notification system
function showNotification(message, type = 'success') {
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;
    notification.innerHTML = `
        <i class="fas fa-${type === 'success' ? 'check-circle' : type === 'error' ? 'exclamation-circle' : 'info-circle'}"></i>
        <span>${message}</span>
    `;
    
    document.body.appendChild(notification);
    
    // Add styles if not already present
    if (!document.getElementById('notification-styles')) {
        const style = document.createElement('style');
        style.id = 'notification-styles';
        style.textContent = `
            .notification {
                position: fixed;
                top: 20px;
                right: 20px;
                background: white;
                padding: 1rem 1.5rem;
                border-radius: 12px;
                box-shadow: 0 8px 24px rgba(0, 0, 0, 0.15);
                display: flex;
                align-items: center;
                gap: 0.75rem;
                z-index: 3000;
                animation: slideIn 0.3s ease;
            }
            
            @keyframes slideIn {
                from {
                    transform: translateX(400px);
                    opacity: 0;
                }
                to {
                    transform: translateX(0);
                    opacity: 1;
                }
            }
            
            @keyframes slideOut {
                from {
                    transform: translateX(0);
                    opacity: 1;
                }
                to {
                    transform: translateX(400px);
                    opacity: 0;
                }
            }
            
            .notification i {
                font-size: 1.5rem;
            }
            
            .notification-success i {
                color: #2e7d32;
            }
            
            .notification-error i {
                color: #c62828;
            }
            
            .notification-info i {
                color: #8519D5;
            }
            
            .notification span {
                color: #333;
                font-weight: 500;
            }
        `;
        document.head.appendChild(style);
    }
    
    // Remove notification after 3 seconds
    setTimeout(() => {
        notification.style.animation = 'slideOut 0.3s ease';
        setTimeout(() => {
            notification.remove();
        }, 300);
    }, 3000);
}

// Project card actions
document.addEventListener('click', (e) => {
    if (e.target.closest('.btn-view')) {
        const card = e.target.closest('.project-card');
        const title = card.querySelector('.project-title').textContent;
        showNotification(`Opening project: ${title}`, 'info');
        // Will implement project view page
    }
    
    if (e.target.closest('.btn-delete')) {
        const card = e.target.closest('.project-card');
        const title = card.querySelector('.project-title').textContent;
        
        if (confirm(`Are you sure you want to delete "${title}"?`)) {
            card.style.animation = 'fadeOut 0.3s ease';
            setTimeout(() => {
                card.remove();
                showNotification('Project deleted successfully', 'success');
            }, 300);
        }
    }
});

// Add fadeOut animation
const style = document.createElement('style');
style.textContent = `
    @keyframes fadeOut {
        from {
            opacity: 1;
            transform: scale(1);
        }
        to {
            opacity: 0;
            transform: scale(0.9);
        }
    }
    
    .user-dropdown {
        position: absolute;
        top: calc(100% + 10px);
        right: 0;
        background: white;
        border-radius: 12px;
        box-shadow: 0 8px 24px rgba(0, 0, 0, 0.15);
        min-width: 200px;
        overflow: hidden;
        animation: dropdownSlide 0.3s ease;
        z-index: 1000;
    }
    
    @keyframes dropdownSlide {
        from {
            opacity: 0;
            transform: translateY(-10px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    .dropdown-item {
        padding: 1rem 1.5rem;
        display: flex;
        align-items: center;
        gap: 0.75rem;
        cursor: pointer;
        transition: all 0.2s ease;
        color: #333;
    }
    
    .dropdown-item:hover {
        background: #f0f0f0;
    }
    
    .dropdown-item i {
        font-size: 1.1rem;
        color: #8519D5;
    }
`;
document.head.appendChild(style);
