/**
 * Custom JavaScript for Pathshala Election 2082
 * Adds modern animations and interactive elements
 */

// Initialize all animations and effects when DOM is loaded
document.addEventListener('DOMContentLoaded', function() {
    // Animate stat counters
    animateCounters();
    
    // Enable glassmorphism effect on cards
    initGlassmorphism();
    
    // Add animation classes to elements as they scroll into view
    initScrollAnimations();
    
    // Initialize hover effects for cards and buttons
    initHoverEffects();
});

/**
 * Animates numeric counters with counting up effect
 */
function animateCounters() {
    const counters = document.querySelectorAll('.count-up');
    
    counters.forEach(counter => {
        const target = parseInt(counter.innerText, 10);
        const duration = 1500; // Animation duration in milliseconds
        const step = Math.ceil(target / (duration / 16)); // 60fps approx
        let current = 0;
        
        const updateCounter = () => {
            current += step;
            
            if (current >= target) {
                counter.innerText = target;
                return;
            }
            
            counter.innerText = current;
            requestAnimationFrame(updateCounter);
        };
        
        // Start the animation when element is in viewport
        const observer = new IntersectionObserver((entries) => {
            entries.forEach(entry => {
                if (entry.isIntersecting) {
                    updateCounter();
                    observer.unobserve(entry.target);
                }
            });
        }, { threshold: 0.5 });
        
        observer.observe(counter);
    });
}

/**
 * Initialize glassmorphism effects for cards
 */
function initGlassmorphism() {
    const glassCards = document.querySelectorAll('.glass-card');
    
    glassCards.forEach(card => {
        // Add mouse movement effect for dynamic lighting
        card.addEventListener('mousemove', e => {
            const rect = card.getBoundingClientRect();
            const x = e.clientX - rect.left;
            const y = e.clientY - rect.top;
            
            // Create light reflection effect
            card.style.background = `
                radial-gradient(
                    circle at ${x}px ${y}px,
                    rgba(255, 255, 255, 0.8) 0%,
                    rgba(255, 255, 255, 0.6) 20%,
                    rgba(255, 255, 255, 0.4) 40%,
                    rgba(255, 255, 255, 0.2) 60%,
                    rgba(255, 255, 255, 0.1) 80%,
                    rgba(255, 255, 255, 0.05) 100%
                ),
                rgba(255, 255, 255, 0.85)
            `;
        });
        
        // Reset background when mouse leaves
        card.addEventListener('mouseleave', () => {
            card.style.background = 'rgba(255, 255, 255, 0.85)';
        });
    });
}

/**
 * Add animation classes to elements as they scroll into view
 */
function initScrollAnimations() {
    const elements = document.querySelectorAll('.animate-on-scroll');
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach(entry => {
            if (entry.isIntersecting) {
                // Get animation class from data attribute
                const animationClass = entry.target.dataset.animation || 'fade-in-up';
                entry.target.classList.add('animate__animated', `animate__${animationClass}`);
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.1 });
    
    elements.forEach(el => {
        observer.observe(el);
    });
}

/**
 * Initialize hover effects for cards and buttons
 */
function initHoverEffects() {
    // Add hover effects to candidate cards
    const candidateCards = document.querySelectorAll('.candidate-card');
    
    candidateCards.forEach(card => {
        card.addEventListener('mouseenter', () => {
            // Add subtle rotation based on mouse position
            const randomRotation = Math.random() * 2 - 1; // Random value between -1 and 1
            card.style.transform = `translateY(-10px) rotate(${randomRotation}deg)`;
        });
        
        card.addEventListener('mouseleave', () => {
            // Reset transform unless card is selected
            if (!card.classList.contains('selected-candidate')) {
                card.style.transform = '';
            } else {
                card.style.transform = 'translateY(-5px)';
            }
        });
    });
} 