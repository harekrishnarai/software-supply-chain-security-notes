// Custom JavaScript for Software Supply Chain Security Notes

// Header enhancement - smooth scroll and header appearance
document.addEventListener('DOMContentLoaded', function() {
  // Enhance header appearance
  const header = document.querySelector('.md-header');
  const headerHeight = header.offsetHeight;
  
  // Handle scroll events for header appearance
  let lastScrollTop = 0;
  window.addEventListener('scroll', function() {
    const scrollTop = window.pageYOffset || document.documentElement.scrollTop;
    
    // Add box shadow when scrolling down
    if (scrollTop > 0) {
      header.classList.add('md-header--shadow');
    } else {
      header.classList.remove('md-header--shadow');
    }
    
    // Auto-hide header when scrolling down, show when scrolling up
    if (scrollTop > lastScrollTop && scrollTop > headerHeight) {
      header.classList.add('md-header--hidden');
    } else {
      header.classList.remove('md-header--hidden');
    }
    
    lastScrollTop = scrollTop;
  });
  
  // Smooth scroll for navigation links
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
      const targetId = this.getAttribute('href');
      if (targetId !== '#') {
        e.preventDefault();
        document.querySelector(targetId).scrollIntoView({
          behavior: 'smooth'
        });
      }
    });
  });

  // Enable dark mode toggle
  const savedTheme = localStorage.getItem('darkMode');
  
  // If a preference is saved, use that, otherwise default to light mode
  if (savedTheme === 'true') {
    document.body.setAttribute('data-md-color-scheme', 'slate');
  } else {
    document.body.setAttribute('data-md-color-scheme', 'default');
  }
  
  // Add keyboard shortcut for toggling dark mode (Alt+T)
  document.addEventListener('keydown', function(e) {
    if (e.altKey && e.key === 't') {
      const currentScheme = document.body.getAttribute('data-md-color-scheme');
      const newScheme = currentScheme === 'slate' ? 'default' : 'slate';
      document.body.setAttribute('data-md-color-scheme', newScheme);
      localStorage.setItem('darkMode', newScheme === 'slate' ? 'true' : 'false');
      
      // Update mermaid diagrams when theme changes
      if (window.mermaid) {
        window.mermaid.initialize({
          theme: newScheme === 'slate' ? 'dark' : 'default'
        });
        window.mermaid.run();
      }
      
      e.preventDefault();
    }
  });
  
  // Check local storage for saved preference
  const darkModeSetting = localStorage.getItem('darkMode');
  if (darkModeSetting) {
    document.body.setAttribute('data-md-color-scheme', 
      darkModeSetting === 'true' ? 'slate' : 'default');
  }
});

// Add support for mermaid diagrams with improved handling
document.addEventListener('DOMContentLoaded', function() {
  // Dynamically load mermaid
  const script = document.createElement('script');
  script.src = 'https://cdn.jsdelivr.net/npm/mermaid@10.6.1/dist/mermaid.min.js';
  script.setAttribute('integrity', 'sha384-jAdMSmkCY9F+VyZbU0JBGD8A+tUKJ5nSHZMqrD+ECgrgQjYiwBlO8l5eKKJACoKO');
  script.setAttribute('crossorigin', 'anonymous');
  
  script.onload = function() {
    // Configure mermaid with better options based on current theme
    const isDarkMode = document.body.getAttribute('data-md-color-scheme') === 'slate';
    mermaid.initialize({
      theme: isDarkMode ? 'dark' : 'default',
      securityLevel: 'loose',
      startOnLoad: true,
      themeVariables: {
        // Custom theme variables for security-focused diagrams
        primaryColor: isDarkMode ? '#00bcd4' : '#009688',
        primaryTextColor: isDarkMode ? '#ffffff' : '#ffffff',
        primaryBorderColor: isDarkMode ? '#0097a7' : '#00796b',
        lineColor: isDarkMode ? '#aaaaaa' : '#666666',
        secondaryColor: isDarkMode ? '#4dd0e1' : '#4db6ac',
        tertiaryColor: isDarkMode ? '#2d2d2d' : '#f5f5f5',
      },
      startOnLoad: true,
      theme: document.body.getAttribute('data-md-color-scheme') === 'slate' ? 'dark' : 'default',
      securityLevel: 'loose',
      flowchart: {
        curve: 'basis',
        diagramPadding: 8,
        htmlLabels: true,
        useMaxWidth: true
      },
      themeVariables: {
        primaryColor: '#2979ff',
        primaryTextColor: '#fff',
        primaryBorderColor: '#7aa6f7',
        lineColor: '#7aa6f7',
        secondaryColor: '#006db3',
        tertiaryColor: '#fff'
      }
    });
    
    // Process any existing mermaid diagrams
    mermaid.run();
  };
  
  document.head.appendChild(script);
  
  // Add custom event handler to redraw diagrams on tab change or page resize
  window.addEventListener('resize', function() {
    if (window.mermaid) {
      window.mermaid.run();
    }
  });
});

// Add interactive features to supply chain diagram
document.addEventListener('DOMContentLoaded', function() {
  // Enhance supply chain diagram interactivity
  setTimeout(function() {
    const svgElements = document.querySelectorAll('.mermaid svg');
    svgElements.forEach(function(svg) {
      const nodes = svg.querySelectorAll('g.node');
      nodes.forEach(function(node) {
        // Add hover effect
        node.addEventListener('mouseenter', function() {
          node.style.transform = 'scale(1.05)';
          node.style.transition = 'transform 0.2s';
          node.style.cursor = 'pointer';
        });
        
        node.addEventListener('mouseleave', function() {
          node.style.transform = 'scale(1)';
        });
        
        // Add click effect for future interactivity
        node.addEventListener('click', function() {
          const nodeText = node.textContent.trim().toLowerCase();
          
          // Scroll to relevant section if exists
          const sections = document.querySelectorAll('h2, h3');
          let targetSection = null;
          
          sections.forEach(function(section) {
            if (section.textContent.toLowerCase().includes(nodeText)) {
              targetSection = section;
            }
          });
          
          if (targetSection) {
            targetSection.scrollIntoView({ behavior: 'smooth' });
          }
        });
      });
    });
  }, 1000); // Allow time for diagrams to render
});

// Add interactive security elements
document.addEventListener('DOMContentLoaded', function() {
  // Add pulse effect to security badges
  const securityElements = document.querySelectorAll('.security-badge');
  securityElements.forEach(element => {
    element.addEventListener('mouseenter', function() {
      this.style.transform = 'scale(1.05)';
    });
    element.addEventListener('mouseleave', function() {
      this.style.transform = 'scale(1)';
    });
  });

  // Add tooltips to security-related elements
  document.querySelectorAll('[data-security-tip]').forEach(element => {
    const tipText = element.getAttribute('data-security-tip');
    
    element.addEventListener('mouseenter', function(e) {
      const tooltip = document.createElement('div');
      tooltip.className = 'security-tooltip';
      tooltip.textContent = tipText;
      tooltip.style.position = 'absolute';
      tooltip.style.backgroundColor = 'rgba(0, 0, 0, 0.8)';
      tooltip.style.color = '#fff';
      tooltip.style.padding = '5px 10px';
      tooltip.style.borderRadius = '4px';
      tooltip.style.fontSize = '14px';
      tooltip.style.zIndex = '1000';
      tooltip.style.maxWidth = '300px';
      
      document.body.appendChild(tooltip);
      
      const rect = element.getBoundingClientRect();
      tooltip.style.top = (rect.bottom + window.scrollY + 10) + 'px';
      tooltip.style.left = (rect.left + window.scrollX) + 'px';
      
      this.tooltip = tooltip;
    });
    
    element.addEventListener('mouseleave', function() {
      if (this.tooltip) {
        this.tooltip.remove();
        this.tooltip = null;
      }
    });
  });
  
  // Add visual highlighting for security vulnerabilities
  document.querySelectorAll('code span.vulnerability').forEach(element => {
    element.style.backgroundColor = 'rgba(244, 67, 54, 0.2)';
    element.style.borderBottom = '2px solid #f44336';
    element.style.padding = '0 2px';
  });
  
  // Add security status indicators
  document.querySelectorAll('[data-security-status]').forEach(element => {
    const status = element.getAttribute('data-security-status');
    const indicator = document.createElement('span');
    
    indicator.className = 'security-status-indicator';
    indicator.style.display = 'inline-block';
    indicator.style.width = '10px';
    indicator.style.height = '10px';
    indicator.style.borderRadius = '50%';
    indicator.style.marginRight = '5px';
    
    switch(status) {
      case 'secure':
        indicator.style.backgroundColor = 'var(--secure-color)';
        indicator.title = 'Secure';
        break;
      case 'vulnerable':
        indicator.style.backgroundColor = 'var(--vulnerable-color)';
        indicator.title = 'Vulnerable';
        break;
      case 'warning':
        indicator.style.backgroundColor = 'var(--warning-color)';
        indicator.title = 'Warning';
        break;
      default:
        indicator.style.backgroundColor = 'var(--info-color)';
        indicator.title = 'Information';
    }
    
    element.prepend(indicator);
  });
});
