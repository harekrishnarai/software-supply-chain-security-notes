// Custom JavaScript for Software Supply Chain Security Notes

// Enable dark mode toggle
document.addEventListener('DOMContentLoaded', function() {
  // Check if dark mode is preferred
  const prefersDarkScheme = window.matchMedia('(prefers-color-scheme: dark)');
  
  // Set theme based on preference
  if (prefersDarkScheme.matches) {
    document.body.setAttribute('data-md-color-scheme', 'slate');
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
    // Configure mermaid with better options
    mermaid.initialize({
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
