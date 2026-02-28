import cytoscape from 'cytoscape';

let cy = null;

export function initTopologyView(containerId) {
  if (cy) return; // already initialized

  const container = document.getElementById(containerId);
  if (!container) return;
  
  container.style.background = 'transparent';

  cy = cytoscape({
    container: container,
    elements: [],
    style: [
      {
        selector: 'node',
        style: {
          'label': 'data(label)',
          'background-color': '#1f2030', // theme secondary
          'border-width': 1.5,
          'border-color': 'data(color)',
          'color': 'white',
          'text-outline-color': '#1f2030',
          'text-outline-width': 1,
          'text-valign': 'bottom',
          'text-halign': 'center',
          'text-margin-y': 4,
          'font-size': '10px',
          'font-family': 'Inter, sans-serif',
          'width': 28,
          'height': 28,
          'background-image': 'data(icon)',
          'background-fit': 'none',
          'background-width': '16px',
          'background-height': '16px',
          'background-clip': 'none',
          'background-image-opacity': 1
        }
      },
      {
        selector: 'node[type="subnet"]', // Compound node
        style: {
          'background-color': 'rgba(255,255,255,0.02)',
          'border-color': 'data(color)',
          'border-width': 1,
          'border-style': 'dashed',
          'text-valign': 'top',
          'text-halign': 'center',
          'font-size': '14px',
          'font-weight': 'bold',
          'color': 'rgba(255,255,255,0.6)',
          'padding': 20
        }
      },
      {
        selector: 'edge',
        style: {
          'width': 2,
          'line-color': 'data(color)',
          'target-arrow-color': 'data(color)',
          'target-arrow-shape': 'none',
          'curve-style': 'bezier',
          'opacity': 0.6
        }
      }
    ],
    layout: {
      name: 'cose',
      padding: 30
    }
  });

  // Attach toolbar listeners
  const btnFit = document.getElementById('btn-topology-fit');
  if (btnFit) {
    btnFit.addEventListener('click', () => {
      if (cy) cy.fit();
    });
  }

  const btnExport = document.getElementById('btn-topology-export');
  if (btnExport) {
    btnExport.addEventListener('click', () => {
      if (!cy) return;
      const png64 = cy.png({ full: true, scale: 2 });
      const a = document.createElement('a');
      a.href = png64;
      a.download = `network_topology_${new Date().getTime()}.png`;
      a.click();
    });
  }

  const selectLayout = document.getElementById('topology-layout');
  if (selectLayout) {
    selectLayout.addEventListener('change', (e) => {
      if (cy) {
        let layoutName = e.target.value;
        if (layoutName === 'cose-bilkent') layoutName = 'cose'; // fallback
        cy.layout({ name: layoutName, animate: true }).run();
      }
    });
  }

  cy.on('tap', 'node', function(evt){
    const node = evt.target;
    if (node.data('type') === 'subnet') return; // ignore subnet cluster clicks
    document.dispatchEvent(new CustomEvent('open-host-details', { detail: node.id() }));
  });
}

export function updateTopologyData(hosts) {
  if (!cy) {
    initTopologyView('cy');
  }

  const elements = [];
  const subnets = new Set();
  const gateways = new Set();

  function extractSubnet(ip) {
    if (!ip) return 'Unknown';
    const parts = ip.split('.');
    if (parts.length === 4) return `${parts[0]}.${parts[1]}.${parts[2]}.0/24`;
    return 'Unknown';
  }

  hosts.forEach(h => {
    if (h.deviceType && h.deviceType.toLowerCase().includes('router')) {
      gateways.add(h.ip);
    }
  });

  hosts.forEach(host => {
    const subnet = extractSubnet(host.ip);
    subnets.add(subnet);

    let type = 'endpoint';
    let iconSvg = '<svg width="24" height="24" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#ffffff"><path d="M20 18c1.1 0 1.99-.9 1.99-2L22 6c0-1.1-.9-2-2-2H4c-1.1 0-2 .9-2 2v10c0 1.1.9 2 2 2H0v2h24v-2h-4zM4 6h16v10H4V6z"/></svg>';
    let borderColor = '#9b59b6';

    let dt = host.deviceType ? host.deviceType.toLowerCase() : '';
    const os = host.os ? host.os.toLowerCase() : '';
    const hn = host.hostname ? host.hostname.toLowerCase() : '';
    const vendor = host.vendor ? host.vendor.toLowerCase() : '';

    // Smart heuristic guessing when deviceType is just generic or blank
    if (!dt || dt === 'general purpose' || dt.includes('general purpose')) {
      if (hn.includes('iphone') || hn.includes('ipad') || os.includes('ios') || vendor.includes('apple')) {
        dt += ' phone';
      } else if (hn.includes('printer') || vendor.includes('hp') || vendor.includes('epson') || vendor.includes('canon')) {
        dt += ' printer';
      } else if (os.includes('routeros') || vendor.includes('mikrotik') || vendor.includes('ubiquiti') || vendor.includes('netgear') || vendor.includes('cisco')) {
        dt += ' router';
      } else if (hn.includes('tv') || hn.includes('chromecast') || vendor.includes('roku') || os.includes('tvos') || vendor.includes('google') || hn.includes('media') || hn.includes('osmc')) {
        dt += ' media';
      } else if (vendor.includes('synology') || hn.includes('nas') || hn.includes('unraid')) {
        dt += ' storage';
      } else if (vendor.includes('nintendo') || vendor.includes('sony') || vendor.includes('microsoft')) {
        // Exclude broad Microsoft matches from consoles unless specific. But for now, safe generic guess.
        if (vendor.includes('nintendo') || vendor.includes('sony')) dt += ' game console';
      } else if (hn.includes('rpi') || hn.includes('raspberry')) {
        dt += ' endpoint'; // rpi is usually general purpose linux
      }
    }
    
    if (gateways.has(host.ip) || dt.includes('router')) {
      type = 'router';
      borderColor = '#3498db';
      iconSvg = '<svg width="24" height="24" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#3498db"><path d="M19 13H5c-1.1 0-2 .9-2 2v4c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2v-4c0-1.1-.9-2-2-2zM7 19c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2zM19 3H5c-1.1 0-2 .9-2 2v4c0 1.1.9 2 2 2h14c1.1 0 2-.9 2-2V5c0-1.1-.9-2-2-2zM7 9c-1.1 0-2-.9-2-2s.9-2 2-2 2 .9 2 2-.9 2-2 2z"/></svg>';
    } else if (dt.includes('switch')) {
      type = 'switch';
      borderColor = '#e67e22';
      iconSvg = '<svg width="24" height="24" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#e67e22"><path d="M4 6h16v12H4z"/></svg>';
    } else if (dt.includes('phone') || dt.includes('mobile')) {
      type = 'phone';
      borderColor = '#1abc9c';
      iconSvg = '<svg width="24" height="24" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#1abc9c"><path d="M17 1.01L7 1c-1.1 0-2 .9-2 2v18c0 1.1.9 2 2 2h10c1.1 0 2-.9 2-2V3c0-1.1-.9-1.99-2-1.99zM17 19H7V5h10v14z"/></svg>';
    } else if (dt.includes('printer')) {
      type = 'printer';
      borderColor = '#95a5a6';
      iconSvg = '<svg width="24" height="24" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#95a5a6"><path d="M19 8h-1V3H6v5H5c-1.66 0-3 1.34-3 3v6h4v4h12v-4h4v-6c0-1.66-1.34-3-3-3zM8 5h8v3H8V5zm8 14H8v-4h8v4zm2-10.5c-.55 0-1-.45-1-1s.45-1 1-1 1 .45 1 1-.45 1-1 1z"/></svg>';
    } else if (dt.includes('wap') || dt.includes('wireless') || dt.includes('access point')) {
      type = 'wap';
      borderColor = '#f1c40f';
      iconSvg = '<svg width="24" height="24" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#f1c40f"><path d="M1 9l2 2c5-5 13-5 18 0l2-2C16.93 2.93 7.08 2.93 1 9zm8 8l3 3 3-3c-1.65-1.66-4.34-1.66-6 0zm-4-4l2 2c2.76-2.76 7.24-2.76 10 0l2-2C15.14 9.14 8.87 9.14 5 13z"/></svg>';
    } else if (dt.includes('game console')) {
      type = 'game-console';
      borderColor = '#e74c3c';
      iconSvg = '<svg width="24" height="24" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#e74c3c"><path d="M21 6H3c-1.1 0-2 .9-2 2v8c0 1.1.9 2 2 2h18c1.1 0 2-.9 2-2V8c0-1.1-.9-2-2-2zm-10 7H8v3H6v-3H3v-2h3V8h2v3h3v2zm4.5 2c-.83 0-1.5-.67-1.5-1.5s.67-1.5 1.5-1.5 1.5.67 1.5 1.5-.67 1.5-1.5 1.5zm3-3c-.83 0-1.5-.67-1.5-1.5S17.67 9 18.5 9s1.5.67 1.5 1.5-.67 1.5-1.5 1.5z"/></svg>';
    } else if (dt.includes('media device') || dt.includes('tv')) {
      type = 'media';
      borderColor = '#fd79a8';
      iconSvg = '<svg width="24" height="24" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#fd79a8"><path d="M21 3H3c-1.1 0-2 .9-2 2v12c0 1.1.9 2 2 2h5v2h8v-2h5c1.1 0 1.99-.9 1.99-2L23 5c0-1.1-.9-2-2-2zm0 14H3V5h18v12z"/></svg>';
    } else if (dt.includes('storage') || dt.includes('nas')) {
      type = 'storage';
      borderColor = '#34495e';
      iconSvg = '<svg width="24" height="24" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="#34495e"><path d="M19 15v4H5v-4h14m1-2H4c-.55 0-1 .45-1 1v6c0 .55.45 1 1 1h16c.55 0 1-.45 1-1v-6c0-.55-.45-1-1-1zM7 18.5c-.82 0-1.5-.67-1.5-1.5s.67-1.5 1.5-1.5 1.5.67 1.5 1.5-.67 1.5-1.5 1.5zM19 5v4H5V5h14m1-2H4c-.55 0-1 .45-1 1v6c0 .55.45 1 1 1h16c.55 0 1-.45 1-1V4c0-.55-.45-1-1-1zM7 8.5c-.82 0-1.5-.67-1.5-1.5S6.18 5.5 7 5.5s1.5.67 1.5 1.5S7.82 8.5 7 8.5z"/></svg>';
    }

    let icon = 'data:image/svg+xml;utf8,' + encodeURIComponent(iconSvg);

    // Apply exact security posture logic
    let badge = '';
    let isDanger = false;
    let isWarning = false;
    if (host.deepAudit && host.deepAudit.vulnerabilities > 0) {
      badge = '🛑 ';
      isDanger = true;
    } else if (host.deepAudit && host.deepAudit.warnings > 0) {
      badge = '⚠️ ';
      isWarning = true;
    } else if (host.ports && host.ports.length > 0) {
      const p = new Set(host.ports);
      if (p.has(21) || p.has(23) || p.has(3306) || p.has(1433) || p.has(27017)) {
         badge = '🛑 ';
         isDanger = true;
      } else if (p.has(80) || p.has(445) || p.has(135)) {
         badge = '⚠️ ';
         isWarning = true;
      }
    }

    if (isDanger) borderColor = '#eb5e5e';   // override border to red
    if (isWarning && !isDanger) borderColor = '#f39c12'; // override border to orange

    let baseLabel = (host.hostname && host.hostname !== 'Unknown') ? host.hostname : host.ip;

    elements.push({
      data: {
        id: host.ip,
        label: badge + baseLabel,
        parent: subnet,
        type: type,
        color: borderColor,
        icon: icon
      }
    });
  });

  subnets.forEach(sub => {
    elements.push({
      data: {
        id: sub,
        label: sub,
        type: 'subnet',
        color: '#444'
      }
    });
  });

  subnets.forEach(sub => {
    const subHosts = hosts.filter(h => extractSubnet(h.ip) === sub);
    let centerIp = subHosts.find(h => gateways.has(h.ip))?.ip;
    let defaultGw = sub.replace('0/24', '1');
    let gwHost = subHosts.find(h => h.ip === defaultGw);
    
    if (centerIp) {
      subHosts.forEach(h => {
        if (h.ip !== centerIp) {
           elements.push({
             data: {
               id: `e-${h.ip}-${centerIp}`,
               source: h.ip,
               target: centerIp,
               color: '#3be282'
             }
           });
        }
      });
    } else if (gwHost) {
      subHosts.forEach(h => {
        if (h.ip !== gwHost.ip) {
           elements.push({
             data: {
               id: `e-${h.ip}-${gwHost.ip}`,
               source: h.ip,
               target: gwHost.ip,
               color: '#3be282'
             }
           });
        }
      });
    } else {
      for(let i=0; i<subHosts.length - 1; i++) {
        elements.push({
          data: {
            id: `e-${subHosts[i].ip}-${subHosts[i+1].ip}`,
            source: subHosts[i].ip,
            target: subHosts[i+1].ip,
            color: '#3be282'
          }
        });
      }
    }
  });

  const gwArray = Array.from(gateways);
  for(let i=0; i<gwArray.length - 1; i++) {
    elements.push({
      data: {
        id: `e-${gwArray[i]}-${gwArray[i+1]}`,
        source: gwArray[i],
        target: gwArray[i+1],
        color: '#3498db'
      }
    });
  }

  cy.elements().remove();
  cy.add(elements);
  
  const layoutName = document.getElementById('topology-layout')?.value || 'cose';
  cy.layout({ name: layoutName === 'cose-bilkent' ? 'cose' : layoutName, animate: true }).run();
}

export function resetTopology() {
  if (cy) {
    cy.elements().remove();
  }
}
