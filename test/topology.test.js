import { describe, it, expect, vi, beforeEach } from 'vitest';
import { updateTopologyData, initTopologyView } from '../src/renderer/topology.js';

// Mock document for cytoscape
global.document = {
  getElementById: vi.fn(),
  createElement: vi.fn(() => ({ click: vi.fn() }))
};

const mockElement = {
  addEventListener: vi.fn(),
  value: 'cose',
  style: {}
};

const mockCyInstance = {
  elements: vi.fn(() => ({
    remove: vi.fn(),
  })),
  add: vi.fn(),
  layout: vi.fn(() => ({
    run: vi.fn(),
  })),
  fit: vi.fn(),
  on: vi.fn(),
};

// Mock cytoscape
vi.mock('cytoscape', () => {
  return {
    default: vi.fn(() => mockCyInstance),
  };
});

describe('topology.js', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('should format host data into cytoscape elements', async () => {
    const mockHosts = [
      { ip: '192.168.1.1', hostname: 'router', deviceType: 'router' },
      { ip: '192.168.1.100', hostname: 'pc1', deviceType: 'endpoint' },
      { ip: '10.0.0.1', hostname: 'core-switch', deviceType: 'switch' }
    ];

    document.getElementById.mockReturnValue(mockElement); // Mock all requested elements

    updateTopologyData(mockHosts);

    // Verify cytoscape was initialized or elements were added
    const cytoscape = await import('cytoscape');
    expect(cytoscape.default).toHaveBeenCalled();
    
    // Check that elements were added
    expect(mockCyInstance.add).toHaveBeenCalled();
    const addedElements = mockCyInstance.add.mock.calls[0][0];
    
    // 3 nodes + 2 subnets + edges
    expect(addedElements.length).toBeGreaterThan(0);
    
    // Check nodes
    const routerNode = addedElements.find(e => e.data.id === '192.168.1.1');
    expect(routerNode.data.type).toBe('router');
    expect(routerNode.data.parent).toBe('192.168.1.0/24');

    const switchNode = addedElements.find(e => e.data.id === '10.0.0.1');
    expect(switchNode.data.type).toBe('switch');
    expect(switchNode.data.parent).toBe('10.0.0.0/24');
  });

  it('should auto-cluster hosts by subnet', async () => {
    const mockHosts = [
      { ip: '192.168.1.1', hostname: 'router', deviceType: 'router' },
      { ip: '192.168.1.10', hostname: 'dev1' },
      { ip: '192.168.1.11', hostname: 'dev2' }
    ];

    document.getElementById.mockReturnValue(mockElement);

    updateTopologyData(mockHosts);

    const addedElements = mockCyInstance.add.mock.calls[0][0];

    // Subnet node
    const subnetNode = addedElements.find(e => e.data.type === 'subnet');
    expect(subnetNode).toBeDefined();
    expect(subnetNode.data.id).toBe('192.168.1.0/24');

    // Devices are parented to subnet
    const dev1Node = addedElements.find(e => e.data.id === '192.168.1.10');
    expect(dev1Node.data.parent).toBe('192.168.1.0/24');
  });
});
