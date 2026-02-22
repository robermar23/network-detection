// Basic MAC OUI vendor mappings (extensible fallback)
export const vendorMap = {
  // Apple
  'E4:5F:01': 'Apple, Inc.',
  'D4:61:9D': 'Apple, Inc.',
  '00:25:00': 'Apple, Inc.',
  'F8:FF:C2': 'Apple, Inc.',
  '00:1E:52': 'Apple, Inc.',
  '00:1C:B3': 'Apple, Inc.',
  'BC:6C:21': 'Apple, Inc.',
  
  // Virtual Machines
  '00:0C:29': 'VMware, Inc.',
  '00:50:56': 'VMware, Inc.',
  '08:00:27': 'PCS Systemtechnik (VirtualBox)',
  '00:15:5D': 'Microsoft Corporation (Hyper-V)',

  // Smart Home / Mobile / IoT
  '00:1A:11': 'Google, Inc.',
  '3C:5A:B4': 'Google, Inc.',
  'F4:F5:D8': 'Google, Inc.',
  'CC:B8:A8': 'Samsung Electronics',
  '00:16:32': 'Samsung Electronics',
  '00:24:E4': 'Withings',
  '44:65:0D': 'Amazon Technologies Inc.',
  '18:74:2E': 'Amazon Technologies Inc.',
  'B4:7C:9C': 'Amazon Technologies Inc.',
  'F4:5E:AB': 'Amazon Technologies Inc.',
  '24:18:1D': 'Amazon Technologies Inc.',
  '54:60:09': 'Google, Inc. (Nest)',

  // Gaming Consoles
  '00:24:8D': 'Sony Interactive Entertainment',
  '00:D9:D1': 'Sony Interactive Entertainment',
  '50:1A:A5': 'Microsoft Corporation (Xbox)',

  // Entertainment & IoT
  'B8:AE:6E': 'Nintendo Co., Ltd',
  '84:EA:ED': 'Roku, Inc',
  '84:E6:57': 'Sony Interactive Entertainment Inc.',
  '00:04:4B': 'NVIDIA',
  '64:52:99': 'The Chamberlain Group, Inc',
  '84:BA:3B': 'CANON INC.',

  // Network Gear & PCs
  'AC:84:C6': 'TP-Link Technologies Co.,Ltd',
  '40:ED:00': 'TP-Link Systems Inc',
  '00:14:22': 'Dell Inc.',
  '18:DB:F2': 'Dell Inc.',
  '00:1B:44': 'Intel Corporate',
  'A4:4C:C8': 'Intel Corporate',
  '00:00:0C': 'Cisco Systems, Inc',
  '00:01:42': 'Cisco Systems, Inc',
  '88:E9:FE': 'Cisco Systems, Inc',
  '00:10:5A': 'Acer Inc.',
  '00:11:0A': 'HP Inc.',
  'B8:27:EB': 'Raspberry Pi Foundation',
  'DC:A6:32': 'Raspberry Pi Foundation',
  'E4:5F:01': 'Raspberry Pi Foundation'
};

export const COMMON_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 548, 993, 995, 1723, 3306, 3389, 5900, 8080
];
