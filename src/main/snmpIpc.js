import { snmpWalk, snmpGet, cancelSnmpWalk } from './snmpWalker.js';
import { IPC_CHANNELS } from '#shared/ipc.js';

export function registerSnmpHandlers(ipcMain, mainWindow) {
  ipcMain.handle(IPC_CHANNELS.SNMP_WALK, async (event, { targetIp, options }) => {
    console.log(`SNMP Walk requested for ${targetIp}`);
    const success = snmpWalk(targetIp, options,
      (resultData)   => mainWindow?.webContents.send(IPC_CHANNELS.SNMP_WALK_RESULT, resultData),
      (progressData) => mainWindow?.webContents.send(IPC_CHANNELS.SNMP_WALK_PROGRESS, progressData),
      (completeData) => mainWindow?.webContents.send(IPC_CHANNELS.SNMP_WALK_COMPLETE, completeData),
      (errorData)    => mainWindow?.webContents.send(IPC_CHANNELS.SNMP_WALK_ERROR, errorData),
    );
    return { status: success ? 'started' : 'failed' };
  });

  ipcMain.handle(IPC_CHANNELS.SNMP_GET, async (event, { targetIp, oids, options }) => {
    try {
      const results = await snmpGet(targetIp, oids, options);
      return { success: true, results };
    } catch (err) {
      return { success: false, error: err.message };
    }
  });

  ipcMain.handle(IPC_CHANNELS.CANCEL_SNMP_WALK, async (event, targetIp) => {
    const success = cancelSnmpWalk(targetIp);
    return { status: success ? 'cancelled' : 'not_found' };
  });
}
