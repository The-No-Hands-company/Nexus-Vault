type RuntimeState = {
  maintenanceMode: boolean;
  maintenanceReason: string;
  restoreInProgress: boolean;
};

const state: RuntimeState = {
  maintenanceMode: false,
  maintenanceReason: '',
  restoreInProgress: false,
};

export function getRuntimeState(): RuntimeState {
  return { ...state };
}

export function setMaintenanceMode(enabled: boolean, reason = ''): RuntimeState {
  state.maintenanceMode = enabled;
  state.maintenanceReason = enabled ? reason.trim() : '';
  return getRuntimeState();
}

export function setRestoreInProgress(value: boolean): RuntimeState {
  state.restoreInProgress = value;
  return getRuntimeState();
}

export function isWriteBlocked(): boolean {
  return state.maintenanceMode || state.restoreInProgress;
}
