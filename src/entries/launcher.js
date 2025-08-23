
import { hookMethod, pass, interdict, LOG } from '../framework.js';

LOG("--- Launcher Hooks Script Start ---");

const hooksToApply = [
    {
        enabled: false,
        target: 'com.android.launcher3.model.AddWorkspaceItemsTask#findSpaceForItem',
        callback: () => {
            // Example: Force add item to hotseat
            const intArray = Java.array('int', [-101, 0, 0]);
            return interdict(intArray);
        }
    }
];

function applyEnabledHooks() {
    LOG("Scanning for enabled hooks...", { subTag: "HookManager" });
    hooksToApply.forEach(hookInfo => {
        if (hookInfo.enabled) {
            const { target, callback, printStack } = hookInfo;
            LOG(`Applying hook to: ${target}`, { subTag: "HookManager" });
            hookMethod(target, callback || null, printStack || false);
        }
    });
    LOG("All enabled hooks have been applied.", { subTag: "HookManager" });
}

applyEnabledHooks();

LOG("--- Launcher Hooks Script End ---");
