
import { hookMethod, pass, interdict, LOG } from '../framework.js';

LOG("--- settings Hooks Script Start ---");

const hooksToApply = [
    {
        enabled: true,
        target: 'com.android.settings.deviceinfo.HardwareInfoPreferenceController#getDeviceModel',
        callback: () => {
            // return interdict("hello");
            return pass()
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

LOG("--- Settings Hooks Script End ---");
