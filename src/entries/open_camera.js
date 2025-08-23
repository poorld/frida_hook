
import { hookMethod, pass, interdict, LOG } from '../framework.js';

LOG("--- OpenCamera Hooks Script Start ---");

const hooksToApply = [
    {
        enabled: false,
        target: 'net.sourceforge.opencamera.preview.Preview#openCameraCore',
        callback: (obj, p1) => {
            console.log('using_android_l ', obj.using_android_l.value);
            obj.using_android_l.value = true;
            return pass();
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

LOG("--- OpenCamera Hooks Script End ---");
