
import { hookMethod, pass, interdict, LOG } from '../framework.js';

LOG("--- HLCT Navigation Hooks Script Start ---");

const hooksToApply = [
    {
        enabled: false,
        target: 'me.f1reking.serialportlib.SerialPortHelper#openSafe',
        callback: (obj, arg0, arg1, arg2, arg3, arg4, arg5, arg6) => {
            let res = obj.openSafe(arg0, 115200, arg2, arg3, arg4, arg5, arg6);
            LOG('res=' + res);
            return interdict(res);
        }
    },
    { enabled: false, target: 'com.hlct.navigation.utlis.L$Companion#d' },
    { enabled: false, target: 'com.hlct.navigation.utlis.L$Companion#e' },
    { enabled: false, target: 'com.hlct.navigation.utlis.L$Companion#i' },
    { enabled: false, target: 'com.hlct.navigation.utlis.L$Companion#v' },
    { enabled: false, target: 'com.hlct.navigation.utlis.L$Companion#w' },
    { enabled: false, target: 'com.hlct.navigation.communication.phone.PhoneServer#sendMsg' },
    { enabled: false, target: 'com.hlct.navigation.communication.phone.PhoneServer$openPort$1#onDataReceived' }
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

LOG("--- HLCT Navigation Hooks Script End ---");
