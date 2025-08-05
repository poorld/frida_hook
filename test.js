/**
 * frida-compile .\test.js -o .\test.bundle.js
 * frida -U xxx -l .\test.bundle.js
 */

// 导入 hookM.js 导出的模块
// import { hookM, hookStack, hookStack, hookMethod, pass, interdict, LOG } from './hookM.js';
import { hookMethod, pass, interdict,LOG } from './hookM.js';
LOG("--- Custom Script Start ---");


let hooksToApply = [
    // --- Mediatek Camera Hooks ---
    {
        enabled: true,
        target: 'com.mediatek.camera.feature.setting.CameraSwitcher#getCamerasFacing',
        callback: (obj, numOfCameras) => {
            console.log("Original mIdList from instance:", obj.mIdList.value);
            const ArrayList = Java.use('java.util.ArrayList');
            const newList = ArrayList.$new();
            newList.add("back");
            newList.add("front");
            return interdict(newList);
        }
    },
    {
        enabled: true,
        target: 'com.mediatek.camera.CameraActivity#onCreateTasks',
        callback: (obj, savedInstanceState) => {
            obj.onCreateTasks(savedInstanceState)
            const View = Java.use('android.view.View');
            const uiOptions =
                View.SYSTEM_UI_FLAG_IMMERSIVE.value |
                View.SYSTEM_UI_FLAG_HIDE_NAVIGATION.value |
                View.SYSTEM_UI_FLAG_FULLSCREEN.value |
                View.SYSTEM_UI_FLAG_LAYOUT_STABLE.value |
                View.SYSTEM_UI_FLAG_LAYOUT_HIDE_NAVIGATION.value |
                View.SYSTEM_UI_FLAG_LAYOUT_FULLSCREEN.value;

            let window = obj.getActivity().getWindow();
            let view = window.getDecorView();
            console.log(view);
            console.log('uiOptions', uiOptions);
            
            view.setSystemUiVisibility(uiOptions);
            obj.getWindow().getDecorView().setSystemUiVisibility(uiOptions);
            return interdict()
        }
    },
    {
        enabled: false,
        target: 'com.mediatek.camera.common.utils.CameraUtil#isTablet',
        callback: () => interdict(false)
    },

    // --- OpenCamera Hooks ---
    {
        enabled: false,
        target: 'net.sourceforge.opencamera.preview.Preview#openCameraCore',
        callback: (obj, p1) => {
            console.log('using_android_l ', obj.using_android_l.value);
            obj.using_android_l.value = true;
            return pass();
        }
    },

    // --- System Server & Framework Hooks ---
    {
        enabled: false,
        target: 'com.android.server.policy.PhoneWindowManager#interceptKeyBeforeDispatching',
        callback: () => interdict(-1)
    },
    {
        enabled: false,
        target: 'com.android.server.wm.DisplayContent#getOrientation',
        callback: () => interdict(4) // Example: Force an orientation
    },
    {
        enabled: false,
        target: 'com.android.server.wm.DisplayPolicy#requestTransientBars',
        callback: () => interdict()
    },
    {
        enabled: false,
        target: 'com.android.systemui.statusbar.policy.BatteryControllerImpl#fireBatteryLevelChanged',
        callback: (obj) => {
            obj.mLevel.value = 15; // Example: Set battery level
            obj.mPluggedIn.value = false;
            obj.mCharging.value = false;
            return pass();
        }
    },

    // --- Launcher Hooks ---
    {
        enabled: false,
        target: 'com.android.launcher3.model.AddWorkspaceItemsTask#findSpaceForItem',
        callback: () => {
            // Example: Force add item to hotseat
            const intArray = Java.array('int', [-101, 0, 0]);
            return interdict(intArray);
        }
    },

    // --- HLCT Navigation Hooks ---
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
    { enabled: false, target: 'com.hlct.navigation.communication.phone.PhoneServer$openPort$1#onDataReceived' },

    // --- Add other hooks here in the same format ---
    // {
    //     enabled: false,
    //     target: 'some.class.name#someMethod',
    //     callback: (obj, args...) => { /* ... */ },
    //     printStack: true // Optional
    // },
];

/**
 * ===================================================================================
 *                                  HOOK APPLICATION
 * ===================================================================================
 * This section automatically applies all hooks marked as 'enabled: true'.
 * You don't need to modify this part.
 * ===================================================================================
 */
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

// 最后，调用 applyEnabledHooks 来应用所有在配置中被启用的 Hook
// 这会处理上面通过 `hookM` 添加的钩子，以及在 `hooksToApply` 中启用的钩子。
applyEnabledHooks();

LOG("--- Custom Script End ---");
