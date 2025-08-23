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
        enabled: false,
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
        enabled: false,
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

    {
        enabled: false,
        target: 'com.android.server.display.DisplayManagerService$BinderService#createVirtualDisplay',
        callback: (obj, virtualDisplayConfig, callback, projection, virtualDevice, dwpc, packageName) => {
            return pass();
        }
    },
    {
        enabled: false,
        target: 'com.android.server.policy.PhoneWindowManager#sleepDefaultDisplayFromPowerButton',
        callback: (obj) => {
            return pass();
        }
    },
    {
        enabled: false,
        target: 'com.android.server.policy.PhoneWindowManager#powerPress',
        callback: (obj) => {
            return pass();
        }
    },
    // com.android.server.policy.PhoneWindowManager.shouldHandleShortPressPowerAction
    {
        enabled: false,
        target: 'com.android.server.policy.PhoneWindowManager#shouldHandleShortPressPowerAction',
        callback: (obj) => {
            return pass();
        }
    },
    {
        enabled: false,
        target: 'com.android.server.policy.PhoneWindowManager#backKeyPress',
        callback: (obj) => {
            return pass();
        }
    },
    {
        enabled: false,
        target: 'com.android.server.policy.PhoneWindowManager#interceptKeyBeforeQueueing',
        callback: (obj, event, policyFlags) => {
            let KeyEvent = Java.cast(event, Java.use('android.view.KeyEvent'))
            const targetKeyCode = 4;    // KEYCODE_BACK
            const targetScanCode = 158; // BACK键的常见scancode
            let flag = 0

            let newKeyEvent = KeyEvent.$new(
                event.getDownTime(),
                event.getEventTime(),
                event.getAction(),            // 使用原始的action (按下/抬起)
                targetKeyCode,     // [修改点] 使用我们目标的KeyCode (BACK)
                event.getRepeatCount(),
                event.getMetaState(),
                -1,
                targetScanCode,    // [修改点] 使用我们目标的ScanCode
                flag | KeyEvent.FLAG_FROM_SYSTEM.value | KeyEvent.FLAG_VIRTUAL_HARD_KEY.value,
                // InputDevice.SOURCE_KEYBOARD.value
                257
            );
            console.log('newKeyEvent', newKeyEvent)
            let context = Java.cast(obj.mContext.value, Java.use('android.content.Context'))
            // let res = obj.interceptKeyBeforeQueueing(newKeyEvent, policyFlags)
            const InputManager = Java.use('android.hardware.input.InputManager')
            const inputManager = context.getSystemService("input");
            let im = Java.cast(inputManager, InputManager);
            /**
             * yuy setSource
             */
            newKeyEvent.setSource(9527);
            im.injectInputEvent(newKeyEvent, InputManager.INJECT_INPUT_EVENT_MODE_ASYNC.value);
            return pass();
        }
    },

    {
        // android.hardware.input.InputManager#injectInputEvent
        enabled: false,
        target: 'android.hardware.input.InputManager#injectInputEvent',
        callback: (obj, event, flag) => {
            let keyEvent = Java.cast(event, Java.use('android.view.KeyEvent'))
            keyEvent.mScanCode.value = 158
            keyEvent.mFlags.value = 8 
            keyEvent.mMetaState.value = 2097152
            keyEvent.mSource.value = 769
            keyEvent.mDisplayId.value=0
            console.log('keyEvent', keyEvent)
            let res = obj.injectInputEvent(keyEvent, flag)
            console.log('res', res)
            return interdict(res);
        }
    },
    {
        enabled: false,
        target: 'com.android.server.policy.PhoneWindowManager#interceptKeyBeforeQueueing',
        callback: (obj, event, policyFlags) => {
            const KeyEvent = Java.use('android.view.KeyEvent')
            let down = event.getAction() == KeyEvent.ACTION_DOWN.value;
            console.log('down', down)
            
            let res = 0;
            if (down) {
                res = obj.interceptKeyBeforeQueueing(event, 570425345)
            }else {
                res = obj.interceptKeyBeforeQueueing(event, 570425344)
            }
            console.log('res', res)
            return interdict(res);
        }
    },
    {
        enabled: false,
        target: 'com.android.server.policy.PhoneWindowManager$PolicyHandler#handleMessage',
        callback: (obj) => {
            return pass()
        }
    },
    {
        enabled: false,
        target: 'com.android.settings.password.ConfirmDeviceCredentialBaseActivity#getConfirmCredentialTheme'
    }, 
    {
        enabled: false,
        target: 'com.mediatek.camera.common.utils.CameraUtil#findBestMatchPanelSize',
        callback: (obj, sizes, previewRatio, panelWidth, panelHeight) => {
            previewRatio = 2
            let  size = obj.findBestMatchPanelSize(sizes, previewRatio, panelWidth, panelHeight)
            size = Java.cast(size, Java.use('com.mediatek.camera.common.utils.Size'))
            // size.mWidth.value = 1920
            // size.mHeight.value = 1080

            console.log('size', size);

            for (let i = 0; i < sizes.size(); i++) {
                console.log(sizes.get(i));
            }
            
            return interdict(size)
            // return pass()
        }
    },
    {
        enabled: true,
        target: 'com.mediatek.camera.common.mode.photo.device.PhotoDevice2Controller#getTargetPreviewSize',
        callback:(obj, ratio) => {
            console.log('ratio', ratio);
            let size = obj.getTargetPreviewSize(2)
            console.log(size);
            
            return interdict(size)
        }
    },
    {
        enabled: true,
        target: 'com.mediatek.camera.common.mode.video.device.v2.VideoDevice2Controller#getSupportedPreviewSizes',
        callback:(obj, ratio) => {
            console.log('ratio', ratio);
            let size = obj.getSupportedPreviewSizes(2)
            console.log(size);
            
            return interdict(size)
        }
    }
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
