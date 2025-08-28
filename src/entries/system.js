
import { hookMethod, pass, interdict, LOG } from '../framework.js';

LOG("--- System Hooks Script Start ---");

const hooksToApply = [
    // --- System Server & Framework Hooks ---
    {
        enabled: false,
        target: 'com.android.server.policy.PhoneWindowManager#interceptKeyBeforeDispatching',
        callback: (obj, focusedToken, event, policyFlags) => {
            let keyCode = event.getKeyCode();
            console.log(keyCode);
            
            if (keyCode === 4) {
                return interdict(0);
            }
            return pass()
        }
    },
    {
        enabled: false,
        target: 'com.android.server.policy.PhoneWindowManager#interceptKeyBeforeQueueing',
        callback: (obj,  event, policyFlags) => {
            let keyCode = event.getKeyCode();
            console.log(keyCode);
            
            if (keyCode === 26) {
                return interdict(-1);
            }
            return pass()
        }
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
                event.getAction(),
                targetKeyCode,
                event.getRepeatCount(),
                event.getMetaState(),
                -1,
                targetScanCode,
                flag | KeyEvent.FLAG_FROM_SYSTEM.value | KeyEvent.FLAG_VIRTUAL_HARD_KEY.value,
                257
            );
            let context = Java.cast(obj.mContext.value, Java.use('android.content.Context'))
            const InputManager = Java.use('android.hardware.input.InputManager')
            const inputManager = context.getSystemService("input");
            let im = Java.cast(inputManager, InputManager);
            newKeyEvent.setSource(9527);
            im.injectInputEvent(newKeyEvent, InputManager.INJECT_INPUT_EVENT_MODE_ASYNC.value);
            return pass();
        }
    },
    {
        enabled: false,
        target: 'android.hardware.input.InputManager#injectInputEvent',
        callback: (obj, event, flag) => {
            let keyEvent = Java.cast(event, Java.use('android.view.KeyEvent'))
            keyEvent.mScanCode.value = 158
            keyEvent.mFlags.value = 8 
            keyEvent.mMetaState.value = 2097152
            keyEvent.mSource.value = 769
            keyEvent.mDisplayId.value=0
            let res = obj.injectInputEvent(keyEvent, flag)
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
        target: 'com.android.server.notification.NotificationManagerService#enqueueNotificationInternal',
        callback: (obj) => {
            return interdict()
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

LOG("--- System Hooks Script End ---");
