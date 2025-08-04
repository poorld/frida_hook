/**
 * Frida Hooking Framework
 *
 * A set of helper functions to simplify hooking Java methods on Android with Frida.
 *
 * @version 2.0
 * @author YourName
 * 
 * frida -U -f net.sourceforge.opencamera -l .\hookM.js
 * frida -f -U "Open Camera" -l .\hookM.js
 */

// 日志工具和常量
const Log = Java.use("android.util.Log");
const TAG = "[FRIDA_SCRIPT]";

const TYPE = {
    INTERDICT: 0, // 拦截并返回指定值
    PASS: 1       // 放行并调用原方法
};

// 返回值构造器
const createResult = (type, obj = null) => ({ return_type: type, return_obj: obj });
const pass = () => createResult(TYPE.PASS);
const interdict = (obj) => createResult(TYPE.INTERDICT, obj);

/**
 * 统一的日志函数
 * @param {string} message - 要记录的消息
 * @param {object} [options] - 配置项
 * @param {string} [options.tag=TAG] - Logcat 标签
 * @param {'log'|'warn'|'error'} [options.level='log'] - 日志级别
 * @param {string} [options.subTag=''] - 日志子标签，会加在消息前面
 */
function LOG(message, { tag = TAG, level = 'log', subTag = '' } = {}) {
    const fullMessage = subTag ? `${subTag}: ${message}` : message;
    console[level](fullMessage);
    const logcatLevel = level === 'error' ? 'e' : 'v';
    Log[logcatLevel](tag, fullMessage);
}

/**
 * 打印调用栈
 * @param {string} [message='StackTrace'] - 打印调用栈时附带的消息
 */
function printStackTrace(message = 'StackTrace') {
    const stack = Log.getStackTraceString(Java.use("java.lang.Throwable").$new());
    LOG(`${message}:\n${stack}`, { level: 'log' });
}

/**
 * 通用 Hook 函数 (核心)
 * @param {string} classAndMethod - 要 Hook 的类和方法，格式为 "com.example.MyClass#myMethod"
 * @param {(thisArg: object, ...args: any[]) => object|void} [callback=null] - 回调函数，处理参数和返回值。如果返回 interdict(value)，则拦截方法调用。
 * @param {boolean} [printStack=false] - 是否打印调用栈
 */
function hookMethod(classAndMethod, callback = null, printStack = false) {
    if (!classAndMethod.includes('#')) {
        LOG(`Invalid format for hookMethod: "${classAndMethod}". Expected "className#methodName".`, { level: 'error' });
        return;
    }

    const [className, methodName] = classAndMethod.split('#');

    Java.perform(() => {
        let clazz;
        try {
            clazz = Java.use(className);
        } catch (e) {
            LOG(`Failed to load class "${className}": ${e}`, { level: 'error' });
            return;
        }

        if (!clazz[methodName] || !clazz[methodName].overloads) {
            LOG(`Method "${methodName}" not found or has no overloads in class "${className}".`, { level: 'warn' });
            // 可以在这里打印所有可用方法以供调试
            // LOG(`Available methods: ${Object.keys(clazz).join(', ')}`);
            return;
        }

        LOG(`Hooking [${classAndMethod}] with ${clazz[methodName].overloads.length} overloads.`);

        clazz[methodName].overloads.forEach((overload, i) => {
            overload.implementation = function (...args) {
                if (printStack) {
                    printStackTrace(`Call to ${classAndMethod}`);
                }

                const logInfo = {
                    hookInfo: `${classAndMethod} [overload ${i}]`,
                    args: args.map(arg => arg?.toString() ?? 'null'),
                    return: 'N/A'
                };

                let resultFromCallback;
                if (callback) {
                    try {
                        resultFromCallback = callback(this, ...args);
                    } catch (e) {
                        LOG(`Error in callback for ${classAndMethod}: ${e.stack}`, { level: 'error' });
                        // Callback 出错，继续执行原方法
                    }
                }

                let retval;
                if (resultFromCallback && resultFromCallback.return_type === TYPE.INTERDICT) {
                    // 拦截调用
                    retval = resultFromCallback.return_obj;
                    logInfo.return = `[INTERDICTED] ${retval?.toString() ?? 'null'}`;
                } else {
                    // 放行，调用原方法
                    try {
                        retval = overload.apply(this, args);
                        logInfo.return = retval?.toString() ?? 'null';
                    } catch (e) {
                        LOG(`Error calling original method ${classAndMethod}: ${e.stack}`, { level: 'error' });
                        throw e; // 将原始异常抛出，避免应用行为异常
                    }
                }

                LOG(JSON.stringify(logInfo, null, 2));
                
                // 【关键修复】无论 retval 是什么值（包括 null），都必须返回，以匹配原始方法的返回类型
                return retval;
            };
        });
    });
}


// --- 简化版别名函数 ---

/** 简单 Hook，可带回调 */
const hookM = (classAndMethod, callback) => hookMethod(classAndMethod, callback, false);

/** Hook 并打印调用栈 */
const hookStack = (classAndMethod, callback) => hookMethod(classAndMethod, callback, true);

/** 仅追踪方法调用（不带回调）*/
const trace = (classAndMethod) => hookMethod(classAndMethod, null, false);

/** 追踪方法调用并打印调用栈 */
const traceStack = (classAndMethod) => hookMethod(classAndMethod, null, true);

 
/**
 * ===================================================================================
 *                                  HOOK CONFIGURATION
 * ===================================================================================
 * 所有的 Hook 都集中在这里管理。
 * 只需要修改 'enabled' 属性为 true 或 false 即可启用或禁用对应的 Hook。
 * ===================================================================================
 */
const hooksToApply = [
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
    Java.perform(() => {
        LOG("Scanning for enabled hooks...", { subTag: "HookManager" });
        hooksToApply.forEach(hookInfo => {
            if (hookInfo.enabled) {
                const { target, callback, printStack } = hookInfo;
                LOG(`Applying hook to: ${target}`, { subTag: "HookManager" });
                hookMethod(target, callback || null, printStack || false);
            }
        });
        LOG("All enabled hooks have been applied.", { subTag: "HookManager" });
    });
}

// Automatically apply all enabled hooks when the script is loaded.
applyEnabledHooks();
