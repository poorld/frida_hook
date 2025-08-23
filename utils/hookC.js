const Color = {
    RESET: "\x1b[39;49;00m",
    Black: "0;01", Blue: "4;01", Cyan: "6;01", Gray: "7;11",
    Green: "2;01", Purple: "5;01", Red: "1;01", Yellow: "3;01",
    Light: {
        Black: "0;11", Blue: "4;11", Cyan: "6;11", Gray: "7;01",
        Green: "2;11", Purple: "5;11", Red: "1;11", Yellow: "3;11"
    }
};

function LOG(input, { level = 'log', color = Color.Yellow, indent = false } = {}) {
    let formattedInput = typeof input === 'object' ? JSON.stringify(input, null, indent ? 2 : null) : input;
    formattedInput = `\x1b[3${color}m${formattedInput}${Color.RESET}`;
    console[level](formattedInput);
}

function traceMethod(targetClassMethod, isPrintStack = false) {
    const delim = targetClassMethod.lastIndexOf('.');
    if (delim === -1) return;

    const targetClass = targetClassMethod.slice(0, delim);
    const targetMethod = targetClassMethod.slice(delim + 1);

    // 可选：跳过 Lambda 方法
    if (targetMethod.includes("lambda")) {
        console.log(`Skipping Lambda method: ${targetClassMethod}`);
        return;
    }

    // access$
    if (targetMethod.includes("access$")) {
        console.log(`Skipping access$ method: ${targetClassMethod}`);
        return;
    }

    const previewMethods = new Set([

    ]);

    if (previewMethods.has(targetMethod)) {
        console.log(`Skipping preview method: ${targetClassMethod}`);
        return;
    }


    let hook;
    try {
        hook = Java.use(targetClass);
    } catch (e) {
        LOG(`Failed to load class ${targetClass}: ${e}`, { level: 'error', color: Color.Red });
        return;
    }

    if (!hook[targetMethod]) {
        LOG(`Method ${targetMethod} not found in ${targetClass}`, { color: Color.Gray });
        return;
    }

    const method = hook[targetMethod];
    if (!method.overloads || !Array.isArray(method.overloads)) {
        LOG(`No valid overloads for ${targetClassMethod}`, { color: Color.Gray });
        return;
    }

    const overloadCount = method.overloads.length;
    LOG(`Hooked ${targetClassMethod} with ${overloadCount} overload(s)`, { color: Color.Green });

    method.overloads.forEach((overload, index) => {
        overload.implementation = function (...args) {
            if (isPrintStack) {
                const stack = Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new());
                LOG(stack, { color: Color.Cyan });
            }

            const log = {
                method: `${targetClassMethod} [overload ${index}]`,
                args: args.map((arg, i) => ({
                    index: i,
                    value: arg,
                    string: arg ? String(arg) : 'null'
                })),
            };

            let retval;
            try {
                retval = overload.apply(this, args);
                log.returns = { value: retval, string: retval ? String(retval) : 'null' };
            } catch (e) {
                LOG(`Error in ${targetClassMethod}: ${e}`, { level: 'error', color: Color.Red });
            }

            LOG(log, { color: Color.Yellow, indent: true });
            return retval;
        };
    });
}


function uniqBy(array) {
    const seen = new Set();
    return array.filter(item => !seen.has(item) && seen.add(item));
}

function traceClass(targetClass, printStack = false) {
    Java.perform(() => {
        let hook;
        try {
            hook = Java.use(targetClass);
        } catch (e) {
            LOG(`Failed to load class ${targetClass}: ${e}`, { level: 'error', color: Color.Red });
            return;
        }

        let methods;
        try {
            methods = hook.class.getDeclaredMethods();
        } catch (e) {
            LOG(`Failed to get methods for ${targetClass}: ${e}`, { level: 'error', color: Color.Red });
            return;
        }

        const parsedMethods = methods.map(method => 
            method.toString().replace(targetClass + ".", "TOKEN").match(/\sTOKEN(.*)\(/)[1]
        );
        
        const uniqueMethods = uniqBy(parsedMethods);
        LOG(`Tracing ${targetClass} with ${uniqueMethods.length} unique methods`, { color: Color.Green });
        console.log("Methods: " + uniqueMethods.join(", "));
        uniqueMethods.forEach((method,index) => {
            traceMethod(`${targetClass}.${method}`, printStack);
        });

        // 释放 hook 对象
        hook.$dispose();
    });
}


// traceClass('com.android.settings.SettingsPreferenceFragment')
// setImmediate(traceClass('androidx.fragment.app.DialogFragment'))
// setImmediate(traceClass('com.android.settingslib.CustomDialogPreferenceCompat'))
// setImmediate(traceClass('com.android.settingslib.CustomDialogPreferenceCompat$CustomPreferenceDialogFragment'))
// setImmediate(traceClass('androidx.preference.PreferenceFragmentCompat'))
// setImmediate(traceClass('com.android.server.power.PowerManagerService'))
// setImmediate(traceClass('com.android.settings.wifi.WifiSettings'))
// setImmediate(traceClass('com.android.settingslib.display.BrightnessUtils'))
// setImmediate(traceClass('com.android.server.power.PowerManagerService'))
// setImmediate(traceClass('com.android.smartrecord.face.FaceDetectActivity', false))
// setImmediate(traceClass('com.mediatek.camera.feature.setting.picturesize.PictureSizeSettingView', true))
// setImmediate(traceClass('com.android.server.pm.PackageManagerService'))
// setImmediate(traceClass('android.os.UpdateEngine'))

// setImmediate(traceClass('com.android.server.StorageManagerService'))
// setImmediate(traceClass('com.android.settings.deviceinfo.StorageWizardFormatProgress$PartitionTask'))
// setImmediate(traceClass('com.android.settings.deviceinfo.StorageWizardFormatProgress'))
// setImmediate(traceClass('com.smarteye.common.WifiUtils'))
// setImmediate(traceClass('com.android.keyguard.KeyguardPinBasedInputView'))


// setImmediate(traceClass('com.android.server.wm.WindowState'))
// setImmediate(traceClass('com.android.server.wm.DisplayPolicy'))
// setImmediate(traceClass('com.android.server.display.DisplayManagerService'))
setImmediate(traceClass('com.android.server.display.DisplayManagerService$BinderService'))


// setImmediate(traceClass('android.hardware.camera2.CameraManager$CameraManagerGlobal'))
// setImmediate(traceClass('com.android.server.biometrics.sensors.fingerprint.FingerprintService$FingerprintServiceWrapper'))
// setImmediate(traceClass('com.android.server.StorageManagerService#onDiskScannedLocked'))
// setImmediate(traceClass('com.android.internal.app.LocaleStore'))  
// setImmediate(traceClass('com.android.camera.VideoModule'))
// setImmediate(traceClass('com.android.server.wm.WindowManagerService'))  
// setImmediate(traceClass('com.android.server.wm.DisplayPolicy'))

// setImmediate(traceClass('net.sourceforge.opencamera.preview.Preview'))

// setImmediate(traceClass('net.sourceforge.opencamera.cameracontroller.CameraController1'))

// setImmediate(traceClass('com.hlct.navigation.utlis.L$Companion'))
// setImmediate(traceClass('com.hlct.navigation.ui.model.MainViewModel'))
// setImmediate(traceClass('com.hlct.navigation.communication.phone.PhoneServer'))
// setImmediate(traceClass('com.android.launcher3.LauncherModel'))
// setImmediate(traceClass('com.android.permissioncontroller.permission.model.AppPermissions'))
// setImmediate(traceClass('com.android.server.policy.PhoneWindowManager'))
