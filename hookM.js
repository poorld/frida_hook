/**
 * Frida Hooking Framework
 *
 * A set of helper functions to simplify hooking Java methods on Android with Frida.
 *
 * @version 2.0
 * @author YourName
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


// 示例使用
// hookM("com.android.settingslib.SomeClass#someMethod", null, true);
// traceClass("com.android.settingslib.SomeClass");

// 导出函数
// module.exports = {
//     hookM: (claAndMethod, callback, printStack = false) => hookMethod(claAndMethod, callback, printStack),
//     hookM_stack: (claAndMethod, callback) => hookMethod(claAndMethod, callback, true),
//     hookM_overload: (claAndMethod, callback) => hookMethod(claAndMethod, callback, false),
//     pass,
//     interdict,
//     LOG,
//     printStackTrace
// };

// hookM('com.android.settings.widget.ValidatedEditTextPreference#onBindViewHolder', (obj, preference) => {
//     console.log('obj', obj)
//     const dialog = obj.getDialog()
//     console.log('dialog', dialog)
// })

// hookM('com.android.settings.SettingsPreferenceFragment#onDisplayPreferenceDialog',(_this, preference) => {
//     var SettingsPreferenceFragment = Java.use("com.android.settings.SettingsPreferenceFragment");
//     var CustomEditTextPreferenceCompat = Java.use("com.android.settingslib.CustomEditTextPreferenceCompat");
//     var CustomPreferenceDialogFragment = Java.use("com.android.settingslib.CustomEditTextPreferenceCompat$CustomPreferenceDialogFragment");
//     var DialogFragment = Java.use("androidx.fragment.app.DialogFragment");
//     var View = Java.use("android.view.View");
//     var Window = Java.use("android.view.Window");

//     var dialogFragment = CustomPreferenceDialogFragment.newInstance(preference.getKey());
//     dialogFragment.setTargetFragment(_this, 0);
//     // dialog.setContentView(View.$new(_this.getActivity()))
//     var fragmentManager = _this.getFragmentManager();
//     dialogFragment.show(fragmentManager, "dialog_preference");
//     _this.onDialogShowing();
//     setTimeout(() => {
//         var dialog = dialogFragment.getDialog();
//         console.log('dialog', dialog);
//         console.log('getContext', _this.getActivity());
//         const title = Java.use('java.lang.String').$new("222222")
//         dialog.setTitle(title); // 在 UI 线程执行
//         // Java.scheduleOnMainThread(function() {
//         //     dialog.setTitle(title); // 在 UI 线程执行
//         //     // dialog.requestWindowFeature(Window.FEATURE_NO_TITLE);
//         //     // dialog.setCustomTitle(View.$new(_this.getContext()))
//         // });
//     }, 50);
//     return interdict()
// })

// hookM('androidx.fragment.app.DialogFragment#onStart', (_this) => {
//     console.log(_this.mDialog);

//     if (_this.mDialog != null) {
//         const title = Java.use('java.lang.String').$new("")
//         let dialog = Java.cast(_this.mDialog.value, Java.use('androidx.appcompat.app.AlertDialog'))
//         dialog.setTitle(title);
//     }
//     _this.onStart()
    
//     return interdict()
// }, true)

// hookM('com.android.server.wifi.WifiServiceImpl#getFactoryMacAddresses', (obj) => {

//     return pass()
// })

// hookM('com.android.inputmethod.latin.LatinIME#onConfigurationChanged', (obj, conf) => {
//     obj.onConfigurationChanged(conf)
//     let view = obj.onCreateInputView()
//     console.log('view--------', view);
    
//     obj.setInputView(view);
//     return interdict()
// })


// hookM('com.android.settings.SettingsPreferenceFragment#onCreateView', (obj,a,b,c) => {
//     const root = obj.onCreateView(a,b,c)
//     const appBar = obj.mAppBarLayout.value;
//     let bar = Java.cast(appBar, Java.use('com.google.android.material.appbar.AppBarLayout'))
//     console.log(bar);
//     // bar.setVisibility(8)
//     return interdict(root)
// })

// hookM('com.android.settings.SettingsPreferenceFragment#onCreateAdapter', (obj, preferenceScreen) => {
//     let title = preferenceScreen.getTitle();
//     if (title == "WLAN" || title == "蓝牙") {
//         let appBar = obj.mAppBarLayout.value;
//         let bar = Java.cast(appBar, Java.use('com.google.android.material.appbar.AppBarLayout'))
//         bar.setVisibility(8)
//     }
//     console.log(title);
    
//     return pass()
// })

// hookM('com.android.settings.applications.manageapplications.ManageApplications#onMenuItemActionCollapse')

// hookM('com.android.server.audio.AudioService#muteRingerModeStreams')


// hookM('com.mediatek.camera.common.utils.CameraUtil#getOptimalPreviewSize')
// hookM('com.mediatek.camera.common.utils.CameraUtil#findBestMatchPanelSize', (obj, sizes, previewRatio, panelWidth, panelHeight) => {
//     // previewRatio = 1.5
//     // let  size = obj.findBestMatchPanelSize(sizes, previewRatio, panelWidth, panelHeight)
//     // size = Java.cast(size, Java.use('com.mediatek.camera.common.utils.Size'))
//     // // size.mWidth.value = 320
//     // // size.mHeight.value = 240

//     // console.log('size', size);

//     // for (let i = 0; i < sizes.size(); i++) {
//     //     console.log(sizes.get(i));
//     // }
    
//     // return interdict(size)
// })

// let start = false
// hookM('com.android.smartrecord.face.FaceDetectActivity#startCamera', (obj) => {
//     if (!start) {
//         start = true
//         console.error('startCamera');
        
//         return pass()
//     }
//     console.error('interdict');
//     return interdict()
// })

// setImmediate(traceClass('com.android.smartrecord.media.CameraHelper'))

// hookM('com.baidu.ota.impl.ApplicationImpl$MyUpgradeImpl#installSystem', (obj,a,b,c) => {
//     obj.recovery.value = false
//     let res = obj.installSystem(a,b,c)
//     return interdict(res)
// })

// hookM('com.baidu.ota.utils.MetaData#isABUpgrade', obj => {
//     return interdict(true)
// })

// hookM('android.os.UpdateEngine#cancel', obj => {
//     return interdict()
// })
// hookM('com.android.launcher3.model.AddWorkspaceItemsTask#findSpaceForItem', 
//     (obj, app, dataModel, workspaceScreens,addedWorkspaceScreensFinal, spanX, spanY) => {
//         let arr = obj.findSpaceForItem(app, dataModel, workspaceScreens,addedWorkspaceScreensFinal, spanX, spanY)
//         console.log(arr);
//         arr[0] = 0;
//         arr[1] = 2;
//         arr[2] = 2;
        
//         return interdict(arr)
        
//     })

// hookM('com.android.server.display.DisplayPowerState#setScreenBrightness')

// hookM('com.mediatek.camera.feature.setting.picturesize.PictureSizeCaptureRequestConfig#getSupportedPictureSize', (obj, s, format) => {
//     let res = obj.getSupportedPictureSize(s, format)
//     let list = Java.cast(res, Java.use('java.util.List'))
//     for (let index = 0; index < list.size(); index++) {
//         const element = list.get(index)
//         const size = Java.cast(element, Java.use('android.util.Size'))
//         console.log(size.getHeight() + 'x' + size.getWidth());
//     }
//     return interdict(res)
// })

// hookM('com.mediatek.camera.feature.setting.picturesize.PictureSize#onValueInitialized', (obj, sizes) => {
//     console.log('mModeKey', obj.mModeKey.value);
//     obj.mModeKey.value = 'com.mediatek.camera.feature.mode.hdr.HdrMode'

// })

// hookM('com.mediatek.camera.feature.setting.picturesize.PictureSizeHelper#filterSizes', (obj, sizes) => {
//     let res = obj.filterSizes(sizes)
//     let list = Java.cast(res, Java.use('java.util.List'))
//     list.add(0, '2560x1440')
//     return interdict(list)
// })

// hookM('com.mediatek.camera.feature.setting.picturesize.PictureSizeSettingView#setEntryValues', (obj, sizes) => {
//     let list = Java.cast(sizes, Java.use('java.util.List'))
//     for (let index = 0; index < list.size(); index++) {
//         const element = list.get(index);
//         console.log(element);
        
//     }
// })


// hookM('com.mediatek.camera.feature.setting.picturesize.PictureSizeSelector#setEntryValues', (obj, sizes) => {
//     let list = Java.cast(sizes, Java.use('java.util.List'))
//     for (let index = 0; index < list.size(); index++) {
//         const element = list.get(index);
//         console.log(element);
        
//     }
// })

// hookM('com.mediatek.camera.feature.setting.picturesize.PictureSizeHelper#getPixelsAndRatio', (obj, value) => {
//     let res = obj.getPixelsAndRatio(value)
//     console.log('val=' + value + ',res=' + res);
//     if (res == null) {
//         res ='5M(16:9)'
//     }
//     return interdict(res)
// })

/**
hookM('android.hardware.camera2.impl.CameraDeviceImpl#createCaptureSession', (obj, outputs, callbacks, handler) => {

    // 获取 CamcorderProfile 类
    var CamcorderProfile = Java.use("android.media.CamcorderProfile");
    var MediaRecorder = Java.use("android.media.MediaRecorder");
    var MediaCodec = Java.use("android.media.MediaCodec");

    // 定义常量
    var QUALITY_720P = CamcorderProfile.QUALITY_720P.value;
    var QUALITY_1080P = CamcorderProfile.QUALITY_1080P.value;
    // var AudioSource_CAMCORDER = MediaRecorder.AudioSource.CAMCORDER.value;
    // var VideoSource_SURFACE = MediaRecorder.VideoSource.SURFACE.value;

    // 假设 width 和 height 是外部传入的变量，这里需要动态获取或硬编码
    var width = 1280;  // 示例值，可根据需要修改
    var height = 720;  // 示例值，可根据需要修改

    // 获取 CamcorderProfile 实例
    var profile = CamcorderProfile.get(0, width * height <= 1280 * 720 ? QUALITY_720P : QUALITY_1080P);
    
    // 修改 profile 的属性
    profile.videoFrameRate.value = 30;
    profile.videoFrameWidth.value = width;
    profile.videoFrameHeight.value = height;

    // 创建 MediaRecorder 实例
    var mMediaRecorder = MediaRecorder.$new();

    // 创建持久化输入 Surface
    var mMediaSurface = MediaCodec.createPersistentInputSurface();

    // 设置 MediaRecorder 的属性
    mMediaRecorder.setInputSurface(mMediaSurface);
    mMediaRecorder.setAudioSource(5);
    mMediaRecorder.setVideoSource(2);
    mMediaRecorder.setProfile(profile);
    mMediaRecorder.setOutputFile("/data/data/com.yulong.testlunch/files/temp.mp4");
    mMediaRecorder.prepare();
    // 输出调试信息
    console.log("CamcorderProfile configured: " + 
        "width=" + profile.videoFrameWidth.value + 
        ", height=" + profile.videoFrameHeight.value + 
        ", frameRate=" + profile.videoFrameRate.value);
    console.log("MediaRecorder initialized with surface: " + mMediaSurface);
    outputs.add(mMediaSurface)
    console.log(outputs.size());

    
    obj.createCaptureSession(outputs, callbacks, handler)

    return interdict()
})
 */

// hookM('com.android.systemui.statusbar.CommandQueue#disable', obj => {
//     const StatusBarManager = Java.use('android.app.StatusBarManager')
//     let flag = StatusBarManager.DISABLE_HOME.value
//                 | StatusBarManager.DISABLE_RECENT.value
//                 | StatusBarManager.DISABLE_BACK.value;
//     obj.disable(0, 0, 0, false)
//     console.log('flag', StatusBarManager.DISABLE_HOME);
    
//     return interdict()
// })

// hookM('com.android.server.policy.PhoneWindowManager#sendSystemKeyToStatusBarAsync', obj => {
//     obj.mHandleVolumeKeysInWM.value = true
//     return interdict()
// })


// hookM('com.android.server.policy.PhoneWindowManager#getStatusBarService', obj => {
//     return interdict(null)
// })

// hookM('com.android.server.policy.PhoneWindowManager#interceptKeyBeforeQueueing')
// hookM('com.android.server.policy.PhoneWindowManager#keyBroadcastHuoErVideoCancel', null, true)
// hookM('com.android.server.pm.PackageManagerService#preparePackageLI')
// hookM('com.android.server.DeviceManagerService#setFlash', (obj,color, onMs, offMs) => {
//     // console.log('onMs', onMs);
//     // console.log('offMs', offMs);
//     obj.setFlash(color, 0, 0)
//     return interdict()
// })


// hookM('com.android.server.StorageManagerService#partitionPublic')
// hookM('com.android.server.StorageManagerService#partitionPrivate')
// hookM('com.android.server.yuy.CustomerManagerService#sdFormat')

// hookM('com.android.systemui.statusbar.policy.BatteryControllerImpl#fireBatteryLevelChanged', obj => {
//     obj.mLevel.value = 0
//     obj.mPluggedIn.value = false
//     obj.mCharging.value = false
//     return pass()
// })

// hookM('com.android.systemui.qs.tiles.BatterySaverTile#onBatteryLevelChanged')

// hookM('com.android.server.BatteryService#sendBatteryChangedIntentLocked', (obj) => {
//     let BatteryManager = Java.use('android.os.BatteryManager')
//     // intent.putExtra(BatteryManager.EXTRA_LEVEL, 0);
//     // intent.putExtra(BatteryManager.EXTRA_BATTERY_LOW, true);
//     // let mHealthInfo = Java.cast(obj.mHealthInfo, Java.use('android.hardware.health.HealthInfo'))
//     // console.log('obj.mHealthInfo', obj.mHealthInfo);
    
//     // console.log('mHealthInfo.batteryStatus', mHealthInfo.batteryStatus);
//     // console.log('mHealthInfo.batteryPresent', mHealthInfo.batteryPresent);
//     // console.log('mHealthInfo', obj.mHealthInfo.value);
//     // console.log('mSentLowBatteryBroadcast', obj.mSentLowBatteryBroadcast.value);
//     // obj.mHealthInfo.batteryLevel = 2
//     // console.log('obj.mHealthInfo.batteryLevel', obj.mHealthInfo.batteryLevel);
    

//     console.log('mHealthInfo', obj.mHealthInfo.value);
// })


// hookM('com.android.systemui.statusbar.phone.StatusBar#disable', (obj, displayId, state1, state2, animate) => {
//     console.log('displayId', displayId);
//     console.log('state1', state1);
//     console.log('state2', state2);
//     console.log('animate', animate);

//     let StatusBarManager = Java.use('android.app.StatusBarManager')
//     state1 = StatusBarManager.DISABLE_BACK.value
//     state2 = StatusBarManager.DISABLE_BACK.value
    
//     state1 = state1 | StatusBarManager.DISABLE_HOME.value
//     obj.mDisabled1.value = state1
//     console.log('state1', state1);
//     console.log('state2', state2);
//     obj.disable(displayId, state1, state2, animate)
//     return interdict()
// })

// hookM('com.android.systemui.navigationbar.NavigationBar#updateBarMode', obj => {
//     return interdict(false)
// }, false)


// hookM('com.android.server.am.ActivityManagerService#broadcastIntentWithFeature', (callingFeatureId,
//     intent, resolvedType, resultTo,
//     resultCode, resultData, resultExtras,
//     requiredPermissions, excludedPermissions, appOp, bOptions,
//     serialized, sticky, userId) => {
//     let action = intent.getAction()
//     if ("android.intent.action.BATTERY_CHANGED" == action) {
//         console.error(action);
//         //     let BatteryManager = Java.use('android.os.BatteryManager')
//         // intent.putExtra(BatteryManager.EXTRA_LEVEL, 0);
//     }
//     let res = obj.broadcastIntentWithFeature(callingFeatureId,
//         intent, resolvedType, resultTo,
//         resultCode, resultData, resultExtras,
//         requiredPermissions, excludedPermissions, appOp, bOptions,
//         serialized, sticky, userId)
//     return interdict(res)
// })


// hookM('com.android.server.locksettings.LockSettingsService#setLockCredentialInternal')
// hookM('com.android.server.locksettings.LockSettingsService#spBasedSetLockCredentialInternalLocked')

// hookM('android.view.InsetsController#onStateChanged', obj => {
//     return interdict()
// }, true)

// hookM('com.android.server.wm.DisplayPolicy#requestTransientBars', obj => {
//     return interdict()
// })

// hookM('com.android.server.wm.DisplayPolicy$DisplayPolicy#onSwipeFromTop')
// hookM('com.android.server.wm.DisplayPolicy#requestTransientBars', (obj, windowState) => {

//     let dlp = Java.cast(obj, Java.use('com.android.server.wm.DisplayPolicy'))
//     console.log('mFocusedWindow', dlp.mFocusedWindow)
//     console.log(dlp);
    
//     let mFocusedWindow = Java.cast(dlp.mFocusedWindow.value, Java.use('com.android.server.wm.WindowState'))
//     // console.log(mFocusedWindow.getPackageName())
//     console.log('mFocusedWindow', mFocusedWindow);
//     console.log(mFocusedWindow.getOwningPackage());
    
//     // Java.cast(obj.mFocusedWindow.mAttrs, Java.use('android.view.WindowManager.LayoutParams'))
// }, true)

// hookM('com.android.server.wm.DisplayPolicy#isCustomKeyguard')
// hookM('com.android.server.wm.DisplayPolicy#updateSystemUiVisibilityLw', obj => {
//     return interdict(false)
// })


// updateSystemBarsLw(,0) return opaqueAppearance=0
// getStatusBarAppearance() return fullscreenAppearance=8

// com.android.server.display.VirtualDisplayAdapter$VirtualDisplayDevice
// hookM('com.android.server.display.VirtualDisplayAdapter#createVirtualDisplayLocked', (obj,callback,
//     projection, ownerUid, ownerPackageName, surface,
//     flags, virtualDisplayConfig) => {
//     console.log(virtualDisplayConfig);
//     return pass()
// })

// hookM('com.android.server.statusbar.StatusBarManagerService$2')


// hookM('com.android.server.wm.DisplayContent#getOrientation', (obj) => {
//     return interdict(4)
// }, false)

// hookM('com.android.server.wm.DisplayContent#getDisplayRotation', (obj) => {
//     return interdict(3)
// }, false)
// hookM('android.view.OrientationEventListener$SensorEventListenerImpl#onSensorChanged')
// hookM('com.android.server.wm.DisplayRotation#rotationForOrientation', (obj, orientation, lastRotation) => {
//     // return interdict(0)
//     // let ro = obj.rotationForOrientation(orientation, lastRotation)
//     console.log('orientation=' + orientation);
    
//     // if (ro == 3) {
//     //     return interdict(0)
//     // }
//     // if (ro == 1) {
//     //     return interdict(0)
//     // }
//     // return interdict(ro)
//     orientation = (orientation + 2) % 4; 
//     console.log('new orientation=' + orientation);
//     return interdict(orientation)
// })


// hookM('com.android.server.wm.DisplayRotation#updateRotationUnchecked', (obj) => {

// })

// hookM('com.android.server.wm.ActivityStarter#startActivityUnchecked', (obj, r, sourceRecord, voiceSession, 
//         voiceInteractor, startFlags, doResume , checkedOptions, inTask,
//                 restrictedBgActivity, intentGrants) => {
    
//         var ActivityStarter = Java.use("com.android.server.wm.ActivityStarter");
//         var ActivityRecord = Java.use("com.android.server.wm.ActivityRecord");
//         var ActivityInfo = Java.use("android.content.pm.ActivityInfo");
//         var ApplicationInfo = Java.use("android.content.pm.ApplicationInfo");

//         // Cast r to ActivityRecord
//         var activityRecord = Java.cast(r, ActivityRecord);
//         console.log('activityRecord', activityRecord);
        

//         // Cast r.info to ActivityInfo
//         var activityInfo = Java.cast(activityRecord.info.value, ActivityInfo);
//         console.log('activityInfo', activityInfo);

//         // Cast applicationInfo to ApplicationInfo
//         var appInfo = Java.cast(activityInfo.applicationInfo.value, ApplicationInfo);
//         console.log('appInfo', appInfo);

//         // Check package name and activity name
//         if (appInfo.packageName.value == "com.android.factorymode" &&
//             activityInfo.name.value == "com.android.factorymode.FTM_Camera") {
            
//             // Set screen orientation to SENSOR
//             activityInfo.screenOrientation.value = ActivityInfo.SCREEN_ORIENTATION_SENSOR.value;
//             console.log('SCREEN_ORIENTATION_SENSOR');
//             console.log('activityInfo.screenOrientation.value', activityInfo.screenOrientation.value);
            
//         }
//     let res = obj.startActivityUnchecked(r, sourceRecord, voiceSession, voiceInteractor, startFlags, doResume, checkedOptions, inTask, restrictedBgActivity, intentGrants)
//     console.log('res=' + res);
    
//     return interdict(res)
// })

// hookM('android.app.ActivityThread#handleLaunchActivity', (obj, r,pendingActions, customIntent) => {
//     console.log('handleLaunchActivity');
    
//     const ActivityThread = Java.use("android.app.ActivityThread");
//     const Activity = Java.use("android.app.Activity");
//     var ActivityInfo = Java.use("android.content.pm.ActivityInfo");

//     let result = obj.handleLaunchActivity(r, pendingActions, customIntent)
//     const activity = Java.cast(result, Activity);
//     const packageName = activity.getPackageName();
//     const className = activity.getClass().getName();

//     if (packageName === "com.huayu.security.equip" &&
//         className === "com.huayu.security.equip.MainActivity") {
//         console.log("[*] Forcing setRequestedOrientation(SENSOR)");
//         activity.setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_SENSOR_PORTRAIT.value); // SCREEN_ORIENTATION_SENSOR
//     }
//     return interdict(activity)
// })

// hookM('android.service.dreams.DreamService#finish', obj => {
//     return interdict()
// }, true)

// hookM('com.android.server.dreams.DreamManagerService#stopDreamLocked', obj => {
//     return interdict()
// })

// hookM('android.hardware.camera2.CameraManager$CameraManagerGlobal#extractCameraIdListLocked', obj => {
//     console.log('mDeviceStatus', obj.mDeviceStatus.value);
//     let map = Java.cast(obj.mDeviceStatus.value, Java.use('java.util.Map'))
//     console.log('map', map.size());

//     let map1 = Java.cast(obj.mConcurrentCameraIdCombinations.value, Java.use('java.util.Set'))
//     console.log('map1', map1.size());

//     let map2 = Java.cast(obj.mUnavailablePhysicalDevices.value, Java.use('java.util.Map'))
//     console.log('map2', map2.size());
    
// })

// hookM('com.android.internal.widget.LockPatternUtils#verifyGatekeeperPasswordHandle')
// hookM('com.android.internal.widget.LockPatternUtils#verifyGatekeeperPasswordHandle')
// hookM('com.android.wifitrackerlib.WifiEntry#updateConnectionInfo', null, true)

// hookM('com.android.server.location.gnss.GnssLocationProvider#handleReportLocation')

// hookM('com.android.server.StorageManagerService#onDiskScannedLocked')


// android.os.storage.StorageManager#partitionPrivate
// android.os.storage.StorageManager#partitionPublic
// android.os.storage.StorageManager#benchmark
// android.os.storage.StorageManager#setPrimaryStorageUuid
// android.app.ApplicationPackageManager#movePrimaryStorage

// hookM('android.os.storage.StorageManager#partitionPrivate');
// hookM('android.os.storage.StorageManager#partitionPublic');
// hookM('android.os.storage.StorageManager#benchmark');
// hookM('android.os.storage.StorageManager#setPrimaryStorageUuid');
// hookM('android.app.ApplicationPackageManager#movePrimaryStorage');

// hookM('com.android.server.pm.PackageManagerService#movePrimaryStorage')
// hookM('com.android.camera.VideoModule#requestCamera')
// hookM('com.android.camera.VideoModule#getCameraId')

// hookM('com.android.server.am.ActivityManagerService#collectReceiverComponents', (obj, intent, resolvedType, callingUid, users, broadcastAllowList) => {
//     console.log('\n-------collectReceiverComponents--------');
//     console.log('intent', intent);
//     console.log('getComponent', intent.getComponent());
//     console.log('resolvedType', resolvedType);
//     console.log('callingUid', callingUid);
//     console.log('users', users[0]);
//     console.log('broadcastAllowList',broadcastAllowList);
//     let res = obj.collectReceiverComponents(intent, resolvedType, callingUid, users, broadcastAllowList)
//     console.log('receivers', res);
//     let rr = Java.cast(obj.mReceiverResolver.value, Java.use('com.android.server.IntentResolver'))

//     let resolvers = rr.queryIntent(intent, resolvedType, false /*defaultOnly*/, users[0]);
//     console.log(resolvers.size());
//     if (resolvers.size() > 0) {
//         let broadcastFilter = resolvers.get(0);
//         console.log(broadcastFilter.toString());
//     }

//     return res;
// })

// hookM('com.android.server.uri.UriGrantsManagerService#checkUriPermissionLocked')
// hookM('com.android.server.uri.UriGrantsManagerService#checkHoldingPermissionsInternalUnlocked', obj => {
//     return interdict(true)
// })
