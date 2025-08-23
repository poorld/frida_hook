
import { hookMethod, pass, interdict, LOG } from '../framework.js';

LOG("--- Mediatek Camera Hooks Script Start ---");

const hooksToApply = [
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
    {
        enabled: false,
        target: 'com.mediatek.camera.common.utils.CameraUtil#findBestMatchPanelSize',
        callback: (obj, sizes, previewRatio, panelWidth, panelHeight) => {
            previewRatio = 2
            let size = obj.findBestMatchPanelSize(sizes, previewRatio, panelWidth, panelHeight)
            return interdict(size)
        }
    },
    {
        enabled: false,
        target: 'com.mediatek.camera.common.mode.photo.device.PhotoDevice2Controller#getTargetPreviewSize',
        callback:(obj, ratio) => {
            let size = obj.getTargetPreviewSize(2)
            return interdict(size)
        }
    },
    {
        enabled: false,
        target: 'com.mediatek.camera.common.mode.video.device.v2.VideoDevice2Controller#getSupportedPreviewSizes',
        callback:(obj, ratio) => {
            let size = obj.getSupportedPreviewSizes(1.777)
            return interdict(size)
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

LOG("--- Mediatek Camera Hooks Script End ---");
