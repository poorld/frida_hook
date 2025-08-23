
// setImmediate(gg)
function gg() {
    Java.perform(function() {

        Java.choose('android.service.persistentdata.PersistentDataBlockManager', {
            onMatch: (instance) => {
                console.log('instance');
                
            },
            onComplete: () => {
                console.log('onComplete');
            }
        })
    })
}


// setImmediate(g1)
function g1() {
    Java.perform(function() {
        Java.choose('com.android.server.biometrics.sensors.fingerprint.FingerprintService', {
            onMatch: (instance) => {
                console.log('instance');
                instance.mServiceWrapper.enroll.overload(
                    'android.os.IBinder', '[B', 'int', 'android.hardware.fingerprint.IFingerprintServiceReceiver', 'java.lang.String', 'int'
                ).implementation = function(token, hardwareAuthToken, userId, receiver, opPackageName, enrollReason) {
                    console.log("[Frida] enroll called, userId=" + userId + ", enrollReason=" + enrollReason);
                    // 你可以修改参数或直接返回
                    return this.enroll(token, hardwareAuthToken, userId, receiver, opPackageName, enrollReason);
                };
            },
            onComplete: () => {
                console.log('onComplete');
            }
        })
    });
}

// setImmediate(g2)
function g2() {
    Java.perform(function() {
        var Location = Java.use('android.location.Location');
        var System = Java.use('java.lang.System');

        Java.choose('com.android.server.location.gnss.GnssLocationProvider', {
            onMatch: (instance) => {
                console.log('instance');
                

                // 创建一个新的 Location 对象
                var mockLocation = Location.$new('gps');
                let lat = 37.4219984
                mockLocation.setLatitude(lat);
                mockLocation.setLongitude(-122.084);
                mockLocation.setAccuracy(2);
                mockLocation.setAltitude(204.17247581481934);
                // mockLocation.setSpeed(2000);
                mockLocation.setBearing(1.2);
                mockLocation.setVerticalAccuracyMeters(1);
                mockLocation.setSpeedAccuracyMetersPerSecond(1);
                mockLocation.setBearingAccuracyDegrees(1);
                mockLocation.makeComplete();

                mockLocation.setSpeed(Math.random(50));
                lat = Math.round((lat + 0.01) * 1e7) / 1e7;
                mockLocation.setLatitude(lat);
                console.log('handleReportLocation',  mockLocation.getLatitude() + "," + mockLocation.getLongitude());
                instance.handleReportLocation(true, mockLocation);
                
            },
            onComplete: () => {
                console.log('onComplete');
            }
        })
    })
}

setImmediate(backKeyPress)
function backKeyPress() {
    Java.perform(function() {
        // com.android.server.policy.PhoneWindowManager#backKeyPress
        Java.choose('com.android.server.policy.PhoneWindowManager', {
            onMatch: (instance) => {
                console.log('Found PhoneWindowManager instance:', instance);
                instance.backKeyPress.implementation = function() {
                    console.log('backKeyPress called, passing through.');
                    console.log('mAutofillManagerInternal', instance.mAutofillManagerInternal.value)
                    return this.backKeyPress();
                };
                setTimeout(() => {
                    // instance.backKeyPress()
                    let Instrumentation =  Java.use('android.app.Instrumentation')
                    let inst = Instrumentation.$new()
                    // Instrumentation inst = new Instrumentation();
                    console.log('sendKeyDownUpSync');
                    
                    inst.sendKeyDownUpSync(4);
                }, 3000)
            },
            onComplete: () => {
                console.log('PhoneWindowManager enumeration complete.');
            }
        });
        
    })
}

// com.android.server.policy.PhoneWindowManager$PolicyHandler#handleMessage
// setImmediate(handleMessage)
function handleMessage() {
    Java.perform(function() {
        Java.choose('com.android.server.policy.PhoneWindowManager$PolicyHandler', {
            onMatch: (instance) => {
                console.log('Found PolicyHandler instance:', instance);
                instance.handleMessage.implementation = function(msg) {
                    console.log('PolicyHandler handleMessage called with msg:', msg);
                    return this.handleMessage(msg);
                };
            },
            onComplete: () => {
                console.log('PolicyHandler enumeration complete.');
            }
        });
    });
}
