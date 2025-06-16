
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

setImmediate(g2)
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
