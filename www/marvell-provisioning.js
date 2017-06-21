var exec = require('cordova/exec');

exports.SendProvisionData = function(ssid,pss,key,data, success, error) {
    exec(success, error, "marvell-provisioning", "SendProvisionData", [ssid,pss,key,data]);
};

exports.GetCurrentSSID = function(success, error) {
    exec(success, error, "marvell-provisioning", "GetCurrentSSID", []);
};
