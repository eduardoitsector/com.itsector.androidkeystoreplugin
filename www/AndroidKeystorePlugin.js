module.exports = {
    encrypt: function (alias, toEncrypt, successCallback, errorCallback) {
        cordova.exec(successCallback, errorCallback, "AndroidKeystorePlugin", "encrypt", [toEncrypt, alias]);
    },
	decrypt: function (alias, toDecrypt, successCallback, errorCallback) {
        cordova.exec(successCallback, errorCallback, "AndroidKeystorePlugin", "decrypt", [toDecrypt, alias]);
    }
};
