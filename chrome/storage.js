/**
 * Retrieve object from Chrome's Local StorageArea
 * @param {string} key 
 */
const getFromLocalStorage = async function(key) {
    return new Promise((resolve, reject) => {
      try {
        chrome.storage.local.get(key, function(value) {
          resolve(value[key]);
        });
      } catch (ex) {
        reject(ex);
      }
    });
  };

 /**
  * Check for object in Chrome's Local StorageArea
  * @param {string} key
  */
 const checkKeyInLocalStorage = async function(key) {
    return new Promise((resolve, reject) => {
      try {
        chrome.storage.local.get(key, function(value) {
            if (typeof value[key] === "undefined") {
                resolve(false);
            } else {
                resolve(true);
            }
        });
      } catch (ex) {
        reject(ex);
      }
    });
};
  
  /**
   * Save Object in Chrome's Local StorageArea
   * @param {*} obj 
   */
  const saveInLocalStorage = async function(obj) {
    return new Promise((resolve, reject) => {
      try {
        chrome.storage.local.set(obj, function() {
          resolve();
        });
      } catch (ex) {
        reject(ex);
      }
    });
  };
  
  /**
   * Removes Object from Chrome Local StorageArea.
   *
   * @param {string or array of string keys} keys
   */
  const removeObjectFromLocalStorage = async function(keys) {
    return new Promise((resolve, reject) => {
      try {
        chrome.storage.local.remove(keys, function() {
          resolve();
        });
      } catch (ex) {
        reject(ex);
      }
    });
  };