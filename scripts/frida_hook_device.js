// Frida hook: Capture device_id + install_id từ TikTok app
// Chạy: frida -U -l frida_hook_device.js -f com.zhiliaoapp.musically

console.log('[*] Frida hook: Capturing device_id from TikTok...\n');

// Hook: TikTok's network response handler
// Search for device_id in response strings
Java.perform(() => {
  const OkHttpClient = Java.use('okhttp3.OkHttpClient');
  const Response = Java.use('okhttp3.Response');
  const String = Java.use('java.lang.String');

  // Hook Response.body() to intercept responses
  const ResponseBody = Java.use('okhttp3.ResponseBody');

  // Try to find device_id in response strings
  if (ResponseBody) {
    const originalString = String.$new;
    String.$new = function() {
      const result = originalString.apply(this, arguments);
      const str = result.toString();

      if (str.includes('device_id') || str.includes('install_id')) {
        console.log('[+] Found response with IDs:');
        console.log(str.substring(0, 500));
        console.log('...\n');
      }

      return result;
    };
  }

  // Hook: Intercept SharedPreferences writes
  const SharedPreferences = Java.use('android.content.SharedPreferences$Editor');
  const putString = SharedPreferences.putString;

  SharedPreferences.putString.overload('java.lang.String', 'java.lang.String').implementation = function(key, value) {
    if (key.includes('device') || key.includes('install') || key.includes('id')) {
      console.log(`[+] SharedPreferences.putString: ${key} = ${value}`);
    }
    return putString.call(this, key, value);
  };

  console.log('[+] Hooks installed. Launch TikTok app now...\n');
});

// Also hook: look for device_id in strings
setInterval(() => {
  // Keep running
}, 1000);
