#!/usr/bin/env python3
"""
Extract device_id từ TikTok app qua Frida hook
Không cần proxy, không cần root (chỉ cần app debuggable)

Usage:
  python re/scripts/extract_device_frida.py
"""

import frida
import json
import sys
import time

def extract_device():
    print('\n🔍 Frida Device Extractor\n')
    print('=' * 60)

    # Frida hook code
    hook_code = """
    Java.perform(() => {
        console.log('[*] Hooking TikTok app...');

        // Try MMKV (TikTok's primary storage)
        try {
            const MMKV = Java.use('com.tencent.mmkv.MMKV');
            const mmkv = MMKV.defaultMMKV();

            const keys = ['device_id', 'install_id', 'iid', 'did', 'mm_device_id'];
            for (const key of keys) {
                const value = mmkv.getString(key, null);
                if (value) {
                    console.log('[MMKV] ' + key + ' = ' + value);
                }
            }
        } catch (e) {
            console.log('[!] MMKV error: ' + e.toString());
        }

        // Try SharedPreferences
        try {
            const context = Java.use('android.app.ActivityThread').currentApplication();

            // Try multiple preference names
            const prefs_names = ['tiktok_prefs', 'device_info', 'tt_app_prefs', 'device'];

            for (const pref_name of prefs_names) {
                try {
                    const prefs = context.getSharedPreferences(pref_name, 0);
                    const map = prefs.getAll();
                    const iterator = map.entrySet().iterator();

                    while (iterator.hasNext()) {
                        const entry = iterator.next();
                        const key = entry.getKey().toString();
                        const value = entry.getValue().toString();

                        if (key.includes('device') || key.includes('install')) {
                            console.log('[PREF] ' + key + ' = ' + value);
                        }
                    }
                } catch (e) {}
            }
        } catch (e) {
            console.log('[!] SharedPreferences error: ' + e.toString());
        }

        // Hook device_register API response
        try {
            const URLConnection = Java.use('java.net.URLConnection');
            const BufferedReader = Java.use('java.io.BufferedReader');

            URLConnection.getInputStream.implementation = function() {
                const result = this.getInputStream();
                const url = this.getURL().toString();

                if (url.includes('device_register')) {
                    console.log('[HOOK] Intercepted: ' + url);
                    try {
                        const reader = BufferedReader.$new(Java.use('java.io.InputStreamReader').$new(result));
                        let line = '';
                        const content = '';
                        while ((line = reader.readLine()) !== null) {
                            // Parse JSON
                            try {
                                const json = JSON.parse(line);
                                if (json.data && json.data.device_id_str) {
                                    console.log('[API] device_id_str = ' + json.data.device_id_str);
                                    console.log('[API] install_id_str = ' + json.data.install_id_str);
                                }
                            } catch (e) {}
                        }
                    } catch (e) {}
                }

                return result;
            };
        } catch (e) {
            console.log('[!] Hook error: ' + e.toString());
        }

        console.log('[*] Hook installed. Waiting for device data...');
    });
    """

    try:
        # Get USB device
        print('[1] Connecting to device...')
        device = frida.get_usb_device()
        print(f'    ✓ Found: {device.name}')

        # Spawn TikTok app
        print('[2] Starting TikTok app...')
        print('    Package: com.zhiliaoapp.musically')

        try:
            pid = device.spawn(['com.zhiliaoapp.musically'])
        except Exception as e:
            print(f'    ⚠️  Spawn error (app may already be running): {e}')
            # Try to get existing process
            processes = device.enumerate_processes()
            tiktok_pids = [p.pid for p in processes if 'musically' in p.name]
            if tiktok_pids:
                pid = tiktok_pids[0]
                print(f'    ✓ Using existing process: {pid}')
            else:
                raise

        # Attach and hook
        print('[3] Attaching Frida...')
        session = device.attach(pid)
        print('    ✓ Attached')

        print('[4] Loading hook script...')
        script = session.create_script(hook_code)

        def on_message(message, data):
            if message['type'] == 'send':
                print(f"    {message['payload']}")

        script.on('message', on_message)
        script.load()
        print('    ✓ Hook loaded')

        # Resume app
        device.resume(pid)
        print('\n[5] Waiting for device_register call...')
        print('    💡 Open TikTok app and wait ~10 seconds\n')

        # Wait for capture
        time.sleep(15)

        print('\n' + '=' * 60)
        print('\n📍 Check output above for device_id/install_id')
        print('\nIf found, save to environment:')
        print('  export RE_DEV="<device_id>|<install_id>"')

    except Exception as e:
        print(f'\n❌ Error: {e}')
        print('\nTroubleshooting:')
        print('  1. Is device connected? (adb devices)')
        print('  2. Is app debuggable? (adb shell getprop ro.debuggable)')
        print('  3. Install Frida tools? (pip install frida frida-tools)')
        sys.exit(1)

if __name__ == '__main__':
    extract_device()
