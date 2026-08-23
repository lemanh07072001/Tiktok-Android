#!/system/bin/sh
# fakedev_profiles.sh — định nghĩa các device profile. Nguồn nội dung file /proc /sys giả.
# Dùng bởi fakedev_apply.sh. Đổi profile: gọi `apply <tên>`.

# ===== profile: s20 (Galaxy S20, Exynos 990, 8 core) =====
prof_s20() {
  MODEL="SM-G981B"; DEVICE="x1s"; BRAND="samsung"; MANUF="samsung"
  BOARD="exynos990"; PLATFORM="exynos990"; HARDWARE="exynos990"
  ABILIST="arm64-v8a,armeabi-v7a,armeabi"; OSVER="12"; SDK="31"
  FP="samsung/x1sxxx/x1s:12/SP1A.210812.016/G981BXXU5EUE1:user/release-keys"
  MEMTOTAL="12000000"
  # per-core: 0-3=A55, 4-5=A76, 6-7=M5
  IMPL="0x41 0x41 0x41 0x41 0x41 0x41 0x53 0x53"
  PART="0xd05 0xd05 0xd05 0xd05 0xd0d 0xd0d 0x004 0x004"
  VARIANT="0x1 0x1 0x1 0x1 0x1 0x1 0x1 0x1"
  REVISION="0 0 0 0 0 0 0 0"
  FEATURES="fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop asimddp"
  ARCH="8"; HWNAME="Samsung EXYNOS990"
  MAXFREQ="1950000 1950000 1950000 1950000 2314000 2314000 2730000 2730000"
  MINFREQ="455000 455000 455000 455000 377000 377000 741000 741000"
  CURFREQ="1053000 1053000 1053000 1053000 864000 864000 741000 741000"
  AVAILFREQ="455000 728000 1053000 1287000 1560000 1950000"
  PRESENT="0-7"; ONLINE="0-7"; POSSIBLE="0-7"; KMAX="7"
  WLAN_MAC="a4:50:46:11:22:33"; GPU_RENDERER="Mali-G77"; GPU_VENDOR="ARM"
}

# ===== profile: pixel6 (Google Pixel 6, Tensor, 8 core) =====
prof_pixel6() {
  MODEL="Pixel 6"; DEVICE="oriole"; BRAND="google"; MANUF="Google"
  BOARD="oriole"; PLATFORM="gs101"; HARDWARE="oriole"
  ABILIST="arm64-v8a,armeabi-v7a,armeabi"; OSVER="13"; SDK="33"
  FP="google/oriole/oriole:13/TQ3A.230805.001/10316531:user/release-keys"
  MEMTOTAL="8000000"
  IMPL="0x41 0x41 0x41 0x41 0x41 0x41 0x41 0x41"
  PART="0xd05 0xd05 0xd05 0xd05 0xd0a 0xd0a 0xd0b 0xd0b"
  VARIANT="0x1 0x1 0x1 0x1 0x0 0x0 0x0 0x0"
  REVISION="0 0 0 0 0 0 0 0"
  FEATURES="fp asimd evtstrm aes pmull sha1 sha2 crc32 atomics fphp asimdhp cpuid asimdrdm lrcpc dcpop sha3 sm3 sm4 asimddp sha512 asimdfhm dit uscat ilrcpc flagm ssbs sb paca pacg"
  ARCH="8"; HWNAME="Google gs101"
  MAXFREQ="1803000 1803000 1803000 1803000 2253000 2253000 2802000 2802000"
  MINFREQ="300000 300000 300000 300000 400000 400000 500000 500000"
  CURFREQ="1098000 1098000 1098000 1098000 500000 500000 500000 500000"
  AVAILFREQ="300000 738000 1098000 1491000 1803000"
  PRESENT="0-7"; ONLINE="0-7"; POSSIBLE="0-7"; KMAX="7"
  WLAN_MAC="da:a1:19:44:55:66"; GPU_RENDERER="Mali-G78"; GPU_VENDOR="ARM"
}