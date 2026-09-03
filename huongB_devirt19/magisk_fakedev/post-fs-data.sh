#!/system/bin/sh
# mount fingerprint spoof lúc boot với profile lưu trong /data/adb/fakedev/current
MODDIR=${0%/*}
DIR=/data/adb/fakedev
[ -f $DIR/fakedev_apply.sh ] || cp $MODDIR/fakedev_apply.sh $MODDIR/fakedev_profiles.sh $DIR/ 2>/dev/null
PROF=$(cat $DIR/current 2>/dev/null || echo s20)
# apply nhưng KHÔNG restart app lúc boot (app chưa chạy)
NOSTOP=1 sh $DIR/fakedev_apply.sh $PROF
