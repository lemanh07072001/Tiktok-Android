#!/system/bin/sh
# (dự phòng) re-apply nếu post-fs-data quá sớm
MODDIR=${0%/*}
DIR=/data/adb/fakedev
PROF=$(cat $DIR/current 2>/dev/null || echo s20)
mount | grep -q " /proc/cpuinfo " || NOSTOP=1 sh $DIR/fakedev_apply.sh $PROF
