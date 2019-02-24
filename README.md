# ocssd-dev

Doing things with Open-Channel SSD. Please see [docs](docs/) in detail.

## OCSSDR

### Goals

As a linux kernel module, this project provides RAID features on many Open-Channel SSDs. It combines RAID2.0 design with new storage deivce,  which has promising advantages compared to raid on conventional flash devices:

1. fast recovery from device failures
2. low-cost to resize 
3. low amplification compared to software raid on pblk
4. global wear-levelling
5. low variation of IO latency

### Design

There are three available methods which can provide a block device survice with reliability on OC-SSDs:
1. software raid on pblk
2. customized raid-like on pblk
3. **enhance pblk with multiple devices support**

This work focuses on the third one.


### Done

1. SD/RAID0/RAID1/RAID5 normal path
2. Recover from poweroff: all modes
3. Read error handling: raid1/raid5
4. Resize: raid5(only support raid5 now)

### TODO

* Recovery from device failures: lines or the whole device
* resize of raid0/raid1

* Perf compared to software raid on multiple pblks
