# ocssd-dev

Doing things with Openchannel SSD. Please see [docs](docs/) in detail.

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
