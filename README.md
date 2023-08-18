# Log-ROC: Log Structured RAID on Open-Channel SSDs

Short paper accepted on [ICCD2022](http://www.iccd-conf.com/Program_2022.html)

### Introduction

As a linux kernel module, this project provides RAID features on many Open-Channel SSDs. By codesign upper-layer storage system with underlying Open-Channel SSDs, the proposed Log-ROC is written inlog structured way, which can eliminate the cost of parities. 

Compared to software raid5 on pblk, Log-ROC has following contributions:
1. higher performance and longer lifespan of SSDs, because parities update need zero read and minimum write. RAID5 on pblk will need 2X read and 2X write in random write workload.
2. flexible data placement, which allows:
	- fast recovery from device failures
	- low-cost to resize 
	- global wear-levelling

### Design

There are three available methods which can provide a block device survice with reliability on OC-SSDs:
1. software raid on pblk
2. customized raid-like on pblk
3. **enhance pblk with multiple devices support**

This work focuses the third one.


### Done

1. SD/RAID0/RAID1/RAID5 normal path
2. Recover from poweroff: SD/RAID5
3. Read error handling: RAID1/RAID5
4. Resize: RAID5
5. GC: SD/RAID5

### TODO
