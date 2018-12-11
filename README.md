# ocssd-dev

doing things with Openchannel SSD


## OCSSDR

There are three available methods which can provide a block device survice with reliability on OC-SSDs:
1. software raid on pblk
2. customized raid-like on pblk
3. enhance pblk with multiple devices support

## OCSSD problems met
- OOB Metadata not completely supported: the first 4 bytes of OOB of tthe first sector of each page fails to write.
- RW check, undefined and no errors returned to write pages which exceed the SSD geometry
- Erase. Write in a page many times doesn't return error and the result is the write at the last time.
