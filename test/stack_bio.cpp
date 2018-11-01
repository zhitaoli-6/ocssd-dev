/*
 * stack_bio.c: make sure that upper bio layer read same value with lower bio layer
 * GIVEN same LBA
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <stdint.h>

#define SECTOR_SIZE	(512)
#define PAGE_SIZE	(4096)


#define DEVICE_UPPER	"/dev/ocssd0"
#define DEVICE_LOWER	"/dev/OCSSDR"

#define TRACE "/home/sirius/mount_gpblk"

int check(size_t off_sec, int *val){
	int ufd = open(DEVICE_UPPER, O_RDONLY);
	if(ufd == -1){
		perror("open device");
		return -1;
	}
	//size_t off_sec = 512;
	char *ubuf = new char[PAGE_SIZE];
	lseek(ufd, off_sec*SECTOR_SIZE, SEEK_SET);
	size_t ucnt = read(ufd, ubuf,PAGE_SIZE);
	close(ufd);

	printf("%s: read %lu bytes\n", DEVICE_UPPER, ucnt);

	int lfd = open(DEVICE_LOWER, O_RDONLY);
	if(lfd == -1){
		perror("open device");
		return -1;
	}
	char *lbuf = new char[PAGE_SIZE];
	lseek(lfd, off_sec*SECTOR_SIZE, SEEK_SET);
	size_t lcnt = read(lfd, lbuf, PAGE_SIZE);

	printf("%s: read %lu bytes\n", DEVICE_LOWER, lcnt);
	int v = memcmp(ubuf, lbuf, PAGE_SIZE);
	printf("offset %lu is %s\n", off_sec, (v == 0 ? "same": "diff"));
	*val = v;
	
	uint32_t magic = 0;
	for(int i = 0; i < lcnt; i++){
		magic += lbuf[i];
	}
	printf("magic %u\n", magic);


	delete []ubuf;
	delete []lbuf;
	close(lfd);
	return 0;
}

int parse_offset(const char *text, size_t *val){
	if(text == NULL) return -1;
	int i = 0;
	while(text[i]){
		if(strncmp(text+i, "bi_sector ", 10) == 0){
			size_t ret = 0;
			int j = i + 10;
			while(text[j] == ' ') j++;
			while(text[j] >= '0' && text[j] <= '9'){
				ret = ret * 10 + text[j] - '0';
				j++;
			}
			*val = ret;
			return 0;
		}
		i++;
	}
	return -1;
}

void check_trace(){
	FILE *filp = fopen(TRACE, "r");
	if(filp == NULL){
		perror("read trace");
		return;
	}
	char text[PAGE_SIZE];
	int skip = 0;
	while(fgets(text, PAGE_SIZE, filp)){
		//printf("%s", text);
		if(!skip){
			size_t off;
			int ret = parse_offset(text, &off);
			if(ret == 0){
				int v = -1;
				ret = check(off, &v);
				printf("off %lu: %d %d\n", off, ret, v);
			}
			else{
				//printf("end;\n");
				break;
			}
		}
		skip ^= 1;
	}
	fclose(filp);
}



int main(){
	check_trace();
	//check(0);
	return 0;
}
