/*
 * SO2 - Block device driver (#8)
 * Test suite for exercise #3 (RAM Disk)
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <iostream>

using namespace std;

#include "common.h"

static void check_filled_data(){
	int fd = open(DEVICE_NAME, O_RDWR);
	if (fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}
	char *_w_buf = new char[SECTOR_SIZE];
	char *_r_buf = new char[SECTOR_SIZE];

	if (!O_RAND)
		rand_data(_w_buf, SECTOR_SIZE);

	for(int page = 0; page < R_PAGE_CNT; page++){
		int sector = page;
		if (O_RAND)
			rand_data(_w_buf, SECTOR_SIZE);
		lseek(fd, sector * SECTOR_SIZE, SEEK_SET);
		int cnt = read(fd, _r_buf, SECTOR_SIZE);
		cout <<  "write page_no " << page << " ";
		printf("%d %s\n", cnt, cnt == SECTOR_SIZE && memcmp(_w_buf, _r_buf, SECTOR_SIZE) == 0 ? "pass" : "fail");
	}
	delete []_w_buf;
	delete []_r_buf;
	close(fd);
}

static void check_injected_data(){
	int fd = open(DEVICE_NAME, O_RDWR);
	if (fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}
	char *_w_buf = new char[SECTOR_SIZE];
	char *_r_buf = new char[SECTOR_SIZE];

	int pre = 32;
	while(pre--)
		rand_data(_w_buf, SECTOR_SIZE);
	
	for(int page = 0; page < 8; page++){
		int sector = page;
		if (O_RAND)
			rand_data(_w_buf, SECTOR_SIZE);
		lseek(fd, sector * SECTOR_SIZE, SEEK_SET);
		int cnt = read(fd, _r_buf, SECTOR_SIZE);
		cout <<  "write page_no " << page << " ";
		printf("%d %s\n", cnt, cnt == SECTOR_SIZE && memcmp(_w_buf, _r_buf, SECTOR_SIZE) == 0 ? "pass" : "fail");
	}
	delete []_w_buf;
	delete []_r_buf;
	close(fd);
}

int main()
{
	struct timeval t1, t2;
	gettimeofday(&t1, NULL);
	check_filled_data();
	//check_injected_data();
	gettimeofday(&t2, NULL);
	printf("bench: BW %.2fMB/s\n", 1.0 * R_PAGE_CNT * SECTOR_SIZE / 1e6 / TIME(t1, t2));
	return 0;
}
