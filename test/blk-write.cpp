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

static void fill_data(){
	int fd = open(DEVICE_NAME, O_RDWR);
	if (fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}
	char *_w_buf = new char[SECTOR_SIZE];
	if (!O_RAND)
		rand_data(_w_buf, SECTOR_SIZE);
	int page_cnt = W_PAGE_CNT;

	for (int page = 0; page < page_cnt; page++)
	{
		int sector = page;

		if (O_RAND)
			rand_data(_w_buf, SECTOR_SIZE);

		lseek(fd, 1ll * sector * SECTOR_SIZE, SEEK_SET);
		size_t cnt = write(fd, _w_buf, SECTOR_SIZE);
		cout <<  "write page_no " << page << " ";
		cout << (cnt == SECTOR_SIZE ? "pass" : "fail") << endl;
	}
	delete []_w_buf;
	fsync(fd);
	close(fd);
}

static void inject_same_ppa(){
	int fd = open(DEVICE_NAME, O_RDWR);
	if (fd < 0) {
		perror("open");
		exit(EXIT_FAILURE);
	}
	char *_w_buf = new char[SECTOR_SIZE];
	if (!O_RAND)
		rand_data(_w_buf, SECTOR_SIZE);
	int page_cnt = 8;

	int t = 5;
	while(t--) {
		for (int page = 0; page < page_cnt; page++)
		{
			int sector = page;

			if (O_RAND)
				rand_data(_w_buf, SECTOR_SIZE);

			lseek(fd, 1ll * sector * SECTOR_SIZE, SEEK_SET);
			size_t cnt = write(fd, _w_buf, SECTOR_SIZE);
			cout <<  "write page_no " << page << " ";
			cout << (cnt == SECTOR_SIZE ? "pass" : "fail") << endl;
			if (page % 8 == 7)
				fsync(fd);
		}
	}
	delete []_w_buf;
	close(fd);
}

int main()
{
	struct timeval t1, t2;
	gettimeofday(&t1, NULL);
	fill_data();
	//inject_same_ppa();
	gettimeofday(&t2, NULL);
	printf("bench: BW %.2fMB/s\n", 1.0 * W_PAGE_CNT * SECTOR_SIZE / 1e6 / TIME(t1, t2));
	return 0;
}
