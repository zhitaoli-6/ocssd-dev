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

#define NR_SECTORS	128
#define SECTOR_SIZE	(4096)


#define DEVICE_NAME	"/dev/pblk_sd"
#define MODULE_NAME	"ram-disk"
#define MY_BLOCK_MAJOR	"240"
#define MY_BLOCK_MINOR	"0"


#define max_elem_value(elem)	\
	(1 << 8*sizeof(elem))

//#define RAND_DATA

#define FILL_DATA

class Tester {
public:
	 unsigned char buffer[SECTOR_SIZE];
	 unsigned char buffer_copy[SECTOR_SIZE];


	 unsigned char w_buf[NR_SECTORS][SECTOR_SIZE];
	 unsigned char r_buf[NR_SECTORS][SECTOR_SIZE];


public:
	 void write_sector(int fd, size_t sector){
		if(sector >= NR_SECTORS) return;
		int i;
		for (i = 0; i < sizeof(buffer) / sizeof(buffer[0]); i++){
			//w_buf[sector][i] = rand() % max_elem_value(buffer[0]);
			w_buf[sector][i] = sector % 26 + 'a';
		}
		lseek(fd, sector * SECTOR_SIZE, SEEK_SET);
		write(fd, w_buf[sector], sizeof(buffer));

		fsync(fd);
	}

	void check_sector(int fd, size_t sector){
		if(sector >= NR_SECTORS) return;
		lseek(fd, sector * SECTOR_SIZE, SEEK_SET);
		read(fd, r_buf[sector], sizeof(buffer));
		printf("test sector %3lu ... ", sector);
		if (memcmp(r_buf[sector], w_buf[sector], sizeof(buffer_copy)) == 0)
			printf("passed\n");
		else
			printf("failed\n");
	}


	static void read_data(size_t offset, int page_cnt){
		int fd = open(DEVICE_NAME, O_RDWR);
		if (fd < 0) {
			perror("open");
			exit(EXIT_FAILURE);
		}
		lseek(fd, offset * SECTOR_SIZE, SEEK_SET);
		/*
		char *_r_buf = new char[SECTOR_SIZE*page_cnt];
		ssize_t cnt = read(fd, _r_buf, SECTOR_SIZE*page_cnt);
		cout << "read page no " << offset  << " ";
		printf("%ld bytes\n", cnt);
		*/
		char *_r_buf = new char[SECTOR_SIZE];
		for(int page = 0; page < page_cnt; page++){
			ssize_t cnt = read(fd, _r_buf, SECTOR_SIZE);
			cout << "read page no " << page+offset  << " ";
			printf("%ld bytes\n", cnt);
		}
		close(fd);
	}

	static void fill_data(size_t capacity, bool single){
		int fd = open(DEVICE_NAME, O_RDWR);
		if (fd < 0) {
			perror("open");
			exit(EXIT_FAILURE);
		}
		char *_w_buf = new char[SECTOR_SIZE];
#ifndef RAND_DATA
		for(int i = 0; i < sizeof(buffer); i++)
			_w_buf[i] = rand() % 26 + 'a';
#endif
		//int page_cnt = capacity/SECTOR_SIZE;
		int page_cnt = 1;
		page_cnt = (single ? 15 : capacity/SECTOR_SIZE);

		for(int page = 0; page < page_cnt; page++){
			int sector = page;
#ifdef RAND_DATA
			for(int i = 0; i < sizeof(buffer); i++)
				_w_buf[i] = rand() % 26 + 'a';
#endif
			lseek(fd, sector * SECTOR_SIZE, SEEK_SET);
			size_t cnt = write(fd, _w_buf, SECTOR_SIZE);
			//fsync(fd);
			//lseek(fd, sector * SECTOR_SIZE, SEEK_SET);
			//read(fd, _r_buf, SECTOR_SIZE);
			cout <<  "write page_no " << page << " ";
			cout << (cnt == SECTOR_SIZE ? "pass" : "fail") << endl;
			//if(memcmp(_w_buf, _r_buf, SECTOR_SIZE) != 0) cout << "failed" << endl;
			//else cout << "passed" << endl;
		}
		delete []_w_buf;
		fsync(fd);
		close(fd);
	}
	static void check_filled_data(size_t capacity, bool single){
		int fd = open(DEVICE_NAME, O_RDWR);
		if (fd < 0) {
			perror("open");
			exit(EXIT_FAILURE);
		}
		char *_w_buf = new char[SECTOR_SIZE];
		char *_r_buf = new char[SECTOR_SIZE];
#ifndef RAND_DATA
		for(int i = 0; i < sizeof(buffer); i++)
			_w_buf[i] = rand() % 26 + 'a';
#endif
		int page_cnt = 1;
		page_cnt = (single ? 15 : capacity/SECTOR_SIZE);
		for(int page = 0; page < page_cnt; page++){
			int sector = page;
#ifdef RAND_DATA
			for(int i = 0; i < sizeof(buffer); i++)
				_w_buf[i] = rand() % 26 + 'a';
#endif
			//size_t cnt = write(fd, _w_buf, SECTOR_SIZE);
			//fsync(fd);
			lseek(fd, sector * SECTOR_SIZE, SEEK_SET);
			int cnt = read(fd, _r_buf, SECTOR_SIZE);
			cout <<  "write page_no " << page << " ";
			printf("%d %s\n", cnt, memcmp(_w_buf, _r_buf, SECTOR_SIZE) == 0 ? "pass" : "fail");
		}
		delete []_w_buf;
		delete []_r_buf;
		close(fd);
	}
	
	void run_many(){
		int fd = open(DEVICE_NAME, O_RDWR);
		if (fd < 0) {
			perror("open");
			exit(EXIT_FAILURE);
		}

		srand(time(NULL));
		//for(i = 0; i < NR_SECTORS; i++)
		//test_sector(fd, i);
		int nr = 64;
		for (int i = 0; i < nr; i++){
			write_sector(fd, i);
		} 
		for(int i = 0; i < nr; i++){
			check_sector(fd, i);
		}
		close(fd);
	}
};

int main()
{

	/*
	   printf("insmod ../kernel/" MODULE_NAME ".ko\n");
	   system("insmod ../kernel/" MODULE_NAME ".ko\n");
	   sleep(1);

	   printf("mknod " DEVICE_NAME " b " MY_BLOCK_MAJOR " " MY_BLOCK_MINOR "\n");
	   system("mknod " DEVICE_NAME " b " MY_BLOCK_MAJOR " " MY_BLOCK_MINOR "\n");
	   printf("mknod finish, sleep 5s...\n");
	   sleep(5);
	   */

	/*
	   sleep(1);
	   printf("rmmod " MODULE_NAME "\n");
	   system("rmmod " MODULE_NAME "\n");
	   */

	//Tester::run();
	//Tester::run_single(4*1024*1024);
	const unsigned long capacity = 1ll * SECTOR_SIZE * 1024 * 16;
	Tester tester;
	struct timeval t1, t2;
	gettimeofday(&t1, NULL);
#ifdef FILL_DATA
	tester.fill_data(capacity, true);
#else
	tester.check_filled_data(capacity, true);
#endif
	gettimeofday(&t2, NULL);
	printf("bench: BW %.2fMB/s\n", 1.0 * capacity / 1e6 / TIME(t1, t2));
	//tester.read_data(2000, 32);
	return 0;
}
