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

#define NR_SECTORS	128
#define SECTOR_SIZE	512

#define DEVICE_NAME	"/dev/myblock"
#define MODULE_NAME	"ram-disk"
#define MY_BLOCK_MAJOR	"240"
#define MY_BLOCK_MINOR	"0"


#define max_elem_value(elem)	\
	(1 << 8*sizeof(elem))

static unsigned char buffer[SECTOR_SIZE];
static unsigned char buffer_copy[SECTOR_SIZE];


static unsigned char w_buf[NR_SECTORS][SECTOR_SIZE];
static unsigned char r_buf[NR_SECTORS][SECTOR_SIZE];


static void write_sector(int fd, size_t sector){
	int i;
	for (i = 0; i < sizeof(buffer) / sizeof(buffer[0]); i++)
		w_buf[sector][i] = rand() % max_elem_value(buffer[0]);
	lseek(fd, sector * SECTOR_SIZE, SEEK_SET);
	write(fd, w_buf[sector], sizeof(buffer));

	fsync(fd);
}

static void check_sector(int fd, size_t sector){
	lseek(fd, sector * SECTOR_SIZE, SEEK_SET);
	read(fd, r_buf[sector], sizeof(buffer));
	printf("test sector %3lu ... ", sector);
	if (memcmp(r_buf[sector], w_buf[sector], sizeof(buffer_copy)) == 0)
		printf("passed\n");
	else
		printf("failed\n");
}



static void test_sector(int fd, size_t sector)
{
	int i;


	for (i = 0; i < sizeof(buffer) / sizeof(buffer[0]); i++)
		buffer[i] = rand() % max_elem_value(buffer[0]);


	lseek(fd, sector * SECTOR_SIZE, SEEK_SET);
	write(fd, buffer, sizeof(buffer));

	fsync(fd);

	//system("echo 3 >> /proc/sys/vm/drop_caches");

	lseek(fd, sector * SECTOR_SIZE, SEEK_SET);
	read(fd, buffer_copy, sizeof(buffer_copy));

	printf("test sector %3lu ... ", sector);
	if (memcmp(buffer, buffer_copy, sizeof(buffer_copy)) == 0)
		printf("passed\n");
	else
		printf("failed\n");
}

int main(void)
{
	int fd;
	size_t i;
	int back_errno;

/*
	printf("insmod ../kernel/" MODULE_NAME ".ko\n");
	system("insmod ../kernel/" MODULE_NAME ".ko\n");
	sleep(1);

	printf("mknod " DEVICE_NAME " b " MY_BLOCK_MAJOR " " MY_BLOCK_MINOR "\n");
	system("mknod " DEVICE_NAME " b " MY_BLOCK_MAJOR " " MY_BLOCK_MINOR "\n");
	printf("mknod finish, sleep 5s...\n");
	sleep(5);
*/

	fd = open(DEVICE_NAME, O_RDWR);
	if (fd < 0) {
		back_errno = errno;
		perror("open");
		fprintf(stderr, "errno is %d\n", back_errno);
		exit(EXIT_FAILURE);
	}

	srand(time(NULL));
	//for(i = 0; i < NR_SECTORS; i++)
	//test_sector(fd, i);
	int nr = 1;
	for (i = 0; i < nr; i++){
		write_sector(fd, i);
	}

	for(i = 0; i < nr; i++){
		check_sector(fd, i);
	}

	close(fd);

/*
	sleep(1);
	printf("rmmod " MODULE_NAME "\n");
	system("rmmod " MODULE_NAME "\n");
*/

	return 0;
}