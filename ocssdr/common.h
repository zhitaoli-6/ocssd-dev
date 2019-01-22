#ifndef COMMON_H_
#define COMMON_H_

static int get_delimiter_cnt(const char *str, char delimiter)
{
	int cnt = 0, i = 0;
	while (str[i]) {
		if (str[i] == delimiter)
			cnt++;
		i++;
 	}
	return cnt;
}

static int parse_by_delimiter(char *str, char delimiter, char *devname[], int off, int nr_dev)
{
	int dev_id = 0;
	int i = 0, j = 0;
	while (str[j]) {
		if (j > i && str[j] == delimiter) {
			memcpy(devname[dev_id] + off, str + i, j - i);
			dev_id ++;
			i = j + 1;
			if (dev_id >= nr_dev) {
				return nr_dev;
			}
		}
		j++;
	}
	if (dev_id < nr_dev && j > i) {
		memcpy(devname[dev_id]+off, str + i, j - i);
		dev_id++;
	}
	return dev_id;
}

#endif

