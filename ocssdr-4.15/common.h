#ifndef COMMON_H_
#define COMMON_H_

static int get_delimiter_cnt(const char *str, char delimiter){
	int cnt = 0, i = 0;
	while(str[i]){
		if(str[i] == delimiter) cnt++;
		i++;
 	}
	return cnt;
}

static int parse_by_delimiter(char *str, char delimiter, char *substr[], int max_substr_cnt){
	//int cnt = get_delimiters_cnt(str, delimiter);
	int cnt = 0;
	int i = 0, j = 0;
	while(str[i]){
		if(str[i] == delimiter) {
			str[i] = '\0';
			substr[cnt] = str + j;
			j = i+1;;
			cnt ++;
			if(cnt == max_substr_cnt){
				return cnt;;
			}
		}
		i++;
	}
	if(i > j) {
		substr[cnt] = str + j;
		cnt++;
	}
	return cnt;
}

#endif

