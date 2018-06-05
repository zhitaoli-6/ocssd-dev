#include <cstdio>

#define SUCCESS 0

#define ENOEXIST -1
#define ETOOLARGE -2
#define ENOSUPPORT -3
#define EDOEXIST -4
#define EPUTFAIL -5
#define EGETFAIL -6


#define ENOMEMORY -7
#define ENOSPACE -8

#define ESETUP -9



char* oss_perror(int eno, char* errstr){
    switch (eno){
        case ENOEXIST:
            sprintf(errstr, "errstr: entry not exist");
            break;
        case ETOOLARGE:
            sprintf(errstr, "errstr: entry too large");
            break;
        case ENOSUPPORT:
            sprintf(errstr, "errstr: op not supported now");
            break;
        case EDOEXIST:
            sprintf(errstr, "errstr: entry has exist");
            break;
        case EPUTFAIL:
            sprintf(errstr, "errstr: entry put fails");
            break;
        case EGETFAIL:
            sprintf(errstr, "errstr: entry get fails");
            break;
        case ENOMEMORY:
            sprintf(errstr, "errstr: host doesn't have enough memory");
            break;
        case ENOSPACE:
            sprintf(errstr, "errstr: device doesn't have enough space");
            break;
        case ESETUP:
            sprintf(errstr, "errstr: device setup fails");
            break;
        default:
            sprintf(errstr, "errstr: unknown errno %d", eno);
    }
    return errstr;
}

