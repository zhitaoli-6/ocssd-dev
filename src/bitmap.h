#ifndef BITMAP_HEADER
#define BITMAP_HEADER
typedef char bitmap_t;
#define bits (sizeof(bitmap_t)*8)

void set_bit(bitmap_t* map, int k){
    map[k/bits] |= (1<<(k%(bits)));
}
void clear_bit(bitmap_t* map, int k){
    map[k/bits] &= ~(1<<(k%bits));
}
int get_bit(bitmap_t* map, int k){
    return (1<<(k%bits)) & map[k/bits]; 
}
#endif
