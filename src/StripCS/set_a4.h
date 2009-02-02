#ifndef __SET_A4_H
#define __SET_A4_H

register void *reg_a4 asm("%a4");

#define SET_A4_FROM_A5 \
    void *save_a4 = reg_a4; asm("moveal %a5,%a4; subal #edata,%a4");
#define SET_A4_FROM_FTR(id, num) \
    void *save_a4 = reg_a4, *my_a4; FtrGet(id, num, (DWord *) &my_a4); \
    reg_a4 = my_a4;
#define SET_A4_FOR_GLIB(id) \
    void *save_a4; struct LibRef *my_libref; FtrGet(id, 0, (DWord *) \
    &my_libref); reg_a4 = my_libref->globals;
#define RESTORE_A4 reg_a4 = save_a4;

/* return the size of the data segment in a ULong variable */
#define RETURN_DATA_SIZE(datasize) asm("movel #edata,%0" : "=g" (datasize) :)

#endif
