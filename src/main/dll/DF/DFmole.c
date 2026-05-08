#include "ghidra_import.h"
#include "main/dll/DF/DFmole.h"

extern void fn_80023800(void *p);
extern void ObjGroup_RemoveObject(void *obj, int group);
extern int *ObjGroup_GetObjects(int group, int *count);

/*
 * --INFO--
 *
 * Function: dfropenode_free
 * EN v1.0 Address: 0x801C1EAC
 * EN v1.0 Size: 176b
 */
#pragma peephole off
#pragma scheduling off
void dfropenode_free(void *obj)
{
    void *node;
    int **objs;
    int count;
    int i;

    node = *(void **)((char *)obj + 0xb8);
    ObjGroup_RemoveObject(obj, 0x17);
    if (*(void **)((char *)node + 0x2c) != NULL && *(void **)((char *)node + 0x2c) != NULL) {
        fn_80023800(*(void **)((char *)node + 0x2c));
    }
    node = *(void **)node;
    if (node != NULL) {
        objs = (int **)ObjGroup_GetObjects(0x17, &count);
        for (i = 0; i < count; i++) {
            if ((void *)objs[i] == node) {
                (*(void (***)(void *))*(void **)((char *)node + 0x68))[17](node);
            }
        }
    }
}
#pragma scheduling reset
#pragma peephole reset
