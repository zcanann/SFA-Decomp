#include "main/dll/DF/DFmole.h"
#include "main/game_object.h"
#include "main/objlib.h"

extern void mm_free(void *p);

/*
 * --INFO--
 *
 * Function: dfropenode_free
 * EN v1.0 Address: 0x801C1EAC
 * EN v1.0 Size: 176b
 */
void dfropenode_free(void *obj)
{
    void *node;
    int **objs;
    int count;
    int i;

    node = ((GameObject *)obj)->extra;
    ObjGroup_RemoveObject((u32)obj, 0x17);
    if (*(void **)((char *)node + 0x2c) != NULL && *(void **)((char *)node + 0x2c) != NULL) {
        mm_free(*(void **)((char *)node + 0x2c));
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
