#include "ghidra_import.h"
#include "main/dll/NW/NWsfx.h"

extern undefined8 ObjGroup_RemoveObject();

/*
 * --INFO--
 *
 * Function: ediblemushroom_free
 * EN v1.0 Address: 0x801D1564
 * EN v1.0 Size: 60b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
void ediblemushroom_free(int obj) {
    ObjGroup_RemoveObject(obj, 0x47);
    ObjGroup_RemoveObject(obj, 0x31);
}
#pragma pop

/*
 * --INFO--
 *
 * Function: ediblemushroom_getExtraSize
 * EN v1.0 Address: 0x801D155C
 * EN v1.0 Size: 8b
 */
int ediblemushroom_getExtraSize(void) {
    return 0x144;
}
