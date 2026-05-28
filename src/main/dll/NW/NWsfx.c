#include "ghidra_import.h"
#include "main/dll/NW/NWsfx.h"

extern undefined8 ObjGroup_RemoveObject();
extern int hitDetectFn_80065e50(void *obj, f32 x, f32 y, f32 z, void *hitsOut, int p6, int p7);
extern int objBboxFn_800640cc(void *from, void *to, f32 radius, int mode, void *hit, void *obj,
                              int p7, int p8, int p9, int p10);

extern f32 lbl_803E5294;
extern f32 lbl_803E52DC;

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

/*
 * --INFO--
 *
 * Function: ediblemushroom_hitDetect
 * EN v1.0 Address: 0x801D15A0
 * EN v1.0 Size: 332b
 */
#pragma push
#pragma scheduling off
#pragma peephole off
void ediblemushroom_hitDetect(u8 *obj) {
    u8 *state;
    u8 *mapObj;
    int hitCount;
    f32 **hits;
    f32 **hitIter;
    int i;
    u8 bboxHit[0x54];

    state = *(u8 **)(obj + 0xb8);
    mapObj = *(u8 **)(obj + 0x4c);

    if (((*(u16 *)(obj + 0xb0) & 0x1000) == 0) &&
        (((state[0x137] & 8) != 0) || ((*(s16 *)(*(int *)(obj + 0x54) + 0x60) & 8) != 0))) {
        hitCount = hitDetectFn_80065e50(obj, *(f32 *)(obj + 0xc), *(f32 *)(obj + 0x10),
                                        *(f32 *)(obj + 0x14), &hits, 0, 0);
        hitIter = hits;
        if (hitCount > 0) {
            for (i = 0; i < hitCount; i++) {
                if (**hitIter < lbl_803E5294 + *(f32 *)(obj + 0x10)) {
                    *(f32 *)(obj + 0x10) = *hits[i];
                    break;
                }
                hitIter++;
            }
        }

        hitCount = objBboxFn_800640cc(obj + 0x80, obj + 0xc, lbl_803E52DC, 2, bboxHit, obj, 8,
                                      -1, 0xff, 0x14);
        if ((mapObj[0x18] == 4) && (hitCount != 0) && ((s8)bboxHit[0x50] == 13)) {
            state[0x137] |= 4;
        }
    }
}
#pragma pop
