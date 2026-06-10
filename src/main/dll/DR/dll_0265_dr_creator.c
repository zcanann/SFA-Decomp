#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"
#include "main/objseq.h"

void drcreator_free(void) {}

int drcreator_getExtraSize(void) { return 0x1c; }

int drcreator_getObjectTypeId(void) { return 0x0; }

void drcreator_hitDetect(void) {}

void drcreator_initialise(void) {}

void drcreator_release(void) {}

void drcreator_render(void) {}

void drcreator_init(int obj, char *arg) {
    char *p = ((GameObject *)obj)->extra;
    *(s16 *)obj = (s16)((s8)arg[0x1e] << 8);
    *(s16 *)(p + 0x4) = *(s16 *)(arg + 0x18);
    *(s16 *)(p + 0x6) = *(s16 *)(arg + 0x1c);
    *(s16 *)(p + 0x8) = (s16)randomGetRange(0, *(s16 *)(p + 0x6));
    *(s16 *)(p + 0xa) = (s8)arg[0x1f];
    *(int *)p = (u8)arg[0x20];
    ((BitFlags8 *)(p + 0x18))->b0 = 1;
    GameBit_Set(0x5dd, 0);
    ((GameObject *)obj)->animEventCallback = (void *)drcreator_spawnProjectileCallback;
}

void drcreator_update(int obj) {
    int q = *(int *)&((GameObject *)obj)->anim.placementData;
    char *runtime = ((GameObject *)obj)->extra;
    int o;
    char *p;
    if (Obj_IsLoadingLocked() != 0) {
        switch (*(s16 *)(q + 0x1a)) {
        case 3:
        case 9:
            if (GameBit_Get(*(s16 *)(runtime + 4)) != 0) {
                (*gObjectTriggerInterface)
                    ->runSequence((*(s16 *)(q + 0x1a) == 3) ? 0 : 4, (void *)obj, -1);
            }
            break;
        case 4:
            if (GameBit_Get(*(s16 *)(runtime + 4)) != 0) {
                *(s16 *)(runtime + 8) -= framesThisStep;
                if (*(s16 *)(runtime + 8) <= 0) {
                    o = Obj_AllocObjectSetup(36, 1725);
                    *(f32 *)(o + 8) = ((GameObject *)obj)->anim.localPosX;
                    *(f32 *)(o + 0xc) = ((GameObject *)obj)->anim.localPosY;
                    *(f32 *)(o + 0x10) = ((GameObject *)obj)->anim.localPosZ;
                    *(u8 *)(o + 4) = 1;
                    *(u8 *)(o + 5) = 1;
                    *(u8 *)(o + 6) = 255;
                    *(u8 *)(o + 7) = 250;
                    if (((GameObject *)obj)->anim.mapEventSlot == 2) {
                        *(u8 *)(o + 0x19) = 4;
                    } else {
                        *(u8 *)(o + 0x19) = 1;
                    }
                    p = (char *)Obj_SetupObject(o, 5, -1, -1, 0);
                    if (p != NULL) {
                        *(s16 *)(p + 2) = 0;
                        *(s16 *)p = (s16)randomGetRange(0, 65535);
                        *(f32 *)(p + 0x24) = lbl_803E69B8 * (lbl_803E69BC * ((f32)*(int *)runtime * -mathSinf((lbl_803E69C0 * (f32)*(s16 *)obj) / lbl_803E69C4)));
                        *(f32 *)(p + 0x28) = lbl_803E69B8 * ((f32)*(int *)runtime * (lbl_803E69C8 * (f32)(int)randomGetRange(0, 1000)));
                        *(f32 *)(p + 0x2c) = lbl_803E69B8 * (lbl_803E69BC * ((f32)*(int *)runtime * -mathCosf((lbl_803E69C0 * (f32)*(s16 *)obj) / lbl_803E69C4)));
                        *(int *)(p + 0xc4) = obj;
                    }
                    *(s16 *)(runtime + 8) = *(s16 *)(runtime + 6) + randomGetRange(0, *(s16 *)(runtime + 0xa));
                }
            }
            break;
        }
    }
}

int drcreator_spawnProjectileCallback(int obj, int unused, ObjAnimUpdateState *animUpdate) {
    int i;
    int q = *(int *)&((GameObject *)obj)->anim.placementData;
    char *runtime;
    int o;
    int p;
    fn_80137948(sDrCreatorTimeFormat, *(s16 *)(q + 0x1a), *(s16 *)((u8 *)animUpdate + 0x58));
    if (Obj_IsLoadingLocked() == 0) {
        return 0;
    }
    for (i = 0; i < animUpdate->eventCount; i++) {
        switch (*(s16 *)(q + 0x1a)) {
        case 3:
        case 4:
        case 9:
            runtime = ((GameObject *)obj)->extra;
            if (GameBit_Get(*(s16 *)(runtime + 4)) != 0) {
                o = Obj_AllocObjectSetup(36, 1725);
                *(f32 *)(o + 8) = ((GameObject *)obj)->anim.localPosX;
                *(f32 *)(o + 0xc) = ((GameObject *)obj)->anim.localPosY;
                *(f32 *)(o + 0x10) = ((GameObject *)obj)->anim.localPosZ;
                *(u8 *)(o + 4) = 1;
                *(u8 *)(o + 5) = 1;
                *(u8 *)(o + 6) = 255;
                *(u8 *)(o + 7) = 255;
                *(u8 *)(o + 0x19) = 2;
                p = Obj_SetupObject(o, 5, -1, -1, 0);
                if ((void *)p != NULL) {
                    *(s16 *)(p + 2) = 0;
                    *(s16 *)p = (s16)randomGetRange(0, 65535);
                    *(f32 *)(p + 0x24) = lbl_803E69A8 * (f32)(int)randomGetRange(-*(s16 *)(runtime + 0xa), *(s16 *)(runtime + 0xa));
                    *(f32 *)(p + 0x28) = lbl_803E69A8 * (f32)*(int *)runtime;
                    *(f32 *)(p + 0x2c) = lbl_803E69A8 * (f32)(int)randomGetRange(-*(s16 *)(runtime + 0xa), *(s16 *)(runtime + 0xa));
                    *(int *)(p + 0xc4) = obj;
                }
            }
            break;
        }
    }
    return 0;
}
