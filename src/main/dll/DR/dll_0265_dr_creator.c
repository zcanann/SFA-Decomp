#include "main/dll/DR/dr_shared.h"
#include "main/game_object.h"
#include "main/objseq.h"

typedef struct DrcreatorPlacement {
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x20 - 0x1C];
} DrcreatorPlacement;


typedef struct DrcreatorSpawnProjectileCallbackPlacement {
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x20 - 0x1C];
} DrcreatorSpawnProjectileCallbackPlacement;


typedef struct DrcreatorSpawnProjectileCallbackState {
    u8 pad0[0x4 - 0x0];
    s16 unk4;
    u8 pad6[0xA - 0x6];
    s16 unkA;
    u8 padC[0x10 - 0xC];
} DrcreatorSpawnProjectileCallbackState;


typedef struct DrcreatorState {
    u8 pad0[0x2 - 0x0];
    s16 unk2;
    s16 unk4;
    s16 unk6;
    s16 unk8;
    s16 unkA;
    u8 padC[0x24 - 0xC];
    f32 unk24;
    f32 unk28;
    f32 unk2C;
    u8 pad30[0xC4 - 0x30];
    s32 unkC4;
} DrcreatorState;


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
    ((DrcreatorState *)p)->unk4 = *(s16 *)(arg + 0x18);
    ((DrcreatorState *)p)->unk6 = *(s16 *)(arg + 0x1c);
    ((DrcreatorState *)p)->unk8 = (s16)randomGetRange(0, ((DrcreatorState *)p)->unk6);
    ((DrcreatorState *)p)->unkA = (s8)arg[0x1f];
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
        switch (((DrcreatorPlacement *)q)->unk1A) {
        case 3:
        case 9:
            if (GameBit_Get(((DrcreatorState *)runtime)->unk4) != 0) {
                (*gObjectTriggerInterface)
                    ->runSequence((((DrcreatorPlacement *)q)->unk1A == 3) ? 0 : 4, (void *)obj, -1);
            }
            break;
        case 4:
            if (GameBit_Get(((DrcreatorState *)runtime)->unk4) != 0) {
                ((DrcreatorState *)runtime)->unk8 -= framesThisStep;
                if (((DrcreatorState *)runtime)->unk8 <= 0) {
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
                        ((DrcreatorState *)p)->unk2 = 0;
                        *(s16 *)p = (s16)randomGetRange(0, 65535);
                        ((DrcreatorState *)p)->unk24 = lbl_803E69B8 * (lbl_803E69BC * ((f32)*(int *)runtime * -mathSinf((lbl_803E69C0 * (f32)*(s16 *)obj) / lbl_803E69C4)));
                        ((DrcreatorState *)p)->unk28 = lbl_803E69B8 * ((f32)*(int *)runtime * (lbl_803E69C8 * (f32)(int)randomGetRange(0, 1000)));
                        ((DrcreatorState *)p)->unk2C = lbl_803E69B8 * (lbl_803E69BC * ((f32)*(int *)runtime * -mathCosf((lbl_803E69C0 * (f32)*(s16 *)obj) / lbl_803E69C4)));
                        ((DrcreatorState *)p)->unkC4 = obj;
                    }
                    ((DrcreatorState *)runtime)->unk8 = ((DrcreatorState *)runtime)->unk6 + randomGetRange(0, ((DrcreatorState *)runtime)->unkA);
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
        switch (((DrcreatorSpawnProjectileCallbackPlacement *)q)->unk1A) {
        case 3:
        case 4:
        case 9:
            runtime = ((GameObject *)obj)->extra;
            if (GameBit_Get(((DrcreatorSpawnProjectileCallbackState *)runtime)->unk4) != 0) {
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
                    *(f32 *)(p + 0x24) = lbl_803E69A8 * (f32)(int)randomGetRange(-((DrcreatorSpawnProjectileCallbackState *)runtime)->unkA, ((DrcreatorSpawnProjectileCallbackState *)runtime)->unkA);
                    *(f32 *)(p + 0x28) = lbl_803E69A8 * (f32)*(int *)runtime;
                    *(f32 *)(p + 0x2c) = lbl_803E69A8 * (f32)(int)randomGetRange(-((DrcreatorSpawnProjectileCallbackState *)runtime)->unkA, ((DrcreatorSpawnProjectileCallbackState *)runtime)->unkA);
                    *(int *)(p + 0xc4) = obj;
                }
            }
            break;
        }
    }
    return 0;
}
