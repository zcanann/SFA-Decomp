#include "main/dll/landedArwing.h"
#include "main/game_object.h"
#include "main/dll/treasurechest_state.h"
#include "main/objanim.h"
#include "main/objseq.h"
#include "main/objfx.h"
#include "main/object_descriptor.h"

typedef struct DllD3Placement {
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x2E - 0x14];
    u8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} DllD3Placement;


extern u32 randomGetRange(int min, int max);
extern void *Obj_GetPlayerObject(void);
extern int ObjContact_AddCallback(int *obj, int p2, void *cb);
extern int ObjList_FindNearestObjectByDefNo(int *obj, int defNo, f32 *radius);
extern int objBboxFn_800640cc(int a, f32 *pos, f32 b, int c, int *out, int *obj, int e, int g, int h, int i);
extern void objRenderFn_8003b8f4(f32);
extern void ObjHits_DisableObject(int obj);
extern f32 sqrtf(f32);
extern void *memset(void *dst, int val, u32 size);

extern ObjectTriggerInterface **gObjectTriggerInterface;
extern int *gBaddieControlInterface;
extern int *gPlayerInterface;

extern int lbl_803202E8[];
extern int lbl_80320360[];
extern int lbl_803AC638[];
extern void *gLandedArwingStateHandlers[];
extern void *gLandedArwingDefaultStateHandler;

extern f32 timeDelta;
extern double lbl_803E3040;
extern f32 lbl_803E3030;
extern f32 lbl_803E3034;
extern f32 lbl_803E3038;
extern f32 lbl_803E3048;
extern f32 lbl_803E3058;
extern f32 lbl_803E2FDC;
extern f32 lbl_803E2FF4;

extern void fn_801659B8(void);
extern void LandedArwing_UpdateRetreatChase(void);
extern void LandedArwing_UpdateBounceFade(void);
extern void LandedArwing_TriggerLaunchTarget(void);
extern void LandedArwing_ReturnZero(void);

extern void skeetlawall_setScale(int *obj, f32 *outVec, u8 *outByte);
extern void fn_80167550(int *obj);

/*
 * --INFO--
 *
 * Function: dll_D3_update
 * EN v1.0 Address: 0x80166F2C
 * EN v1.0 Size: 1228b
 */
void dll_D3_update(int *obj)
{
    int trans;
    int *state;
    LandedArwingState *extra;
    int *player;
    int iVar3;
    int rc;
    int hits;
    f32 local_90;
    f32 local_8c;
    f32 local_88;
    f32 local_84;
    int aiStack_80[20];
    char local_30;

    trans = *(int *)&((GameObject *)obj)->anim.placementData;
    state = ((GameObject *)obj)->extra;
    extra = *(LandedArwingState **)((char *)state + 0x40c);
    player = (int *)Obj_GetPlayerObject();
    local_90 = lbl_803E3034;

    if (extra->boundsObj == NULL) {
        extra->surfaceMode = 6;
        if (((u32)extra->flags92 >> 4) != 0) {
            *(int *)&extra->boundsObj = ObjList_FindNearestObjectByDefNo(obj, 0x4ad, &local_90);
            if (extra->boundsObj != NULL) {
                (*(void (**)(int, int, int))(*(int **)(*(int *)&extra->boundsObj + 0x68) + 0x20 / 4))(
                    *(int *)&extra->boundsObj,
                    (int)&extra->boundsMinX,
                    (int)&extra->bounceFlags);
                extra->surfaceMode = 5;
            }
            extra->flags92 =
                (u8)((((extra->flags92 >> 4) - 1) << 4) |
                     (extra->flags92 & 0xf));
        }
    }

    if (((GameObject *)obj)->unkF4 != 0) return;

    if (((GameObject *)obj)->unkF8 == 0) {
        ((GameObject *)obj)->anim.localPosX  = ((DllD3Placement *)trans)->unk8;
        ((GameObject *)obj)->anim.localPosY = ((DllD3Placement *)trans)->unkC;
        ((GameObject *)obj)->anim.localPosZ = ((DllD3Placement *)trans)->unk10;
        (*gObjectTriggerInterface)->runSequence((s8)((DllD3Placement *)trans)->unk2E, obj, -1);
        ((GameObject *)obj)->unkF8 = 1;
        return;
    }

    rc = ((int (*)(int *, int *, int))((void **)*(int *)gBaddieControlInterface)[0x30 / 4])(obj, state, 0);
    if (rc == 0) return;

    if ((extra->flags92 & 2) == 0) {
        if (ObjContact_AddCallback(obj, (int)player, fn_80167550) != 0) {
            extra->flags92 =
                (u8)((extra->flags92 & 0xfd) | 2);
        }
    }

    ((int (*)(int, f32, f32, void *))ObjAnim_AdvanceCurrentMove)((int)obj, extra->animSpeed, timeDelta, NULL);

    if (((TreasureChestState *)state)->targetState != 1) {
        rc = ((int (*)(f32, int *, int *, int))((void **)*(int *)gBaddieControlInterface)[0x48 / 4])(
            (f32)((double)(u32)((TreasureChestState *)state)->aggroRange - lbl_803E3040),
            obj, state, 0x18000);
        if (rc != 0) {
            ((void (*)(int *, int *, int, int, int, int, int, int, int))((void **)*(int *)gBaddieControlInterface)[0x28 / 4])(
                obj, state,
                (int)state + 0x35c,
                (int)((TreasureChestState *)state)->gameBitB,
                0, 0, 1, 0, -1);
            ((TreasureChestState *)state)->targetObj = rc;
            ((TreasureChestState *)state)->unk349 = 0;
            ((TreasureChestState *)state)->targetState = 1;
            ((TreasureChestState *)state)->unk405 = 2;
        }
    }

    if (((TreasureChestState *)state)->targetObj != 0 &&
        ((TreasureChestState *)state)->targetState == 2) {
        if (((TreasureChestState *)state)->targetDistance <=
            (f32)((double)(u32)((TreasureChestState *)state)->aggroRange - lbl_803E3040)) {
            ((TreasureChestState *)state)->targetState = 1;
        }
    }

    if (((TreasureChestState *)state)->targetObj != 0) {
        local_8c = *(f32 *)((char *)(((TreasureChestState *)state)->targetObj) + 0x18) -
                   ((GameObject *)obj)->anim.worldPosX;
        local_88 = *(f32 *)((char *)(((TreasureChestState *)state)->targetObj) + 0x1c) -
                   ((GameObject *)obj)->anim.worldPosY;
        local_84 = *(f32 *)((char *)(((TreasureChestState *)state)->targetObj) + 0x20) -
                   ((GameObject *)obj)->anim.worldPosZ;
        ((TreasureChestState *)state)->targetDistance =
            sqrtf(local_8c * local_8c + local_88 * local_88 + local_84 * local_84);
    }

    ((void (*)(int *, int *, int, int, int, int, int, int))((void **)*(int *)gBaddieControlInterface)[0x54 / 4])(
        obj, state,
        (int)((char *)state + 0x35c),
        (int)((TreasureChestState *)state)->gameBitB,
        0, 0, 0, 0);

    hits = (int)((TreasureChestState *)state)->hitPoints;
    if (hits > 0) {
        ((void (*)(int *, int *, int, int, int *, int *, int, int *))((void **)*(int *)gBaddieControlInterface)[0x50 / 4])(
            obj, state,
            (int)((char *)state + 0x35c),
            (int)((TreasureChestState *)state)->gameBitB,
            lbl_803202E8, lbl_80320360, 0, lbl_803AC638);
        if ((int)((TreasureChestState *)state)->hitPoints < hits) {
            (*(void (**)(void))(*(int **)(*(int *)&((GameObject *)player)->unkC8 + 0x68) + 0x50 / 4))();
            *(f32 *)((char *)lbl_803AC638 + 0xc)  = ((GameObject *)obj)->anim.localPosX;
            *(f32 *)((char *)lbl_803AC638 + 0x10) = ((GameObject *)obj)->anim.localPosY;
            *(f32 *)((char *)lbl_803AC638 + 0x14) = ((GameObject *)obj)->anim.localPosZ;
            objLightFn_8009a1dc(obj, lbl_803E3038, lbl_803AC638, 1, 0);
        }
    }

    ((void (*)(int *, int *, f32, int))((void **)*(int *)gBaddieControlInterface)[0x2c / 4])(
        obj, state, lbl_803E2FDC, -1);

    ((TreasureChestState *)state)->savedObjC0 = *(int *)&((GameObject *)obj)->unkC0;
    *(int *)&((GameObject *)obj)->unkC0 = 0;

    ((void (*)(f32, f32, int *, int *, void **, void *))((void **)*(int *)gPlayerInterface)[8 / 4])(
        timeDelta, timeDelta, obj, state, gLandedArwingStateHandlers, &gLandedArwingDefaultStateHandler);

    *(int *)&((GameObject *)obj)->unkC0 = ((TreasureChestState *)state)->savedObjC0;

    if ((extra->flags92 & 1) == 0 &&
        extra->surfaceMode == 6) {
        iVar3 = objBboxFn_800640cc(
            (int)((char *)obj + 0x80),
            &((GameObject *)obj)->anim.localPosX,
            lbl_803E3030, 0,
            aiStack_80, obj, -0x7c, -1, 0xff, 0);
        if (iVar3 != 0 && local_30 == 13) {
            extra->flags92 =
                (u8)((extra->flags92 & 0xfe) | 1);
            *(s16 *)&extra->scriptTimer = (s16)(randomGetRange(10, 0xf) * 0x3c);
        }
    }
}

/*
 * --INFO--
 *
 * Function: dll_D3_init
 * EN v1.0 Address: 0x801673F8
 * EN v1.0 Size: 344b
 */
void dll_D3_init(int obj, int def, int flag)
{
    int state;
    LandedArwingState *extra;
    u8 setupFlags;
    f32 fz;
    s16 ftag;

    state = *(int *)&((GameObject *)obj)->extra;
    setupFlags = 6;
    if (flag != 0) {
        setupFlags |= 1;
    }
    ((void (*)(int, int, int, int, int, int, int, f32))((void **)*(int *)gBaddieControlInterface)[22])
        (obj, def, state, 5, 1, 0x108, setupFlags, lbl_803E3048);
    ((GameObject *)obj)->animEventCallback = NULL;

    extra = *(LandedArwingState **)(state + 0x40c);
    memset((void *)extra, 0, 0x94);
    extra->surfaceMode = 5;
    extra->flags92 = (extra->flags92 & 0xf) | 0x30;
    fz = lbl_803E2FDC;
    extra->surfaceNormalX = fz;
    extra->surfaceNormalY = lbl_803E2FF4;
    extra->surfaceNormalZ = fz;
    extra->surfacePlaneD = -((GameObject *)obj)->anim.localPosY;
    extra->scriptTargetX = ((GameObject *)obj)->anim.localPosX;
    extra->scriptTargetY = ((GameObject *)obj)->anim.localPosY;
    extra->scriptTargetZ = ((GameObject *)obj)->anim.localPosZ;

    ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
    if (*(u8 *)(def + 0x2b) != 0) {
        ftag = 1;
    } else {
        ftag = 0;
    }
    ((TreasureChestState *)state)->controlMode = ftag;
    ((TreasureChestState *)state)->unk270 = 0;
    ((TreasureChestState *)state)->targetState = 0;
    ((TreasureChestState *)state)->unk405 = 0;
    ((TreasureChestState *)state)->unk25F = 0;
    ObjHits_DisableObject(obj);

    fz = lbl_803E2FF4;
    extra->unk_04 = fz;
    extra->unk_18 = fz;
    extra->unk_2C = fz;
    extra->unk_40 = fz;
}

void dll_D3_initialise(void)
{
    gLandedArwingStateHandlers[0] = fn_801659B8;
    gLandedArwingStateHandlers[1] = LandedArwing_UpdateFlightChase;
    gLandedArwingStateHandlers[2] = LandedArwing_UpdateRetreatChase;
    gLandedArwingStateHandlers[3] = LandedArwing_UpdateBounceFade;
    gLandedArwingStateHandlers[4] = LandedArwing_TriggerLaunchTarget;
    gLandedArwingDefaultStateHandler = LandedArwing_ReturnZero;
}


/* Trivial 4b 0-arg blr leaves. */
void dll_D3_release_nop(void) {}
void skeetlawall_free(void) {}
void skeetlawall_hitDetect(void) {}
void skeetlawall_update(void) {}
void skeetlawall_release(void) {}
void skeetlawall_initialise(void) {}

/* 8b "li r3, N; blr" returners. */
int skeetlawall_getExtraSize(void) { return 0x7; }
int skeetlawall_getObjectTypeId(void) { return 0x0; }

typedef struct SkeetlaWallState {
    u8 negXExtent;
    u8 posXExtent;
    u8 posZExtent;
    u8 negZExtent;
    u8 posYExtent;
    u8 negYExtent;
    u8 shapeFlag;
} SkeetlaWallState;

void skeetlawall_render(int obj, int p2, int p3, int p4, int p5, s8 visible) {
    if (visible != 0) {
        switch (((GameObject *)obj)->unkF4) {
        case 0:
            ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E3058);
            break;
        }
    }
}

void skeetlawall_init(int obj, u8 *def) {
    SkeetlaWallState *state = ((GameObject *)obj)->extra;
    state->negXExtent = def[0x18];
    state->posXExtent = def[0x19];
    state->posZExtent = def[0x1A];
    state->negZExtent = def[0x1B];
    state->posYExtent = def[0x1C];
    state->negYExtent = def[0x1D];
    state->shapeFlag = def[0x1E];
}

ObjectDescriptor11WithPadding gSkeetlaWallObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)skeetlawall_initialise,
        (ObjectDescriptorCallback)skeetlawall_release,
        0,
        (ObjectDescriptorCallback)skeetlawall_init,
        (ObjectDescriptorCallback)skeetlawall_update,
        (ObjectDescriptorCallback)skeetlawall_hitDetect,
        (ObjectDescriptorCallback)skeetlawall_render,
        (ObjectDescriptorCallback)skeetlawall_free,
        (ObjectDescriptorCallback)skeetlawall_getObjectTypeId,
        skeetlawall_getExtraSize,
        (ObjectDescriptorCallback)skeetlawall_setScale,
    },
    0,
};

void fn_80167550(int *obj) {
    int *state = ((GameObject *)obj)->extra;
    ((void (*)(int *, int *, int))((void **)*gPlayerInterface)[5])(obj, state, 2);
}

void skeetlawall_setScale(int *obj, f32 *outVec, u8 *outByte) {
    SkeetlaWallState *state = ((GameObject *)obj)->extra;
    outVec[0] = ((GameObject *)obj)->anim.worldPosX - (f32)(u32)state->negXExtent;
    outVec[1] = ((GameObject *)obj)->anim.worldPosX + (f32)(u32)state->posXExtent;
    outVec[2] = ((GameObject *)obj)->anim.worldPosZ + (f32)(u32)state->posZExtent;
    outVec[3] = ((GameObject *)obj)->anim.worldPosZ - (f32)(u32)state->negZExtent;
    outVec[4] = ((GameObject *)obj)->anim.worldPosY + (f32)(u32)state->posYExtent;
    outVec[5] = ((GameObject *)obj)->anim.worldPosY - (f32)(u32)state->negYExtent;
    outByte[0] = state->shapeFlag;
}
