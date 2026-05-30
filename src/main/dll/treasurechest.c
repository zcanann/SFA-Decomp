#include "ghidra_import.h"
#include "main/object_descriptor.h"

extern u32 randomGetRange(int min, int max);
extern void *Obj_GetPlayerObject(void);
extern int ObjContact_AddCallback(int *obj, int p2, void *cb);
extern int ObjList_FindNearestObjectByDefNo(int *obj, int defNo, f32 *radius);
extern int objBboxFn_800640cc(int a, f32 *pos, f32 b, int c, int *out, int *obj, int e, int g, int h, int i);
extern void objLightFn_8009a1dc(int *obj, f32 a, int b, int c);
extern void objRenderFn_8003b8f4(f32);
extern void ObjAnim_AdvanceCurrentMove(int *obj, int a, f32 b, f32 c);
extern void ObjAnim_SetCurrentMove(int obj, int move, f32 progress, int flags);
extern void ObjHits_DisableObject(int obj);
extern f32 sqrtf(f32);
extern void *memset(void *dst, int val, u32 size);

extern int *gObjectTriggerInterface;
extern int *gBaddieControlInterface;
extern int *gPlayerInterface;

extern int lbl_803202E8[];
extern int lbl_80320360[];
extern int lbl_803AC638[];
extern void *lbl_803AC650[];
extern void *lbl_803DDA88;

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
extern void LandedArwing_UpdateFlightChase(void);
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
#pragma scheduling off
#pragma peephole off
void dll_D3_update(int *obj)
{
    int trans;
    int *state;
    int *extra;
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

    trans = *(int *)((char *)obj + 0x4c);
    state = *(int **)((char *)obj + 0xb8);
    extra = *(int **)((char *)state + 0x40c);
    player = (int *)Obj_GetPlayerObject();
    local_90 = lbl_803E3034;

    if (*(int *)extra == 0) {
        *(u8 *)((char *)extra + 0x90) = 6;
        if ((*(u8 *)((char *)extra + 0x92) >> 4) != 0) {
            iVar3 = ObjList_FindNearestObjectByDefNo(obj, 0x4ad, &local_90);
            *(int *)extra = iVar3;
            if (iVar3 != 0) {
                (*(void (**)(int, int, int))(*(int **)(*(int *)extra + 0x68) + 0x20 / 4))(
                    *(int *)extra,
                    (int)((char *)extra + 0x48),
                    (int)((char *)extra + 0x91));
                *(u8 *)((char *)extra + 0x90) = 5;
            }
            *(u8 *)((char *)extra + 0x92) =
                (u8)((((*(u8 *)((char *)extra + 0x92) >> 4) - 1) << 4) |
                     (*(u8 *)((char *)extra + 0x92) & 0xf));
        }
    }

    if (*(int *)((char *)obj + 0xf4) != 0) return;

    if (*(int *)((char *)obj + 0xf8) == 0) {
        *(f32 *)((char *)obj + 0xc)  = *(f32 *)((char *)trans + 0x8);
        *(f32 *)((char *)obj + 0x10) = *(f32 *)((char *)trans + 0xc);
        *(f32 *)((char *)obj + 0x14) = *(f32 *)((char *)trans + 0x10);
        (*(void (**)(int, int *, int))((void **)*(int *)gObjectTriggerInterface)[0x48 / 4])(
            (int)*(s8 *)((char *)trans + 0x2e), obj, -1);
        *(int *)((char *)obj + 0xf8) = 1;
        return;
    }

    rc = ((int (*)(int *, int *, int))((void **)*(int *)gBaddieControlInterface)[0x30 / 4])(obj, state, 0);
    if (rc == 0) return;

    if ((*(u8 *)((char *)extra + 0x92) & 2) == 0) {
        if (ObjContact_AddCallback(obj, (int)player, fn_80167550) != 0) {
            *(u8 *)((char *)extra + 0x92) =
                (u8)((*(u8 *)((char *)extra + 0x92) & 0xfd) | 2);
        }
    }

    ObjAnim_AdvanceCurrentMove(obj, 0, *(f32 *)((char *)extra + 0x44), timeDelta);

    if (*(s16 *)((char *)state + 0x402) != 1) {
        rc = ((int (*)(f32, int *, int *, int))((void **)*(int *)gBaddieControlInterface)[0x48 / 4])(
            (f32)((double)(u32)*(u16 *)((char *)state + 0x3fe) - lbl_803E3040),
            obj, state, 0x18000);
        if (rc != 0) {
            ((void (*)(int *, int *, int, int, int, int, int, int, int))((void **)*(int *)gBaddieControlInterface)[0x28 / 4])(
                obj, state,
                (int)((char *)state + 0x35c),
                (int)*(s16 *)((char *)state + 0x3f4),
                0, 0, 1, 0, -1);
            *(int *)((char *)state + 0x2d0) = rc;
            *(u8 *)((char *)state + 0x349) = 0;
            *(s16 *)((char *)state + 0x402) = 1;
            *(u8 *)((char *)state + 0x405) = 2;
        }
    }

    if (*(int *)((char *)state + 0x2d0) != 0 &&
        *(s16 *)((char *)state + 0x402) == 2) {
        if (*(f32 *)((char *)state + 0x2c0) <=
            (f32)((double)(u32)*(u16 *)((char *)state + 0x3fe) - lbl_803E3040)) {
            *(s16 *)((char *)state + 0x402) = 1;
        }
    }

    if (*(int *)((char *)state + 0x2d0) != 0) {
        local_8c = *(f32 *)((char *)(*(int *)((char *)state + 0x2d0)) + 0x18) -
                   *(f32 *)((char *)obj + 0x18);
        local_88 = *(f32 *)((char *)(*(int *)((char *)state + 0x2d0)) + 0x1c) -
                   *(f32 *)((char *)obj + 0x1c);
        local_84 = *(f32 *)((char *)(*(int *)((char *)state + 0x2d0)) + 0x20) -
                   *(f32 *)((char *)obj + 0x20);
        *(f32 *)((char *)state + 0x2c0) =
            sqrtf(local_8c * local_8c + local_88 * local_88 + local_84 * local_84);
    }

    ((void (*)(int *, int *, int, int, int, int, int, int))((void **)*(int *)gBaddieControlInterface)[0x54 / 4])(
        obj, state,
        (int)((char *)state + 0x35c),
        (int)*(s16 *)((char *)state + 0x3f4),
        0, 0, 0, 0);

    hits = (int)*(s8 *)((char *)state + 0x354);
    if (hits > 0) {
        ((void (*)(int *, int *, int, int, int *, int *, int, int *))((void **)*(int *)gBaddieControlInterface)[0x50 / 4])(
            obj, state,
            (int)((char *)state + 0x35c),
            (int)*(s16 *)((char *)state + 0x3f4),
            lbl_803202E8, lbl_80320360, 0, lbl_803AC638);
        if ((int)*(s8 *)((char *)state + 0x354) < hits) {
            (*(void (**)(void))(*(int **)(*(int *)((char *)player + 0xc8) + 0x68) + 0x50 / 4))();
            *(f32 *)((char *)lbl_803AC638 + 0xc)  = *(f32 *)((char *)obj + 0xc);
            *(f32 *)((char *)lbl_803AC638 + 0x10) = *(f32 *)((char *)obj + 0x10);
            *(f32 *)((char *)lbl_803AC638 + 0x14) = *(f32 *)((char *)obj + 0x14);
            objLightFn_8009a1dc(obj, lbl_803E3038, 1, 0);
        }
    }

    ((void (*)(int *, int *, f32, int))((void **)*(int *)gBaddieControlInterface)[0x2c / 4])(
        obj, state, lbl_803E2FDC, -1);

    *(int *)((char *)state + 0x3e0) = *(int *)((char *)obj + 0xc0);
    *(int *)((char *)obj + 0xc0) = 0;

    ((void (*)(f32, f32, int *, int *, void **, void *))((void **)*(int *)gPlayerInterface)[8 / 4])(
        timeDelta, timeDelta, obj, state, lbl_803AC650, &lbl_803DDA88);

    *(int *)((char *)obj + 0xc0) = *(int *)((char *)state + 0x3e0);

    if ((*(u8 *)((char *)extra + 0x92) & 1) == 0 &&
        *(u8 *)((char *)extra + 0x90) == 6) {
        iVar3 = objBboxFn_800640cc(
            (int)((char *)obj + 0x80),
            (f32 *)((char *)obj + 0xc),
            lbl_803E3030, 0,
            aiStack_80, obj, -0x7c, -1, 0xff, 0);
        if (iVar3 != 0 && local_30 == 13) {
            *(u8 *)((char *)extra + 0x92) =
                (u8)((*(u8 *)((char *)extra + 0x92) & 0xfe) | 1);
            *(s16 *)((char *)extra + 0x8e) = (s16)(randomGetRange(10, 0xf) * 0x3c);
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

/*
 * --INFO--
 *
 * Function: dll_D3_init
 * EN v1.0 Address: 0x801673F8
 * EN v1.0 Size: 344b
 */
#pragma scheduling off
#pragma peephole off
void dll_D3_init(int obj, int def, int flag)
{
    int state;
    int extra;
    u8 setupFlags;
    f32 zero;

    state = *(int *)(obj + 0xb8);
    setupFlags = 6;
    if (flag != 0) {
        setupFlags |= 1;
    }
    ((void (*)(int, int, int, int, int, int, int, f32))((void **)*(int *)gBaddieControlInterface)[22])
        (obj, def, state, 5, 1, 0x108, setupFlags, lbl_803E3048);
    *(int *)(obj + 0xbc) = 0;

    extra = *(int *)(state + 0x40c);
    memset((void *)extra, 0, 0x94);
    *(u8 *)(extra + 0x90) = 5;
    *(u8 *)(extra + 0x92) = (*(u8 *)(extra + 0x92) & 0xf) | 0x30;
    *(f32 *)(extra + 0x7c) = lbl_803E2FDC;
    *(f32 *)(extra + 0x80) = lbl_803E2FF4;
    *(f32 *)(extra + 0x84) = lbl_803E2FDC;
    *(f32 *)(extra + 0x88) = -*(f32 *)(obj + 0x10);
    *(f32 *)(extra + 0x70) = *(f32 *)(obj + 0xc);
    *(f32 *)(extra + 0x74) = *(f32 *)(obj + 0x10);
    *(f32 *)(extra + 0x78) = *(f32 *)(obj + 0x14);

    ObjAnim_SetCurrentMove(obj, 0, 0.0f, 0);
    *(s16 *)(state + 0x274) = *(u8 *)(def + 0x2b) != 0;
    *(s16 *)(state + 0x270) = 0;
    *(s16 *)(state + 0x402) = 0;
    *(u8 *)(state + 0x405) = 0;
    *(u8 *)(state + 0x25f) = 0;
    ObjHits_DisableObject(obj);

    zero = lbl_803E2FF4;
    *(f32 *)(extra + 4) = zero;
    *(f32 *)(extra + 0x18) = zero;
    *(f32 *)(extra + 0x2c) = zero;
    *(f32 *)(extra + 0x40) = zero;
}
#pragma peephole reset
#pragma scheduling reset

void dll_D3_initialise(void)
{
    lbl_803AC650[0] = fn_801659B8;
    lbl_803AC650[1] = LandedArwing_UpdateFlightChase;
    lbl_803AC650[2] = LandedArwing_UpdateRetreatChase;
    lbl_803AC650[3] = LandedArwing_UpdateBounceFade;
    lbl_803AC650[4] = LandedArwing_TriggerLaunchTarget;
    lbl_803DDA88 = LandedArwing_ReturnZero;
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

#pragma scheduling off
#pragma peephole off
void skeetlawall_render(int obj, int p2, int p3, int p4, int p5, s8 visible) {
    if (visible != 0) {
        if (*(int *)((char *)obj + 0xF4) == 0) {
            ((void(*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E3058);
        }
    }
}

void skeetlawall_init(int obj, u8 *def) {
    u8 *state = *(u8 **)((char *)obj + 0xB8);
    state[0] = def[0x18];
    state[1] = def[0x19];
    state[2] = def[0x1A];
    state[3] = def[0x1B];
    state[4] = def[0x1C];
    state[5] = def[0x1D];
    state[6] = def[0x1E];
}
#pragma peephole reset
#pragma scheduling reset

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

#pragma scheduling off
#pragma peephole off
void fn_80167550(int *obj) {
    int *state = *(int **)((char *)obj + 0xb8);
    ((void (*)(int *, int *, int))((void **)*gPlayerInterface)[5])(obj, state, 2);
}
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
void skeetlawall_setScale(int *obj, f32 *outVec, u8 *outByte) {
    u8 *state = *(u8 **)((char *)obj + 0xb8);
    outVec[0] = *(f32 *)((char *)obj + 0x18) - (f32)(u32)state[0];
    outVec[1] = *(f32 *)((char *)obj + 0x18) + (f32)(u32)state[1];
    outVec[2] = *(f32 *)((char *)obj + 0x20) + (f32)(u32)state[2];
    outVec[3] = *(f32 *)((char *)obj + 0x20) - (f32)(u32)state[3];
    outVec[4] = *(f32 *)((char *)obj + 0x1c) + (f32)(u32)state[4];
    outVec[5] = *(f32 *)((char *)obj + 0x1c) - (f32)(u32)state[5];
    outByte[0] = state[6];
}
#pragma peephole reset
#pragma scheduling reset
