/* === moved from main/dll/DR/DRCloudball.c [801E9328-801E9344) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/DR/dll_0287_spscarab.h"
#include "main/dll/shwgpipe_struct.h"





extern void Sfx_PlayFromObject(int obj, int sfxId);

extern f32 timeDelta;

extern void spscarab_hitDetect(void);
extern void spscarab_render(void);
extern void spscarab_free(int x);
extern int spscarab_getObjectTypeId(void);
extern int spscarab_getExtraSize(void);

/*
 * --INFO--
 *
 * Function: spscarab_update
 * EN v1.0 Address: 0x801E8EE0
 * EN v1.0 Size: 588b
 */

/*
 * --INFO--
 *
 * Function: spscarab_init
 * EN v1.0 Address: 0x801E912C
 * EN v1.0 Size: 500b
 */

/*
 * --INFO--
 *
 * Function: spscarab_release
 * EN v1.0 Address: 0x801E9320
 * EN v1.0 Size: 4b
 */

/*
 * --INFO--
 *
 * Function: spscarab_initialise
 * EN v1.0 Address: 0x801E9324
 * EN v1.0 Size: 4b
 */

ObjectDescriptor gSPScarabObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)spscarab_initialise,
    (ObjectDescriptorCallback)spscarab_release,
    0,
    (ObjectDescriptorCallback)spscarab_init,
    (ObjectDescriptorCallback)spscarab_update,
    (ObjectDescriptorCallback)spscarab_hitDetect,
    (ObjectDescriptorCallback)spscarab_render,
    (ObjectDescriptorCallback)spscarab_free,
    (ObjectDescriptorCallback)spscarab_getObjectTypeId,
    spscarab_getExtraSize,
};

/*
 * --INFO--
 *
 * Function: spdrape_getExtraSize
 * EN v1.0 Address: 0x801E9328
 * EN v1.0 Size: 8b
 */
int spdrape_getExtraSize(void)
{
    return 0x18;
}

/*
 * --INFO--
 *
 * Function: spdrape_getObjectTypeId
 * EN v1.0 Address: 0x801E9330
 * EN v1.0 Size: 8b
 */
int spdrape_getObjectTypeId(void)
{
    return 0;
}

/*
 * --INFO--
 *
 * Function: spdrape_free
 * EN v1.0 Address: 0x801E9338
 * EN v1.0 Size: 4b
 */
void spdrape_free(void)
{
}

/*
 * --INFO--
 *
 * Function: spdrape_render
 * EN v1.0 Address: 0x801E933C
 * EN v1.0 Size: 4b
 */
void spdrape_render(void)
{
}

/*
 * --INFO--
 *
 * Function: spdrape_hitDetect
 * EN v1.0 Address: 0x801E9340
 * EN v1.0 Size: 4b
 */
void spdrape_hitDetect(void)
{
}

#include "main/objanim_internal.h"
#include "main/game_object.h"
#include "main/dll/DR/DRsimplehuman.h"



typedef struct SpdrapeObjectDef
{
    u8 pad0[0x18 - 0x0];
    s8 unk18;
    u8 pad19[0x1A - 0x19];
    s16 unk1A;
    u8 pad1C[0x20 - 0x1C];
} SpdrapeObjectDef;


typedef struct SpdrapeState
{
    u8 pad0[0x10 - 0x0];
    s32 unk10;
    s16 unk14;
    u8 unk16;
    u8 pad17[0x18 - 0x17];
} SpdrapeState;




/*
 * --INFO--
 *
 * Function: spdrape_update
 * EN v1.0 Address: 0x801E9344
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801E93B4
 * EN v1.1 Size: 312b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern void Sfx_PlayFromObject(int obj, int sfx);
extern void Sfx_StopObjectChannel(int obj, int channel);
extern void Camera_GetCurrentViewSlot(void);
extern f32 lbl_803DC0B0;
extern f32 lbl_803DC0B4;
extern byte framesThisStep;
extern f32 lbl_803E5AA0;
extern f32 lbl_803E5AA4;
extern f32 lbl_803E5AA8;
extern f32 lbl_803E5AAC;
extern f32 lbl_803E5AB0;
extern f32 lbl_803E5AB4;
extern f32 lbl_803E5AB8;
extern f32 lbl_803E5ABC;

void spdrape_update(int obj)
{
    extern f32 getXZDistance(f32 * a, f32 * b); /* #57 */
    extern void* Obj_GetPlayerObject(void); /* #57 */
    extern u32 randomGetRange(int min, int max); /* #57 */
    f32* state;
    char* player;

    state = ((GameObject*)obj)->extra;
    player = (char*)Obj_GetPlayerObject();
    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 0:
        if ((s16)(((SpdrapeState*)state)->unk14 -= framesThisStep) <= 0)
        {
            Sfx_PlayFromObject(obj, 0x13f);
            ((SpdrapeState*)state)->unk14 = randomGetRange(0xb4, 300);
        }
        if (getXZDistance(&((GameObject*)obj)->anim.worldPosX, (f32*)(player + 0x18)) < lbl_803E5AA4)
        {
            if (player != 0)
            {
                if (state[3] + (state[1] * *(f32*)(player + 0xc) + state[2] * *(f32*)(player + 0x14)) < lbl_803E5AA0)
                {
                    ((SpdrapeState*)state)->unk10 = (int)&lbl_803DC0B0;
                }
                else
                {
                    ((SpdrapeState*)state)->unk10 = (int)&lbl_803DC0B4;
                }
            }
            ObjAnim_SetCurrentMove(obj, **(u8**)&((SpdrapeState*)state)->unk10, lbl_803E5AA0, 0);
            *state = lbl_803E5AA8;
            Sfx_PlayFromObject(obj, 0x140);
            Camera_GetCurrentViewSlot();
        }
        break;
    case 1:
    case 4:
        if (((SpdrapeState*)state)->unk16 != 0)
        {
            if (getXZDistance(&((GameObject*)obj)->anim.worldPosX, (f32*)(player + 0x18)) > lbl_803E5AAC)
            {
                ObjAnim_SetCurrentMove(obj, (*(u8**)&((SpdrapeState*)state)->unk10)[2], lbl_803E5AA0, 0);
                Sfx_PlayFromObject(obj, 0x140);
                *state = lbl_803E5AB0;
            }
            else
            {
                ObjAnim_SetCurrentMove(obj, (*(u8**)&((SpdrapeState*)state)->unk10)[1], lbl_803E5AA0, 0);
                *state = lbl_803E5AB4;
            }
        }
        break;
    case 2:
    case 5:
        Sfx_PlayFromObject(obj, 0x141);
        if (getXZDistance(&((GameObject*)obj)->anim.worldPosX, (f32*)(player + 0x18)) > lbl_803E5AAC)
        {
            ObjAnim_SetCurrentMove(obj, (*(u8**)&((SpdrapeState*)state)->unk10)[2], lbl_803E5AA0, 0);
            Sfx_StopObjectChannel(obj, 0x40);
            Sfx_PlayFromObject(obj, 0x140);
            *state = lbl_803E5AB0;
        }
        break;
    case 3:
    case 6:
        if ((((GameObject*)obj)->anim.currentMoveProgress > lbl_803E5AB8) && (getXZDistance(
            &((GameObject*)obj)->anim.worldPosX, (f32*)(player + 0x18)) < lbl_803E5AA4))
        {
            if (player != 0)
            {
                if (state[3] + (state[1] * *(f32*)(player + 0xc) + state[2] * *(f32*)(player + 0x14)) < lbl_803E5AA0)
                {
                    ((SpdrapeState*)state)->unk10 = (int)&lbl_803DC0B0;
                }
                else
                {
                    ((SpdrapeState*)state)->unk10 = (int)&lbl_803DC0B4;
                }
            }
            ObjAnim_SetCurrentMove(obj, **(u8**)&((SpdrapeState*)state)->unk10, lbl_803E5AA0, 0);
            Sfx_PlayFromObject(obj, 0x140);
            *state = lbl_803E5AA8;
        }
        else if (((SpdrapeState*)state)->unk16 != 0)
        {
            ObjAnim_SetCurrentMove(obj, 0, lbl_803E5AA0, 0);
            *state = lbl_803E5ABC;
            Camera_GetCurrentViewSlot();
        }
        break;
    }
    ((SpdrapeState*)state)->unk16 = ((int (*)(int, f32, f32, void*))ObjAnim_AdvanceCurrentMove)(
        obj, *state, timeDelta, NULL);
}


/*
 * --INFO--
 *
 * Function: FUN_801e9368
 * EN v1.0 Address: 0x801E9368
 * EN v1.0 Size: 808b
 * EN v1.1 Address: 0x801E9518
 * EN v1.1 Size: 588b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: FUN_801e983c
 * EN v1.0 Address: 0x801E983C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801E997C
 * EN v1.1 Size: 760b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: spitembeam_init
 * EN v1.0 Address: 0x801E9900
 * EN v1.0 Size: 20b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void spitembeam_init(int obj);


/* Trivial 4b 0-arg blr leaves. */
void spdrape_release(void)
{
}

void spdrape_initialise(void)
{
}

void spitembeam_free(void);







/* 8b "li r3, N; blr" returners. */

extern f32 lbl_803E5AC0;
extern f32 lbl_803E5AC4;
extern f32 lbl_803E5AC8;
extern f32 lbl_803E5ACC;

void spdrape_init(int* obj, u8* def)
{
    extern f32 mathCosf(f32 x); /* #57 */
    extern f32 mathSinf(f32 x); /* #57 */
    extern void* Obj_GetPlayerObject(void); /* #57 */
    extern unsigned long randomGetRange(int a, int b); /* #57 */
    f32* state;
    int* player;
    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->objectFlags |= 0x2000;
    ((GameObject*)obj)->objectFlags |= 0x4000;
    *(s16*)obj = (s16)((s32)((SpdrapeObjectDef*)def)->unk18 << 8);
    if (((SpdrapeObjectDef*)def)->unk1A != 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = (f32)(s32)((SpdrapeObjectDef*)def)->unk1A / lbl_803E5AC4 *
            lbl_803E5AC0;
    }
    state[0] = lbl_803E5ABC;
    state[1] = mathSinf(lbl_803E5AC8 * (f32)(s32) * (s16*)obj / lbl_803E5ACC);
    state[2] = mathCosf(lbl_803E5AC8 * (f32)(s32) * (s16*)obj / lbl_803E5ACC);
    state[3] = -(state[1] * ((GameObject*)obj)->anim.localPosX + state[2] * ((GameObject*)obj)->anim.localPosZ);
    ((SpdrapeState*)state)->unk14 = (s16)randomGetRange(0xb4, 0x12c);
    player = (int*)Obj_GetPlayerObject();
    if (player != NULL)
    {
        if (state[1] * ((GameObject*)player)->anim.localPosX + state[2] * ((GameObject*)player)->anim.localPosZ + state[
            3] < lbl_803E5AA0)
        {
            ((SpdrapeState*)state)->unk10 = (int)&lbl_803DC0B0;
        }
        else
        {
            ((SpdrapeState*)state)->unk10 = (int)&lbl_803DC0B4;
        }
    }
}



volatile ShWGPipe GXWGFifo : (0xCC008000);

static inline void shPos3f32(const f32 x, const f32 y, const f32 z)
{
    GXWGFifo.f32 = x;
    GXWGFifo.f32 = y;
    GXWGFifo.f32 = z;
}

static inline void shColor4u8(const u8 r, const u8 g, const u8 b, const u8 a)
{
    GXWGFifo.u8 = r;
    GXWGFifo.u8 = g;
    GXWGFifo.u8 = b;
    GXWGFifo.u8 = a;
}

static inline void shTexCoord2f32(const f32 s, const f32 t)
{
    GXWGFifo.f32 = s;
    GXWGFifo.f32 = t;
}



/*
 * --INFO--
 *
 * Function: fn_801E991C
 * EN v1.0 Address: 0x801E991C
 * EN v1.0 Size: 740b
 */
#pragma opt_common_subs off
#pragma opt_common_subs reset
