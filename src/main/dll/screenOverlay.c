#include "ghidra_import.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/screenOverlay.h"
#include "main/objanim_internal.h"
#include "main/objhits_types.h"

typedef struct ProjectileSwitchPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    u8 unk1E;
    u8 pad1F[0x20 - 0x1F];
    u8 unk20;
    u8 unk21;
    u8 unk22;
    u8 unk23;
    u8 pad24[0x28 - 0x24];
} ProjectileSwitchPlacement;


typedef struct InvisibleHitSwitchPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 unk1A;
    u8 pad1C[0x1E - 0x1C];
    u8 unk1E;
    u8 pad1F[0x20 - 0x1F];
} InvisibleHitSwitchPlacement;


typedef struct ProjectileSwitchState
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    u8 pad8[0x20 - 0x8];
    u8 unk20;
    u8 unk21;
    u8 unk22;
    u8 unk23;
    u8 pad24[0x28 - 0x24];
} ProjectileSwitchState;


typedef struct InvisibleHitSwitchState
{
    u8 pad0[0x1 - 0x0];
    u8 unk1;
    u8 pad2[0x4 - 0x2];
    f32 unk4;
    f32 unk8;
    u8 padC[0x20 - 0xC];
    u8 unk20;
    u8 unk21;
    u8 unk22;
    u8 unk23;
    u8 pad24[0x28 - 0x24];
} InvisibleHitSwitchState;


extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);
extern void ObjHitbox_SetSphereRadius(int obj, short radius);
extern int ObjHits_GetPriorityHit(int obj, int* outArr, int* outA, uint* outB);
extern void Sfx_PlayFromObject(int obj, int soundId);
extern void* objFindTexture(int obj, int a, int b);
extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, float arg);
extern int seqStreamLookupFn_8007fff8(void* table, int mode, int seq);
extern void fn_8003B608(u32 a, u32 b, u32 c);

extern u8 framesThisStep;
extern f32 timeDelta;
extern u8 lbl_80321008[];
extern f32 lbl_803E3700;
extern f32 lbl_803E3704;
extern f32 lbl_803E3708;
extern f64 lbl_803E3710;
extern f32 lbl_803E3718;
extern f64 lbl_803E3720;
extern f32 lbl_803E3728;
extern f32 lbl_803E3730;
extern f32 lbl_803E3734;
extern f32 lbl_803E3738;
extern f32 lbl_803E373C;
extern f64 lbl_803E3740;
extern f64 lbl_803E3748;


/*
 * --INFO--
 *
 * Function: ProjectileSwitch_render
 * EN v1.0 Address: 0x8017A38C
 * EN v1.0 Size: 140b
 */
void ProjectileSwitch_render(int obj, int p2, int p3, int p4, int p5, char flag)
{
    int state = *(int*)&((GameObject*)obj)->anim.placementData;
    if ((int)(signed char)flag != 0)
    {
        if ((((ProjectileSwitchPlacement*)state)->unk23 & 1) != 0)
        {
            fn_8003B608(((ProjectileSwitchPlacement*)state)->unk20, ((ProjectileSwitchPlacement*)state)->unk21,
                        ((ProjectileSwitchPlacement*)state)->unk22);
        }
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E3700);
    }
}

/*
 * --INFO--
 *
 * Function: ProjectileSwitch_hitDetect
 * EN v1.0 Address: 0x8017A418
 * EN v1.0 Size: 460b
 */
void ProjectileSwitch_hitDetect(int obj)
{
    int state2;
    int state;
    int hitId;
    int hit;
    int hitObj;
    void* tex;
    int isSpecial;

    state2 = *(int*)&((GameObject*)obj)->anim.placementData;
    state = *(int*)&((GameObject*)obj)->extra;
    hitId = ObjHits_GetPriorityHit(obj, &hitObj, (int*)0x0, (uint*)0x0);
    if (hitId != 0xe && hitId != 0xf) return;

    isSpecial = 0;
    if (*(short*)(hitObj + 0x46) == 0x14b)
    {
        if (((*(ObjHitsPriorityState**)(hitObj + 0x54))->contactFlags & 2) != 0)
        {
            isSpecial = 1;
        }
    }
    if (isSpecial != 0) return;

    if (*(u8*)state != 0)
    {
        /* deactivate */
        if ((((ProjectileSwitchPlacement*)state2)->unk1E & 3) != 1) return;
        state = *(int*)&((GameObject*)obj)->extra;
        if (((GameObject*)obj)->anim.mapEventSlot == 0x2c)
        {
            Sfx_PlayFromObject(obj, SFXsp_lf_mutter4);
        }
        else
        {
            Sfx_PlayFromObject(obj, SFXmn_cling01);
        }
        tex = objFindTexture(obj, 0, 0);
        if (tex != 0)
        {
            *(int*)tex = 0;
        }
        *(u8*)state = 0;
        GameBit_Set((int)*(short*)(state + 2), 0);
    }
    else
    {
        /* activate */
        state = *(int*)&((GameObject*)obj)->extra;
        if (((GameObject*)obj)->anim.mapEventSlot == 0x2c)
        {
            Sfx_PlayFromObject(obj, SFXsp_lf_mutter4);
        }
        else
        {
            Sfx_PlayFromObject(obj, SFXms_windlift_loop);
        }
        tex = objFindTexture(obj, 0, 0);
        if (tex != 0)
        {
            *(int*)tex = 0x100;
        }
        *(u8*)state = 1;
        GameBit_Set((int)*(short*)(state + 2), 1);
        if ((((ProjectileSwitchPlacement*)state2)->unk1E & 3) == 2)
        {
            ((ProjectileSwitchState*)state)->unk4 =
                lbl_803E3704 * lbl_803E3708 *
                (f32)((ProjectileSwitchPlacement*)state2)->unk1A;
        }
    }
}

/*
 * --INFO--
 *
 * Function: ProjectileSwitch_update
 * EN v1.0 Address: 0x8017A5E4
 * EN v1.0 Size: 280b
 */
void ProjectileSwitch_update(int obj)
{
    int state;
    int state2;
    void* tex;

    state = *(int*)&((GameObject*)obj)->extra;
    if (*(u8*)state != 0)
    {
        if (GameBit_Get((int)*(short*)(state + 2)) == 0)
        {
            state2 = *(int*)&((GameObject*)obj)->extra;
            tex = objFindTexture(obj, 0, 0);
            if (tex != 0) *(int*)tex = 0;
            *(u8*)state2 = 0;
        }
    }
    else
    {
        if (GameBit_Get((int)*(short*)(state + 2)) != 0)
        {
            state2 = *(int*)&((GameObject*)obj)->extra;
            tex = objFindTexture(obj, 0, 0);
            if (tex != 0) *(int*)tex = 0x100;
            *(u8*)state2 = 1;
        }
    }
    if (lbl_803E3718 < ((ProjectileSwitchState*)state)->unk4)
    {
        ((ProjectileSwitchState*)state)->unk4 =
            ((ProjectileSwitchState*)state)->unk4 - (f32)(u32)
        framesThisStep;
        if (((ProjectileSwitchState*)state)->unk4 <= lbl_803E3718)
        {
            ((ProjectileSwitchState*)state)->unk4 = lbl_803E3718;
            GameBit_Set((int)*(short*)(state + 2), 0);
        }
    }
}

/*
 * --INFO--
 *
 * Function: ProjectileSwitch_init
 * EN v1.0 Address: 0x8017A6FC
 * EN v1.0 Size: 488b
 */
void ProjectileSwitch_init(int obj, u8* initData)
{
    ObjAnimComponent* objAnim;
    int state;
    u8* linkObj;
    u8* linkSub;
    void* tex;

    objAnim = (ObjAnimComponent*)obj;
    state = *(int*)&((GameObject*)obj)->extra;
    *(short*)obj = (short)(initData[0x1f] << 8);
    ((GameObject*)obj)->anim.rotY = (short)(initData[0x1c] << 8);
    if (initData[0x1d] == 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = *(float*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 4);
    }
    else
    {
        f32 scaledRadius =
                (f32)(u32)initData[0x1d] * *(
        float*
        )
        (*(int*)&((GameObject*)obj)->anim.modelInstance + 4);
        ((GameObject*)obj)->anim.rootMotionScale = scaledRadius * lbl_803E3728;
    }
    ObjHitbox_SetSphereRadius(
        obj, (short)(((int)initData[0x1d] * (int)*(u8*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 0x62)) / 64));
    objAnim->bankIndex = initData[0x1e] >> 2;
    if ((int)objAnim->bankIndex >= (int)objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }

    linkObj = ((GameObject*)obj)->anim.parent;
    if (linkObj != 0)
    {
        linkSub = *(u8**)&((GameObject*)linkObj)->anim.placementData;
        if (linkSub != 0)
        {
            *(short*)(state + 2) =
                (short)seqStreamLookupFn_8007fff8(lbl_80321008, 2, *(int*)(linkSub + 0x14));
        }
        else
        {
            *(short*)(state + 2) = -1;
        }
    }
    else
    {
        *(short*)(state + 2) = *(short*)(initData + 0x18);
    }
    *(u8*)state = (u8)GameBit_Get((int)*(short*)(state + 2));
    if (*(u8*)state != 0)
    {
        state = *(int*)&((GameObject*)obj)->extra;
        tex = objFindTexture(obj, 0, 0);
        if (tex != 0) *(int*)tex = 0x100;
        *(u8*)state = 1;
    }
    else
    {
        state = *(int*)&((GameObject*)obj)->extra;
        tex = objFindTexture(obj, 0, 0);
        if (tex != 0) *(int*)tex = 0;
        *(u8*)state = 0;
    }
    if ((initData[0x23] & 1) == 0)
    {
        ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0x4000);
    }
}

/* Trivial 4b 0-arg blr leaves. */
void ProjectileSwitch_release(void)
{
}

void ProjectileSwitch_initialise(void)
{
}

/* 8b "li r3, N; blr" returners. */
int InvisibleHitSwitch_getExtraSize(void) { return 0xc; }

/*
 * --INFO--
 *
 * Function: InvisibleHitSwitch_update
 * EN v1.0 Address: 0x8017A8F4
 * EN v1.0 Size: 556b
 */
void InvisibleHitSwitch_update(int obj)
{
    int state2;
    int state;
    int hitId;

    state2 = *(int*)&((GameObject*)obj)->anim.placementData;
    state = *(int*)&((GameObject*)obj)->extra;
    if (*(u8*)state != 0)
    {
        if (GameBit_Get((int)*(short*)(state2 + 0x18)) == 0)
        {
            *(u8*)state = 0;
        }
    }
    else
    {
        if (GameBit_Get((int)*(short*)(state2 + 0x18)) != 0)
        {
            *(u8*)state = 1;
        }
    }

    if (lbl_803E3730 < ((InvisibleHitSwitchState*)state)->unk4)
    {
        ((InvisibleHitSwitchState*)state)->unk4 =
            ((InvisibleHitSwitchState*)state)->unk4 - (f32)(u32)
        framesThisStep;
        if (((InvisibleHitSwitchState*)state)->unk4 <= lbl_803E3730)
        {
            ((InvisibleHitSwitchState*)state)->unk4 = lbl_803E3730;
            GameBit_Set((int)*(short*)(state2 + 0x18), 0);
            return;
        }
        return;
    }

    if (((InvisibleHitSwitchState*)state)->unk8 != lbl_803E3730)
    {
        ((InvisibleHitSwitchState*)state)->unk8 = ((InvisibleHitSwitchState*)state)->unk8 - timeDelta;
        if (((InvisibleHitSwitchState*)state)->unk8 < lbl_803E3734)
        {
            hitId = ObjHits_GetPriorityHit(obj, 0, 0, 0);
            if ((int)((InvisibleHitSwitchState*)state)->unk1 == hitId)
            {
                ((InvisibleHitSwitchState*)state)->unk8 = lbl_803E3730;
                *(u8*)state = 1;
                GameBit_Set((int)*(short*)(state2 + 0x18), 1);
            }
            else if (lbl_803E3730 < ((InvisibleHitSwitchState*)state)->unk8)
            {
                /* nothing */
            }
            else
            {
                ((InvisibleHitSwitchState*)state)->unk8 = lbl_803E3730;
            }
        }
    }
    else
    {
        hitId = ObjHits_GetPriorityHit(obj, 0, 0, 0);
        if ((int)((InvisibleHitSwitchState*)state)->unk1 != hitId) return;
        if (*(u8*)state != 0)
        {
            if ((((InvisibleHitSwitchPlacement*)state2)->unk1E & 3) != 1) return;
            *(u8*)state = 0;
            GameBit_Set((int)*(short*)(state2 + 0x18), 0);
        }
        else
        {
            if ((((InvisibleHitSwitchPlacement*)state2)->unk1E & 3) == 3)
            {
                ((InvisibleHitSwitchState*)state)->unk8 = lbl_803E3738;
                return;
            }
            *(u8*)state = 1;
            GameBit_Set((int)*(short*)(state2 + 0x18), 1);
            if ((((InvisibleHitSwitchPlacement*)state2)->unk1E & 3) == 2)
            {
                ((InvisibleHitSwitchState*)state)->unk4 =
                    lbl_803E3734 * lbl_803E373C *
                    (f32)((InvisibleHitSwitchPlacement*)state2)->unk1A;
            }
        }
    }
}
