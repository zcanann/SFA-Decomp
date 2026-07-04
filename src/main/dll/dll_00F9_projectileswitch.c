/* DLL 0x00F9 (projectileswitch) — Projectile switch object [0x8017A350-0x8017A8EC). */
#include "main/dll/tFrameAnimator.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/audio/sfx_ids.h"
#include "main/objtexture.h"
#include "main/gamebits.h"
#include "main/gameplay_runtime.h"
#include "main/objlib.h"
#include "main/audio/sfx.h"

#define PROJECTILESWITCH_OBJFLAG_HIDDEN 0x4000

/*
 * Low 2 bits of ProjectileSwitchPlacement.triggerMode select switch behaviour.
 * (Same mode field as dll_00FA invisiblehitswitch.)
 */
#define SWITCH_MODE_MASK 3
#define SWITCH_MODE_LATCH 0     /* activates and stays on; cannot be toggled off */
#define SWITCH_MODE_TOGGLE 1    /* a second hit while active turns it back off */
#define SWITCH_MODE_MOMENTARY 2 /* activates, then auto-clears after cooldownFrames */
#define SWITCH_MODE_DELAYED 3   /* hit arms an activation wind-up before turning on */

int area_getExtraSize(void);
int area_getObjectTypeId(void);

void area_free(void);

void area_render(void);

void area_hitDetect(void);

void area_update(void);

void area_init(u16* obj);

void area_release(void);

void area_initialise(void);

extern u8 framesThisStep;

extern int seqStreamLookupFn_8007fff8(void* table, int mode, int seq);
extern void fn_8003B608(s16 a, s16 b, s16 c);
extern u8 lbl_80321008[];
extern f32 lbl_803E3700;
extern f32 lbl_803E3704;
extern f32 lbl_803E3708;
extern const f32 lbl_803E3718;
extern f32 lbl_803E3728;

void ProjectileSwitch_free(void)
{
}

int ProjectileSwitch_getExtraSize(void) { return 0x8; }

int ProjectileSwitch_getObjectTypeId(int* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    int v = (int)*(u8*)((char*)*(int**)&((GameObject*)obj)->anim.placementData + 0x1e) >> 2;
    int max = objAnim->modelInstance->modelCount;
    if (v >= max)
    {
        v = 0;
    }
    return ((u32)v << 11) | 0x400;
}

ObjectDescriptor gAreaObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)area_initialise,
    (ObjectDescriptorCallback)area_release,
    0,
    (ObjectDescriptorCallback)area_init,
    (ObjectDescriptorCallback)area_update,
    (ObjectDescriptorCallback)area_hitDetect,
    (ObjectDescriptorCallback)area_render,
    (ObjectDescriptorCallback)area_free,
    (ObjectDescriptorCallback)area_getObjectTypeId,
    area_getExtraSize,
};

typedef struct ProjectileSwitchPlacement
{
    u8 pad0[0x1A - 0x0];
    s16 cooldownFrames;
    u8 pad1C[0x1E - 0x1C];
    u8 triggerMode;
    u8 pad1F[0x20 - 0x1F];
    u8 colorR;
    u8 colorG;
    u8 colorB;
    u8 flags;
    u8 pad24[0x28 - 0x24];
} ProjectileSwitchPlacement;

typedef struct ProjectileSwitchState
{
    u8 isOn;
    u8 pad1[0x2 - 0x1];
    s16 gameBitId;
    f32 cooldownTimer;
    u8 pad8[0x20 - 0x8];
    u8 unk20;
    u8 unk21;
    u8 unk22;
    u8 unk23;
    u8 pad24[0x28 - 0x24];
} ProjectileSwitchState;

void ProjectileSwitch_render(int obj, int p2, int p3, int p4, int p5, char flag)
{
    int state = *(int*)&((GameObject*)obj)->anim.placementData;
    if ((int)(signed char)flag != 0)
    {
        if ((((ProjectileSwitchPlacement*)state)->flags & 1) != 0)
        {
            fn_8003B608(((ProjectileSwitchPlacement*)state)->colorR, ((ProjectileSwitchPlacement*)state)->colorG,
                        ((ProjectileSwitchPlacement*)state)->colorB);
        }
        objRenderFn_8003b8f4(obj, p2, p3, p4, p5, lbl_803E3700);
    }
}

void ProjectileSwitch_hitDetect(int obj)
{
    int state;
    int stateB;
    int state2;
    int hitId;
    int hit;
    int hitObj;
    ObjTextureRuntimeSlot* tex;
    int isSpecial;

    state2 = *(int*)&((GameObject*)obj)->anim.placementData;
    state = *(int*)&((GameObject*)obj)->extra;
    hitId = ObjHits_GetPriorityHit(obj, &hitObj, 0x0, 0x0);
    if (hitId != 0xe && hitId != 0xf) return;

    isSpecial = 0;
    if (((GameObject*)hitObj)->anim.seqId == 0x14b)
    {
        ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)((GameObject*)hitObj)->anim.hitReactState;
        if ((hitState->contactFlags & OBJHITS_CONTACT_FLAG_KIND_NONZERO) != 0)
        {
            isSpecial = 1;
        }
    }
    if (isSpecial != 0) return;

    if (((ProjectileSwitchState*)state)->isOn != 0)
    {
        if (((((ProjectileSwitchPlacement*)state2)->triggerMode & SWITCH_MODE_MASK)) != SWITCH_MODE_TOGGLE) return;
        stateB = *(int*)&((GameObject*)obj)->extra;
        if (((GameObject*)obj)->anim.mapEventSlot == 0x2c)
        {
            Sfx_PlayFromObject(obj, SFXsp_lf_mutter4);
        }
        else
        {
            Sfx_PlayFromObject(obj, SFXmn_cling01);
        }
        tex = objFindTexture((void*)obj, 0, 0);
        if (tex != 0)
        {
            tex->textureId = 0;
        }
        ((ProjectileSwitchState*)stateB)->isOn = 0;
        GameBit_Set((int)((ProjectileSwitchState*)state)->gameBitId, 0);
    }
    else
    {
        stateB = *(int*)&((GameObject*)obj)->extra;
        if (((GameObject*)obj)->anim.mapEventSlot == 0x2c)
        {
            Sfx_PlayFromObject(obj, SFXsp_lf_mutter4);
        }
        else
        {
            Sfx_PlayFromObject(obj, SFXms_windlift_loop);
        }
        tex = objFindTexture((void*)obj, 0, 0);
        if (tex != 0)
        {
            tex->textureId = 0x100;
        }
        ((ProjectileSwitchState*)stateB)->isOn = 1;
        GameBit_Set((int)((ProjectileSwitchState*)state)->gameBitId, 1);
        if ((((ProjectileSwitchPlacement*)state2)->triggerMode & SWITCH_MODE_MASK) == SWITCH_MODE_MOMENTARY)
        {
            ((ProjectileSwitchState*)state)->cooldownTimer =
                lbl_803E3704 * (lbl_803E3708 *
                (f32)((ProjectileSwitchPlacement*)state2)->cooldownFrames);
        }
    }
}

void ProjectileSwitch_update(int obj)
{

    int state;
    int state2;
    ObjTextureRuntimeSlot* tex;

    state = *(int*)&((GameObject*)obj)->extra;
    if (((ProjectileSwitchState*)state)->isOn != 0)
    {
        if (GameBit_Get((int)((ProjectileSwitchState*)state)->gameBitId) == 0)
        {
            state2 = *(int*)&((GameObject*)obj)->extra;
            tex = objFindTexture((void*)obj, 0, 0);
            if (tex != 0) tex->textureId = 0;
            ((ProjectileSwitchState*)state2)->isOn = 0;
        }
    }
    else
    {
        if (GameBit_Get((int)((ProjectileSwitchState*)state)->gameBitId) != 0)
        {
            state2 = *(int*)&((GameObject*)obj)->extra;
            tex = objFindTexture((void*)obj, 0, 0);
            if (tex != 0) tex->textureId = 0x100;
            ((ProjectileSwitchState*)state2)->isOn = 1;
        }
    }
    if (((ProjectileSwitchState*)state)->cooldownTimer > lbl_803E3718)
    {
        ((ProjectileSwitchState*)state)->cooldownTimer =
            ((ProjectileSwitchState*)state)->cooldownTimer - (f32)(u32)
        framesThisStep;
        if (((ProjectileSwitchState*)state)->cooldownTimer <= lbl_803E3718)
        {
            ((ProjectileSwitchState*)state)->cooldownTimer = lbl_803E3718;
            GameBit_Set((int)((ProjectileSwitchState*)state)->gameBitId, 0);
        }
    }
}

void ProjectileSwitch_init(int obj, u8* initData)
{

    ObjAnimComponent* objAnim;
    int state;
    u8* linkObj;
    u8* linkSub;
    ObjTextureRuntimeSlot* tex;

    objAnim = (ObjAnimComponent*)obj;
    state = *(int*)&((GameObject*)obj)->extra;
    *(short*)obj = (short)(initData[0x1f] << 8);
    ((GameObject*)obj)->anim.rotY = (short)(initData[0x1c] << 8);
    if (initData[0x1d] == 0)
    {
        ((GameObject*)obj)->anim.rootMotionScale = ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
    }
    else
    {
        f32 scaledRadius = (f32)(u32)initData[0x1d] * ((GameObject*)obj)->anim.modelInstance->rootMotionScaleBase;
        ((GameObject*)obj)->anim.rootMotionScale = scaledRadius * lbl_803E3728;
    }
    ObjHitbox_SetSphereRadius(
        obj,
        (short)(((int)initData[0x1d] * (int)((GameObject*)obj)->anim.modelInstance->primaryHitboxRadius) / 64));
    objAnim->bankIndex = initData[0x1e] >> 2;
    if ((int)objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }

    linkObj = ((GameObject*)obj)->anim.parent;
    if (linkObj != 0)
    {
        linkSub = *(u8**)&((GameObject*)linkObj)->anim.placementData;
        if (linkSub != 0)
        {
            ((ProjectileSwitchState*)state)->gameBitId =
                seqStreamLookupFn_8007fff8(lbl_80321008, 2, *(int*)(linkSub + 0x14));
        }
        else
        {
            ((ProjectileSwitchState*)state)->gameBitId = -1;
        }
    }
    else
    {
        ((ProjectileSwitchState*)state)->gameBitId = *(short*)(initData + 0x18);
    }
    ((ProjectileSwitchState*)state)->isOn = GameBit_Get((int)((ProjectileSwitchState*)state)->gameBitId);
    if (((ProjectileSwitchState*)state)->isOn != 0)
    {
        state = *(int*)&((GameObject*)obj)->extra;
        tex = objFindTexture((void*)obj, 0, 0);
        if (tex != 0) tex->textureId = 0x100;
        ((ProjectileSwitchState*)state)->isOn = 1;
    }
    else
    {
        state = *(int*)&((GameObject*)obj)->extra;
        tex = objFindTexture((void*)obj, 0, 0);
        if (tex != 0) tex->textureId = 0;
        ((ProjectileSwitchState*)state)->isOn = 0;
    }
    if ((initData[0x23] & 1) == 0)
    {
        ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | PROJECTILESWITCH_OBJFLAG_HIDDEN);
    }
}

void ProjectileSwitch_release(void)
{
}

void ProjectileSwitch_initialise(void)
{
}

