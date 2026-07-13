/* DLL 0x00F9 (projectileswitch) - Projectile switch object [0x8017A350-0x8017A8EC). */
#include "main/dll/tFrameAnimator.h"
#include "main/game_object.h"
#include "main/objhits.h"
#include "main/objprint_api.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/objtexture.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/frame_timing.h"
#include "main/object_render_legacy.h"

/*
 * Low 2 bits of ProjectileSwitchPlacement.modelIndexAndMode select switch behaviour;
 * the upper 6 bits select the model bank.
 * (Same mode field as dll_00FA invisiblehitswitch.)
 * Modes 0 and 3 both latch on in this DLL. Mode 2 and its delay units were
 * verified live against the first Magic Cave switch.
 */
#define SWITCH_MODE_MASK 3
#define SWITCH_MODE_TOGGLE 1      /* a second hit while active turns it back off */
#define SWITCH_MODE_TIMED_RESET 2 /* auto-clears after autoResetDelayTenths */

#define PROJECTILESWITCH_HIT_PRIORITY_FIREBALL 0xe
#define PROJECTILESWITCH_HIT_PRIORITY_ALT      0xf /* accepted, exact source still unknown */
#define PROJECTILESWITCH_FIREBALL_SEQ_ID       0x14b
#define PROJECTILESWITCH_PLACEMENT_CUSTOM_COLOR 1


extern int seqStreamLookupFn_8007fff8(void* table, int mode, int seq);
extern u8 lbl_80321008[];

int ProjectileSwitch_getExtraSize(void) { return 0x8; }

int ProjectileSwitch_getObjectTypeId(int* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    int modelIndex = (int)*(u8*)((char*)*(int**)&((GameObject*)obj)->anim.placementData + 0x1e) >> 2;
    int max = objAnim->modelInstance->modelCount;
    if (modelIndex >= max)
    {
        modelIndex = 0;
    }
    return ((u32)modelIndex << 11) | 0x400;
}

void ProjectileSwitch_free(void)
{
}

typedef struct ProjectileSwitchPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 gameBitId;
    s16 autoResetDelayTenths;
    u8 rotYByte;
    u8 scale64;
    u8 modelIndexAndMode;
    u8 rotXByte;
    u8 colorR;
    u8 colorG;
    u8 colorB;
    u8 renderFlags;
    u8 pad24[0x28 - 0x24];
} ProjectileSwitchPlacement;

STATIC_ASSERT(offsetof(ProjectileSwitchPlacement, gameBitId) == 0x18);
STATIC_ASSERT(offsetof(ProjectileSwitchPlacement, modelIndexAndMode) == 0x1e);
STATIC_ASSERT(sizeof(ProjectileSwitchPlacement) == 0x28);

typedef struct ProjectileSwitchState
{
    u8 isOn;
    u8 pad1[0x2 - 0x1];
    s16 gameBitId;
    f32 autoResetTimerFrames;
} ProjectileSwitchState;

STATIC_ASSERT(sizeof(ProjectileSwitchState) == 0x8);

void ProjectileSwitch_render(GameObject *obj, int p2, int p3, int p4, int p5, char flag)
{
    int placement = *(int*)&(obj)->anim.placementData;
    if ((int)(signed char)flag != 0)
    {
        if ((((ProjectileSwitchPlacement*)placement)->renderFlags & PROJECTILESWITCH_PLACEMENT_CUSTOM_COLOR) != 0)
        {
            fn_8003B608(((ProjectileSwitchPlacement*)placement)->colorR,
                        ((ProjectileSwitchPlacement*)placement)->colorG,
                        ((ProjectileSwitchPlacement*)placement)->colorB);
        }
        objRenderModelAndHitVolumes((int)obj, p2, p3, p4, p5, 1.0f);
    }
}

void ProjectileSwitch_hitDetect(GameObject *obj)
{
    int switchState;
    int switchStateReloaded;
    int placement;
    int hitPriority;
    int hitObj;
    ObjTextureRuntimeSlot* tex;
    int rejectFireballHit;

    placement = *(int*)&(obj)->anim.placementData;
    switchState = *(int*)&(obj)->extra;
    hitPriority = ObjHits_GetPriorityHit(obj, &hitObj, 0x0, 0x0);
    if (hitPriority != PROJECTILESWITCH_HIT_PRIORITY_FIREBALL &&
        hitPriority != PROJECTILESWITCH_HIT_PRIORITY_ALT) return;

    rejectFireballHit = 0;
    if (((GameObject*)hitObj)->anim.seqId == PROJECTILESWITCH_FIREBALL_SEQ_ID)
    {
        ObjHitsPriorityState* hitState = (ObjHitsPriorityState*)((GameObject*)hitObj)->anim.hitReactState;
        if ((hitState->contactFlags & OBJHITS_CONTACT_FLAG_KIND_NONZERO) != 0)
        {
            rejectFireballHit = 1;
        }
    }
    if (rejectFireballHit != 0) return;

    if (((ProjectileSwitchState*)switchState)->isOn != 0)
    {
        if (((((ProjectileSwitchPlacement*)placement)->modelIndexAndMode & SWITCH_MODE_MASK)) != SWITCH_MODE_TOGGLE)
            return;
        switchStateReloaded = *(int*)&(obj)->extra;
        if ((obj)->anim.mapEventSlot == 0x2c)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_menuups16k);
        }
        else
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_dn_boar1_c_63);
        }
        tex = objFindTexture(obj, 0, 0);
        if (tex != 0)
        {
            tex->textureId = 0;
        }
        ((ProjectileSwitchState*)switchStateReloaded)->isOn = 0;
        mainSetBits((int)((ProjectileSwitchState*)switchState)->gameBitId, 0);
    }
    else
    {
        switchStateReloaded = *(int*)&(obj)->extra;
        if ((obj)->anim.mapEventSlot == 0x2c)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_menuups16k);
        }
        else
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_wp_mpwru1_62);
        }
        tex = objFindTexture(obj, 0, 0);
        if (tex != 0)
        {
            tex->textureId = 0x100;
        }
        ((ProjectileSwitchState*)switchStateReloaded)->isOn = 1;
        mainSetBits((int)((ProjectileSwitchState*)switchState)->gameBitId, 1);
        if ((((ProjectileSwitchPlacement*)placement)->modelIndexAndMode & SWITCH_MODE_MASK) == SWITCH_MODE_TIMED_RESET)
        {
            ((ProjectileSwitchState*)switchState)->autoResetTimerFrames =
                60.0f * (0.1f *
                (f32)((ProjectileSwitchPlacement*)placement)->autoResetDelayTenths);
        }
    }
}

void ProjectileSwitch_update(GameObject *obj)
{

    int switchState;
    int switchStateReloaded;
    ObjTextureRuntimeSlot* tex;

    switchState = *(int*)&(obj)->extra;
    if (((ProjectileSwitchState*)switchState)->isOn != 0)
    {
        if (mainGetBit((int)((ProjectileSwitchState*)switchState)->gameBitId) == 0)
        {
            switchStateReloaded = *(int*)&(obj)->extra;
            tex = objFindTexture(obj, 0, 0);
            if (tex != 0) tex->textureId = 0;
            ((ProjectileSwitchState*)switchStateReloaded)->isOn = 0;
        }
    }
    else
    {
        if (mainGetBit((int)((ProjectileSwitchState*)switchState)->gameBitId) != 0)
        {
            switchStateReloaded = *(int*)&(obj)->extra;
            tex = objFindTexture(obj, 0, 0);
            if (tex != 0) tex->textureId = 0x100;
            ((ProjectileSwitchState*)switchStateReloaded)->isOn = 1;
        }
    }
    if (((ProjectileSwitchState*)switchState)->autoResetTimerFrames > 0.0f)
    {
        ((ProjectileSwitchState*)switchState)->autoResetTimerFrames =
            ((ProjectileSwitchState*)switchState)->autoResetTimerFrames - (f32)(u32)
        framesThisStep;
        if (((ProjectileSwitchState*)switchState)->autoResetTimerFrames <= 0.0f)
        {
            ((ProjectileSwitchState*)switchState)->autoResetTimerFrames = 0.0f;
            mainSetBits((int)((ProjectileSwitchState*)switchState)->gameBitId, 0);
        }
    }
}

void ProjectileSwitch_init(GameObject *obj, u8* initData)
{

    ObjAnimComponent* objAnim;
    ProjectileSwitchPlacement* placement;
    int switchState;
    u8* linkObj;
    u8* linkSub;
    ObjTextureRuntimeSlot* tex;

    objAnim = (ObjAnimComponent*)obj;
    placement = (ProjectileSwitchPlacement*)initData;
    switchState = *(int*)&(obj)->extra;
    *(short*)obj = (short)(placement->rotXByte << 8);
    (obj)->anim.rotY = (short)(placement->rotYByte << 8);
    if (placement->scale64 == 0)
    {
        (obj)->anim.rootMotionScale = (obj)->anim.modelInstance->rootMotionScaleBase;
    }
    else
    {
        f32 scaledRadius = (f32)(u32)placement->scale64 * (obj)->anim.modelInstance->rootMotionScaleBase;
        (obj)->anim.rootMotionScale = scaledRadius / 64.0f;
    }
    ObjHitbox_SetSphereRadius(
        (ObjAnimComponent*)obj,
        (short)(((int)placement->scale64 * (int)(obj)->anim.modelInstance->primaryHitboxRadius) / 64));
    objAnim->bankIndex = placement->modelIndexAndMode >> 2;
    if ((int)objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }

    linkObj = (obj)->anim.parent;
    if (linkObj != 0)
    {
        linkSub = *(u8**)&((GameObject*)linkObj)->anim.placementData;
        if (linkSub != 0)
        {
            ((ProjectileSwitchState*)switchState)->gameBitId =
                seqStreamLookupFn_8007fff8(lbl_80321008, 2, *(int*)(linkSub + 0x14));
        }
        else
        {
            ((ProjectileSwitchState*)switchState)->gameBitId = -1;
        }
    }
    else
    {
        ((ProjectileSwitchState*)switchState)->gameBitId = placement->gameBitId;
    }
    ((ProjectileSwitchState*)switchState)->isOn =
        mainGetBit((int)((ProjectileSwitchState*)switchState)->gameBitId);
    if (((ProjectileSwitchState*)switchState)->isOn != 0)
    {
        switchState = *(int*)&(obj)->extra;
        tex = objFindTexture(obj, 0, 0);
        if (tex != 0) tex->textureId = 0x100;
        ((ProjectileSwitchState*)switchState)->isOn = 1;
    }
    else
    {
        switchState = *(int*)&(obj)->extra;
        tex = objFindTexture(obj, 0, 0);
        if (tex != 0) tex->textureId = 0;
        ((ProjectileSwitchState*)switchState)->isOn = 0;
    }
    if ((placement->renderFlags & PROJECTILESWITCH_PLACEMENT_CUSTOM_COLOR) == 0)
    {
        (obj)->objectFlags = (u16)((obj)->objectFlags | OBJECT_OBJFLAG_HIDDEN);
    }
}

void ProjectileSwitch_release(void)
{
}

void ProjectileSwitch_initialise(void)
{
}
