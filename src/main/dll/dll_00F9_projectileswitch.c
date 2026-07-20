/* DLL 0x00F9 (projectileswitch) - Projectile switch object [0x8017A350-0x8017A8EC). */
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objhits.h"
#include "main/objprint_api.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/objtexture.h"
#include "main/gamebits.h"
#include "main/audio/sfx.h"
#include "main/frame_timing.h"
#include "main/object_render.h"
#include "main/object_descriptor.h"
#include "main/maketex_sequence_api.h"

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


u32 lbl_80321008[4] = {0x00031ccf, 0x00000522, 0x00031ce0, 0x00000e6e};

typedef struct ProjectileSwitchPlacement
{
    ObjPlacement base;
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

typedef struct ProjectileSwitchState
{
    u8 isOn;
    u8 pad1[0x2 - 0x1];
    s16 gameBitId;
    f32 autoResetTimerFrames;
} ProjectileSwitchState;

STATIC_ASSERT(sizeof(ProjectileSwitchPlacement) == 0x28);
STATIC_ASSERT(offsetof(ProjectileSwitchPlacement, base) == 0x0);
STATIC_ASSERT(offsetof(ProjectileSwitchPlacement, gameBitId) == 0x18);
STATIC_ASSERT(offsetof(ProjectileSwitchPlacement, autoResetDelayTenths) == 0x1A);
STATIC_ASSERT(offsetof(ProjectileSwitchPlacement, modelIndexAndMode) == 0x1E);
STATIC_ASSERT(offsetof(ProjectileSwitchPlacement, renderFlags) == 0x23);
STATIC_ASSERT(sizeof(ProjectileSwitchState) == 0x8);
STATIC_ASSERT(offsetof(ProjectileSwitchState, gameBitId) == 0x2);
STATIC_ASSERT(offsetof(ProjectileSwitchState, autoResetTimerFrames) == 0x4);

int ProjectileSwitch_getExtraSize(void) { return 0x8; }

int ProjectileSwitch_getObjectTypeId(GameObject* obj)
{
    ObjAnimComponent* objAnim = (ObjAnimComponent*)obj;
    ProjectileSwitchPlacement* placement = (ProjectileSwitchPlacement*)obj->anim.placementData;
    int modelIndex = (int)placement->modelIndexAndMode >> 2;
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

void ProjectileSwitch_render(GameObject *obj, int p2, int p3, int p4, int p5, char flag)
{
    ProjectileSwitchPlacement* placement = (ProjectileSwitchPlacement*)obj->anim.placementData;
    if ((int)(signed char)flag != 0)
    {
        if ((placement->renderFlags & PROJECTILESWITCH_PLACEMENT_CUSTOM_COLOR) != 0)
        {
            fn_8003B608(placement->colorR, placement->colorG, placement->colorB);
        }
        objRenderModelAndHitVolumes(obj, p2, p3, p4, p5, 1.0f);
    }
}

void ProjectileSwitch_hitDetect(GameObject *obj)
{
    ProjectileSwitchState* switchState;
    ProjectileSwitchState* switchStateReloaded;
    ProjectileSwitchPlacement* placement;
    int hitPriority;
    int hitObj;
    ObjTextureRuntimeSlot* tex;
    int rejectFireballHit;

    placement = (ProjectileSwitchPlacement*)obj->anim.placementData;
    switchState = obj->extra;
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

    if (switchState->isOn != 0)
    {
        if ((placement->modelIndexAndMode & SWITCH_MODE_MASK) != SWITCH_MODE_TOGGLE)
            return;
        switchStateReloaded = obj->extra;
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
        switchStateReloaded->isOn = 0;
        mainSetBits((int)switchState->gameBitId, 0);
    }
    else
    {
        switchStateReloaded = obj->extra;
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
        switchStateReloaded->isOn = 1;
        mainSetBits((int)switchState->gameBitId, 1);
        if ((placement->modelIndexAndMode & SWITCH_MODE_MASK) == SWITCH_MODE_TIMED_RESET)
        {
            switchState->autoResetTimerFrames = 60.0f * (0.1f * (f32)placement->autoResetDelayTenths);
        }
    }
}

void ProjectileSwitch_update(GameObject *obj)
{

    ProjectileSwitchState* switchState;
    ProjectileSwitchState* switchStateReloaded;
    ObjTextureRuntimeSlot* tex;

    switchState = obj->extra;
    if (switchState->isOn != 0)
    {
        if (mainGetBit((int)switchState->gameBitId) == 0)
        {
            switchStateReloaded = obj->extra;
            tex = objFindTexture(obj, 0, 0);
            if (tex != 0) tex->textureId = 0;
            switchStateReloaded->isOn = 0;
        }
    }
    else
    {
        if (mainGetBit((int)switchState->gameBitId) != 0)
        {
            switchStateReloaded = obj->extra;
            tex = objFindTexture(obj, 0, 0);
            if (tex != 0) tex->textureId = 0x100;
            switchStateReloaded->isOn = 1;
        }
    }
    if (switchState->autoResetTimerFrames > 0.0f)
    {
        switchState->autoResetTimerFrames = switchState->autoResetTimerFrames - (f32)(u32)framesThisStep;
        if (switchState->autoResetTimerFrames <= 0.0f)
        {
            switchState->autoResetTimerFrames = 0.0f;
            mainSetBits((int)switchState->gameBitId, 0);
        }
    }
}

void ProjectileSwitch_init(GameObject *obj, ProjectileSwitchPlacement* placement)
{

    ObjAnimComponent* objAnim;
    ProjectileSwitchState* switchState;
    GameObject* linkObj;
    ObjPlacement* linkPlacement;
    ObjTextureRuntimeSlot* tex;

    objAnim = (ObjAnimComponent*)obj;
    switchState = obj->extra;
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

    linkObj = (GameObject*)obj->anim.parent;
    if (linkObj != 0)
    {
        linkPlacement = (ObjPlacement*)linkObj->anim.placementData;
        if (linkPlacement != 0)
        {
            switchState->gameBitId = seqStreamLookupFn_8007fff8(lbl_80321008, 2, linkPlacement->mapId);
        }
        else
        {
            switchState->gameBitId = -1;
        }
    }
    else
    {
        switchState->gameBitId = placement->gameBitId;
    }
    switchState->isOn = mainGetBit((int)switchState->gameBitId);
    if (switchState->isOn != 0)
    {
        switchState = obj->extra;
        tex = objFindTexture(obj, 0, 0);
        if (tex != 0) tex->textureId = 0x100;
        switchState->isOn = 1;
    }
    else
    {
        switchState = obj->extra;
        tex = objFindTexture(obj, 0, 0);
        if (tex != 0) tex->textureId = 0;
        switchState->isOn = 0;
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

ObjectDescriptor gProjectileSwitchObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    ProjectileSwitch_initialise,
    ProjectileSwitch_release,
    0,
    (ObjectDescriptorCallback)ProjectileSwitch_init,
    (ObjectDescriptorCallback)ProjectileSwitch_update,
    (ObjectDescriptorCallback)ProjectileSwitch_hitDetect,
    (ObjectDescriptorCallback)ProjectileSwitch_render,
    (ObjectDescriptorCallback)ProjectileSwitch_free,
    (ObjectDescriptorCallback)ProjectileSwitch_getObjectTypeId,
    ProjectileSwitch_getExtraSize,
};
