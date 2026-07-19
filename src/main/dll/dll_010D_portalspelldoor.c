/*
 * PortalSpellStone (DLL 0x10D, descriptor gPortalSpellDoorObjDescriptor).
 * TU = 0x80186498..0x80186704.
 */
#include "main/game_object.h"
#include "main/object_render.h"
#include "main/dll/player_api.h"
#include "main/object.h"
#include "main/dll/dll_80136a40.h"
#include "main/object_api.h"
#include "main/object_descriptor.h"
#include "main/dll/windlift107state_struct.h"
#include "main/dll/portalspelldoorstate_struct.h"
#include "main/dll/scarabstate_struct.h"
#include "main/objseq.h"
#include "main/gamebits.h"
#include "main/frame_timing.h"
#include "main/dll/dll_00E7_flammablevine.h"
#include "main/dll/dll_0119_coldwatercontrol.h"
#include "main/dll/dll_00EC_infopoint.h"
#include "main/dll/dll_011A_decoration11a.h"
#include "main/dll/dll_010C_lanternfirefly.h"
#include "main/dll/dll_010B_fireflylantern.h"
#include "main/dll/dll_010A_fallladders.h"
#include "main/dll/dll_0109_unk.h"
#include "main/dll/CF/windlift.h"

typedef struct PortalspelldoorPlacement
{
    u8 pad0[0x1E - 0x0];
    s16 openedGameBit;
} PortalspelldoorPlacement;

STATIC_ASSERT(sizeof(ScarabState) == 0x34);

STATIC_ASSERT(sizeof(WindLift107State) == 0x2c);

STATIC_ASSERT(sizeof(PortalSpellDoorState) == 0x10);

#define PORTALSPELLDOOR_OBJFLAG_UPDATE_DISABLED    0x8000
#define PORTALSPELLDOOR_OBJFLAG_HIDDEN             0x4000
#define PORTALSPELLDOOR_OBJFLAG_HITDETECT_DISABLED 0x2000

extern f32 lbl_803E3A8C;
extern f32 lbl_803E3A90;
extern f32 lbl_803E3A88;

int PortalSpellDoor_getExtraSize(void)
{
    return 0x10;
}
int PortalSpellDoor_getObjectTypeId(void)
{
    return 0x0;
}

void PortalSpellDoor_free(void)
{
}

void PortalSpellDoor_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0)
        objRenderModelAndHitVolumes((GameObject*)p1, p2, p3, p4, p5, lbl_803E3A88);
}

void PortalSpellDoor_hitDetect(void)
{
}

void PortalSpellDoor_update(GameObject* obj)
{
    typedef struct
    {
        u8 open : 1;
    } PortalFlags;
    PortalSpellDoorState* state;
    int player;
    int p4c;
    int timer;

    player = (int)Obj_GetPlayerObject();
    state = obj->extra;
    p4c = *(int*)&obj->anim.placementData;
    if (playerHasSpell((GameObject*)(player), 3) != 0)
    {
        *(u8*)&obj->anim.resetHitboxMode &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
    }
    else
    {
        *(u8*)&obj->anim.resetHitboxMode |= INTERACT_FLAG_PROMPT_SUPPRESSED;
    }
    if (((PortalFlags*)&state->flags0C)->open)
    {
        obj->anim.flags |= OBJANIM_FLAG_HIDDEN;
        if (objGetAnimState80A((GameObject*)(player)) == 0x5bd)
        {
            playerCancelSpell((GameObject*)player, -1);
        }
        mainSetBits(((PortalspelldoorPlacement*)p4c)->openedGameBit, 1);
    }
    else
    {
        if (objGetAnimState80A((GameObject*)(player)) == 0x5bd && state->openTimer == -1)
        {
            state->openTimer = 0;
        }
    }
    if (state->openTimer != -1)
    {
        timer = state->openTimer - framesThisStep;
        state->openTimer = timer;
        if (timer < 0)
        {
            int tricky;
            *(u8*)&obj->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            tricky = (int)getTrickyObject();
            if ((void*)tricky != NULL)
            {
                trickyImpress((GameObject*)tricky);
            }
            ((PortalFlags*)&state->flags0C)->open = 1;
            state->openTimer = -1;
        }
    }
}

void PortalSpellDoor_init(u8* obj, u8* data)
{
    PortalSpellDoorState* sub = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)(s8)data[0x18] << 8);
    ((GameObject*)obj)->anim.rotY = (s16)((s32) * (s16*)(data + 0x1c) << 8);
    ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3A8C;
    {
        f32 _ab = ((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.rootMotionScale;
        sub->openAmount = _ab * lbl_803E3A90;
    }
    if (mainGetBit(*(s16*)(data + 0x1e)) != 0)
    {
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        ((GameObject*)obj)->objectFlags =
            (u16)(((GameObject*)obj)->objectFlags |
                  (PORTALSPELLDOOR_OBJFLAG_UPDATE_DISABLED | PORTALSPELLDOOR_OBJFLAG_HIDDEN |
                   PORTALSPELLDOOR_OBJFLAG_HITDETECT_DISABLED));
    }
    sub->openTimer = -1;
}

void PortalSpellDoor_release(void)
{
}

void PortalSpellDoor_initialise(void)
{
}

ObjectDescriptor gPortalSpellDoorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)PortalSpellDoor_initialise,
    (ObjectDescriptorCallback)PortalSpellDoor_release,
    0,
    (ObjectDescriptorCallback)PortalSpellDoor_init,
    (ObjectDescriptorCallback)PortalSpellDoor_update,
    (ObjectDescriptorCallback)PortalSpellDoor_hitDetect,
    (ObjectDescriptorCallback)PortalSpellDoor_render,
    (ObjectDescriptorCallback)PortalSpellDoor_free,
    (ObjectDescriptorCallback)PortalSpellDoor_getObjectTypeId,
    PortalSpellDoor_getExtraSize,
};

/* descriptor/ptr table auto 0x80321830-0x80321a28 */
ObjectDescriptor13WithPadding gLanternFireFlyObjDescriptor = {
    {
        0,
        0,
        0,
        OBJECT_DESCRIPTOR_FLAGS_13_SLOTS,
        (ObjectDescriptorCallback)LanternFireFly_initialise,
        (ObjectDescriptorCallback)LanternFireFly_release,
        0,
        (ObjectDescriptorCallback)LanternFireFly_init,
        (ObjectDescriptorCallback)LanternFireFly_update,
        (ObjectDescriptorCallback)LanternFireFly_hitDetect,
        (ObjectDescriptorCallback)LanternFireFly_render,
        (ObjectDescriptorCallback)LanternFireFly_free,
        (ObjectDescriptorCallback)LanternFireFly_getObjectTypeId,
        LanternFireFly_getExtraSize,
        (ObjectDescriptorCallback)LanternFireFly_setScale,
        (ObjectDescriptorCallback)LanternFireFly_func0B,
        (ObjectDescriptorCallback)LanternFireFly_modelMtxFn,
    },
    0,
};
ObjectDescriptor gFireFlyLanternObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)FireFlyLantern_init,
    (ObjectDescriptorCallback)FireFlyLantern_update,
    0,
    (ObjectDescriptorCallback)FireFlyLantern_render,
    (ObjectDescriptorCallback)FireFlyLantern_free,
    (ObjectDescriptorCallback)FireFlyLantern_getObjectTypeId,
    FireFlyLantern_getExtraSize,
};
ObjectDescriptor gFlammableVineObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)FlammableVine_initialise,
    (ObjectDescriptorCallback)FlammableVine_release,
    0,
    (ObjectDescriptorCallback)FlammableVine_init,
    (ObjectDescriptorCallback)FlammableVine_update,
    (ObjectDescriptorCallback)FlammableVine_hitDetect,
    (ObjectDescriptorCallback)FlammableVine_render,
    (ObjectDescriptorCallback)FlammableVine_free,
    (ObjectDescriptorCallback)FlammableVine_getObjectTypeId,
    FlammableVine_getExtraSize,
};
u32 lbl_803218E8[14] = {0x00000000,
                        0x00000000,
                        0x00000000,
                        0x00090000,
                        (u32)dll_109_initialise_nop,
                        (u32)dll_109_release_nop,
                        0x00000000,
                        (u32)dll_109_init,
                        (u32)carryable_break_respawn_update,
                        (u32)dll_109_hitDetect_nop,
                        (u32)dll_109_render,
                        (u32)dll_109_free,
                        (u32)dll_109_getObjectTypeId,
                        (u32)dll_109_getExtraSize_ret_16};
ObjectDescriptor gFall_LaddersObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)Fall_Ladders_initialise,
    (ObjectDescriptorCallback)Fall_Ladders_release,
    0,
    (ObjectDescriptorCallback)Fall_Ladders_init,
    (ObjectDescriptorCallback)Fall_Ladders_update,
    (ObjectDescriptorCallback)Fall_Ladders_hitDetect,
    (ObjectDescriptorCallback)Fall_Ladders_render,
    (ObjectDescriptorCallback)Fall_Ladders_free,
    (ObjectDescriptorCallback)Fall_Ladders_getObjectTypeId,
    Fall_Ladders_getExtraSize,
};
ObjectDescriptor gColdWaterControlObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)ColdWaterControl_init,
    (ObjectDescriptorCallback)ColdWaterControl_update,
    0,
    0,
    0,
    0,
    ColdWaterControl_getExtraSize,
};
u32 lbl_80321990[4] = {0x00000050, 0x00000230, 0x0000003c, 0x00000190};
u32 lbl_803219A0[6] = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
ObjectDescriptor gInfoPointObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)InfoPoint_initialise,
    (ObjectDescriptorCallback)InfoPoint_release,
    0,
    (ObjectDescriptorCallback)InfoPoint_init,
    (ObjectDescriptorCallback)InfoPoint_update,
    (ObjectDescriptorCallback)InfoPoint_hitDetect,
    (ObjectDescriptorCallback)InfoPoint_render,
    (ObjectDescriptorCallback)InfoPoint_free,
    (ObjectDescriptorCallback)InfoPoint_getObjectTypeId,
    InfoPoint_getExtraSize,
};
ObjectDescriptor gDecoration11AObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)decoration11a_init,
    (ObjectDescriptorCallback)decoration11a_update,
    (ObjectDescriptorCallback)decoration11a_hitDetect,
    (ObjectDescriptorCallback)decoration11a_render,
    (ObjectDescriptorCallback)decoration11a_free,
    0,
    decoration11a_getExtraSize,
};
