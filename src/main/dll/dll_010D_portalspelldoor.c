/*
 * PortalSpellStone (DLL 0x10D, descriptor gPortalSpellDoorObjDescriptor).
 * TU = 0x80186498..0x80186704.
 */
#include "main/game_object.h"
#include "main/object_descriptor.h"
#include "main/dll/windlift107state_struct.h"
#include "main/dll/portalspelldoorstate_struct.h"
#include "main/dll/scarabstate_struct.h"
#include "main/objseq.h"
#include "main/gamebits.h"

extern void LanternFireFly_modelMtxFn(void);

extern void LanternFireFly_func0B(void);

extern void LanternFireFly_setScale(void);

extern void LanternFireFly_getExtraSize(void);
extern void flammablevine_getExtraSize(void);
extern void dll_109_getExtraSize_ret_16(void);
extern void Fall_Ladders_getExtraSize(void);
extern void infopoint_getExtraSize(void);

extern void LanternFireFly_getObjectTypeId(void);
extern void flammablevine_getObjectTypeId(void);
extern void dll_109_getObjectTypeId(void);
extern void Fall_Ladders_getObjectTypeId(void);
extern void infopoint_getObjectTypeId(void);

extern void LanternFireFly_free(void);
extern void flammablevine_free(void);
extern void dll_109_free(void);
extern void Fall_Ladders_free(void);
extern void infopoint_free(void);

extern void LanternFireFly_render(void);
extern void FireFlyLantern_getExtraSize(void);
extern void flammablevine_render(void);
extern void dll_109_render(void);
extern void Fall_Ladders_render(void);
extern void infopoint_render(void);
extern void decoration11a_getExtraSize(void);

extern void LanternFireFly_hitDetect(void);
extern void FireFlyLantern_getObjectTypeId(void);
extern void flammablevine_hitDetect(void);
extern void dll_109_hitDetect_nop(void);
extern void Fall_Ladders_hitDetect(void);
extern void infopoint_hitDetect(void);
extern void decoration11a_free(void);

extern void LanternFireFly_update(void);
extern void FireFlyLantern_free(void);
extern void flammablevine_update(void);
extern void carryable_break_respawn_update(void);
extern void Fall_Ladders_update(void);
extern void infopoint_update(void);
extern void decoration11a_render(void);

extern void LanternFireFly_init(void);
extern void FireFlyLantern_render(void);
extern void flammablevine_init(void);
extern void dll_109_init(void);
extern void Fall_Ladders_init(void);
extern void coldwatercontrol_getExtraSize(void);
extern void infopoint_init(void);
extern void decoration11a_hitDetect(void);

extern void LanternFireFly_release(void);
extern void FireFlyLantern_update(void);
extern void flammablevine_release(void);
extern void dll_109_release_nop(void);
extern void Fall_Ladders_release(void);
extern void coldwatercontrol_update(void);
extern void infopoint_release(void);
extern void decoration11a_update(void);

extern void LanternFireFly_initialise(void);
extern void FireFlyLantern_init(void);
extern void flammablevine_initialise(void);
extern void dll_109_initialise_nop(void);
extern void Fall_Ladders_initialise(void);
extern void coldwatercontrol_init(void);
extern void infopoint_initialise(void);
extern void decoration11a_init(void);

#define PORTALSPELLDOOR_OBJFLAG_UPDATE_DISABLED 0x8000
#define PORTALSPELLDOOR_OBJFLAG_HIDDEN 0x4000
#define PORTALSPELLDOOR_OBJFLAG_HITDETECT_DISABLED 0x2000

typedef struct PortalspelldoorPlacement
{
    u8 pad0[0x1E - 0x0];
    s16 openedGameBit;
} PortalspelldoorPlacement;

STATIC_ASSERT(sizeof(ScarabState) == 0x34);

STATIC_ASSERT(sizeof(WindLift107State) == 0x2c);

STATIC_ASSERT(sizeof(PortalSpellDoorState) == 0x10);

extern u8 framesThisStep;
extern int Obj_GetPlayerObject(void);
extern f32 lbl_803E3A8C;
extern f32 lbl_803E3A90;
extern f32 lbl_803E3A88;
extern void objRenderFn_8003b8f4(f32);

void portalspelldoor_update(int obj)
{
    extern int playerHasSpell(int obj, int spell);
    extern int objGetAnimState80A(int player);
    extern void fn_80296B78(int player, int v);
    extern int getTrickyObject(void);
    extern void trickyImpress(int tricky);
    typedef struct
    {
        u8 open : 1;
    } PortalFlags;
    PortalSpellDoorState* state;
    int player;
    int p4c;
    int t;

    player = Obj_GetPlayerObject();
    state = ((GameObject*)obj)->extra;
    p4c = *(int*)&((GameObject*)obj)->anim.placementData;
    if (playerHasSpell(player, 3) != 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~INTERACT_FLAG_PROMPT_SUPPRESSED;
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_PROMPT_SUPPRESSED;
    }
    if (((PortalFlags*)&state->flags0C)->open)
    {
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        if (objGetAnimState80A(player) == 0x5bd)
        {
            fn_80296B78(player, -1);
        }
        GameBit_Set(((PortalspelldoorPlacement*)p4c)->openedGameBit, 1);
    }
    else
    {
        if (objGetAnimState80A(player) == 0x5bd && state->openTimer == -1)
        {
            state->openTimer = 0;
        }
    }
    if (state->openTimer != -1)
    {
        t = state->openTimer - framesThisStep;
        state->openTimer = t;
        if (t < 0)
        {
            int tricky;
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
            (*gObjectTriggerInterface)->runSequence(0, (void*)obj, -1);
            tricky = getTrickyObject();
            if ((void*)tricky != NULL)
            {
                trickyImpress(tricky);
            }
            ((PortalFlags*)&state->flags0C)->open = 1;
            state->openTimer = -1;
        }
    }
}

void portalspelldoor_free(void)
{
}

void portalspelldoor_hitDetect(void)
{
}

void portalspelldoor_release(void)
{
}

void portalspelldoor_initialise(void)
{
}

int portalspelldoor_getExtraSize(void) { return 0x10; }
int portalspelldoor_getObjectTypeId(void) { return 0x0; }

/* portalspelldoor_init: byte<<8 / halfword<<8 stash at obj+0..+2, prime
 * obj+8 with lbl_803E3A8C, derive sub+4 = obj->_a8 * obj+8 * lbl_803E3A90,
 * GameBit-gated bit-set on obj+6 (0x4000) and obj+b0 (0xe000), then
 * latch sub+8 = -1. */

void portalspelldoor_init(u8* obj, u8* data)
{
    PortalSpellDoorState* sub = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->anim.rotX = (s16)((s32)(s8)data[0x18] << 8);
    ((GameObject*)obj)->anim.rotY = (s16)((s32) * (s16*)(data + 0x1c) << 8);
    ((GameObject*)obj)->anim.rootMotionScale = lbl_803E3A8C;
    {
        f32 _ab = ((GameObject*)obj)->anim.hitboxScale * ((GameObject*)obj)->anim.rootMotionScale;
        sub->openAmount = _ab * lbl_803E3A90;
    }
    if (GameBit_Get(*(s16*)(data + 0x1e)) != 0)
    {
        ((GameObject*)obj)->anim.flags = (s16)(((GameObject*)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
        ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | (PORTALSPELLDOOR_OBJFLAG_UPDATE_DISABLED | PORTALSPELLDOOR_OBJFLAG_HIDDEN | PORTALSPELLDOOR_OBJFLAG_HITDETECT_DISABLED));
    }
    sub->openTimer = -1;
}

void portalspelldoor_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3A88);
}

ObjectDescriptor gPortalSpellDoorObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)portalspelldoor_initialise,
    (ObjectDescriptorCallback)portalspelldoor_release,
    0,
    (ObjectDescriptorCallback)portalspelldoor_init,
    (ObjectDescriptorCallback)portalspelldoor_update,
    (ObjectDescriptorCallback)portalspelldoor_hitDetect,
    (ObjectDescriptorCallback)portalspelldoor_render,
    (ObjectDescriptorCallback)portalspelldoor_free,
    (ObjectDescriptorCallback)portalspelldoor_getObjectTypeId,
    portalspelldoor_getExtraSize,
};

/* descriptor/ptr table auto 0x80321830-0x80321a28 */
u32 gLanternFireFlyObjDescriptor[18] = { 0x00000000, 0x00000000, 0x00000000, 0x000c0000, (u32)LanternFireFly_initialise, (u32)LanternFireFly_release, 0x00000000, (u32)LanternFireFly_init, (u32)LanternFireFly_update, (u32)LanternFireFly_hitDetect, (u32)LanternFireFly_render, (u32)LanternFireFly_free, (u32)LanternFireFly_getObjectTypeId, (u32)LanternFireFly_getExtraSize, (u32)LanternFireFly_setScale, (u32)LanternFireFly_func0B, (u32)LanternFireFly_modelMtxFn, 0x00000000 };
u32 gFireFlyLanternObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, 0x00000000, 0x00000000, 0x00000000, (u32)FireFlyLantern_init, (u32)FireFlyLantern_update, 0x00000000, (u32)FireFlyLantern_render, (u32)FireFlyLantern_free, (u32)FireFlyLantern_getObjectTypeId, (u32)FireFlyLantern_getExtraSize };
u32 gFlammableVineObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)flammablevine_initialise, (u32)flammablevine_release, 0x00000000, (u32)flammablevine_init, (u32)flammablevine_update, (u32)flammablevine_hitDetect, (u32)flammablevine_render, (u32)flammablevine_free, (u32)flammablevine_getObjectTypeId, (u32)flammablevine_getExtraSize };
u32 lbl_803218E8[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)dll_109_initialise_nop, (u32)dll_109_release_nop, 0x00000000, (u32)dll_109_init, (u32)carryable_break_respawn_update, (u32)dll_109_hitDetect_nop, (u32)dll_109_render, (u32)dll_109_free, (u32)dll_109_getObjectTypeId, (u32)dll_109_getExtraSize_ret_16 };
u32 gFall_LaddersObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)Fall_Ladders_initialise, (u32)Fall_Ladders_release, 0x00000000, (u32)Fall_Ladders_init, (u32)Fall_Ladders_update, (u32)Fall_Ladders_hitDetect, (u32)Fall_Ladders_render, (u32)Fall_Ladders_free, (u32)Fall_Ladders_getObjectTypeId, (u32)Fall_Ladders_getExtraSize };
u32 gColdWaterControlObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, 0x00000000, 0x00000000, 0x00000000, (u32)coldwatercontrol_init, (u32)coldwatercontrol_update, 0x00000000, 0x00000000, 0x00000000, 0x00000000, (u32)coldwatercontrol_getExtraSize };
u32 lbl_80321990[4] = { 0x00000050, 0x00000230, 0x0000003c, 0x00000190 };
u32 lbl_803219A0[6] = { 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000 };
u32 gInfoPointObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, (u32)infopoint_initialise, (u32)infopoint_release, 0x00000000, (u32)infopoint_init, (u32)infopoint_update, (u32)infopoint_hitDetect, (u32)infopoint_render, (u32)infopoint_free, (u32)infopoint_getObjectTypeId, (u32)infopoint_getExtraSize };
u32 gDecoration11AObjDescriptor[14] = { 0x00000000, 0x00000000, 0x00000000, 0x00090000, 0x00000000, 0x00000000, 0x00000000, (u32)decoration11a_init, (u32)decoration11a_update, (u32)decoration11a_hitDetect, (u32)decoration11a_render, (u32)decoration11a_free, 0x00000000, (u32)decoration11a_getExtraSize };
