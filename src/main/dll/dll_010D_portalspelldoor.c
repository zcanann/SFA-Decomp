/*
 * PortalSpellStone (DLL 0x10D, descriptor gPortalSpellDoorObjDescriptor).
 * TU = 0x80186498..0x80186704.
 */
#include "main/game_object.h"
#include "main/object.h"
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

extern void LanternFireFly_modelMtxFn(void);

extern void LanternFireFly_func0B(GameObject*);

extern void LanternFireFly_setScale(void);

extern void LanternFireFly_getExtraSize(void);
extern void dll_109_getExtraSize_ret_16(void);
extern void Fall_Ladders_getExtraSize(void);

extern void LanternFireFly_getObjectTypeId(void);
extern void dll_109_getObjectTypeId(void);
extern void Fall_Ladders_getObjectTypeId(void);

extern void LanternFireFly_free(void);
extern void dll_109_free(void);
extern void Fall_Ladders_free(void);

extern void LanternFireFly_render(void);
extern void FireFlyLantern_getExtraSize(void);
extern void dll_109_render(void);
extern void Fall_Ladders_render(void);

extern void LanternFireFly_hitDetect(void);
extern void FireFlyLantern_getObjectTypeId(void);
extern void dll_109_hitDetect_nop(void);
extern void Fall_Ladders_hitDetect(void);

extern void LanternFireFly_update(GameObject*);
extern void FireFlyLantern_free(void);
extern void carryable_break_respawn_update(GameObject*);
extern void Fall_Ladders_update(GameObject*);

extern void LanternFireFly_init(GameObject*);
extern void FireFlyLantern_render(void);
extern void dll_109_init(GameObject*);
extern void Fall_Ladders_init(void);

extern void LanternFireFly_release(void);
extern void FireFlyLantern_update(GameObject*);
extern void dll_109_release_nop(void);
extern void Fall_Ladders_release(void);

extern void LanternFireFly_initialise(void);
extern void FireFlyLantern_init(GameObject*);
extern void dll_109_initialise_nop(void);
extern void Fall_Ladders_initialise(void);

extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);
extern int playerHasSpell(GameObject* obj, int spell);
extern int objGetAnimState80A(GameObject* player);
extern void playerCancelSpell(int player, int v);
extern void trickyImpress(int tricky);

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
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E3A88);
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
            playerCancelSpell(player, -1);
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
                trickyImpress(tricky);
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
u32 gLanternFireFlyObjDescriptor[18] = {0x00000000,
                                        0x00000000,
                                        0x00000000,
                                        0x000c0000,
                                        (u32)LanternFireFly_initialise,
                                        (u32)LanternFireFly_release,
                                        0x00000000,
                                        (u32)LanternFireFly_init,
                                        (u32)LanternFireFly_update,
                                        (u32)LanternFireFly_hitDetect,
                                        (u32)LanternFireFly_render,
                                        (u32)LanternFireFly_free,
                                        (u32)LanternFireFly_getObjectTypeId,
                                        (u32)LanternFireFly_getExtraSize,
                                        (u32)LanternFireFly_setScale,
                                        (u32)LanternFireFly_func0B,
                                        (u32)LanternFireFly_modelMtxFn,
                                        0x00000000};
u32 gFireFlyLanternObjDescriptor[14] = {0x00000000,
                                        0x00000000,
                                        0x00000000,
                                        0x00090000,
                                        0x00000000,
                                        0x00000000,
                                        0x00000000,
                                        (u32)FireFlyLantern_init,
                                        (u32)FireFlyLantern_update,
                                        0x00000000,
                                        (u32)FireFlyLantern_render,
                                        (u32)FireFlyLantern_free,
                                        (u32)FireFlyLantern_getObjectTypeId,
                                        (u32)FireFlyLantern_getExtraSize};
u32 gFlammableVineObjDescriptor[14] = {0x00000000,
                                       0x00000000,
                                       0x00000000,
                                       0x00090000,
                                       (u32)FlammableVine_initialise,
                                       (u32)FlammableVine_release,
                                       0x00000000,
                                       (u32)FlammableVine_init,
                                       (u32)FlammableVine_update,
                                       (u32)FlammableVine_hitDetect,
                                       (u32)FlammableVine_render,
                                       (u32)FlammableVine_free,
                                       (u32)FlammableVine_getObjectTypeId,
                                       (u32)FlammableVine_getExtraSize};
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
u32 gFall_LaddersObjDescriptor[14] = {0x00000000,
                                      0x00000000,
                                      0x00000000,
                                      0x00090000,
                                      (u32)Fall_Ladders_initialise,
                                      (u32)Fall_Ladders_release,
                                      0x00000000,
                                      (u32)Fall_Ladders_init,
                                      (u32)Fall_Ladders_update,
                                      (u32)Fall_Ladders_hitDetect,
                                      (u32)Fall_Ladders_render,
                                      (u32)Fall_Ladders_free,
                                      (u32)Fall_Ladders_getObjectTypeId,
                                      (u32)Fall_Ladders_getExtraSize};
u32 gColdWaterControlObjDescriptor[14] = {0x00000000,
                                          0x00000000,
                                          0x00000000,
                                          0x00090000,
                                          0x00000000,
                                          0x00000000,
                                          0x00000000,
                                          (u32)ColdWaterControl_init,
                                          (u32)ColdWaterControl_update,
                                          0x00000000,
                                          0x00000000,
                                          0x00000000,
                                          0x00000000,
                                          (u32)ColdWaterControl_getExtraSize};
u32 lbl_80321990[4] = {0x00000050, 0x00000230, 0x0000003c, 0x00000190};
u32 lbl_803219A0[6] = {0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000, 0x00000000};
u32 gInfoPointObjDescriptor[14] = {0x00000000,
                                   0x00000000,
                                   0x00000000,
                                   0x00090000,
                                   (u32)InfoPoint_initialise,
                                   (u32)InfoPoint_release,
                                   0x00000000,
                                   (u32)InfoPoint_init,
                                   (u32)InfoPoint_update,
                                   (u32)InfoPoint_hitDetect,
                                   (u32)InfoPoint_render,
                                   (u32)InfoPoint_free,
                                   (u32)InfoPoint_getObjectTypeId,
                                   (u32)InfoPoint_getExtraSize};
u32 gDecoration11AObjDescriptor[14] = {0x00000000,
                                       0x00000000,
                                       0x00000000,
                                       0x00090000,
                                       0x00000000,
                                       0x00000000,
                                       0x00000000,
                                       (u32)decoration11a_init,
                                       (u32)decoration11a_update,
                                       (u32)decoration11a_hitDetect,
                                       (u32)decoration11a_render,
                                       (u32)decoration11a_free,
                                       0x00000000,
                                       (u32)decoration11a_getExtraSize};
