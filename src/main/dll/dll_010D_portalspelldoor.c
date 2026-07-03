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
        ((GameObject*)obj)->objectFlags = (u16)(((GameObject*)obj)->objectFlags | 0xe000);
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
