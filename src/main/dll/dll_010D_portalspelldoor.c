/*
 * PortalSpellStone (DLL 0x10D, descriptor gPortalSpellDoorObjDescriptor).
 * Re-split (descriptor forensics, docs/boundary_audit.md): TU =
 * 0x80186498..0x80186704, formerly inside windlift.c.
 */
#include "main/game_object.h"
#include "main/objseq.h"

typedef struct PortalspelldoorPlacement
{
    u8 pad0[0x1E - 0x0];
    s16 unk1E;
} PortalspelldoorPlacement;




/* scarab_getExtraSize == 0x34 (collectible money beetle). */
typedef struct ScarabState
{
    f32 velX; /* 0x00 */
    f32 velZ; /* 0x04 */
    f32 riseAmount; /* 0x08 */
    f32 baseY; /* 0x0c: def spawn height */
    s16 despawnTimer; /* 0x10 */
    u8 pad12[2];
    s16 mode; /* 0x14 */
    s16 yawSpeed; /* 0x16 */
    s16 spawnYaw; /* 0x18 */
    s16 fleeTimer; /* 0x1a */
    s16 riseLimit; /* 0x1c */
    s16 pickupSfx; /* 0x1e */
    s16 particleId; /* 0x20 */
    s16 unk22; /* 0x22 */
    u8 phase; /* 0x24 */
    u8 pad25[2];
    u8 moneyKind; /* 0x27 */
    u8 flags28; /* 0x28: 1 = collected, waiting on the money message */
    u8 pad29[3];
    s16 msgParamA; /* 0x2c */
    s16 msgParamB; /* 0x2e */
    f32 msgParamC; /* 0x30 */
} ScarabState;

STATIC_ASSERT(sizeof(ScarabState) == 0x34);

/* dll_107_getExtraSize == 0x2c (CF wind lift / blow vent). */
typedef struct WindLift107State
{
    int holdTimer; /* 0x00: countdown while the vent is plugged */
    int holdReload; /* 0x04 */
    f32 radius; /* 0x08 */
    s16 yawLow; /* 0x0c */
    s16 yawHigh; /* 0x0e */
    s16 ventState; /* 0x10 */
    s16 maxDist; /* 0x12 */
    s16 unk14; /* 0x14 */
    s16 unk16; /* 0x16 */
    s16 unk18; /* 0x18 */
    s16 liftTimer; /* 0x1a */
    u8 pad1C[2];
    s16 spitTimer; /* 0x1e */
    u8 pad20;
    u8 rideState; /* 0x21 */
    u8 riding; /* 0x22 */
    u8 launchPhase; /* 0x23 */
    u8 pad24;
    u8 unk25; /* 0x25 */
    u8 glowPulse; /* 0x26 */
    u8 unk27; /* 0x27 */
    u8 pad28[4];
} WindLift107State;

STATIC_ASSERT(sizeof(WindLift107State) == 0x2c);

/* portalspelldoor_getExtraSize == 0x10. */
typedef struct PortalSpellDoorState
{
    u8 pad00[4];
    f32 openAmount; /* 0x04 */
    int openTimer; /* 0x08 */
    u8 flags0C; /* 0x0c: bit 7 = open (via PortalFlags cast) */
    u8 pad0D[3];
} PortalSpellDoorState;

STATIC_ASSERT(sizeof(PortalSpellDoorState) == 0x10);


extern uint GameBit_Get(int eventId);
extern undefined4 GameBit_Set(int eventId, int value);


extern u8 framesThisStep;

extern int Obj_GetPlayerObject(void);
/*
 * --INFO--
 *
 * Function: portalspelldoor_update
 * EN v1.0 Address: 0x80186748
 * EN v1.0 Size: 344b
 * EN v1.1 Address: 0x80186A38
 * EN v1.1 Size: 364b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void portalspelldoor_update(int obj)
{
    extern int playerHasSpell(int player, int spell);
    extern int objGetAnimState80A(int player);
    extern void fn_80296B78(int player, int v);
    extern int getTrickyObject(void);
    extern void trickyImpress(int tricky);
    extern ObjectTriggerInterface** gObjectTriggerInterface;
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
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~0x10;
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 0x10;
    }
    if (((PortalFlags*)&state->flags0C)->open)
    {
        ((GameObject*)obj)->anim.flags |= OBJANIM_FLAG_HIDDEN;
        if (objGetAnimState80A(player) == 0x5bd)
        {
            fn_80296B78(player, -1);
        }
        GameBit_Set(((PortalspelldoorPlacement*)p4c)->unk1E, 1);
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
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
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

/* 8b "li r3, N; blr" returners. */
int portalspelldoor_getExtraSize(void) { return 0x10; }
int portalspelldoor_getObjectTypeId(void) { return 0x0; }

/* portalspelldoor_init: byte<<8 / halfword<<8 stash at obj+0..+2, prime
 * obj+8 with lbl_803E3A8C, derive sub+4 = obj->_a8 * obj+8 * lbl_803E3A90,
 * GameBit-gated bit-set on obj+6 (0x4000) and obj+b0 (0xe000), then
 * latch sub+8 = -1. */
extern f32 lbl_803E3A8C;
extern f32 lbl_803E3A90;

void portalspelldoor_init(u8* obj, u8* data)
{
    PortalSpellDoorState* sub = ((GameObject*)obj)->extra;
    *(s16*)obj = (s16)((s32)(s8)data[0x18] << 8);
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

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E3A88;
extern void objRenderFn_8003b8f4(f32);

void portalspelldoor_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E3A88);
}
