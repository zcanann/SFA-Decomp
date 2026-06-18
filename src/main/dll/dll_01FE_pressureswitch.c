/*
 * pressureswitch (DLL 0x1FE) - a floor pressure pad / button that sinks
 * when a heavy object (or Tricky, on map slot 11 act 3) rests on it and
 * springs back up when released.
 *
 * update() walks the switch's hit list: it sinks the pad while held
 * (holdTimer), plays the press/release sfx, and drives the per-map game
 * bit (0xf45/0xf46) plus the placement's own trigger bit. A chime sfx is
 * latched once per press when a chime-sequence object lands on it, gated
 * by distance to the player. init() seeds the rest/retrigger timers and
 * pre-latches the bit if the placement bit is already set.
 *
 * The animation sequence callback (PressureSwitch_SeqFn) is defined here;
 * ARWarwingattachment merely references it.
 */
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/dll/laserbeamstate_struct.h"
#include "main/dll/dll200state_struct.h"
#include "main/game_object.h"
#include "main/mapEvent.h"
#include "main/dll/ARW/ARWarwingattachment.h"

typedef struct PressureswitchPlacement
{
    u8 pad0[0xC - 0x0];
    f32 unkC;
    u8 pad10[0x1A - 0x10];
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    u8 pad20[0x4C - 0x20];
    u8 unk4C;
    u8 pad4D[0x2F8 - 0x4D];
    u8 unk2F8;
    u8 unk2F9;
    s8 unk2FA;
    u8 pad2FB[0x300 - 0x2FB];
} PressureswitchPlacement;

#define PSWITCH_HITLIST_OFFSET 0x58
#define PSWITCH_HITLIST_OBJECTS_OFFSET 0x100
#define PSWITCH_HITLIST_COUNT_OFFSET 0x10f
#define PSWITCH_TRIGGER_SEQ_ID 0x6d
#define PSWITCH_CHIME_SEQ_ID 0x146

STATIC_ASSERT(offsetof(LaserBeamState, beamKind) == 0x4e);

/* pressureswitch_getExtraSize == 0x8. */
typedef struct PressureSwitchState
{
    s8 holdTimer; /* frames the switch stays pressed */
    s8 chimeLatch;
    s16 retriggerTimer;
    s16 mapGameBit; /* 0xf45/0xf46 per-map bit, -1 none */
    u8 flags; /* PressureSwitchFlags / PswFlags overlay */
    u8 pad7;
} PressureSwitchState;

typedef struct PressureSwitchFlags
{
    u8 active : 1;
    u8 mapBitLatched : 1;
    u8 otherFlags : 6;
} PressureSwitchFlags;

typedef struct PswFlags
{
    u8 active : 1;
    u8 latched : 1;
} PswFlags;

STATIC_ASSERT(sizeof(Dll200State) == 0x28);

extern f32 lbl_803E5D78;
extern f32 lbl_803E5D58;
extern void objRenderFn_8003b8f4(f32);
extern void* Obj_GetPlayerObject(void);
extern void* getTrickyObject(void);
extern f32 Vec_distance(f32* a, f32* b);

void pressureswitch_free(void)
{
}

void pressureswitch_hitDetect(void)
{
}

void pressureswitch_release(void)
{
}

void pressureswitch_initialise(void)
{
}

void pressureswitch_init(int* obj, u8* init)
{
    PressureSwitchState* sub;
    uint mapId;

    sub = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = (void*)PressureSwitch_SeqFn;
    ((GameObject*)obj)->anim.rotX = (s16)((s8)init[0x18] << 8);
    sub->retriggerTimer = (s16)(*(s16*)(init + 0x1e) * 0x3c);
    sub->chimeLatch = 0;
    mapId = *(int*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14);
    if (mapId == 0x1f1a)
    {
        sub->mapGameBit = 0xf45;
    }
    else if (mapId == 0x47293)
    {
        sub->mapGameBit = 0xf46;
    }
    else
    {
        sub->mapGameBit = -1;
    }
    if (sub->mapGameBit != -1)
    {
        if (GameBit_Get(sub->mapGameBit) != 0)
        {
            ((PressureSwitchFlags*)&sub->flags)->mapBitLatched = 1;
        }
    }
    if (GameBit_Get(*(s16*)(init + 0x1c)) != 0)
    {
        ((GameObject*)obj)->anim.localPosY = *(f32*)(init + 0xc) - lbl_803E5D78;
        sub->holdTimer = 0x1e;
    }
}

int pressureswitch_getExtraSize(void) { return 0x8; }
int pressureswitch_getObjectTypeId(void) { return 0x0; }

void pressureswitch_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E5D58);
}

int PressureSwitch_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    animUpdate->hitVolumePair = -1;
    animUpdate->sequenceEventActive = 0;
    return 0;
}

#pragma opt_strength_reduction off

#pragma opt_common_subs off
void pressureswitch_update(int obj)
{
    extern u8 framesThisStep;
    extern f32 timeDelta;
    extern f32 lbl_803E5D5C;
    extern f32 lbl_803E5D60;
    extern f32 lbl_803E5D64;
    extern f32 lbl_803E5D68;
    extern f32 lbl_803E5D6C;
    extern f32 lbl_803E5D74;
    extern f32 lbl_803E5D70;
    PressureswitchPlacement* t;
    GameObject* self;
    PressureSwitchState* sub;
    s8 far;
    int i;
    GameObject* player;
    GameObject* tricky;
    int ac;
    int v;
    s8 played;
    f32 cur;
    f32 lim;
    f32 thr;
    f32 f;

    self = (GameObject*)obj;
    player = (GameObject*)Obj_GetPlayerObject();
    t = (PressureswitchPlacement*)self->anim.placementData;
    sub = self->extra;
    far = 0;
    if (Vec_distance(&self->anim.worldPosX, &player->anim.worldPosX) > lbl_803E5D5C)
    {
        far = 1;
    }
    sub->holdTimer -= 1;
    if (sub->holdTimer < 0)
    {
        sub->holdTimer = 0;
        sub->chimeLatch = 0;
    }
    ((PswFlags*)&sub->flags)->active = 0;
    if (*(char**)(obj + PSWITCH_HITLIST_OFFSET) != NULL &&
        *(s8*)(*(char**)(obj + PSWITCH_HITLIST_OFFSET) + PSWITCH_HITLIST_COUNT_OFFSET) > 0)
    {
        sub->retriggerTimer = (s16)(t->unk1E * 60);
        i = 0;
        thr = lbl_803E5D60;
        for (; i < *(s8*)(*(char**)(obj + PSWITCH_HITLIST_OFFSET) + PSWITCH_HITLIST_COUNT_OFFSET); i++)
        {
            GameObject* ent =
                *(GameObject**)(*(char**)(obj + PSWITCH_HITLIST_OFFSET) + i * 4 + PSWITCH_HITLIST_OBJECTS_OFFSET);
            if (ent->anim.seqId == PSWITCH_TRIGGER_SEQ_ID)
            {
                ((PswFlags*)&sub->flags)->active = 1;
            }
            if (ent->anim.localPosY - self->anim.localPosY > thr)
            {
                sub->holdTimer = 5;
            }
            if (sub->chimeLatch == 0 && ent != NULL && ent->anim.seqId == PSWITCH_CHIME_SEQ_ID)
            {
                if (far == 0)
                {
                    Sfx_PlayFromObject(obj, 0x7e);
                }
                sub->chimeLatch = 1;
            }
        }
    }
    else
    {
        ac = self->anim.mapEventSlot;
        if (ac == 11 && (*gMapEventInterface)->getMapAct(ac) == 3 &&
            (tricky = (GameObject*)getTrickyObject()) != NULL &&
            Vec_distance(&self->anim.worldPosX, &tricky->anim.worldPosX) < lbl_803E5D64)
        {
            sub->holdTimer = 5;
        }
    }
    ac = self->anim.mapEventSlot;
    if (ac == 11 && (*gMapEventInterface)->getMapAct(ac) == 1 && far == 0)
    {
        if (sub->holdTimer != 0)
        {
            f = t->unkC - self->anim.localPosY;
            if (f > lbl_803E5D68 && f < lbl_803E5D6C && GameBit_Get(sub->mapGameBit) == 0)
            {
                GameBit_Set(0x905, 1);
            }
            else if (GameBit_Get(0x905) != 0)
            {
                GameBit_Set(0x905, 0);
            }
        }
        else if (GameBit_Get(0x905) != 0)
        {
            GameBit_Set(0x905, 0);
        }
    }
    played = 0;
    if (sub->holdTimer != 0)
    {
        lim = t->unkC - lbl_803E5D6C;
        cur = self->anim.localPosY;
        if (cur < lim)
        {
            self->anim.localPosY = lbl_803E5D70 * timeDelta + cur;
            if (self->anim.localPosY > lim)
            {
                self->anim.localPosY = lim;
            }
            GameBit_Set(t->unk1C, 1);
            if (((PswFlags*)&sub->flags)->active)
            {
                GameBit_Set(sub->mapGameBit, 1);
            }
        }
        else
        {
            self->anim.localPosY = -(lbl_803E5D74 * timeDelta - cur);
            if (self->anim.localPosY < lim)
            {
                self->anim.localPosY = lim;
                GameBit_Set(t->unk1C, 1);
                v = sub->mapGameBit;
                if (v != -1)
                {
                    GameBit_Set(v, 1);
                    if (((PswFlags*)&sub->flags)->active)
                    {
                        ((PswFlags*)&sub->flags)->latched = 1;
                    }
                }
            }
            else
            {
                played = 1;
            }
        }
    }
    else
    {
        if (sub->retriggerTimer == 0)
        {
            self->anim.localPosY = lbl_803E5D74 * timeDelta + self->anim.localPosY;
            if (self->anim.localPosY > t->unkC)
            {
                self->anim.localPosY = t->unkC;
            }
            else
            {
                played = 1;
            }
            GameBit_Set(t->unk1C, 0);
            v = sub->mapGameBit;
            if (v != -1)
            {
                if (!((PswFlags*)&sub->flags)->latched)
                {
                    GameBit_Set(v, 0);
                }
            }
        }
    }
    if (played != 0)
    {
        Sfx_PlayFromObject(obj, 0x7f);
    }
    else
    {
        Sfx_StopObjectChannel(obj, 8);
    }
    if (sub->retriggerTimer != 0)
    {
        sub->retriggerTimer -= framesThisStep;
        if (sub->retriggerTimer < 0)
        {
            sub->retriggerTimer = 0;
        }
    }
}
#pragma opt_common_subs reset
