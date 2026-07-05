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
#include "main/dll/fx_800944A0_shared.h"
#include "main/audio/sfx_trigger_ids.h"

typedef struct PressureswitchPlacement
{
    u8 pad0[0xC - 0x0];
    f32 restPosY;    /* 0x0C: rest (up) Y position; pad sinks below this */
    u8 pad10[0x1A - 0x10];
    s16 unk1A;
    s16 triggerGameBit; /* 0x1C: game bit raised while the pad is pressed */
    s16 retriggerDelay; /* 0x1E: seconds before the pad can re-trigger (*60) */
    u8 pad20[0x4C - 0x20];
    u8 unk4C;
    u8 pad4D[0x2F8 - 0x4D];
    u8 unk2F8;
    u8 unk2F9;
    s8 unk2FA;
    u8 pad2FB[0x300 - 0x2FB];
} PressureswitchPlacement;

/*
 * The contact list reached via GameObject+0x58 (ObjAnimComponent's pad58):
 * the objects currently resting on / hitting this object. Only the fields
 * this DLL reads are mapped; the engine struct is larger.
 */
typedef struct PswContactList
{
    u8 pad00[0x100];
    GameObject* objects[3]; /* 0x100: contacts; `count` of them are valid */
    u8 pad10C[0x10F - 0x10C];
    s8 count;               /* 0x10F */
} PswContactList;

/* Re-derefs the +0x58 list pointer per use. */
#define PSW_CONTACT_LIST(obj) ((PswContactList*)*(char**)((obj) + 0x58))

/* seqIds of objects this pad reacts to (compared against ent->anim.seqId). */
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
    u8 flags; /* PressureSwitchFlags overlay */
    u8 pad7;
} PressureSwitchState;

typedef struct PressureSwitchFlags
{
    u8 active : 1;        /* bit0: a trigger-type object (seqId 0x6d) is on the pad */
    u8 mapBitLatched : 1; /* bit1: map game bit latched on (not auto-cleared on release) */
    u8 otherFlags : 6;
} PressureSwitchFlags;

STATIC_ASSERT(sizeof(Dll200State) == 0x28);

extern void objRenderFn_8003b8f4(int obj, int p2, int p3, int p4, int p5, f32 scale);

extern void* getTrickyObject(void);
extern f32 Vec_distance(f32* a, f32* b);

int PressureSwitch_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    animUpdate->hitVolumePair = -1;
    animUpdate->sequenceEventActive = 0;
    return 0;
}

int pressureswitch_getExtraSize(void) { return 0x8; }
int pressureswitch_getObjectTypeId(void) { return 0x0; }

void pressureswitch_free(void)
{
}

void pressureswitch_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(p1, p2, p3, p4, p5, 1.0f);
}

void pressureswitch_hitDetect(void)
{
}

#pragma opt_strength_reduction off

#pragma opt_common_subs off
void pressureswitch_update(int obj)
{
    int off[1];
    PressureswitchPlacement* t;
    GameObject* self;
    PressureSwitchState* sub;
    PswContactList* list;
    s8 far;
    int i;
    GameObject* player;
    GameObject* tricky;
    s8 ac;
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
    if (Vec_distance(&self->anim.worldPosX, &player->anim.worldPosX) > 100.0f)
    {
        far = 1;
    }
    sub->holdTimer -= 1;
    if (sub->holdTimer < 0)
    {
        sub->holdTimer = 0;
        sub->chimeLatch = 0;
    }
    off[0] = 0;
    ((PressureSwitchFlags*)&sub->flags)->active = off[0];
    if (PSW_CONTACT_LIST(obj) != NULL &&
        PSW_CONTACT_LIST(obj)->count > 0)
    {
        sub->retriggerTimer = (s16)(t->retriggerDelay * 60);
        i = 0;
        thr = 7.0f;
        for (; i < (list = PSW_CONTACT_LIST(obj))->count; i++)
        {
            GameObject* ent = *(GameObject**)((char*)list + off[0] + 256);
            if (ent->anim.seqId == PSWITCH_TRIGGER_SEQ_ID)
            {
                ((PressureSwitchFlags*)&sub->flags)->active = 1;
            }
            if (ent->anim.localPosY - self->anim.localPosY > thr)
            {
                sub->holdTimer = 5;
            }
            if (sub->chimeLatch == 0 && ent != NULL && ent->anim.seqId == PSWITCH_CHIME_SEQ_ID)
            {
                if (far == 0)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_mpick1_b);
                }
                sub->chimeLatch = 1;
            }
            off[0] += 4;
        }
    }
    else
    {
        ac = self->anim.mapEventSlot;
        if (ac == 11 && (*gMapEventInterface)->getMapAct(ac) == 3 &&
            (tricky = (GameObject*)getTrickyObject()) != NULL &&
            Vec_distance(&self->anim.worldPosX, &tricky->anim.worldPosX) < 50.0f)
        {
            sub->holdTimer = 5;
        }
    }
    ac = self->anim.mapEventSlot;
    if (ac == 11 && (*gMapEventInterface)->getMapAct(ac) == 1 && far == 0)
    {
        if (sub->holdTimer != 0)
        {
            f = t->restPosY - self->anim.localPosY;
            if (f > 2.5f && f < 5.0f && GameBit_Get(sub->mapGameBit) == 0)
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
        lim = t->restPosY - 5.0f;
        cur = self->anim.localPosY;
        if (cur < lim)
        {
            self->anim.localPosY = 0.25f * timeDelta + cur;
            if (self->anim.localPosY > lim)
            {
                self->anim.localPosY = lim;
            }
            GameBit_Set(t->triggerGameBit, 1);
            if (((PressureSwitchFlags*)&sub->flags)->active)
            {
                GameBit_Set(sub->mapGameBit, 1);
            }
        }
        else
        {
            self->anim.localPosY = -(0.125f * timeDelta - cur);
            if (self->anim.localPosY < lim)
            {
                self->anim.localPosY = lim;
                GameBit_Set(t->triggerGameBit, 1);
                v = sub->mapGameBit;
                if (v != -1)
                {
                    GameBit_Set(v, 1);
                    if (((PressureSwitchFlags*)&sub->flags)->active)
                    {
                        ((PressureSwitchFlags*)&sub->flags)->mapBitLatched = 1;
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
            self->anim.localPosY = 0.125f * timeDelta + self->anim.localPosY;
            if (self->anim.localPosY > (f = t->restPosY))
            {
                self->anim.localPosY = f;
            }
            else
            {
                played = 1;
            }
            GameBit_Set(t->triggerGameBit, 0);
            v = sub->mapGameBit;
            if (v != -1)
            {
                if (!((PressureSwitchFlags*)&sub->flags)->mapBitLatched)
                {
                    GameBit_Set(v, 0);
                }
            }
        }
    }
    if (played != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_en_treedrum16);
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

void pressureswitch_init(int* obj, u8* init)
{
    PressureSwitchState* sub;
    u32 mapId;

    sub = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = PressureSwitch_SeqFn;
    ((GameObject*)obj)->anim.rotX = (s16)((s8)init[0x18] << 8);
    sub->retriggerTimer = (s16)(((PressureswitchPlacement*)init)->retriggerDelay * 0x3c);
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
    if (GameBit_Get(((PressureswitchPlacement*)init)->triggerGameBit) != 0)
    {
        ((GameObject*)obj)->anim.localPosY = ((PressureswitchPlacement*)init)->restPosY - 25.0f;
        sub->holdTimer = 0x1e;
    }
}

void pressureswitch_release(void)
{
}

void pressureswitch_initialise(void)
{
}
