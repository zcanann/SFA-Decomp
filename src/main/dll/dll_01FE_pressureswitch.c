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

extern void objRenderModelAndHitVolumes(int obj, int p2, int p3, int p4, int p5, f32 scale);

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
    s32 isVisible = visible;
    if (isVisible != 0) objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, 1.0f);
}

void pressureswitch_hitDetect(void)
{
}

#pragma opt_strength_reduction off

#pragma opt_common_subs off
void pressureswitch_update(int obj)
{
    int byteOff[1];
    PressureswitchPlacement* placement;
    GameObject* self;
    PressureSwitchState* state;
    PswContactList* contacts;
    s8 playerFar;
    int i;
    GameObject* player;
    GameObject* tricky;
    s8 mapSlot;
    int bit;
    s8 moving;
    f32 curY;
    f32 pressedY;
    f32 heightThreshold;
    f32 posY;

    self = (GameObject*)obj;
    player = (GameObject*)Obj_GetPlayerObject();
    placement = (PressureswitchPlacement*)self->anim.placementData;
    state = self->extra;
    playerFar = 0;
    if (Vec_distance(&self->anim.worldPosX, &player->anim.worldPosX) > 100.0f)
    {
        playerFar = 1;
    }
    state->holdTimer -= 1;
    if (state->holdTimer < 0)
    {
        state->holdTimer = 0;
        state->chimeLatch = 0;
    }
    byteOff[0] = 0;
    ((PressureSwitchFlags*)&state->flags)->active = byteOff[0];
    if (PSW_CONTACT_LIST(obj) != NULL &&
        PSW_CONTACT_LIST(obj)->count > 0)
    {
        state->retriggerTimer = (s16)(placement->retriggerDelay * 60);
        i = 0;
        heightThreshold = 7.0f;
        for (; i < (contacts = PSW_CONTACT_LIST(obj))->count; i++)
        {
            GameObject* ent = *(GameObject**)((char*)contacts + byteOff[0] + 256);
            if (ent->anim.seqId == PSWITCH_TRIGGER_SEQ_ID)
            {
                ((PressureSwitchFlags*)&state->flags)->active = 1;
            }
            if (ent->anim.localPosY - self->anim.localPosY > heightThreshold)
            {
                state->holdTimer = 5;
            }
            if (state->chimeLatch == 0 && ent != NULL && ent->anim.seqId == PSWITCH_CHIME_SEQ_ID)
            {
                if (playerFar == 0)
                {
                    Sfx_PlayFromObject(obj, SFXTRIG_mpick1_b);
                }
                state->chimeLatch = 1;
            }
            byteOff[0] += 4;
        }
    }
    else
    {
        mapSlot = self->anim.mapEventSlot;
        if (mapSlot == 11 && (*gMapEventInterface)->getMapAct(mapSlot) == 3 &&
            (tricky = (GameObject*)getTrickyObject()) != NULL &&
            Vec_distance(&self->anim.worldPosX, &tricky->anim.worldPosX) < 50.0f)
        {
            state->holdTimer = 5;
        }
    }
    mapSlot = self->anim.mapEventSlot;
    if (mapSlot == 11 && (*gMapEventInterface)->getMapAct(mapSlot) == 1 && playerFar == 0)
    {
        if (state->holdTimer != 0)
        {
            posY = placement->restPosY - self->anim.localPosY;
            if (posY > 2.5f && posY < 5.0f && GameBit_Get(state->mapGameBit) == 0)
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
    moving = 0;
    if (state->holdTimer != 0)
    {
        pressedY = placement->restPosY - 5.0f;
        curY = self->anim.localPosY;
        if (curY < pressedY)
        {
            self->anim.localPosY = 0.25f * timeDelta + curY;
            if (self->anim.localPosY > pressedY)
            {
                self->anim.localPosY = pressedY;
            }
            GameBit_Set(placement->triggerGameBit, 1);
            if (((PressureSwitchFlags*)&state->flags)->active)
            {
                GameBit_Set(state->mapGameBit, 1);
            }
        }
        else
        {
            self->anim.localPosY = -(0.125f * timeDelta - curY);
            if (self->anim.localPosY < pressedY)
            {
                self->anim.localPosY = pressedY;
                GameBit_Set(placement->triggerGameBit, 1);
                bit = state->mapGameBit;
                if (bit != -1)
                {
                    GameBit_Set(bit, 1);
                    if (((PressureSwitchFlags*)&state->flags)->active)
                    {
                        ((PressureSwitchFlags*)&state->flags)->mapBitLatched = 1;
                    }
                }
            }
            else
            {
                moving = 1;
            }
        }
    }
    else
    {
        if (state->retriggerTimer == 0)
        {
            self->anim.localPosY = 0.125f * timeDelta + self->anim.localPosY;
            if (self->anim.localPosY > (posY = placement->restPosY))
            {
                self->anim.localPosY = posY;
            }
            else
            {
                moving = 1;
            }
            GameBit_Set(placement->triggerGameBit, 0);
            bit = state->mapGameBit;
            if (bit != -1)
            {
                if (!((PressureSwitchFlags*)&state->flags)->mapBitLatched)
                {
                    GameBit_Set(bit, 0);
                }
            }
        }
    }
    if (moving != 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_en_treedrum16);
    }
    else
    {
        Sfx_StopObjectChannel(obj, 8);
    }
    if (state->retriggerTimer != 0)
    {
        state->retriggerTimer -= framesThisStep;
        if (state->retriggerTimer < 0)
        {
            state->retriggerTimer = 0;
        }
    }
}
#pragma opt_common_subs reset

void pressureswitch_init(int* obj, u8* init)
{
    PressureSwitchState* state;
    u32 mapId;

    state = ((GameObject*)obj)->extra;
    ((GameObject*)obj)->animEventCallback = PressureSwitch_SeqFn;
    ((GameObject*)obj)->anim.rotX = (s16)((s8)init[0x18] << 8);
    state->retriggerTimer = (s16)(((PressureswitchPlacement*)init)->retriggerDelay * 0x3c);
    state->chimeLatch = 0;
    mapId = *(int*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x14);
    if (mapId == 0x1f1a)
    {
        state->mapGameBit = 0xf45;
    }
    else if (mapId == 0x47293)
    {
        state->mapGameBit = 0xf46;
    }
    else
    {
        state->mapGameBit = -1;
    }
    if (state->mapGameBit != -1)
    {
        if (GameBit_Get(state->mapGameBit) != 0)
        {
            ((PressureSwitchFlags*)&state->flags)->mapBitLatched = 1;
        }
    }
    if (GameBit_Get(((PressureswitchPlacement*)init)->triggerGameBit) != 0)
    {
        ((GameObject*)obj)->anim.localPosY = ((PressureswitchPlacement*)init)->restPosY - 25.0f;
        state->holdTimer = 0x1e;
    }
}

void pressureswitch_release(void)
{
}

void pressureswitch_initialise(void)
{
}
