/*
 * SB_CageKyte (DLL 0x01F2) - Kyte, the captive baby Cloudrunner held in the
 * deck cage (SB_KyteCage) during the ShipBattle prologue (SB = the retail
 * "ShipBattle" map). This is the objType-0x121 child Krystal walks up to and
 * talks to after landing on the galleon. TU: 0x801E4288-0x801E42F8.
 *
 * Its extra state is a single s16 chirp timer. Each update tick it counts
 * the timer down by framesThisStep, forces hitbox-reset bit 0x8, and
 * measures its distance to the player; when the timer expires it plays a
 * "beep"/chirp sfx (unless suppressed by a GameBit) and re-arms with a
 * random 400-600 frame delay.
 */
#include "main/dll/shipbattlestate_struct.h"
#include "main/dll/sbkytecagestate_struct.h"
#include "main/dll/sbfireballstate_struct.h"
#include "main/dll/sbcloudballstate_struct.h"
#include "main/game_object.h"
#include "main/objanim_update.h"
#include "main/audio/sfx_ids.h"
#include "main/gameplay_runtime.h"
#include "main/gamebits.h"
extern u8 framesThisStep;

/* anim.resetHitboxMode bit forced on each SeqFn / update tick. */
#define SB_CAGEKYTE_HITBOX_RESET_BIT 0x8

/* GameBit that, when set, suppresses the chirp sfx. */
#define SB_CAGEKYTE_SILENCE_GAMEBIT 0xA71

/* random re-arm window (frames) for the chirp timer. */
#define SB_CAGEKYTE_CHIRP_MIN 400
#define SB_CAGEKYTE_CHIRP_MAX 600

#define SB_CAGEKYTE_OBJFLAG_HIDDEN 0x4000
#define SB_CAGEKYTE_OBJFLAG_HITDETECT_DISABLED 0x2000

STATIC_ASSERT(sizeof(SBCloudBallState) == 0x24);
STATIC_ASSERT(sizeof(SBFireBallState) == 0x18);
STATIC_ASSERT(sizeof(SBKyteCageState) == 0x8);
STATIC_ASSERT(sizeof(ShipBattleState) == 0x140);

void SB_CageKyte_free(void)
{
}

void SB_CageKyte_hitDetect(void)
{
}

void SB_CageKyte_release(void)
{
}

void SB_CageKyte_initialise(void)
{
}

int SB_CageKyte_getExtraSize(void) { return 0x2; }
int SB_CageKyte_getObjectTypeId(void) { return 0x1; }

int SB_CageKyte_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    int holdTimer = obj->unkF4;
    if (holdTimer > 0)
    {
        obj->unkF4 = holdTimer - 1;
    }
    obj->anim.resetHitboxFlags |= SB_CAGEKYTE_HITBOX_RESET_BIT;
    animUpdate->hitVolumePair = -2;
    animUpdate->sequenceEventActive = 0;
    return 0;
}

void SB_CageKyte_init(GameObject* obj)
{
    obj->animEventCallback = SB_CageKyte_SeqFn;
    obj->objectFlags = (u16)((u32)obj->objectFlags | (SB_CAGEKYTE_OBJFLAG_HIDDEN | SB_CAGEKYTE_OBJFLAG_HITDETECT_DISABLED));
}

void SB_CageKyte_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible == 0)
    {
        return;
    }
}

void SB_CageKyte_update(GameObject* obj)
{
    extern f32 Vec_distance(f32* a, f32* b);
    extern void Sfx_PlayFromObject(int* obj, int sfxId);
    s16* timer;
    GameObject* player;

    timer = obj->extra;
    if (obj->unkF4 > 0)
    {
        obj->unkF4 = obj->unkF4 - 1;
    }

    obj->anim.resetHitboxFlags |= SB_CAGEKYTE_HITBOX_RESET_BIT;
    *timer -= framesThisStep;
    player = Obj_GetPlayerObject();
    Vec_distance(&obj->anim.worldPosX, &player->anim.worldPosX);

    if (*timer <= 0)
    {
        randomGetRange(0, 10);
        if ((u32)GameBit_Get(SB_CAGEKYTE_SILENCE_GAMEBIT) == 0u)
        {
            Sfx_PlayFromObject((int*)obj, SFXfend_rob_beep3);
        }
        *timer = randomGetRange(SB_CAGEKYTE_CHIRP_MIN, SB_CAGEKYTE_CHIRP_MAX);
    }
}
