/*
 * sbseqdoor (DLL 0x01F1) - a galleon door that opens via a trigger sequence
 * in the ShipBattle prologue (SB = the retail "ShipBattle" map). This one
 * DLL drives all three retail door objects - SB_SeqDoor, SB_SeqDoor2 and
 * SB_DeckDoor - the last being the deck hatch that opens (once Kyte is
 * talked to) onto the passage where the golden key is found.
 * TU: 0x801E4288-0x801E42F8.
 *
 * The door faces a placement-supplied heading and, once its arming GameBit
 * is set, runs trigger sequence 0 a single time (latched through obj->unkF4)
 * to play the open animation. Each tick it also forces hitbox-reset bit 0x10.
 */
#include "main/dll/shipbattlestate_struct.h"
#include "main/dll/sbkytecagestate_struct.h"
#include "main/dll/sbfireballstate_struct.h"
#include "main/dll/sbcloudballstate_struct.h"
#include "main/game_object.h"
#include "main/objanim_update.h"
#include "main/objseq.h"
#include "main/dll/VF/vf_shared.h"
#include "main/gamebits.h"
extern f32 lbl_803E5920;

/* The sequence-door seqId and the GameBit that arms it. */
#define SB_SEQDOOR_SEQ_ID 0x173
#define SB_SEQDOOR_ARM_GAMEBIT 0xA4B

/* anim.resetHitboxMode bit forced on each update tick. */
#define SB_SEQDOOR_HITBOX_RESET_BIT 0x10

/* Placement record: heading byte + a nonzero->bankIndex selector. */
typedef struct SBSeqDoorPlacement
{
    u8 pad0[0x18];
    s8 rotXByte;  /* 0x18: heading, scaled to anim.rotX (<<8) */
    s8 bankSelect; /* 0x19: nonzero picks bank index 1 */
    u8 unk1A;
    u8 pad1B[0x20 - 0x1B];
} SBSeqDoorPlacement;

STATIC_ASSERT(sizeof(SBCloudBallState) == 0x24);
STATIC_ASSERT(sizeof(SBFireBallState) == 0x18);
STATIC_ASSERT(sizeof(SBKyteCageState) == 0x8);
STATIC_ASSERT(sizeof(ShipBattleState) == 0x140);

void SB_SeqDoor_free(void)
{
}

void SB_SeqDoor_hitDetect(void)
{
}

void SB_SeqDoor_release(void)
{
}

void SB_SeqDoor_initialise(void)
{
}

int SB_SeqDoor_getExtraSize(void) { return 0x0; }
int SB_SeqDoor_getObjectTypeId(void) { return 0x0; }

int SB_SeqDoor_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate);

void SB_SeqDoor_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    if (visible != 0)
    {
        objRenderModelAndHitVolumes(p1, p2, p3, p4, p5, lbl_803E5920);
    }
}

int SB_SeqDoor_SeqFn(GameObject* obj, int unused, ObjAnimUpdateState* animUpdate)
{
    if (obj->anim.seqId != SB_SEQDOOR_SEQ_ID)
    {
        animUpdate->hitVolumePair = -2;
    }
    animUpdate->sequenceEventActive = 0;
    return 0;
}

void SB_SeqDoor_init(GameObject* obj, SBSeqDoorPlacement* placement)
{
    obj->animEventCallback = SB_SeqDoor_SeqFn;
    obj->anim.rotX = (s16)((s32)placement->rotXByte << 8);
    {
        s8 bankSelect = placement->bankSelect;
        obj->anim.bankIndex = (s8)(((u32)-bankSelect | (u32)bankSelect) >> 31);
    }
}

void SB_SeqDoor_update(GameObject* obj)
{
    if (obj->anim.seqId == SB_SEQDOOR_SEQ_ID)
    {
        if (obj->unkF4 == 0)
        {
            if ((u32)GameBit_Get(SB_SEQDOOR_ARM_GAMEBIT) != 0u)
            {
                (*gObjectTriggerInterface)->runSequence(0, obj, -1);
                obj->unkF4 = 1;
            }
        }
    }
    obj->anim.resetHitboxFlags |= SB_SEQDOOR_HITBOX_RESET_BIT;
}
