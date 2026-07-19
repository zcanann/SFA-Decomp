/*
 * seqObj11E - shared baddie-behavior handlers dispatched from the
 * enemy DLL (dll_00C9_enemy) by object type id. Each handler operates on
 * a GameObject plus its BaddieState scratch block; the pairs below are
 * (init, update) sets plus hit/reaction callbacks selected per type:
 *
 *   guardClaw_init / guardClaw_update: a 12-byte-row state-table driver (gSeq11EStateTable)
 *     that advances on GameBit + sequence flags and kicks the matching anim.
 *   gcRobotLight_init: spawns and sets up a child object at the parent's pos.
 *   (gcRobotPatrol and mikaladon_updateWhileFrozen live in gcrobotpatrol.c.)
 *
 * defNos handled (from the enemy dispatch table, named per retail OBJECTS.bin):
 * 0xd8 GuardClaw (state-table).
 */
#include "main/audio/sfx_ids.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/trig_float_helpers.h"
#include "main/audio/sfx.h"
#include "main/gamebits.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/obj_link.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/objhits.h"
#include "main/objfx.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/baddie_state.h"
#include "main/dll/baddie_setmove.h"
#include "main/objtexture.h"
#include "main/dll/seqObj11E.h"
#include "main/dll/objfsa.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/dll/seqobj11d_ext.h"
#include "main/dll/groundbaddiepush_ext.h"
#include "main/dll/dll_00C9_enemy_ext.h"
#include "main/dll/dll_0150_gcrobotlightbea.h"

int lbl_803DBCA8[2] = {2, 3};
f32 lbl_803DBCB0 = 0.018f;
f32 lbl_803DBCB4 = 240.0f;

/* gcRobotPatrol (mikaladon_update): periodically dropped object; parented back to
 * the dropper via +0xC4 and announced with SFX 0x249. */
#define SEQOBJ11E_GCROBOT_DROP_OBJ 0x6b5

typedef void (*SeqObj11ESetMovePointerStateFn)(GameObject* obj, void* state, int moveId, f32 speed, int p5,
                                               int flags);

/* guardClaw_update: state-table driver: walks the 12-byte gSeq11EStateTable state
 * rows, advancing on GameBit + sequence flags and kicking the matching anim. */

typedef struct
{
    f32 animSpeed; /* 0x0 */
    u32 unk4;      /* 0x4 */
    u8 anim;       /* 0x8 */
    u8 next;       /* 0x9 */
    u8 alt;        /* 0xa */
    u8 flagB;      /* 0xb */
} Seq11ERow;

extern Seq11ERow gSeq11EStateTable[];

void guardClaw_update(int* obj, u8* state)
{
    int* def = *(int**)&((GameObject*)obj)->anim.placementData;
    u32 flags;

    if (((BaddieState*)state)->userData1 == 2 && mainGetBit(*(s16*)((char*)def + 0x1c)) == 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
            (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED);
        if (*(u8*)&((GameObject*)obj)->anim.resetHitboxMode & INTERACT_FLAG_ACTIVATED)
        {
            fn_80151C68((int)obj, state);
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
            (u8)(*(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED);
    }
    flags = ((BaddieState*)state)->controlFlags;
    if (flags & BADDIE_CONTROL_JUST_TRIGGERED)
    {
        if (gSeq11EStateTable[((BaddieState*)state)->userData1].unk4 != 0)
        {
            ((BaddieState*)state)->controlFlags = flags | (u64)BADDIE_CONTROL_SEQUENCE_DRIVEN;
        }
    }
    flags = ((BaddieState*)state)->controlFlags;
    if (flags & BADDIE_CONTROL_SEQUENCE_DRIVEN)
    {
        int anim;
        u8* animTbl;

        if (((BaddieState*)state)->userData1 == 0)
        {
            if (flags & 0x20000000)
            {
                if (mainGetBit(*(s16*)((char*)def + 0x1c)) != 0)
                {
                    ((BaddieState*)state)->userData1 = gSeq11EStateTable[((BaddieState*)state)->userData1].alt;
                }
                else
                {
                    ((BaddieState*)state)->userData1 = gSeq11EStateTable[((BaddieState*)state)->userData1].next;
                }
            }
        }
        else if (((BaddieState*)state)->userData1 == 2)
        {
            if (mainGetBit(*(s16*)((char*)def + 0x1c)) != 0 || !(((BaddieState*)state)->controlFlags & 0x20000000))
            {
                ((BaddieState*)state)->userData1 = gSeq11EStateTable[((BaddieState*)state)->userData1].next;
            }
        }
        else if (((BaddieState*)state)->userData1 == 3)
        {
            if (mainGetBit(*(s16*)((char*)def + 0x1c)) != 0)
            {
                ((BaddieState*)state)->userData1 = gSeq11EStateTable[((BaddieState*)state)->userData1].alt;
            }
            else
            {
                ((BaddieState*)state)->userData1 = gSeq11EStateTable[((BaddieState*)state)->userData1].next;
            }
        }
        else
        {
            ((BaddieState*)state)->userData1 = gSeq11EStateTable[((BaddieState*)state)->userData1].next;
        }
        anim = ((GameObject*)obj)->anim.currentMove;
        if (anim != (animTbl = (u8*)gSeq11EStateTable + 8)[((BaddieState*)state)->userData1 * 12])
        {
            if (animTbl[((BaddieState*)state)->userData1 * 12] != 0 &&
                animTbl[((BaddieState*)state)->userData1 * 12] != 4)
            {
                Sfx_PlayFromObject((u32)obj, SFXTRIG_baddie_eggsnatch_carry3);
            }
            ((SeqObj11ESetMovePointerStateFn)fn_8014D08C)(
                (GameObject*)obj, state, animTbl[((BaddieState*)state)->userData1 * 12],
                *(f32*)((u8*)gSeq11EStateTable + ((BaddieState*)state)->userData1 * 12), 0, 0xf);
        }
    }
    if (gSeq11EStateTable[((BaddieState*)state)->userData1].flagB != 0)
    {
        groundBaddiePushPlayerOut((int)obj, state);
    }
}

void guardClaw_init(int* obj, u8* state)
{
    int* sub = *(int**)&((GameObject*)obj)->anim.placementData;
    f32 fz;
    ((BaddieState*)state)->speedScale = 200.0f;
    ((BaddieState*)state)->unk2A8 = 300.0f;
    ((BaddieState*)state)->unk2E4 = 1;
    ((BaddieState*)state)->unk2E4 |= 0xC80;
    ((BaddieState*)state)->unk308 = 0.0055555557f;
    ((BaddieState*)state)->animDeltaScale = 0.17f;
    ((BaddieState*)state)->unk304 = 0.97f;
    ((BaddieState*)state)->unk320 = 0;
    fz = 1.0f;
    *(f32*)&((BaddieState*)state)->eventFlags = fz;
    ((BaddieState*)state)->unk321 = 0;
    ((BaddieState*)state)->unk318 = fz;
    ((BaddieState*)state)->unk322 = 0;
    ((BaddieState*)state)->unk31C = fz;
    if (*((s8*)sub + 0x2e) != -1)
    {
        *(int*)&((BaddieState*)state)->controlFlags |= 1;
    }
    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= INTERACT_FLAG_DISABLED;
}

GameObject* gcRobotLight_init(GameObject* obj, int childId)
{
    int sub;
    u8* setup;

    sub = *(int*)&obj->anim.placementData;
    Obj_GetPlayerObject();
    if (Obj_IsLoadingLocked() == 0)
        return NULL;
    setup = (u8*)Obj_AllocObjectSetup(36, childId);
    *(s16*)(setup + 0) = childId;
    ((ObjPlacement*)setup)->color[0] = ((ObjPlacement*)sub)->color[0];
    ((ObjPlacement*)setup)->color[2] = ((ObjPlacement*)sub)->color[2];
    ((ObjPlacement*)setup)->color[1] = 1;
    ((ObjPlacement*)setup)->color[3] = ((ObjPlacement*)sub)->color[3];
    ((ObjPlacement*)setup)->posX = obj->anim.localPosX;
    ((ObjPlacement*)setup)->posY = obj->anim.localPosY;
    ((ObjPlacement*)setup)->posZ = obj->anim.localPosZ;
    ((Seq11EChildSetup*)setup)->unk19 = 0;
    ((Seq11EChildSetup*)setup)->unk20 = 149;
    return Obj_SetupObject((ObjPlacement*)setup, 5, obj->anim.mapEventSlot, -1, obj->anim.parent);
}

Seq11ERow gSeq11EStateTable[6] = {
    {3.0f, 0x1, 0, 1, 4, 1}, {2.0f, 0x0, 1, 2, 2, 1}, {3.0f, 0x1, 2, 3, 3, 1},
    {2.0f, 0x0, 7, 0, 4, 1}, {2.0f, 0x0, 3, 5, 5, 0}, {3.5f, 0x1, 4, 5, 5, 0},
};
