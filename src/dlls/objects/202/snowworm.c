#include "dlls/objects/202.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "game/objects/object.h"
#include "game/objects/object_setup.h"
#include "main/audio/sfx_play_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/camera.h"
#include "main/camera_shake_api.h"
#include "main/dll/baddie_control_interface.h"
#include "main/dll/partfx_interface.h"
#include "main/frame_timing.h"
#include "main/gamebits_api.h"
#include "main/mapEventTypes.h"
#include "main/object_render.h"
#include "main/objtype.h"
#include "main/obj_message.h"
#include "main/obj_path.h"
#include "main/objanim.h"
#include "main/objhits.h"
#include "main/objprint_api.h"
#include "main/objseq.h"
#include "main/player_control_interface.h"
#include "main/vecmath.h"
#include "main/voxmaps.h"
#include "sys/objects.h"
#include "sys/objects/lifecycle.h"
#include "main/dll/baddie_state.h"
#include "main/dll/dll_00C9_enemy.h"
#include "main/dll/wispbaddie_baddie.h"
#include "main/audio/sfx_position_api.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/baddie_setmove.h"
#include "main/pad_api.h"
#include "main/dll/seqobj11d_ext.h"
#include "main/dll/wispbaddieseq_ext.h"
#include "main/gameloop_api.h"
#include "main/audio/sfx.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/gamebits.h"
#include "main/dll/objfsa.h"
#include "main/dll/newseqobj_baddie.h"
#include "main/dll/baddie_frozen.h"
#include "main/game_ui_interface.h"
#include "main/dll/tricky_api.h"
#include "main/model.h"
#include "main/object_transform.h"
#include "main/dll/player_target.h"
#include "main/dll/player_api.h"
#include "dlls/objects/225_WispBaddie.h"
#include "main/trig_float_helpers.h"
#include "main/obj_link.h"
#include "main/objfx.h"
#include "main/objtexture.h"
#include "main/dll/seqObj11E.h"
#include "main/dll/groundbaddiepush_ext.h"
#include "main/dll/dll_00C9_enemy_ext.h"
#include "dlls/objects/336_GCRobotLigh.h"
#include "dolphin/mtx.h"
#include "main/dll/mikaladon.h"
#include "main/dll/magicPlant.h"
#include "main/dll/kooshy.h"
#include "main/dll/weevil.h"
#include "main/trig.h"
#include "main/dll/waterfx_interface.h"
#include "main/dll/fall_ladders.h"
#include "main/dll/fireflyLantern.h"
#include "main/dll/duster_api.h"
#include "main/track_bbox_api.h"
#include "main/sky_interface.h"
#include "main/dll/duster.h"
#include "dlls/objects/216_PinPonSpike.h"
#include "main/dll/duster_wb.h"
#include "main/obj_query.h"
#include "main/dll/hoodedzyck.h"
#include "main/camera_interface.h"
#include "main/model_light.h"
#include "main/dll/firecrawler.h"
#include "main/dll/dll_0273_firepipe.h"
#include "main/dll/hagabon_mk2.h"
#include "main/dll/snowworm.h"
#include "main/dll/baddiewhirlpool.h"
#include "main/audio/sfx_limited_object_api.h"

/* Baddie-family animation data shared with the sequence-driver TUs. */

#define KALDACHOM_SPIT_OBJ 0x51b

/* The magic-plant's one particle-fx effect (spawned per hit-count in the
   attack handler). */

static inline int hoodedZyck_getAngleDelta(GameObject* obj, GameObject* target)
{
    f32 d = (f32)(int)((u16)getAngle(obj->anim.localPosX - target->anim.localPosX,
                                     obj->anim.localPosZ - target->anim.localPosZ) -
                       (u16)obj->anim.rotX);
    if (d > 32768.0f)
    {
        d = -65535.0f + d;
    }
    if (d < -32768.0f)
    {
        d = 65535.0f + d;
    }
    return d;
}

#define FIRECRAWLER_PARTFX_MOVE_TURN 0x802
/* movement dust spawned on the move-loop event: moving straight (turnDelta == 0) */

#define FIRECRAWLER_PARTFX_MOVE_STRAIGHT 0x809



#define SNOWWORM_SEQID_BABY            0x84b /* "snowworm_ba" - the baby variant of 0x842 "snowworm" */

void snowworm_spawnProjectile(GameObject* obj);

u8 gSnowwormSeqIndexReset[4] = {2, 2, 0, 0};

u8 gSnowwormSeqIndexMax[4] = {0xD, 7, 0, 0};

u8 gSnowwormTurnRates[4] = {0x3C, 0xB4, 0, 0};

u8 gSnowwormHitReactionSeqIndices[4] = {3, 5, 9, 0xB};

u8 gSnowwormBabyHitReactionSeqIndices[8] = {3, 5, 3, 5, 0, 0, 0, 0};

u8 gSnowwormMoveSequence[0xa8] = {
    0x3f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x07, 0x07, 0x07, 0x00, 0x40, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0xcc, 0xcc, 0xcd, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x3e, 0xcc,
    0xcc, 0xcd, 0x00, 0x00, 0x00, 0x01, 0x02, 0x02, 0x02, 0x00, 0x3f, 0x33, 0x33, 0x33, 0x00, 0x00, 0x00, 0x03, 0x03,
    0x03, 0x09, 0x00, 0x3f, 0x33, 0x33, 0x33, 0x00, 0x00, 0x00, 0x03, 0x08, 0x08, 0x08, 0x00, 0x3f, 0x80, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x02, 0x07, 0x07, 0x07, 0x00, 0x40, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x3e, 0xcc, 0xcc, 0xcd, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x3e, 0xcc, 0xcc, 0xcd, 0x00, 0x00,
    0x00, 0x01, 0x02, 0x02, 0x02, 0x00, 0x3f, 0xa6, 0x66, 0x66, 0x00, 0x00, 0x00, 0x03, 0x04, 0x04, 0x09, 0x00, 0x3f,
    0x33, 0x33, 0x33, 0x00, 0x00, 0x00, 0x03, 0x08, 0x08, 0x08, 0x00, 0x3f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
    0x07, 0x07, 0x07, 0x00, 0x40, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

u8 gSnowwormBabyMoveSequence[0x60] = {0x3f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x07, 0x07, 0x07, 0x00, 0x40, 0x20,
                         0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0xcc, 0xcc, 0xcd,
                         0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x3f, 0x19, 0x99, 0x9a, 0x00, 0x00,
                         0x00, 0x01, 0x02, 0x02, 0x02, 0x00, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
                         0x09, 0x09, 0x09, 0x00, 0x3f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x08, 0x08,
                         0x08, 0x00, 0x3f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x07, 0x07, 0x07, 0x00,
                         0x40, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

typedef struct SnowwormReactionTablePair {
    u8* moveSequence;
    u8* hitReactionSeqIndices;
} SnowwormReactionTablePair;

SnowwormReactionTablePair gCrawlerReactionTables[] = {
    {gSnowwormMoveSequence, gSnowwormHitReactionSeqIndices},
    {gSnowwormBabyMoveSequence, gSnowwormBabyHitReactionSeqIndices},
};

void snowworm_spawnProjectile(GameObject* obj)
{
    u8 locked = Obj_IsLoadingLocked();
    if (locked != 0)
    {
        int* setup = (int*)Obj_AllocObjectSetup(0x24, KALDACHOM_SPIT_OBJ);
        ((ObjPlacement*)setup)->posX = obj->anim.localPosX;
        ((ObjPlacement*)setup)->posY = 15.0f + obj->anim.localPosY;
        ((ObjPlacement*)setup)->posZ = obj->anim.localPosZ;
        ((ObjPlacement*)setup)->color[0] = 1;
        ((ObjPlacement*)setup)->color[1] = 4;
        ((ObjPlacement*)setup)->color[3] = 0xff;
        setup = (int*)objSetupObject((ObjPlacement*)setup, 5, -1, -1, 0);
        if (setup != NULL)
        {
            ((GameObject*)setup)->anim.velocityX =
                3.0f * -mathSinf((3.1415927f * (f32)*(s16*)obj) / 32768.0f);
            ((GameObject*)setup)->anim.velocityY = 0.0f;
            ((GameObject*)setup)->anim.velocityZ =
                3.0f * -mathCosf((3.1415927f * (f32)*(s16*)obj) / 32768.0f);
        }
    }
}

void snowworm_updateWhileFrozen(GameObject* obj, u8* st, GameObject* attacker, int cmd, int p5, int sub, Vec* wpad0, int wpad1)
{
    u8* base;
    u32 r;

    base = gCrawlerReactionTables[((EnemyState*)st)->phaseAngle].hitReactionSeqIndices;

    if (cmd == 0x11)
    {
        return;
    }
    if (cmd == 0x10)
    {
        ((EnemyState*)st)->flags2E8 |= 0x20;
        return;
    }
    if (((EnemyState*)st)->turnOctant > 3)
    {
        baddieSetMove((GameObject*)obj, st, 6, 0.5f, 0, 0);
    }
    else
    {
        baddieSetMove((GameObject*)obj, st, 5, 0.5f, 0, 0);
    }
    r = randomGetRange(0, 3);
    ((EnemyState*)st)->userData1 = base[r];
    ((EnemyState*)st)->flags2E8 |= 0x8;
    if (sub > (int)((EnemyState*)st)->current)
    {
        ((EnemyState*)st)->current = 0;
    }
    else
    {
        ((EnemyState*)st)->current = (u16)(((EnemyState*)st)->current - sub);
    }
    if (((EnemyState*)st)->current == 0)
    {
        Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_baddie_eggsnatch_carry2);
    }
    if (cmd == 0x1a)
        return;
    Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_stftest);
}

void crawler_playReactionEffects(GameObject* obj, int* st)
{
    u16 flag = 0;
    switch (obj->anim.currentMove)
    {
    case 2:
        if (((EnemyState*)st)->animEventMask != 0)
        {
            Sfx_PlayFromObjectLimited(obj, SFXTRIG_baddie_blooplaugh3, 2);
        }
        flag = 1;
        break;
    case 3:
        if (((EnemyState*)st)->animEventMask != 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_baddie_haga_death);
        }
        break;
    case 4:
        if (((EnemyState*)st)->animEventMask != 0)
        {
            if (obj->anim.currentMoveProgress < 0.15f)
            {
                Sfx_PlayFromObject(obj, SFXTRIG_baddie_blooplaugh1);
            }
            else
            {
                Sfx_PlayFromObject(obj, SFXTRIG_baddie_rach_call1);
            }
        }
        break;
    case 5:
        if (((EnemyState*)st)->animEventMask != 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_baddie_eggsnatch);
        }
        break;
    case 6:
        if (((EnemyState*)st)->animEventMask != 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_baddie_eggsnatch);
        }
        break;
    case 7:
        if (((EnemyState*)st)->animEventMask != 0)
        {
            Sfx_PlayFromObjectLimited(obj, SFXTRIG_baddie_eggsnatch_movelp, 2);
        }
        flag = 1;
        break;
    case 9:
        if (((EnemyState*)st)->animEventMask != 0)
        {
            Sfx_PlayFromObject(obj, SFXTRIG_baddie_blooplaugh2);
        }
        break;
    }
    if (flag != 0)
    {
        if (((EnemyState*)st)->phaseAngle != 0)
        {
            (*gPartfxInterface)->spawnObject(obj, FIRECRAWLER_PARTFX_MOVE_TURN, NULL, 2, -1, NULL);
        }
        else
        {
            (*gPartfxInterface)->spawnObject(obj, FIRECRAWLER_PARTFX_MOVE_STRAIGHT, NULL, 2, -1, NULL);
        }
    }
}

void snowworm_update(GameObject* obj, u8* state)
{
    u8* tbl = gCrawlerReactionTables[((EnemyState*)state)->phaseAngle].moveSequence;
    int i;

    ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumePriority = 10;
    ((ObjHitsPriorityState*)obj->anim.hitReactState)->hitVolumeId = 1;
    if (obj->anim.currentMove == 0)
    {
        obj->anim.resetHitboxFlags =
            obj->anim.resetHitboxFlags | INTERACT_FLAG_DISABLED;
        ObjHits_DisableObject(obj);
    }
    else
    {
        obj->anim.resetHitboxFlags =
            obj->anim.resetHitboxFlags & ~INTERACT_FLAG_DISABLED;
        ObjHits_EnableObject(obj);
    }

    if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_JUST_TRIGGERED) != 0 &&
        ((EnemyState*)state)->userData1 <= 1)
    {
        if (((EnemyState*)state)->phaseAngle != 0 || (int)randomGetRange(0, 0x14) < 10)
        {
            ((EnemyState*)state)->userData1 = 1;
        }
        else
        {
            ((EnemyState*)state)->userData1 = 7;
        }
        ((EnemyState*)state)->controlFlags |= (u64)BADDIE_CONTROL_SEQUENCE_DRIVEN;
    }

    if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        *(char*)&((EnemyState*)state)->userData1 += 1;
        if (((EnemyState*)state)->userData1 > gSnowwormSeqIndexMax[((EnemyState*)state)->phaseAngle])
        {
            ((EnemyState*)state)->userData1 = gSnowwormSeqIndexReset[((EnemyState*)state)->phaseAngle];
        }
        if (((EnemyState*)state)->turnOctant < 4)
        {
            i = ((EnemyState*)state)->userData1 * 0xc;
            baddieSetMove(obj, state, (tbl + i)[8], *(f32*)((int)tbl + i), 0, 0);
        }
        else
        {
            i = ((EnemyState*)state)->userData1 * 0xc;
            baddieSetMove(obj, state, (tbl + i)[9], *(f32*)((int)tbl + i), 0, 0);
        }
        if (obj->anim.currentMove == 9)
        {
            snowworm_spawnProjectile(obj);
        }
        else if (obj->anim.currentMove == 1)
        {
            int r = randomGetRange(0, ((EnemyState*)state)->userData2);
            s16 a = randomGetRange(-0x8000, 0x7fff);
            f32 angle = (3.1415927f * a) / 32768.0f;
            obj->anim.localPosX =
                r * mathSinf(angle) + ((ObjPlacement*)obj->anim.placementData)->posX;
            obj->anim.localPosZ =
                r * mathCosf(angle) + ((ObjPlacement*)obj->anim.placementData)->posZ;
            baddieTurnTowardPoint(obj, state, ((GameObject*)((EnemyState*)state)->trackedObj)->anim.localPosX,
                        ((GameObject*)((EnemyState*)state)->trackedObj)->anim.localPosZ, 1, 0);
        }
    }

    baddieTurnTowardPoint(obj, state, ((GameObject*)((EnemyState*)state)->trackedObj)->anim.localPosX,
                ((GameObject*)((EnemyState*)state)->trackedObj)->anim.localPosZ,
                gSnowwormTurnRates[((EnemyState*)state)->phaseAngle], 0);
    crawler_playReactionEffects(obj, (int*)state);
}

void snowworm_applyReactionState(GameObject* obj, int* st)
{
    u8* t1 = gCrawlerReactionTables[((EnemyState*)st)->phaseAngle].moveSequence;
    *((u8*)obj + 0xaf) = (u8)(*((u8*)obj + 0xaf) | 0x8);
    if ((((EnemyState*)st)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        s16 a = obj->anim.currentMove;
        if (a == 7)
        {
            ((EnemyState*)st)->userData1 = 1;
        }
        else if (a != 0)
        {
            ((EnemyState*)st)->userData1 = 0;
        }
        {
            u8* bbase = t1;
            f32* fbase = (f32*)t1;
            u32 idx2 = ((EnemyState*)st)->userData1;
            u32 off = idx2 * 0xc;
            baddieSetMove(obj, st, bbase[off + 8], *(f32*)((char*)fbase + off), 0, 0);
        }
    }
    crawler_playReactionEffects(obj, st);
}

void snowworm_init(GameObject* obj, int* st)
{
    ((EnemyState*)st)->sightRange = 60.0f;
    ((EnemyState*)st)->userData2 = ((EnemyState*)st)->aggroRange;
    ((EnemyState*)st)->aggroRange = 160.0f;
    ((EnemyState*)st)->flags2E4 = 0x42003;
    ((EnemyState*)st)->animPlaySpeed = 0.01f;
    ((EnemyState*)st)->gravity = 0.006f;
    ((EnemyState*)st)->drag = 0.95f;
    *((u8*)st + 0x320) = 0;
    {
        f32 d = 1.0f;
        ((EnemyState*)st)->moveSpeedScale0 = d;
        *((u8*)st + 0x321) = 0xa;
        ((EnemyState*)st)->moveSpeedScale1 = d;
        *((u8*)st + 0x322) = 7;
        ((EnemyState*)st)->moveSpeedScale2 = d;
    }
    ((EnemyState*)st)->userData1 = 1;
    ((EnemyState*)st)->phaseAngle = (u16)(obj->anim.romDefNo == SNOWWORM_SEQID_BABY);
}
