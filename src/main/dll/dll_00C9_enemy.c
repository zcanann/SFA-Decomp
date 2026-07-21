/*
 * DLL 0xC9 - the generic enemy/baddie controller. It runs several romlist
 * enemy types, including GCRobotPatrol ("GCRobotPatr[ol]"), the floating
 * patrol robot of CloudRunner Fortress (placed in fortress.romlist).
 * GCRobotPatrol carries the GCRobotLight scanning beam (DLL 0x150,
 * dll_0150_gcrobotlightbea.c) as childObjs[0] and reads that child's
 * "player caught in the beam" hit flag to react - the sharp-claw disguise
 * fools the beam. ("GC" = GameCube; see the dll_0150 header.)
 */
#include "main/object_descriptor.h"
#include "main/camera_interface.h"
#include "main/dll/objfx_api.h"
#include "main/dll/dll_005A_staffcollisionfunc03.h"
#include "main/object_render.h"
#include "main/objanim.h"
#include "main/game_object.h"
#include "main/dll/player_api.h"
#include "main/dll/baddie_setmove.h"
#include "main/obj_group.h"
#include "main/obj_link.h"
#include "main/objprint_character_api.h"
#include "main/object.h"
#include "main/object_api.h"
#include "main/model.h"
#include "main/mm.h"
#include "main/objseq.h"
#include "main/dll/rom_curve_interface.h"
#include "main/dll/dll_00C9_enemy.h"
#include "main/dll/dll_00CA_icebaddie.h"
#include "main/dll/tricky_state.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx_keep_alive_api.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/obj_placement.h"
#include "main/objhits.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/path_control_interface.h"
#include "main/mapEventTypes.h"
#include "main/resource.h"
#include "main/vecmath.h"
#include "main/dll/duster.h"
#include "main/gamebits.h"
#include "main/dll/tricky_api.h"
#include "main/lightmap_api.h"
#include "main/frame_timing.h"
#include "main/model.h"
#include "main/model_engine.h"
#include "main/model_light.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "main/dll/hagabon_mk2.h"
#include "main/dll/duster_wb.h"
#include "main/dll/weevil.h"
#include "main/dll/hoodedzyck.h"
#include "main/dll/snowworm.h"
#include "main/dll/kooshy.h"
#include "main/dll/mikaladon.h"
#include "main/dll/baddiewhirlpool.h"
#include "main/dll/newseqobj_baddie.h"
#include "main/dll/fireflyLantern.h"
#include "main/dll/firecrawler_baddie.h"
#include "main/dll/seqobj11e_baddie.h"
#include "main/dll/wispbaddie_baddie.h"
#include "main/dll/seqobj11d_baddie.h"
#include "main/dll/magicPlant.h"
#include "main/dll/seqObj11D.h"
#include "main/dll/dll_00C4_tricky.h"
#include "main/dll/fall_ladders.h"
#include "string.h"

int lbl_803DBC58[2] = {2, 3};
f32 lbl_803DBC60 = 20.0f;
f32 lbl_803DBC64 = 20.0f;
f32 lbl_803DBC68 = 2.3509887e-38f;

typedef struct BaddieAfterUpdateBonesCbState
{
    u8 pad0[0x2B0 - 0x0];
    s16 unk2B0;
    u16 unk2B2;
    u8 pad2B4[0x2D8 - 0x2B4];
    f32 freezeRecoverTimer;
    u32 unk2DC;
    u8 pad2E0[0x2F2 - 0x2E0];
    u8 unk2F2;
    u8 unk2F3;
    u8 unk2F4;
    u8 pad2F5[0x36C - 0x2F5];
    s32 tailBoneChain; /* 0x36C: bone chain passed to ObjModelChain_Update for tail sim */
} BaddieAfterUpdateBonesCbState;

typedef struct
{
    f32 dx, dy, dz;
    u8 pad0[2];
    s16 dAngle;
    u8 pad1[3];
    s8 events[8];
    s8 eventCount;
} TrickyMoveResult;

#define ENEMY_OBJFLAG_PARENT_SLACK 0x1000
#define ENEMY_OBJFLAG_FREED        0x40

/* object groups: the enemy's own group / secondary group left on a message */
#define ENEMY_OBJGROUP           3
#define ENEMY_OBJGROUP_SECONDARY 0x50

/* camera mode DLL 0x49 = dll_0049_cameramodecombat */
#define ENEMY_CAMMODE_COMBAT 0x49

/* enemy defNos (anim.seqId) - names read from retail OBJECTS.bin at def+0x91;
   every id below gates to this file's own DLL 0xC9 */
#define ENEMY_SHARPCLAW_GR_OBJ     0x11
#define ENEMY_GUARDCLAW_OBJ        0xd8
#define ENEMY_SHARPCLAW_SN_OBJ     0x13a
#define ENEMY_PINPON_OBJ           0x251
#define ENEMY_RACHNOP_OBJ          0x25d
#define ENEMY_WEEVIL_OBJ           0x369
#define ENEMY_VAMBAT_OBJ           0x3fe
#define ENEMY_BATTLEDROID_OBJ      0x427
#define ENEMY_SPITTINGEBA_OBJ      0x457
#define ENEMY_MUTATEDEBA_OBJ       0x458
#define ENEMY_HOODEDZYCK_OBJ       0x4ac
#define ENEMY_WB_OBJ               0x4d7
#define ENEMY_KOOSHY_OBJ           0x58b
#define ENEMY_SHARPCLAW_CO_OBJ     0x5b7
#define ENEMY_SHARPCLAW_AS_OBJ     0x5b8
#define ENEMY_SHARPCLAW_SH_OBJ     0x5b9
#define ENEMY_SHARPCLAW_SO_OBJ     0x5e1
#define ENEMY_GCROBOTPATROL_OBJ    0x613
#define ENEMY_MIKALADON_OBJ        0x642
#define ENEMY_FIRECRAWLER_OBJ      0x6a2
#define ENEMY_REDEYE_OBJ           0x6a3
#define ENEMY_SHADOWHUNTER_OBJ     0x6a4
#define ENEMY_SWAMPSTRIDER_OBJ     0x6a5
#define ENEMY_BOSSGENERAL_OBJ      0x7a6
#define ENEMY_FIREBAT_OBJ          0x7c6
#define ENEMY_HAGABONMK2_OBJ       0x7c8
#define ENEMY_SNOWWORM_OBJ         0x842
#define ENEMY_SNOWWORM_BABY_OBJ    0x84b
#define ENEMY_WHIRLPOOL_OBJ        0x851

extern f32 lbl_803E256C;
extern f32 lbl_803E2570;
extern f32 lbl_803E2574;
extern f32 lbl_803E2578;
extern f32 lbl_803E257C;
extern f32 lbl_803E25CC;
extern f32 lbl_803E25D0;
extern f32 lbl_803E25D4;
extern f32 lbl_803E2598;

extern f32 lbl_803E25DC;
extern f32 lbl_803E25B8;
extern f32 lbl_803E25EC;
extern f32 lbl_803E25F0;
extern f32 lbl_803E25F4;
extern f32 lbl_803E25D8;
extern f32 lbl_803E25C4;
extern f32 lbl_803E25E8;
extern StaffCollisionInterface** lbl_803DDA50;
extern f32 lbl_803E25F8;
extern f32 lbl_803E25FC;

void baddie_updateEngagementState(int* obj, int* sub);
void baddieTurnTowardTarget(int* node, int* sub);
typedef struct
{
    f32 x, y, z;
} TrickyVec3;

extern f32 enemyRespawnDistanceSq;
extern u8 lbl_8031DBD8[];
extern u8 lbl_8031DBE4[];
extern f32 enemySightRange;

void enemyObjAnimUpdate(short* obj, int state)
{
    f32 vy;
    f32 dz;
    f32 dx;
    f32 dy;
    u32 flags;
    int mode;
    int i;
    f32 vel;
    f32 c;
    f32 phase;
    f32 outY;
    TrickyMoveResult res;
    MatrixTransform rec;
    f32 mtx[16];

    memcpy((void*)(state + 0x2c4), (void*)(state + 0x2b8), 0xc);
    memcpy((void*)(state + 0x2b8), obj + 0x12, 0xc);
    if ((((TrickyState*)state)->controlFlags & 0x400) != 0)
    {
        characterDoEyeAnims((GameObject*)obj, (void*)(state + 0x26c));
    }
    if ((((TrickyState*)state)->actionTargetObj != NULL) && ((((TrickyState*)state)->controlFlags & 0x800) != 0))
    {
        fn_8003B0D0((GameObject*)obj, ((TrickyState*)state)->actionTargetObj,
                    (CharacterEyeAnimState*)(state + 0x26c), 0x19);
    }
    ((TrickyState*)state)->prevActionId = ((TrickyState*)state)->actionId;
    flags = ((TrickyState*)state)->flags2DC;
    if ((flags & 0x800) != 0)
    {
        tricky_handleDefeat((GameObject*)(obj), state);
    }
    else if ((flags & 0x1000) != 0)
    {
        Tricky_resumeAfterCommand((GameObject*)(obj), state);
    }
    else if ((flags & 0x20000000) != 0)
    {
        if ((flags & 0x400) != 0)
        {
            ((TrickyState*)state)->actionId = 3;
            switch (((GameObject*)obj)->anim.seqId)
            {
            case ENEMY_SHARPCLAW_GR_OBJ:
            case ENEMY_SHARPCLAW_SN_OBJ:
            case ENEMY_SHARPCLAW_CO_OBJ:
            case ENEMY_SHARPCLAW_AS_OBJ:
            case ENEMY_SHARPCLAW_SH_OBJ:
            case ENEMY_SHARPCLAW_SO_OBJ:
            case ENEMY_BOSSGENERAL_OBJ:
                sharpClawUpdateAttack((GameObject*)(obj), (u8*)state);
                break;
            case ENEMY_GUARDCLAW_OBJ:
            case 0x281:
                guardClaw_update((int*)obj, (u8*)state);
                break;
            case ENEMY_GCROBOTPATROL_OBJ:
                gcRobotPatrol_update((int*)obj, (u8*)state);
                break;
            case ENEMY_MIKALADON_OBJ:
                mikaladon_update((GameObject*)obj, (MikaladonState*)state);
                break;
            case ENEMY_VAMBAT_OBJ:
            case ENEMY_FIREBAT_OBJ:
                vambat_updateEngaged((GameObject*)(obj), state);
                break;
            case ENEMY_KOOSHY_OBJ:
                kooshy_updateEngaged((GameObject*)(obj), state);
                break;
            case ENEMY_WEEVIL_OBJ:
                weevil_updateEngaged((int)obj, state);
                break;
            case ENEMY_PINPON_OBJ:
                pinPon_updateEngaged((GameObject*)(obj), (int*)state);
                break;
            case ENEMY_RACHNOP_OBJ:
                rachnopUpdateAttack((int*)obj, state);
                break;
            case ENEMY_SPITTINGEBA_OBJ:
                spittingEbaUpdateEngaged((u32)obj, state);
                break;
            case ENEMY_WB_OBJ:
                wbUpdateEngaged((u32)obj, state);
                break;
            case ENEMY_MUTATEDEBA_OBJ:
                mutatedEbaUpdateEngaged((u32)obj, state);
                break;
            case ENEMY_WHIRLPOOL_OBJ:
                iceBaddie_enterWhirlpoolGroup((GameObject*)obj, (GroundBaddieState*)state);
                break;
            case ENEMY_SNOWWORM_OBJ:
            case ENEMY_SNOWWORM_BABY_OBJ:
                snowworm_update((int*)obj, (u8*)state);
                break;
            case ENEMY_HOODEDZYCK_OBJ:
                hoodedZyck_update(obj, (u8*)state);
                break;
            case ENEMY_BATTLEDROID_OBJ:
                battleDroidUpdateAttack((int)obj, state);
                break;
            case ENEMY_FIRECRAWLER_OBJ:
            case ENEMY_REDEYE_OBJ:
            case ENEMY_SHADOWHUNTER_OBJ:
            case ENEMY_SWAMPSTRIDER_OBJ:
                crawler_update((int*)obj, (u8*)state);
                break;
            case ENEMY_HAGABONMK2_OBJ:
                hagabonMK2_updateB(obj, (u8*)state);
                break;
            case 0x7c7:
            default:
                battleDroidUpdateAttack((int)obj, state);
                break;
            }
        }
        else
        {
            ((TrickyState*)state)->actionId = 4;
            switch (((GameObject*)obj)->anim.seqId)
            {
            case ENEMY_SHARPCLAW_GR_OBJ:
            case ENEMY_SHARPCLAW_SN_OBJ:
            case ENEMY_SHARPCLAW_CO_OBJ:
            case ENEMY_SHARPCLAW_AS_OBJ:
            case ENEMY_SHARPCLAW_SH_OBJ:
            case ENEMY_SHARPCLAW_SO_OBJ:
            case ENEMY_BOSSGENERAL_OBJ:
                sharpClawUpdateApproach((GameObject*)(obj), (void*)state);
                break;
            case ENEMY_GUARDCLAW_OBJ:
            case 0x281:
                guardClaw_update((int*)obj, (u8*)state);
                break;
            case ENEMY_GCROBOTPATROL_OBJ:
                gcRobotPatrol_update((int*)obj, (u8*)state);
                break;
            case ENEMY_MIKALADON_OBJ:
                mikaladon_update((GameObject*)obj, (MikaladonState*)state);
                break;
            case ENEMY_VAMBAT_OBJ:
            case ENEMY_FIREBAT_OBJ:
                vambat_updateEngaged((GameObject*)(obj), state);
                break;
            case ENEMY_KOOSHY_OBJ:
                kooshy_updateEngaged((GameObject*)(obj), state);
                break;
            case ENEMY_WEEVIL_OBJ:
                weevil_updateEngaged((int)obj, state);
                break;
            case ENEMY_PINPON_OBJ:
                pinPon_updateEngaged((GameObject*)(obj), (int*)state);
                break;
            case ENEMY_RACHNOP_OBJ:
                rachnopUpdateApproach((int*)obj, state);
                break;
            case ENEMY_SPITTINGEBA_OBJ:
                spittingEbaUpdateEngaged((u32)obj, state);
                break;
            case ENEMY_WB_OBJ:
                wbUpdateEngaged((u32)obj, state);
                break;
            case ENEMY_MUTATEDEBA_OBJ:
                mutatedEbaUpdateEngaged((u32)obj, state);
                break;
            case ENEMY_WHIRLPOOL_OBJ:
                iceBaddie_enterWhirlpoolGroup((GameObject*)obj, (GroundBaddieState*)state);
                break;
            case ENEMY_SNOWWORM_OBJ:
            case ENEMY_SNOWWORM_BABY_OBJ:
                snowworm_update((int*)obj, (u8*)state);
                break;
            case ENEMY_HOODEDZYCK_OBJ:
                hoodedZyck_updateB(obj, (u8*)state);
                break;
            case ENEMY_BATTLEDROID_OBJ:
                battleDroidUpdate((int)obj, state);
                break;
            case ENEMY_FIRECRAWLER_OBJ:
            case ENEMY_REDEYE_OBJ:
            case ENEMY_SHADOWHUNTER_OBJ:
            case ENEMY_SWAMPSTRIDER_OBJ:
                crawler_updateB(obj, (u8*)state);
                break;
            case ENEMY_HAGABONMK2_OBJ:
                hagabonMK2_update(obj, (u8*)state);
                break;
            case 0x7c7:
            default:
                battleDroidUpdate((int)obj, state);
                break;
            }
        }
    }
    else if ((flags & 0x100) != 0)
    {
        ((TrickyState*)state)->actionId = 2;
        if (((((TrickyState*)state)->flags2DC & 0x100) != 0) && ((((TrickyState*)state)->flags2E0 & 0x100) == 0))
        {
            int moveId = ((TrickyState*)state)->moveId2;
            ((TrickyState*)state)->animPlaySpeed =
                lbl_803E256C / (lbl_803E2570 * ((TrickyState*)state)->moveSpeedScale2);
            ((TrickyState*)state)->flags323 = 1;
            ObjAnim_SetCurrentMove((int)obj, moveId, lbl_803E2574, OBJANIM_MOVE_CONTROL_SKIP_EVENT_COUNTDOWN);
            if (*(void**)(obj + 0x2a) != 0)
            {
                *(u8*)(*(int*)&((GameObject*)obj)->anim.hitReactState + 0x70) = 0;
            }
        }
        if ((((TrickyState*)state)->flags2DC & 0x40000000) != 0)
        {
            ((TrickyState*)state)->animPlaySpeed = lbl_803E2578;
            ((TrickyState*)state)->flags323 = 0;
            ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E2574, 0);
            if (*(void**)(obj + 0x2a) != 0)
            {
                *(u8*)(*(int*)&((GameObject*)obj)->anim.hitReactState + 0x70) = 0;
            }
            ((TrickyState*)state)->flags2DC &= ~0x100LL;
            ((GameObject*)obj)->anim.alpha = 0xff;
        }
        else
        {
            ((GameObject*)obj)->anim.alpha = (u8)(int)(lbl_803E257C * ((GameObject*)obj)->anim.currentMoveProgress);
            ((GameObject*)obj)->anim.flags = ((GameObject*)obj)->anim.flags & ~OBJANIM_FLAG_HIDDEN;
        }
    }
    else
    {
        ((TrickyState*)state)->actionId = 5;
        switch (((GameObject*)obj)->anim.seqId)
        {
        case ENEMY_SHARPCLAW_GR_OBJ:
        case ENEMY_SHARPCLAW_SN_OBJ:
        case ENEMY_SHARPCLAW_CO_OBJ:
        case ENEMY_SHARPCLAW_AS_OBJ:
        case ENEMY_SHARPCLAW_SH_OBJ:
        case ENEMY_SHARPCLAW_SO_OBJ:
        case ENEMY_BOSSGENERAL_OBJ:
            sharpClawUpdateIdle((int*)obj, (u8*)state);
            break;
        case ENEMY_GUARDCLAW_OBJ:
        case 0x281:
            guardClaw_update((int*)obj, (u8*)state);
            break;
        case ENEMY_GCROBOTPATROL_OBJ:
            gcRobotPatrol_update((int*)obj, (u8*)state);
            break;
        case ENEMY_MIKALADON_OBJ:
            mikaladon_update((GameObject*)obj, (MikaladonState*)state);
            break;
        case ENEMY_VAMBAT_OBJ:
        case ENEMY_FIREBAT_OBJ:
            vambat_updateIdle((GameObject*)(obj), state);
            break;
        case ENEMY_KOOSHY_OBJ:
            kooshy_updateIdle((GameObject*)(obj), state);
            break;
        case ENEMY_WEEVIL_OBJ:
            weevil_updateIdle((GameObject*)(obj), state);
            break;
        case ENEMY_PINPON_OBJ:
            pinPon_updateIdle((GameObject*)(obj), state);
            break;
        case ENEMY_RACHNOP_OBJ:
            rachnopUpdateIdle((int*)obj, state);
            break;
        case ENEMY_SPITTINGEBA_OBJ:
            spittingEbaUpdateIdle((GameObject*)(obj), state);
            break;
        case ENEMY_WB_OBJ:
            wbUpdateIdle((u32)obj, state);
            break;
        case ENEMY_MUTATEDEBA_OBJ:
            mutatedEbaUpdateIdle((u32)obj, state);
            break;
        case ENEMY_WHIRLPOOL_OBJ:
            iceBaddie_leaveWhirlpoolGroup((GameObject*)obj, (GroundBaddieState*)state);
            break;
        case ENEMY_SNOWWORM_OBJ:
        case ENEMY_SNOWWORM_BABY_OBJ:
            snowworm_applyReactionState((int*)obj, (int*)state);
            break;
        case ENEMY_HOODEDZYCK_OBJ:
            hoodedZyck_updateIdle((GameObject*)(obj), state);
            break;
        case ENEMY_BATTLEDROID_OBJ:
            battleDroidUpdate((int)obj, state);
            break;
        case ENEMY_FIRECRAWLER_OBJ:
        case ENEMY_REDEYE_OBJ:
        case ENEMY_SHADOWHUNTER_OBJ:
        case ENEMY_SWAMPSTRIDER_OBJ:
            crawler_updateC(obj, (u8*)state);
            break;
        case ENEMY_HAGABONMK2_OBJ:
            hagabonMK2_updateB(obj, (u8*)state);
            break;
        case 0x7c7:
        default:
            battleDroidUpdate((int)obj, state);
            break;
        }
    }
    if (((TrickyState*)state)->actionId != ((TrickyState*)state)->prevActionId)
    {
        ((TrickyState*)state)->flags2DC = ((TrickyState*)state)->flags2DC | 0x80000000;
    }
    else
    {
        ((TrickyState*)state)->flags2DC = ((TrickyState*)state)->flags2DC & 0x7fffffff;
    }
    res.eventCount = 0;
    if (ObjAnim_AdvanceCurrentMove((int)obj, ((TrickyState*)state)->animPlaySpeed,
                                                                    timeDelta, (ObjAnimEventList*)&res) != 0)
    {
        ((TrickyState*)state)->flags2DC |= 0x40000000LL;
    }
    else
    {
        ((TrickyState*)state)->flags2DC &= ~0x40000000LL;
    }
    ((TrickyState*)state)->animEventMask = 0;
    for (i = 0; i < res.eventCount; i++)
    {
        ((TrickyState*)state)->animEventMask |= 1 << res.events[i];
    }
    vy = lbl_803E2574;
    if ((((((TrickyState*)state)->controlFlags & 0x20) != 0) &&
         ((((TrickyState*)state)->controlFlags & 0x400000) == 0)) &&
        (((((TrickyState*)state)->flags2DC & 0x1800) == 0) && ((((TrickyState*)state)->flags323 & 4) == 0)))
    {
        vy = -(((TrickyState*)state)->gravity * timeDelta - ((GameObject*)obj)->anim.velocityY);
    }
    vel = ((GameObject*)obj)->anim.velocityX;
    ((GameObject*)obj)->anim.velocityX =
        (vel < lbl_803E25CC) ? lbl_803E25CC : ((vel > lbl_803E25D0) ? lbl_803E25D0 : vel);
    vel = ((GameObject*)obj)->anim.velocityY;
    ((GameObject*)obj)->anim.velocityY =
        (vel < lbl_803E25CC) ? lbl_803E25CC : ((vel > lbl_803E25D0) ? lbl_803E25D0 : vel);
    vel = ((GameObject*)obj)->anim.velocityZ;
    ((GameObject*)obj)->anim.velocityZ =
        (vel < lbl_803E25CC) ? lbl_803E25CC : ((vel > lbl_803E25D0) ? lbl_803E25D0 : vel);
    mode = 0;
    if (((((TrickyState*)state)->controlFlags & 0x80) != 0) && (((TrickyState*)state)->flags323 != 0))
    {
        mode = 1;
    }
    else if ((((TrickyState*)state)->controlFlags & 0x100) != 0)
    {
        mode = 2;
    }
    else if ((((TrickyState*)state)->controlFlags & 0x10) != 0)
    {
        mode = 3;
    }
    if (((((TrickyState*)state)->controlFlags & 0x200) != 0) && ((((TrickyState*)state)->flags2DC & 0x4010) != 0))
    {
        mode = 3;
    }
    if (mode == 1)
    {
        f32 zero;
        dx = (dz = lbl_803E2574);
        dy = dz;
        if ((((TrickyState*)state)->flags323 & 2) != 0)
        {
            dx = res.dx * oneOverTimeDelta;
        }
        if ((((TrickyState*)state)->flags323 & 4) != 0)
        {
            dy = res.dy * oneOverTimeDelta;
        }
        if ((((TrickyState*)state)->flags323 & 1) != 0)
        {
            dz = -res.dz * oneOverTimeDelta;
        }
        if ((((TrickyState*)state)->flags323 & 8) != 0)
        {
            ((GameObject*)obj)->anim.rotX += res.dAngle;
        }
        rec.rotX = ((GameObject*)obj)->anim.rotX;
        rec.rotY = ((GameObject*)obj)->anim.rotY;
        rec.rotZ = ((GameObject*)obj)->anim.rotZ;
        rec.scale = lbl_803E256C;
        zero = lbl_803E2574;
        rec.x = zero;
        rec.y = zero;
        rec.z = zero;
        setMatrixFromObjectPos(mtx, &rec);
        if ((((TrickyState*)state)->flags323 & 4) != 0)
        {
            Matrix_TransformPoint(mtx, dx, dy, -dz, (f32*)(obj + 0x12), (f32*)(obj + 0x14), (f32*)(obj + 0x16));
        }
        else
        {
            Matrix_TransformPoint(mtx, dx, lbl_803E2574, -dz, (f32*)(obj + 0x12), &outY, (f32*)(obj + 0x16));
        }
    }
    else if (mode == 2)
    {
        if (ObjAnim_SampleRootCurvePhase((ObjAnimComponent*)obj,
                                         sqrtf(((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
                                               ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ),
                                         &phase) != 0)
        {
            ((TrickyState*)state)->animPlaySpeed = phase;
        }
    }
    else if (mode == 3)
    {
        if ((((TrickyState*)state)->flags2F1 & 0x80) == 0)
        {
            ((GameObject*)obj)->anim.velocityX =
                ((GameObject*)obj)->anim.velocityX * powfBitEstimate(((TrickyState*)state)->base, timeDelta);
            ((GameObject*)obj)->anim.velocityY =
                ((GameObject*)obj)->anim.velocityY * powfBitEstimate(((TrickyState*)state)->base, timeDelta);
            ((GameObject*)obj)->anim.velocityZ =
                ((GameObject*)obj)->anim.velocityZ * powfBitEstimate(((TrickyState*)state)->base, timeDelta);
        }
    }
    Tricky_applyFloorResponse((GameObject*)(obj), state);
    if (((((TrickyState*)state)->controlFlags & 0x400000) != 0) || ((((TrickyState*)state)->flags2DC & 0x8100000) != 0))
    {
        if ((((TrickyState*)state)->flags2F1 & 0x80) == 0)
        {
            objMove((GameObject*)obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
                    ((GameObject*)obj)->anim.velocityZ * timeDelta);
        }
    }
    else if ((((TrickyState*)state)->controlFlags & 0x20) != 0)
    {
        f32 newY = (((GameObject*)obj)->anim.velocityY * timeDelta + ((GameObject*)obj)->anim.localPosY) -
                   lbl_803E25D4 * (((TrickyState*)state)->gravity * (timeDelta * timeDelta));
        if ((((TrickyState*)state)->flags2F1 & 0x80) == 0)
        {
            objMove((GameObject*)obj, ((GameObject*)obj)->anim.velocityX * timeDelta, newY - ((GameObject*)obj)->anim.localPosY,
                    ((GameObject*)obj)->anim.velocityZ * timeDelta);
            ((GameObject*)obj)->anim.velocityY = vy;
        }
    }
    else if ((((TrickyState*)state)->flags2F1 & 0x80) == 0)
    {
        objMove((GameObject*)obj, ((GameObject*)obj)->anim.velocityX * timeDelta, ((GameObject*)obj)->anim.velocityY * timeDelta,
                ((GameObject*)obj)->anim.velocityZ * timeDelta);
    }
}

void baddie_updateEngagementState(int* obj, int* sub)
{
    int* player;
    int* tricky;
    int* target;
    int* camTarget;

    player = (int*)Obj_GetPlayerObject();
    tricky = (int*)getTrickyObject();
    target = (int*)((TrickyState*)sub)->actionTargetObj;
    if (target != NULL && (((TrickyState*)sub)->controlFlags & 0x10000) == 0 &&
        (target != player || (((GameObject*)player)->objectFlags & ENEMY_OBJFLAG_PARENT_SLACK) == 0))
    {
        ((TrickyState*)sub)->flags2DC &= ~0x800000LL;
        camTarget = (int*)(*gCameraInterface)->getOverrideTarget();
        if (camTarget == obj)
        {
            ((TrickyState*)sub)->flags2DC |= 0x800200LL;
        }
        {
            u16 dist = ((TrickyState*)sub)->targetDist;
            u16 near = (u16)(int)((TrickyState*)sub)->waterLevel;
            if (dist < near)
            {
                ((TrickyState*)sub)->flags2DC |= 0x400LL;
                ((TrickyState*)sub)->flags2DC &= ~0x200LL;
            }
            else
            {
                f32 midf = ((BaddieState*)sub)->unk2A8;
                u16 mid = (u16)(int)midf;
                if (dist < mid)
                {
                    ((TrickyState*)sub)->flags2DC |= 0x200LL;
                    ((TrickyState*)sub)->flags2DC &= ~0x400LL;
                }
                else
                {
                    u16 far = (u16)(int)(lbl_803E25D8 * midf);
                    if (dist > far)
                    {
                        ((TrickyState*)sub)->flags2DC &= ~0x20000600LL;
                    }
                }
            }
        }
    }
    else
    {
        ((TrickyState*)sub)->flags2DC &= ~0x800600LL;
        if ((((TrickyState*)sub)->controlFlags & 0x10000) != 0 ||
            (((TrickyState*)sub)->actionTargetObj == (GameObject*)player &&
             (((GameObject*)player)->objectFlags & ENEMY_OBJFLAG_PARENT_SLACK) != 0))
        {
            ((TrickyState*)sub)->flags2DC &= ~0x20000000LL;
        }
    }
    ((TrickyState*)sub)->flags2DC &= ~0x76f0008LL;
    if (tricky != NULL)
    {
        u8 r = (*(u8(**)(int*))(*(int*)*(int*)((char*)tricky + 0x68) + 0x40))(tricky);
        if (r != 0)
            ((TrickyState*)sub)->flags2DC |= 0x200000LL;
    }
    if (((TrickyState*)sub)->actionTargetObj == (GameObject*)player)
    {
        if (playerIsDisguised((GameObject*)player) != 0)
        {
            ((TrickyState*)sub)->flags2DC |= 8LL;
            if ((((TrickyState*)sub)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW) != 0)
            {
                ((TrickyState*)sub)->flags2DC &= ~0x800600LL;
            }
        }
    }
    if ((((TrickyState*)sub)->flags2DC & 0x20000600) != 0)
    {
        if ((((TrickyState*)sub)->controlFlags & 0x1000) != 0)
        {
            u8 r = baddie_canSeeTarget((GameObject*)obj, (int)sub, (f32*)((char*)obj + 0x18),
                                           (u8*)((TrickyState*)sub)->actionTargetObj + 0x18);
            if (r != 0)
                ((TrickyState*)sub)->flags2DC |= 0x1000000LL;
            if ((((TrickyState*)sub)->flags2DC & 0x1000000) == 0)
            {
                ((TrickyState*)sub)->flags2DC &= ~0x20000000LL;
            }
        }
        else
        {
            ((TrickyState*)sub)->flags2DC |= 0x1000000LL;
        }
        {
            u16 mode = ((TrickyState*)sub)->turnOctant;
            if (mode < 2 || mode > 5)
            {
                ((TrickyState*)sub)->flags2DC |= 0x400000LL;
            }
            else if ((((TrickyState*)sub)->flags2DC & 0x1000000) != 0)
            {
                ((TrickyState*)sub)->flags2DC |= 0x2000000LL;
            }
        }
        if ((((TrickyState*)sub)->controlFlags & 0x4000) == 0)
        {
            f32* t = (f32*)((TrickyState*)sub)->actionTargetObj;
            f32 mag = sqrtf(t[11] * t[11] + (t[9] * t[9] + t[10] * t[10]));
            if (mag > lbl_803E25D4)
                ((TrickyState*)sub)->flags2DC |= 0x4000000LL;
        }
        if ((((TrickyState*)sub)->flags2DC & 0x600) != 0 && (((TrickyState*)sub)->flags2DC & 0x6800000) != 0 &&
            (((TrickyState*)sub)->flags2DC & 0x1000000) != 0)
        {
            ((TrickyState*)sub)->flags2DC |= 0x20000000LL;
        }
        if ((((TrickyState*)sub)->flags2DC & 0x20000000) != 0)
        {
            if ((((TrickyState*)sub)->controlFlags & 0x40) != 0)
            {
                baddie_updateSightQuadrants((int)obj, (int)sub, ((TrickyState*)sub)->waterLevel);
            }
            else
            {
                ((TrickyState*)sub)->flags2DC |= 0xf0000LL;
            }
        }
    }
    if (((BaddieState*)sub)->hitCounter == 0)
    {
        ((TrickyState*)sub)->flags2DC |= 0x800LL;
    }
}
void baddieTurnTowardTarget(int* node, int* sub)
{
    GameObject* target = ((TrickyState*)sub)->actionTargetObj;
    if (target != NULL)
    {
        f32 d[3];
        f32* dp = d;
        int raw;
        s32 delta;
        f32 dist;
        u16 ua;

        if ((((TrickyState*)sub)->controlFlags & 0x8000) != 0)
        {
            dp[0] = ((GameObject*)node)->anim.worldPosX - target->anim.worldPosX;
            dp[1] = lbl_803E2574;
            dp[2] = ((GameObject*)node)->anim.worldPosZ - target->anim.worldPosZ;
        }
        else
        {
            dp[0] = ((GameObject*)node)->anim.worldPosX - target->anim.worldPosX;
            dp[1] = ((GameObject*)node)->anim.worldPosY - target->anim.worldPosY;
            dp[2] = ((GameObject*)node)->anim.worldPosZ - target->anim.worldPosZ;
        }
        ua = getAngle(-dp[0], -dp[2]);
        if (*(int**)&((GameObject*)node)->anim.parent != NULL)
        {
            raw = (s16)(((GameObject*)node)->anim.rotX + **(s16**)&((GameObject*)node)->anim.parent);
        }
        else
        {
            raw = ((GameObject*)node)->anim.rotX;
        }
        delta = ua - (u16)(s16)raw;
        if (delta > 0x8000)
            delta -= 0xFFFF;
        if (delta < -0x8000)
            delta += 0xFFFF;
        ((TrickyState*)sub)->turnAngleDelta = delta;
        ((TrickyState*)sub)->turnOctant = (u32)(u16)delta >> 13;

        {
            f32 sqX;
            f32 sqZ;
            f32 sqY;
            f32 t;
            t = dp[2];
            sqZ = t * t;
            t = dp[0];
            sqX = t * t;
            t = dp[1];
            sqY = t * t;
            dist = sqrtf(sqZ + (sqX + sqY));
        }
        *(s16*)&((TrickyState*)sub)->targetDist = (s16)dist;

        {
            GameObject* t = ((TrickyState*)sub)->actionTargetObj;
            *(s16*)&((TrickyState*)sub)->targetHeightDelta =
                (s16)(t->anim.worldPosY - ((GameObject*)node)->anim.worldPosY);
        }
    }
}

u32 gEnemySelfAngleFlagClearMask[] = {
    0x40000, 0x80000, 0x80000, 0x10000, 0x10000, 0x20000, 0x20000, 0x40000,
};

u32 gEnemyTargetAngleFlagClearMask[] = {
    0x10000, 0x20000, 0x20000, 0x40000, 0x40000, 0x80000, 0x80000, 0x10000,
};

ObjectDescriptor gBaddieObjDescriptor = {
    0,
    0,
    0,
    OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)enemy_initialise,
    (ObjectDescriptorCallback)enemy_release,
    0,
    (ObjectDescriptorCallback)enemy_init,
    (ObjectDescriptorCallback)enemy_update,
    (ObjectDescriptorCallback)enemy_hitDetect,
    (ObjectDescriptorCallback)enemy_render,
    (ObjectDescriptorCallback)enemy_free,
    (ObjectDescriptorCallback)enemy_getObjectTypeId,
    enemy_getExtraSize,
};

int enemy_SeqFn(GameObject* node, int unused, ObjAnimUpdateState* animUpdate)
{
    char* sub = *(char**)&((GameObject*)node)->extra;
    s8* n29 = *(s8**)&((GameObject*)node)->anim.placementData;
    int i;
    int* obj;

    if (((GameObject*)node)->userData1 != 0)
        return 0;
    ((TrickyState*)sub)->flags2DC |= 0x8000LL;
    memcpy(sub + 0x2c4, sub + 0x2b8, 0xc);
    memcpy(sub + 0x2b8, (char*)node + 0x24, 0xc);
    for (i = 0; i < animUpdate->eventCount; i++)
    {
        switch (animUpdate->eventIds[i])
        {
        case 1:
            obj = (int*)getTrickyObject();
            if (obj != NULL)
            {
                (*(void (*)(int*, int, int*))(*(int*)(*(int*)(*(int*)&((GameObject*)obj)->anim.dll) + 0x34)))(
                    obj, 1, (int*)node);
                ((TrickyState*)sub)->flags2DC |= 0x200000LL;
                ((TrickyState*)sub)->actionTargetObj = (GameObject*)obj;
            }
            break;
        case 4:
            obj = (int*)Obj_GetPlayerObject();
            if (obj != NULL)
            {
                ((TrickyState*)sub)->flags2DC &= ~0x200000LL;
                ((TrickyState*)sub)->actionTargetObj = (GameObject*)obj;
            }
            break;
        case 2:
            if (((GameObject*)node)->anim.seqId == ENEMY_BOSSGENERAL_OBJ)
                *(u16*)(sub + 0x2b6) = 0x7a5;
            else
                *(u16*)(sub + 0x2b6) = 0x33;
            break;
        case 3:
            (*gObjectTriggerInterface)->setCamVars(ENEMY_CAMMODE_COMBAT, 4, (int)node, 0x3c);
            break;
        case 6:
            if (*(int**)&((TrickyState*)sub)->modelChain != NULL)
                ObjModelChain_SetEnabled(*(ObjModelChain**)&((TrickyState*)sub)->modelChain, 1);
            break;
        case 7:
            if (*(int**)&((TrickyState*)sub)->modelChain != NULL)
                ObjModelChain_SetEnabled(*(ObjModelChain**)&((TrickyState*)sub)->modelChain, 0);
            break;
        }
    }
    baddieInstantiateWeapon((GameObject*)(node), (int)sub);
    if (((GameObject*)node)->seqIndex == -1)
    {
        ((TrickyState*)sub)->flags2E8 &= ~3LL;
        ObjHits_DisableObject(node);
        return 0;
    }
    if ((((TrickyState*)sub)->flags2DC & 0x1800) == 0)
    {
        baddieTurnTowardTarget((int*)node, (int*)sub);
        baddie_updateEngagementState((int*)node, (int*)sub);
    }
    if (n29[0x2e] != -1)
    {
        if ((((TrickyState*)sub)->flags2DC & 0x600) != 0)
        {
            if (animUpdate->sequenceSlot == ((GameObject*)node)->seqIndex)
                return 4;
        }
    }
    return 0;
}

/* sidekickToy_updateCurveTargetLatch: pre-curve probe + state-bit gate. If state's 0x2000 bit is
 * set, ask baddie_canSeeTarget whether the target is locked on; on hit,
 * leave state[0x2dc] alone. Otherwise initialise the rom-curve walker with
 * (data, obj, lbl_803E25DC, &lbl_803DBC58, -1) and toggle
 * the 0x2000 bit based on the u8 result. */
void sidekickToy_updateCurveTargetLatch(GameObject* obj)
{
    u8* state = (obj)->extra;
    u8* data = *(u8**)state;
    if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW) != 0)
    {
        if ((u8)baddie_canSeeTarget((GameObject*)obj, (int)state, &(obj)->anim.worldPosX, data + 0x68) != 0)
        {
            return;
        }
    }
    if ((*gRomCurveInterface)->initCurve(*(u8**)state, (void*)obj, lbl_803E25DC, (int*)&lbl_803DBC58, -1) != 0)
    {
        ((EnemyState*)state)->controlFlags &= ~(u64)BADDIE_CONTROL_PATH_FOLLOW;
    }
    else
    {
        ((EnemyState*)state)->controlFlags = ((EnemyState*)state)->controlFlags | BADDIE_CONTROL_PATH_FOLLOW;
    }
}

int fn_8014C11C(GameObject* obj, f32 radius, u8 flags, int max, EnemyTargetSearchResult* out)
{
    EnemyTargetSearchResult* cur[1];
    int state;
    int n;
    GameObject** arr;
    short ang;
    GameObject* tgt;
    u32 diff;
    int i;
    f32 d2;
    int count;
    TrickyVec3 d;
    void* dp = &d;

    cur[0] = 0;
    state = *(int*)&obj->extra;
    count = 0;
    n = 0;
    if ((flags & 1) != 0)
    {
        tgt = (GameObject*)ObjGroup_FindNearestObject(ENEMY_OBJGROUP, obj, &radius);
        out->obj = tgt;
        if (tgt != 0)
        {
            out->dist = radius;
            n = 1;
            if ((flags & 2) != 0)
            {
                if ((((TrickyState*)state)->controlFlags & 0x8000) != 0)
                {
                    d.x = obj->anim.worldPosX - out->obj->anim.worldPosX;
                    d.y = lbl_803E2574;
                    d.z = obj->anim.worldPosZ - out->obj->anim.worldPosZ;
                }
                else
                {
                    d.x = obj->anim.worldPosX - out->obj->anim.worldPosX;
                    d.y = obj->anim.worldPosY - out->obj->anim.worldPosY;
                    d.z = obj->anim.worldPosZ - out->obj->anim.worldPosZ;
                }
                diff = getAngle(-d.x, -d.z) & 0xffff;
                if (obj->anim.parent != 0)
                {
                    ang = (s16)(obj->anim.rotX + *(s16*)obj->anim.parent);
                }
                else
                {
                    ang = obj->anim.rotX;
                }
                diff = diff - ((int)ang & 0xffffU);
                if (0x8000 < (int)diff)
                {
                    diff = diff - 0xffff;
                }
                if ((int)diff < -0x8000)
                {
                    diff = diff + 0xffff;
                }
                ang = (short)((diff & 0xffff) >> 0xd);
                ((TrickyState*)state)->flags2DC = ((TrickyState*)state)->flags2DC & ~gEnemySelfAngleFlagClearMask[ang];
                if ((flags & 4) != 0)
                {
                    ((TrickyState*)out->obj->extra)->flags2DC &= ~gEnemyTargetAngleFlagClearMask[ang];
                }
            }
        }
    }
    else
    {
        radius = radius * radius;
        arr = (GameObject**)ObjGroup_GetObjects(ENEMY_OBJGROUP, &count);
        if (count != 0)
        {
            i = 0;
            cur[0] = out;
            for (; i < count; i++)
            {
                d2 = vec3f_distanceSquared(&obj->anim.worldPosX, &arr[i]->anim.worldPosX);
                if ((d2 < radius) && (arr[i] != obj))
                {
                    cur[0]->obj = arr[i];
                    cur[0]->dist = sqrtf(d2);
                    if ((flags & 2) != 0)
                    {
                        if ((((TrickyState*)state)->controlFlags & 0x8000) != 0)
                        {
                            d.x = obj->anim.worldPosX - cur[0]->obj->anim.worldPosX;
                            d.y = lbl_803E2574;
                            d.z = obj->anim.worldPosZ - cur[0]->obj->anim.worldPosZ;
                        }
                        else
                        {
                            d.x = obj->anim.worldPosX - cur[0]->obj->anim.worldPosX;
                            d.y = obj->anim.worldPosY - cur[0]->obj->anim.worldPosY;
                            d.z = obj->anim.worldPosZ - cur[0]->obj->anim.worldPosZ;
                        }
                        diff = getAngle(-d.x, -d.z) & 0xffff;
                        if (obj->anim.parent != 0)
                        {
                            ang = (s16)(obj->anim.rotX + *(s16*)obj->anim.parent);
                        }
                        else
                        {
                            ang = obj->anim.rotX;
                        }
                        diff = diff - ((int)ang & 0xffffU);
                        if (0x8000 < (int)diff)
                        {
                            diff = diff - 0xffff;
                        }
                        if ((int)diff < -0x8000)
                        {
                            diff = diff + 0xffff;
                        }
                        ang = (short)((diff & 0xffff) >> 0xd);
                        ((TrickyState*)state)->flags2DC =
                            ((TrickyState*)state)->flags2DC & ~gEnemySelfAngleFlagClearMask[ang];
                        if ((flags & 4) != 0)
                        {
                            ((TrickyState*)cur[0]->obj->extra)->flags2DC &= ~gEnemyTargetAngleFlagClearMask[ang];
                        }
                    }
                    cur[0]++;
                    n++;
                    if (n >= max)
                    {
                        i = count;
                    }
                }
            }
        }
    }
    return n;
}

u8 fn_8014C4D8(GameObject* obj)
{
    int* state;
    f32 val;
    if (obj != NULL)
    {
        state = obj->extra;
    }
    else
    {
        return 0;
    }
    if (state != NULL)
    {
        val = ((EnemyState*)state)->freezeRecoverTimer;
        if (val != lbl_803E2574)
        {
            return (u8)((s32)(val / lbl_803E2598) + 1);
        }
        else
        {
            return 0;
        }
    }
    return 0;
}

void fn_8014C540(GameObject* obj, int* outIdx, f32* outA, f32* outB)
{
    int* state;
    f32 fz;
    if (obj != NULL)
    {
        state = obj->extra;
        if (state != NULL)
        {
            *outA = (f32)(u32)((EnemyState*)state)->curveParamA / lbl_803E257C;
            *outB = (f32)(u32)((EnemyState*)state)->curveParamB;
            *outIdx = ((EnemyState*)state)->curveIndex;
            return;
        }
    }
    fz = lbl_803E2574;
    *outA = fz;
    *outB = fz;
    *outIdx = 0;
}
void enemy_setHealthZero(GameObject* obj)
{
    EnemyState* state = obj->extra;
    state->current = 0;
}

f32 enemy_getHealthFraction(register GameObject* obj)
{
    register u16 maxHealth;
    register EnemyState* state;
    u16 curHealth;
    state = obj->extra;
    if (state == NULL)
        return lbl_803E2574;
    maxHealth = state->max;
    if (maxHealth != 0)
    {
        curHealth = *(u16*)&state->current;
        if (curHealth != 0)
        {
            return (f32)(u32)curHealth / (f32)(u32)maxHealth;
        }
    }
    return lbl_803E2574;
}

void enemy_trackPlayer(GameObject* obj)
{
    EnemyState* state = obj->extra;
    state->trackedObj = Obj_GetPlayerObject();
}

void enemy_setTrackedObj(GameObject* obj, GameObject* target)
{
    ((EnemyState*)obj->extra)->trackedObj = target;
}
