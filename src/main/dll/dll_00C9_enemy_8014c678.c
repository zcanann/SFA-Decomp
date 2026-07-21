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

extern int lbl_803DBC58[2];
extern f32 lbl_803DBC60;
extern f32 lbl_803DBC64;
extern f32 lbl_803DBC68;

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

extern u32 gEnemySelfAngleFlagClearMask[];
extern u32 gEnemyTargetAngleFlagClearMask[];

void fn_8014C678(GameObject* obj, void* state, f32* desiredVec, f32 maxSpeed, f32 speedBand, f32 maxTurnRad, u8 clampToGround)
{
    f32 curMag, targetMag, axisMag, speed;
    f32 curDir[3];
    f32 targetDir[3];
    f32 turnAxis[3];
    f32 rotMtx[12];

    curMag = PSVECMag((f32*)((int)state + 0x2b8));
    if (curMag > lbl_803E2574)
    {
        f32 inv = lbl_803E256C / curMag;
        curDir[0] = ((f32*)state)[174] * inv;
        curDir[1] = ((f32*)state)[175] * inv;
        curDir[2] = ((f32*)state)[176] * inv;
        PSVECNormalize(curDir, curDir);
    }
    else
    {
        curDir[0] = lbl_803E2574;
        curDir[1] = lbl_803E2574;
        curDir[2] = lbl_803E2574;
    }

    targetMag = PSVECMag(desiredVec);
    if (targetMag > lbl_803E2574)
    {
        f32 inv = lbl_803E256C / targetMag;
        targetDir[0] = desiredVec[0] * inv;
        targetDir[1] = desiredVec[1] * inv;
        targetDir[2] = desiredVec[2] * inv;
    }
    else
    {
        targetDir[0] = lbl_803E2574;
        targetDir[1] = lbl_803E2574;
        targetDir[2] = lbl_803E2574;
    }

    PSVECCrossProduct(curDir, targetDir, turnAxis);
    axisMag = PSVECMag(turnAxis);
    if (axisMag > lbl_803E2574)
    {
        f32 angle;
        int gt;
        f64 gtf;
        angle = fn_80291FF4(PSVECDotProduct(curDir, targetDir));
        gt = (angle > maxTurnRad);
        gtf = __fabs((f32)gt);
        if (gtf != lbl_803E2574)
        {
            f32 rot = maxTurnRad * ((angle > lbl_803E2574) ? lbl_803E256C : lbl_803E25C4);
            PSMTXRotAxisRad(rotMtx, turnAxis, rot);
            PSMTXMultVecSR(rotMtx, curDir, targetDir);
        }
    }

    speed = targetMag * lbl_803E25E8;
    {
        f32 cap_high = curMag + speedBand;
        if (speed > cap_high)
        {
            speed = cap_high;
        }
        else
        {
            f32 cap_low = curMag - speedBand;
            if (speed < cap_low)
                speed = cap_low;
        }
        if (speed > maxSpeed)
            speed = maxSpeed;
    }

    ((GameObject*)obj)->anim.velocityX = targetDir[0] * speed;
    ((GameObject*)obj)->anim.velocityY = targetDir[1] * speed;
    ((GameObject*)obj)->anim.velocityZ = targetDir[2] * speed;

    if (clampToGround != 0)
    {
        f32 y = ((GameObject*)obj)->anim.velocityY;
        if (y < lbl_803E2574)
        {
            f32 floor_height = ((GameObject*)obj)->anim.localPosY;
            GameObject* target = *(GameObject**)((char*)state + 0x29c);
            f32 ground = lbl_803E25D0 + target->anim.localPosY;
            if (floor_height < ground)
            {
                f32 t = (ground - floor_height) / lbl_803E25D0;
                ((GameObject*)obj)->anim.velocityY = y * (lbl_803E256C - t);
            }
        }
    }
}

/* sidekickToy_accelerateTowardTarget3D: 3D physics step toward a target. Variant of sidekickToy_accelerateTowardTargetXZ that
 * uses the full 3D distance (xyz) instead of planar (xz), and also nudges
 * the y-axis velocity at obj+0x28. Returns the y-delta. */
