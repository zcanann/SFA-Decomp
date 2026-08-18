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
#include "main/audio/sfx_stop_object_api.h"

/* Baddie-family animation data shared with the sequence-driver TUs. */

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

extern s32 gHagabonMK2ModelChain0BoneIds[];

extern s32 gHagabonMK2ModelChain1BoneIds[];

extern s32 gHagabonMK2ModelChain2BoneIds[];

extern s32 gHagabonMK2ModelChain3BoneIds[];

extern s32 gHagabonMK2ModelChain4BoneIds[];


#define FIRECRAWLER_OBJFLAG_RENDERED     0x800
#define FIRECRAWLER_OBJFLAG_PARENT_SLACK 0x1000
#define FIREHOLE_OBJ_ID                  0x710 /* FireHole child spawned by firecrawler (firepipe DLL 0x273) */

typedef struct
{
    u8 pad[6];
    u16 sfxId; /* 0x6 */
    f32 vol;   /* 0x8 */
    f32 x;     /* 0xc */
    f32 y;     /* 0x10 */
    f32 z;     /* 0x14 */
} CrawlerSfxParams;

static const f32 gHagabonMK2LightAttenNear[1] = {100.0f};

static const f32 gHagabonMK2LightAttenFar[1] = {150.0f};

static const f32 gHagabonMK2LightIntensity[1] = {0.5f};

static inline void crawler_createEngineLight(GameObject* obj, u8* state)
{
    if (((EnemyState*)state)->modelLight == NULL)
    {
        ((EnemyState*)state)->modelLight = objCreateLight(NULL, 1);
    }
    if (((EnemyState*)state)->modelLight != NULL)
    {
        modelLightStruct_setLightKind(((EnemyState*)state)->modelLight, MODEL_LIGHT_KIND_POINT);
        modelLightStruct_setPosition(((EnemyState*)state)->modelLight, obj->anim.localPosX,
                                     obj->anim.localPosY, obj->anim.localPosZ);
        modelLightStruct_setDiffuseColor(((EnemyState*)state)->modelLight, 0xc0, 0x40, 0xff, 0xff);
        modelLightStruct_setSpecularColor(((EnemyState*)state)->modelLight, 0xc0, 0x40, 0xff, 0xff);
        modelLightStruct_setDistanceAttenuation(((EnemyState*)state)->modelLight, gHagabonMK2LightAttenNear[0],
                                                gHagabonMK2LightAttenFar[0]);
        lightSetField4D(((EnemyState*)state)->modelLight, 1);
        modelLightStruct_setEnabled(((EnemyState*)state)->modelLight, 1, gHagabonMK2LightIntensity[0]);
        modelLightStruct_startColorFade(((EnemyState*)state)->modelLight, 0, 0);
        modelLightStruct_setAffectsAabbLightSelection(((EnemyState*)state)->modelLight, 0);
    }
}

int gHagabonMK2CurveInitData[2] = {2, 3};

ObjModelChainDesc gHagabonMK2ModelChain0 = {gHagabonMK2ModelChain0BoneIds, 6};

ObjModelChainDesc gHagabonMK2ModelChain1 = {gHagabonMK2ModelChain1BoneIds, 6};

ObjModelChainDesc gHagabonMK2ModelChain2 = {gHagabonMK2ModelChain2BoneIds, 6};

ObjModelChainDesc gHagabonMK2ModelChain3 = {gHagabonMK2ModelChain3BoneIds, 6};

ObjModelChainDesc gHagabonMK2ModelChain4 = {gHagabonMK2ModelChain4BoneIds, 5};

CrawlerSeq12 gCrawlerSeqTable[6] = {
    {4.0f, 0, 0, 0, 1}, {1.0f, 0, 1, 2, 2}, {0.5f, 0, 3, 0, 0},
    {2.0f, 0, 1, 4, 4}, {1.0f, 0, 2, 4, 5}, {2.0f, 0, 3, 0, 0},
};

s32 gHagabonMK2ModelChain0BoneIds[6] = {1, 2, 3, 4, 5, 6};

s32 gHagabonMK2ModelChain1BoneIds[6] = {12, 13, 14, 15, 16, 17};

s32 gHagabonMK2ModelChain2BoneIds[6] = {18, 19, 20, 21, 22, 23};

s32 gHagabonMK2ModelChain3BoneIds[6] = {24, 25, 26, 27, 28, 29};

s32 gHagabonMK2ModelChain4BoneIds[5] = {7, 8, 9, 10, 11};

ObjModelChainDesc* gCrawlerModelChainIds[] = {
    &gHagabonMK2ModelChain0, &gHagabonMK2ModelChain1, &gHagabonMK2ModelChain2, &gHagabonMK2ModelChain3, &gHagabonMK2ModelChain4,
};

void crawler_rotateVectorYaw(int unused1, int* unused2, f32* vec, int unused3, int nodeIndex, f32 phase)
{
    f32 mtx[12];
    f32 a;
    a = 0.02f * mathCosfHighPrecision(0.08f * phase - 1.1f * (f32)nodeIndex);
    PSMTXRotRad((MtxPtr)mtx, 'y', a);
    PSMTXMultVecSR((MtxPtr)mtx, (Vec*)vec, (Vec*)vec);
}

void hagabonMK2_stopLoopSfx(int obj, u8* state)
{
    Sfx_StopFromObject((GameObject*)obj, SFXTRIG_baddie_rach_death);
}

void hagabonMK2_updateWhileFrozen(int obj, u8* st, GameObject* attacker, int cmd, int wpad0, int wpad1, Vec* wpad2,
                                  int wpad3)
{
    int objI = obj;
    if (cmd == 0x11)
    {
    }
    else if (cmd == 0x10)
    {
        ((EnemyState*)st)->flags2E8 |= 0x20;
    }
    else
    {
        ((EnemyState*)st)->flags2E8 |= 0x8;
        Sfx_StopFromObject((GameObject*)objI, SFXTRIG_baddie_rach_death);
        Sfx_PlayFromObject((GameObject*)obj, SFXTRIG_baddie_eba_leavesopen);
        ((EnemyState*)st)->current = 0;
    }
}

void hagabonMK2_updateB(GameObject* obj, u8* state)
{
    RomCurveWalker* base = *(RomCurveWalker**)state;
    f32 spd;
    f32 cap;
    CrawlerSfxParams sp;
    f32 dv[3];
    int i;

    if (((EnemyState*)state)->crawler.warpTimer)
    {
        cap = 0.0f;
        ((EnemyState*)state)->crawler.warpTimer = ((EnemyState*)state)->crawler.warpTimer - timeDelta;
        if (((EnemyState*)state)->crawler.warpTimer <= cap)
        {
            ((EnemyState*)state)->crawler.warpTimer = cap;
        }
    }
    ((EnemyState*)state)->flags2E8 = ((EnemyState*)state)->flags2E8 | 0x100;
    sp.x = 0.0f;
    sp.y = 4.0f;
    sp.z = 0.0f;
    sp.vol = 1.1f;
    sp.sfxId = 0x605;
    if ((obj->objectFlags & FIRECRAWLER_OBJFLAG_RENDERED) != 0)
    {
        (*gPartfxInterface)->spawnObject(obj, 1999, &sp, 2, -1, NULL);
        if (((EnemyState*)state)->modelLight == NULL)
        {
            crawler_createEngineLight(obj, state);
        }
        else
        {
            modelLightStruct_setPosition(((EnemyState*)state)->modelLight, obj->anim.localPosX,
                                         obj->anim.localPosY, obj->anim.localPosZ);
        }
    }

    if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_JUST_TRIGGERED) != 0)
    {
        ((EnemyState*)state)->userData1 = gCrawlerSeqTable[((EnemyState*)state)->userData1].mode;
        ((EnemyState*)state)->crawler.emergeTimer = 200.0f;
        Sfx_StopFromObject(obj, SFXTRIG_baddie_rach_death);
    }

    if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW) != 0)
    {
        f32* dp = dv;
        f32 t;
        dp[0] = base->posX - obj->anim.worldPosX;
        dp[1] = base->posY - obj->anim.worldPosY;
        dp[2] = base->posZ - obj->anim.worldPosZ;
        ((EnemyState*)state)->crawler.distToCurve = sqrtf(dp[2] * dp[2] + (dp[0] * dp[0] + dp[1] * dp[1]));
        if (((EnemyState*)state)->crawler.distToCurve < gHagabonMK2LightAttenNear[0] &&
            !((EnemyState*)state)->crawler.warpTimer)
        {
            ((EnemyState*)state)->flags2E4 = ((EnemyState*)state)->flags2E4 & ~0x10000LL;
        }
        t = 1.0f - ((EnemyState*)state)->crawler.distToCurve / 400.0f;
        if (t < 0.0f)
        {
            t = 0.0f;
        }
        else if (t > 1.0f)
        {
            t = 1.0f;
        }
        if ((Curve_AdvanceAlongPath(&base->curve, ((EnemyState*)state)->pathStep * t) != 0 ||
             base->atSegmentEnd != 0) &&
            (*gRomCurveInterface)->goNextPoint(base) != 0 &&
            (*gRomCurveInterface)->initCurve(*(RomCurveWalker**)state, obj, 700.0f, (int*)&gHagabonMK2CurveInitData, -1) != 0)
        {
            ((EnemyState*)state)->controlFlags =
                ((EnemyState*)state)->controlFlags & ~(u64)BADDIE_CONTROL_PATH_FOLLOW;
        }
        sidekickToy_accelerateTowardTarget3D(obj, base->posX, base->posY, base->posZ, 60.0f,
                                             0.05f, 5.0f, ((EnemyState*)state)->drag);
    }

    if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        i = ((EnemyState*)state)->userData1;
        baddieSetMove(obj, (int)state, gCrawlerSeqTable[i].moveId, gCrawlerSeqTable[i].spd, 0, 0);
        ((EnemyState*)state)->userData1 = gCrawlerSeqTable[((EnemyState*)state)->userData1].next;
    }

    if (((EnemyState*)state)->crawler.engineTimer > 0.0f)
    {
        ((EnemyState*)state)->crawler.engineTimer = -(18.2f * timeDelta - ((EnemyState*)state)->crawler.engineTimer);
        *(s16*)obj = ((EnemyState*)state)->crawler.engineTimer * timeDelta + (f32)(int)*(s16*)obj;
    }
    else
    {
        f32 ratio;
        ((EnemyState*)state)->crawler.engineTimer = 0.0f;
        spd = 1.0f - (((EnemyState*)state)->crawler.emergeTimer - 15.0f) / 185.0f;
        if (spd < 0.0001f)
        {
            spd = 0.0001f;
        }
        else if (spd > 1.0f)
        {
            spd = 1.0f;
        }
        if (((EnemyState*)state)->crawler.emergeTimer > 15.0f)
        {
            ((EnemyState*)state)->crawler.emergeTimer -= timeDelta;
        }
        else
        {
            ((EnemyState*)state)->crawler.emergeTimer = 15.0f;
        }
        ratio = sqrtf(obj->anim.velocityX * obj->anim.velocityX +
                      obj->anim.velocityZ * obj->anim.velocityZ) /
                60.0f;
        if (ratio < 0.0f)
        {
            ratio = 0.0f;
        }
        else if (ratio > 1.0f)
        {
            ratio = 1.0f;
        }
        {
            f32 t = 6370.0f * spd;
            ratio *= t * timeDelta;
        }
        obj->anim.rotY = (f32)obj->anim.rotY - ratio;
        baddieTurnTowardLookDir(obj, state, (int)((EnemyState*)state)->crawler.emergeTimer, 10.0f * spd,
                    0.0f, 1);
    }

    {
        f32 pw = powfBitEstimate(((EnemyState*)state)->drag, timeDelta);
        obj->anim.rotY = (f32)obj->anim.rotY * pw;
        pw = powfBitEstimate(((EnemyState*)state)->drag, timeDelta);
        obj->anim.rotZ = (f32)obj->anim.rotZ * pw;
    }

    if ((int)randomGetRange(0, 0x2ee) == 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_baddie_eba);
    }

    if (((EnemyState*)state)->crawler.engineTimer > 0.0f)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_baddie_rach_death);
        {
            f32 t = ((EnemyState*)state)->crawler.engineTimer;
            Sfx_SetObjectSfxVolume(obj, SFXTRIG_baddie_rach_death,
                                   (127.0f * t) / 2184.0f,
                                   t / 2184.0f);
        }
    }
    else
    {
        Sfx_StopFromObject(obj, SFXTRIG_baddie_rach_death);
    }

    {
        s16 t;
        if (((EnemyState*)state)->lastHitObject != NULL &&
            ((t = (((EnemyState*)state)->lastHitObject)->anim.romDefNo) == 0x1f || t == 0))
        {
            Sfx_PlayFromObject(obj, SFXTRIG_fball2_c);
        }
    }
}

void hagabonMK2_update(GameObject* obj, u8* state)
{
    RomCurveWalker* base = *(RomCurveWalker**)state;
    f32 d[3];
    CrawlerSfxParams sp;
    int i;
    f32 pw;

    if (((EnemyState*)state)->lastHitObject != NULL && ((EnemyState*)state)->lastHitObject == ((EnemyState*)state)->trackedObj)
    {
        ((EnemyState*)state)->flags2E4 |= 0x10000LL;
        ((EnemyState*)state)->crawler.warpTimer = 180.0f;
    }
    ((EnemyState*)state)->flags2E8 = ((EnemyState*)state)->flags2E8 | 0x100;
    sp.x = 0.0f;
    sp.y = 4.0f;
    sp.z = 0.0f;
    sp.vol = 1.1f;
    sp.sfxId = 0x605;
    if ((obj->objectFlags & FIRECRAWLER_OBJFLAG_RENDERED) != 0)
    {
        (*gPartfxInterface)->spawnObject(obj, 1999, &sp, 2, -1, NULL);
        if (((EnemyState*)state)->modelLight == NULL)
        {
            crawler_createEngineLight(obj, state);
        }
        else
        {
            modelLightStruct_setPosition(((EnemyState*)state)->modelLight, obj->anim.localPosX,
                                         obj->anim.localPosY, obj->anim.localPosZ);
        }
    }
    if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_JUST_TRIGGERED) != 0)
    {
        ((EnemyState*)state)->userData1 = 3;
        ((EnemyState*)state)->controlFlags |= (u64)BADDIE_CONTROL_SEQUENCE_DRIVEN;
    }
    sidekickToy_accelerateTowardTarget3D(
        obj, ((GameObject*)((EnemyState*)state)->trackedObj)->anim.worldPosX,
        60.0f + ((GameObject*)((EnemyState*)state)->trackedObj)->anim.worldPosY,
        ((GameObject*)((EnemyState*)state)->trackedObj)->anim.worldPosZ, 60.0f, 0.025f,
        5.0f, ((EnemyState*)state)->drag);
    if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        i = ((EnemyState*)state)->userData1;
        baddieSetMove(obj, (int)state, gCrawlerSeqTable[i].moveId, gCrawlerSeqTable[i].spd, 0, 0);
        ((EnemyState*)state)->userData1 = gCrawlerSeqTable[((EnemyState*)state)->userData1].next;
    }
    pw = powfBitEstimate(((EnemyState*)state)->drag, timeDelta);
    obj->anim.rotY = (f32)obj->anim.rotY * pw;
    pw = powfBitEstimate(((EnemyState*)state)->drag, timeDelta);
    obj->anim.rotZ = (f32)obj->anim.rotZ * pw;
    if (((EnemyState*)state)->crawler.engineTimer < 2184.0f)
    {
        ((EnemyState*)state)->crawler.engineTimer = 18.2f * timeDelta + ((EnemyState*)state)->crawler.engineTimer;
    }
    else
    {
        ((EnemyState*)state)->crawler.engineTimer = 2184.0f;
    }
    *(s16*)obj = ((EnemyState*)state)->crawler.engineTimer * timeDelta + (f32)(int)*(s16*)obj;
    ((EnemyState*)state)->crawler.emergeTimer = 200.0f;
    if ((((EnemyState*)state)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW) != 0)
    {
        f32* dp = d;
        dp[0] = base->posX - obj->anim.worldPosX;
        dp[1] = base->posY - obj->anim.worldPosY;
        dp[2] = base->posZ - obj->anim.worldPosZ;
        ((EnemyState*)state)->crawler.distToCurve = sqrtf(dp[2] * dp[2] + (dp[0] * dp[0] + dp[1] * dp[1]));
        if (((EnemyState*)state)->crawler.distToCurve > 400.0f)
        {
            ((EnemyState*)state)->flags2E4 |= 0x10000LL;
            ((EnemyState*)state)->crawler.warpTimer = 0.0f;
        }
    }
    if (((EnemyState*)state)->crawler.engineTimer > 0.0f)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_baddie_rach_death);
        {
            f32 t = ((EnemyState*)state)->crawler.engineTimer;
            Sfx_SetObjectSfxVolume(obj, SFXTRIG_baddie_rach_death,
                                   (127.0f * t) / 2184.0f,
                                   t / 2184.0f);
        }
    }
    else
    {
        Sfx_StopFromObject(obj, SFXTRIG_baddie_rach_death);
    }
    if (((EnemyState*)state)->lastHitObject != NULL && ((((EnemyState*)state)->lastHitObject)->anim.romDefNo == 0x1f ||
                                                (((EnemyState*)state)->lastHitObject)->anim.romDefNo == 0))
    {
        Sfx_PlayFromObject(obj, SFXTRIG_fball2_c);
    }
}

void hagabonMK2_init(GameObject* obj, EnemyState* st)
{
    st->sightRange = 40.0f;
    st->flags2E4 = 0x405009;
    st->drag = 0.97f;
    st->moveId0 = 0;
    {
        f32 d1 = 1.5f;
        st->moveSpeedScale0 = d1;
        st->moveId1 = 0;
        st->moveSpeedScale1 = 1.0f;
        st->moveId2 = 0;
        st->moveSpeedScale2 = d1;
    }
    st->pathStep *= 3.0f;
    {
        u32 idx = st->userData1;
        baddieSetMove(obj, (int)st, gCrawlerSeqTable[idx].moveId, gCrawlerSeqTable[idx].spd, 0, 0);
    }
    st->crawler.emergeTimer = 15.0f;
    ObjHits_SetHitVolumeMasks(&obj->anim, 0xe, 1, 0xfff);
    st->tailSimHandle = ObjModelChain_Alloc(gCrawlerModelChainIds, 5);
    ObjModelChain_SetOrigin(st->tailSimHandle, 0.1f, 0.85f, -0.075f);
    st->flags2E8 = st->flags2E8 | 0x100;
    obj->afterBonesCallback = &baddieAfterUpdateBonesCb;
}
