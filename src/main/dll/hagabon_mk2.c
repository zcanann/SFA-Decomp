/*
 * hagabonMK2 - the HagabonMK2 flying enemy (anim.seqId 0x7c8) plus the
 * crawler-family tail-model and vector helpers that share its original
 * translation unit:
 *   crawler_rotateVectorYaw      rotates a vector about the yaw axis.
 *   hagabonMK2_stopLoopSfx       stops the looping engine sfx.
 *   hagabonMK2_updateWhileFrozen freeze-event handler.
 *   hagabonMK2_updateB           per-frame update: curve walk, engine sfx and
 *                                the dynamic light.
 *   hagabonMK2_update            per-frame update for the second variant.
 *   crawler_initTailModel        seeds the tail model chain and hit volumes.
 */
#include "main/dll/partfx_interface.h"
#include "main/camera_interface.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "main/frame_timing.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/math_api.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/trig_float_helpers.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/track_bbox_api.h"
#include "main/obj_group.h"
#include "main/obj_link.h"
#include "main/obj_path.h"
#include "main/object.h"
#include "main/model_light.h"
#include "main/object_api.h"
#include "main/obj_query.h"
#include "main/model.h"
#include "main/gamebits.h"
#include "main/dll/baddie_state.h"
#include "main/dll/baddie_setmove.h"
#include "main/dll/curve_walker.h"
#include "main/dll/dll_00C9_enemy.h"
#include "main/dll/rom_curve_interface.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/gameloop_api.h"
#include "main/objhits.h"
#include "main/dll/modgfx.h"
#include "main/dll/firecrawler.h"
#include "main/dll/player_api.h"
#include "main/dll/objfsa.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/gamebit_ids.h"
#include "main/camera_shake_api.h"
#include "main/pad_api.h"
#include "main/dll/dll_0273_firepipe.h"

extern f32 lbl_803DBCE0;
extern f32 lbl_803DBCE4;
extern f32 lbl_803DBCE8;
extern f32 lbl_803DBCEC;
extern int lbl_803DBCF8[2];

typedef struct CrawlerModelChainList
{
    u8* modelIds;
    s32 count;
} CrawlerModelChainList;

STATIC_ASSERT(sizeof(CrawlerModelChainList) == 8);

extern u8 gSnowwormSeqIndexReset[4];
extern u8 gSnowwormSeqIndexMax[4];

/* group owned by another DLL, queried here */
#define LANTERNFIREFLY_OBJGROUP          0x30 /* DLL 0x10C lanternfirefly */
#define FIRECRAWLER_OBJFLAG_RENDERED     0x800
#define FIRECRAWLER_OBJFLAG_PARENT_SLACK 0x1000
#define FIREPIPE_OBJ_ID                  0x710 /* child object spawned by firecrawler */
/* crawler-family enemy anim.seqIds (docblock table: seqId -> enemy name) */
#define FIRECRAWLER_SEQID_FIRECRAWLER  0x6a2 /* FireCrawler */
#define FIRECRAWLER_SEQID_REDEYE       0x6a3 /* RedEye */
#define FIRECRAWLER_SEQID_SHADOWHUNTER 0x6a4 /* ShadowHunter */

/* movement dust spawned on the move-loop event: turning (turnDelta != 0) */
#define FIRECRAWLER_PARTFX_MOVE_TURN 0x802
/* movement dust spawned on the move-loop event: moving straight (turnDelta == 0) */
#define FIRECRAWLER_PARTFX_MOVE_STRAIGHT 0x809
#define FIRECRAWLER_HIT_VOLUME_SLOT      9

/* Spawn-setup buffer for the firepipe child (obj id 0x710): ObjPlacement head
 * (pos/color) plus the class-specific fields the parent seeds at +0x18. */
typedef struct FirepipeSetup
{
    ObjPlacement head; /* 0x00 */
    u8 unk18;          /* 0x18 */
    u8 unk19;          /* 0x19 */
    s16 unk1A;         /* 0x1a */
    s16 unk1C;         /* 0x1c */
    s16 unk1E;         /* 0x1e */
    s16 unk20;         /* 0x20 */
    u8 unk22;          /* 0x22 */
    u8 unk23;          /* 0x23 */
} FirepipeSetup;
extern f32 lbl_803E2C3C;
extern f32 lbl_803E2C58;
extern f32 lbl_803E2C7C;
extern f32 lbl_803E2C80;
extern f32 lbl_803E2C84;
extern f32 lbl_803E2C88;
extern f32 lbl_803E2C8C;
extern f32 lbl_803E2C90;
extern f32 lbl_803E2C94;
extern u8 gCrawlerSeqTable[];
extern void* gCrawlerModelChainIds[];
extern void* gCrawlerDescriptorTable[];
extern u8* gCrawlerReactionTables[];

extern f32 lbl_803E2C1C;
extern f32 lbl_803E2C20;
extern f32 lbl_803E2C24;
extern f32 lbl_803E2BA0;
extern f32 lbl_803E2BA4;
extern f32 gCrawlerS8Norm127;
extern int fn_8014C11C(int obj, f32 dist, u8 flag, int maxCount, void* buf);
extern int gCrawlerNearbyObjectBuffer[0x20];
extern f32 gCrawlerPi;
extern f32 gCrawlerHalfCircleBams;
extern void fn_8014CF7C(int* obj, u8* state, f32 x, f32 z, int p5, int p6);
extern f32 lbl_803DBCE0;
extern f32 lbl_803DBCE4;
extern f32 lbl_803DBCEC;

void fn_80157B58(int* obj, u8* state);

extern f32 lbl_803E2C74;
extern f32 lbl_803E2C30;
extern f32 lbl_803E2C34;
extern f32 lbl_803E2C10;
extern f32 lbl_803E2C14;
extern f32 lbl_803E2C18;
extern f32 lbl_803E2C48;
extern f32 lbl_803E2C78;
extern f32 lbl_803E2C50;
extern f32 lbl_803E2C70;
extern f32 lbl_803E2C54;
extern f32 lbl_803E2C38;
extern f32 lbl_803E2C40;
extern f32 gCrawlerSfxVolMax127;
extern f32 lbl_803DBCE8;
extern f32 gCrawlerHitSfxTimer;

extern u8 gCrawlerSpeedThresholds[];
extern f32 lbl_803E2BA0;
extern f32 lbl_803E2BA4;
extern f32 lbl_803E2C44;
extern f32 lbl_803E2C4C;
extern f32 lbl_803E2C5C;
extern f32 lbl_803E2C60;
extern f32 lbl_803E2C64;
extern f32 lbl_803E2C68;
extern void fn_8014CD1C(s16* obj, u8* state, int p3, f32 a, f32 b, int p6);

/*
 * FCVars - file-local overlay naming the crawler/HagabonMK2-family scratch
 * region of the actor-control blob (the shared BaddieState header
 * deliberately leaves 0x323-0x345 as per-family padding; these fields carry
 * this TU's meaning). Cast state to (FCVars*) to read/write named fields.
 * NOTE 0x330 is an f32 timer here, overlapping BaddieState's s16 cameraYaw -
 * this is the documented per-family union, hence a file-local overlay rather
 * than a shared-header field.
 */
typedef struct FCVars
{
    u8 pad000[0x2a0];
    u16 moveTableIndex; /* 0x2a0: reaction/move sub-table index (*0xc stride) */
    u8 pad2a2[0x2a4 - 0x2a2];
    u16 projectileTimer; /* 0x2a4: firepipe launch timing counter (>=0x50 gate) */
    u8 pad2a6[0x2ec - 0x2a6];
    u16 hitCountScalar; /* 0x2ec: hit-count scalar folded into emergeTimer */
    u8 pad2ee[0x2f1 - 0x2ee];
    u8 hitConfigFlags; /* 0x2f1: bit 0x40 = group-0 hit-immunity config */
    u8 pad2f2[0x2f8 - 0x2f2];
    u16 moveEventMask; /* 0x2f8: per-frame move-progress event bitmask (bit 1<<i) */
    u8 pad2fa[0x310 - 0x2fa];
    f32 pathSpeed; /* 0x310: per-frame curve-advance speed */
    u8 pad314[0x323 - 0x314];
    u8 moveStartFlags; /* 0x323: bit 8 = move suppresses target-facing */
    f32 engineTimer;   /* 0x324: engine-sfx / spin-down timer (dt-decremented) */
    f32 emergeTimer;   /* 0x328: emerge/burrow fade timer */
    f32 distToCurve;   /* 0x32c: distance from object to its curve point */
    f32 warpTimer;     /* 0x330: HagabonMK2 warp/teleport cooldown timer */
    u8 pad334[0x338 - 0x334];
    u16 turnDelta; /* 0x338: signed turn amount / variant index (dual use) */
    u8 pad33a[0x33c - 0x33a];
    u8 flagsC;         /* 0x33c: bit1 hitVolumeIndex, bit4 invuln */
    u8 flagsD;         /* 0x33d: move/link state bits (0x8/0x10/0x18/0x20/0x30/0x40) */
    u8 moveChainIndex; /* 0x33e: index into the chained-move table (tbl4) */
    u8 reactStep;      /* 0x33f: reaction/hit sequence step (indexes seq/CrawlerSeq16) */
    void* linkedObj;   /* 0x340: linked/tracked object pointer (HagabonMK2, hoodedZyck) */
} FCVars;

STATIC_ASSERT(offsetof(FCVars, moveTableIndex) == 0x2a0);
STATIC_ASSERT(offsetof(FCVars, projectileTimer) == 0x2a4);
STATIC_ASSERT(offsetof(FCVars, hitCountScalar) == 0x2ec);
STATIC_ASSERT(offsetof(FCVars, hitConfigFlags) == 0x2f1);
STATIC_ASSERT(offsetof(FCVars, moveEventMask) == 0x2f8);
STATIC_ASSERT(offsetof(FCVars, pathSpeed) == 0x310);
STATIC_ASSERT(offsetof(FCVars, moveStartFlags) == 0x323);
STATIC_ASSERT(offsetof(FCVars, engineTimer) == 0x324);
STATIC_ASSERT(offsetof(FCVars, emergeTimer) == 0x328);
STATIC_ASSERT(offsetof(FCVars, distToCurve) == 0x32c);
STATIC_ASSERT(offsetof(FCVars, warpTimer) == 0x330);
STATIC_ASSERT(offsetof(FCVars, turnDelta) == 0x338);
STATIC_ASSERT(offsetof(FCVars, flagsC) == 0x33c);
STATIC_ASSERT(offsetof(FCVars, flagsD) == 0x33d);
STATIC_ASSERT(offsetof(FCVars, moveChainIndex) == 0x33e);
STATIC_ASSERT(offsetof(FCVars, reactStep) == 0x33f);
STATIC_ASSERT(offsetof(FCVars, linkedObj) == 0x340);

typedef struct
{
    f32 spd;   /* 0x0 */
    u32 mask;  /* 0x4 */
    u8 moveId; /* 0x8 */
    u8 next;   /* 0x9 */
    u8 mode;   /* 0xa */
    u8 pad;
} CrawlerSeq12;

typedef struct
{
    u8 pad[6];
    u16 sfxId; /* 0x6 */
    f32 vol;   /* 0x8 */
    f32 x;     /* 0xc */
    f32 y;     /* 0x10 */
    f32 z;     /* 0x14 */
} CrawlerSfxParams;


void crawler_rotateVectorYaw(int unused1, int unused2, f32* vec, f32 f1, int p5, u32 int_deg)
{
    f32 mtx[12];
    f32 a;
    a = lbl_803E2C20 * f1 - lbl_803E2C24 * (f32)(s32)int_deg;
    a = fn_802943F4(a);
    a = lbl_803E2C1C * a;
    PSMTXRotRad(mtx, 0x79, a);
    PSMTXMultVecSR(mtx, vec, vec);
}

void hagabonMK2_stopLoopSfx(int obj)
{
    Sfx_StopFromObject(obj, SFXTRIG_baddie_rach_death);
}

void hagabonMK2_updateWhileFrozen(int obj, int* st, int unused, int cmd)
{
    int objI = (int)obj;
    if (cmd == 0x11)
    {
    }
    else if (cmd == 0x10)
    {
        ((BaddieState*)st)->reactionFlags |= 0x20;
    }
    else
    {
        ((BaddieState*)st)->reactionFlags |= 0x8;
        Sfx_StopFromObject(objI, SFXTRIG_baddie_rach_death);
        Sfx_PlayFromObject(obj, SFXTRIG_baddie_eba_leavesopen);
        *(s16*)&((BaddieState*)st)->hitCounter = 0;
    }
}

void hagabonMK2_updateB(s16* obj, u8* state)
{
    RomCurveWalker* base = *(RomCurveWalker**)state;
    f32 spd;
    f32 cap;
    CrawlerSfxParams sp;
    f32 dv[3];
    int i;

    if (((FCVars*)state)->warpTimer != *(f32*)&lbl_803E2C30)
    {
        cap = lbl_803E2C30;
        ((FCVars*)state)->warpTimer = ((FCVars*)state)->warpTimer - timeDelta;
        if (((FCVars*)state)->warpTimer <= cap)
        {
            ((FCVars*)state)->warpTimer = cap;
        }
    }
    ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x100;
    sp.x = lbl_803E2C30;
    sp.y = lbl_803E2C34;
    sp.z = lbl_803E2C30;
    sp.vol = lbl_803E2C24;
    sp.sfxId = 0x605;
    if ((((GameObject*)obj)->objectFlags & FIRECRAWLER_OBJFLAG_RENDERED) != 0)
    {
        (*gPartfxInterface)->spawnObject(obj, 1999, &sp, 2, -1, NULL);
        if (((FireCrawlerState*)state)->engineLight == NULL)
        {
            if (((FireCrawlerState*)state)->engineLight == NULL)
            {
                ((FireCrawlerState*)state)->engineLight = objCreateLight(NULL, 1);
            }
            if (((FireCrawlerState*)state)->engineLight != NULL)
            {
                modelLightStruct_setLightKind(((FireCrawlerState*)state)->engineLight, MODEL_LIGHT_KIND_POINT);
                modelLightStruct_setPosition(((FireCrawlerState*)state)->engineLight,
                                             ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                             ((GameObject*)obj)->anim.localPosZ);
                modelLightStruct_setDiffuseColor(((FireCrawlerState*)state)->engineLight, 0xc0, 0x40, 0xff, 0xff);
                modelLightStruct_setSpecularColor(((FireCrawlerState*)state)->engineLight, 0xc0, 0x40, 0xff, 0xff);
                modelLightStruct_setDistanceAttenuation(((FireCrawlerState*)state)->engineLight, lbl_803E2C10,
                                                        lbl_803E2C14);
                lightSetField4D(((FireCrawlerState*)state)->engineLight, 1);
                modelLightStruct_setEnabled(((FireCrawlerState*)state)->engineLight, 1, lbl_803E2C18);
                modelLightStruct_startColorFade(((FireCrawlerState*)state)->engineLight, 0, 0);
                modelLightStruct_setAffectsAabbLightSelection(((FireCrawlerState*)state)->engineLight, 0);
            }
        }
        else
        {
            modelLightStruct_setPosition(((FireCrawlerState*)state)->engineLight, ((GameObject*)obj)->anim.localPosX,
                                         ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ);
        }
    }

    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_JUST_TRIGGERED) != 0)
    {
        CrawlerSeq12* sq = (CrawlerSeq12*)gCrawlerSeqTable;
        ((BaddieState*)state)->seqEntryIndex = sq[((BaddieState*)state)->seqEntryIndex].mode;
        ((FCVars*)state)->emergeTimer = lbl_803E2C38;
        Sfx_StopFromObject((int)obj, SFXTRIG_baddie_rach_death);
    }

    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW) != 0)
    {
        f32* dp = dv;
        f32 t;
        dp[0] = base->posX - ((GameObject*)obj)->anim.worldPosX;
        dp[1] = base->posY - ((GameObject*)obj)->anim.worldPosY;
        dp[2] = base->posZ - ((GameObject*)obj)->anim.worldPosZ;
        ((FCVars*)state)->distToCurve = sqrtf(dp[2] * dp[2] + (dp[0] * dp[0] + dp[1] * dp[1]));
        if (((FCVars*)state)->distToCurve < lbl_803E2C10 && ((FCVars*)state)->warpTimer == lbl_803E2C30)
        {
            *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 & ~0x10000LL;
        }
        t = lbl_803E2C3C - ((FCVars*)state)->distToCurve / lbl_803E2C40;
        if (t < lbl_803E2C30)
        {
            t = lbl_803E2C30;
        }
        else if (t > lbl_803E2C3C)
        {
            t = lbl_803E2C3C;
        }
        if ((Curve_AdvanceAlongPath(base, ((BaddieState*)state)->pathStep * t) != 0 || base->atSegmentEnd != 0) &&
            (*gRomCurveInterface)->goNextPoint(base) != 0 &&
            (*gRomCurveInterface)->initCurve(*(RomCurveWalker**)state, obj, lbl_803E2C44, (int*)&lbl_803DBCF8, -1) != 0)
        {
            ((BaddieState*)state)->controlFlags =
                ((BaddieState*)state)->controlFlags & ~(u64)BADDIE_CONTROL_PATH_FOLLOW;
        }
        sidekickToy_accelerateTowardTarget3D((GameObject*)(obj), base->posX, base->posY, base->posZ, lbl_803E2C48,
                                             lbl_803E2C4C, lbl_803E2C50, ((BaddieState*)state)->unk304);
    }

    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        CrawlerSeq12* sq = (CrawlerSeq12*)gCrawlerSeqTable;
        i = ((BaddieState*)state)->seqEntryIndex * 0xc;
        Baddie_SetMove((int*)obj, state, *(u8*)(gCrawlerSeqTable + i + 8), *(f32*)((int)gCrawlerSeqTable + i), 0, 0);
        ((BaddieState*)state)->seqEntryIndex = sq[((BaddieState*)state)->seqEntryIndex].next;
    }

    if (((FCVars*)state)->engineTimer > lbl_803E2C30)
    {
        ((FCVars*)state)->engineTimer = -(lbl_803E2C54 * timeDelta - ((FCVars*)state)->engineTimer);
        *(s16*)obj = ((FCVars*)state)->engineTimer * timeDelta + (f32)(int)*obj;
    }
    else
    {
        f32 ratio;
        ((FCVars*)state)->engineTimer = lbl_803E2C30;
        spd = lbl_803E2C3C - (((FCVars*)state)->emergeTimer - lbl_803E2C58) / lbl_803E2C5C;
        if (spd < lbl_803E2C60)
        {
            spd = lbl_803E2C60;
        }
        else if (spd > lbl_803E2C3C)
        {
            spd = lbl_803E2C3C;
        }
        if (((FCVars*)state)->emergeTimer > *(f32*)&lbl_803E2C58)
        {
            ((FCVars*)state)->emergeTimer -= timeDelta;
        }
        else
        {
            ((FCVars*)state)->emergeTimer = *(f32*)&lbl_803E2C58;
        }
        ratio = sqrtf(((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX +
                      ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ) /
                lbl_803E2C48;
        if (ratio < lbl_803E2C30)
        {
            ratio = lbl_803E2C30;
        }
        else if (ratio > lbl_803E2C3C)
        {
            ratio = lbl_803E2C3C;
        }
        {
            f32 t = lbl_803E2C64 * spd;
            ratio *= t * timeDelta;
        }
        ((GameObject*)obj)->anim.rotY = (f32)(int)((GameObject*)obj)->anim.rotY - ratio;
        fn_8014CD1C(obj, state, (int)((FCVars*)state)->emergeTimer, lbl_803E2C68 * spd, lbl_803E2C30, 1);
    }

    {
        f32 pw = powfBitEstimate(((BaddieState*)state)->unk304, timeDelta);
        ((GameObject*)obj)->anim.rotY = (f32)((GameObject*)obj)->anim.rotY * pw;
        pw = powfBitEstimate(((BaddieState*)state)->unk304, timeDelta);
        ((GameObject*)obj)->anim.rotZ = (f32)((GameObject*)obj)->anim.rotZ * pw;
    }

    if ((int)randomGetRange(0, 0x2ee) == 0)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_baddie_eba);
    }

    if (((FCVars*)state)->engineTimer > lbl_803E2C30)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_baddie_rach_death);
        {
            f32 t = ((FCVars*)state)->engineTimer;
            Sfx_SetObjectSfxVolumeU32IntLegacy((u32)obj, SFXTRIG_baddie_rach_death,
                                               (int)((gCrawlerSfxVolMax127 * t) / lbl_803E2C70),
                                               t / *(f32*)&lbl_803E2C70);
        }
    }
    else
    {
        Sfx_StopFromObject((int)obj, SFXTRIG_baddie_rach_death);
    }

    {
        s16 t;
        if (((FCVars*)state)->linkedObj != NULL &&
            ((t = ((GameObject*)((FCVars*)state)->linkedObj)->anim.seqId) == 0x1f || t == 0))
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_fball2_c);
        }
    }
}

void hagabonMK2_update(s16* obj, u8* state)
{
    RomCurveWalker* base = *(RomCurveWalker**)state;
    f32 d[3];
    CrawlerSfxParams sp;
    int i;
    f32 pw;

    if (((FCVars*)state)->linkedObj != NULL && ((FCVars*)state)->linkedObj == ((BaddieState*)state)->trackedObj)
    {
        *(u32*)&((BaddieState*)state)->unk2E4 |= 0x10000LL;
        ((FCVars*)state)->warpTimer = lbl_803E2C74;
    }
    ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x100;
    sp.x = lbl_803E2C30;
    sp.y = lbl_803E2C34;
    sp.z = lbl_803E2C30;
    sp.vol = lbl_803E2C24;
    sp.sfxId = 0x605;
    if ((((GameObject*)obj)->objectFlags & FIRECRAWLER_OBJFLAG_RENDERED) != 0)
    {
        (*gPartfxInterface)->spawnObject(obj, 1999, &sp, 2, -1, NULL);
        if (((FireCrawlerState*)state)->engineLight == NULL)
        {
            if (((FireCrawlerState*)state)->engineLight == NULL)
            {
                ((FireCrawlerState*)state)->engineLight = objCreateLight(NULL, 1);
            }
            if (((FireCrawlerState*)state)->engineLight != NULL)
            {
                modelLightStruct_setLightKind(((FireCrawlerState*)state)->engineLight, MODEL_LIGHT_KIND_POINT);
                modelLightStruct_setPosition(((FireCrawlerState*)state)->engineLight,
                                             ((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                             ((GameObject*)obj)->anim.localPosZ);
                modelLightStruct_setDiffuseColor(((FireCrawlerState*)state)->engineLight, 0xc0, 0x40, 0xff, 0xff);
                modelLightStruct_setSpecularColor(((FireCrawlerState*)state)->engineLight, 0xc0, 0x40, 0xff, 0xff);
                modelLightStruct_setDistanceAttenuation(((FireCrawlerState*)state)->engineLight, lbl_803E2C10,
                                                        lbl_803E2C14);
                lightSetField4D(((FireCrawlerState*)state)->engineLight, 1);
                modelLightStruct_setEnabled(((FireCrawlerState*)state)->engineLight, 1, lbl_803E2C18);
                modelLightStruct_startColorFade(((FireCrawlerState*)state)->engineLight, 0, 0);
                modelLightStruct_setAffectsAabbLightSelection(((FireCrawlerState*)state)->engineLight, 0);
            }
        }
        else
        {
            modelLightStruct_setPosition(((FireCrawlerState*)state)->engineLight, ((GameObject*)obj)->anim.localPosX,
                                         ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ);
        }
    }
    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_JUST_TRIGGERED) != 0)
    {
        ((BaddieState*)state)->seqEntryIndex = 3;
        ((BaddieState*)state)->controlFlags |= (u64)BADDIE_CONTROL_SEQUENCE_DRIVEN;
    }
    sidekickToy_accelerateTowardTarget3D(
        (GameObject*)(obj), ((GameObject*)((BaddieState*)state)->trackedObj)->anim.worldPosX,
        lbl_803E2C48 + ((GameObject*)((BaddieState*)state)->trackedObj)->anim.worldPosY,
        ((GameObject*)((BaddieState*)state)->trackedObj)->anim.worldPosZ, *(f32*)&lbl_803E2C48, lbl_803E2C78,
        lbl_803E2C50, ((BaddieState*)state)->unk304);
    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        i = ((BaddieState*)state)->seqEntryIndex * 0xc;
        Baddie_SetMove((int*)obj, state, *(u8*)(gCrawlerSeqTable + i + 8), *(f32*)((int)gCrawlerSeqTable + i), 0, 0);
        {
            CrawlerSeq12* sq = (CrawlerSeq12*)gCrawlerSeqTable;
            ((BaddieState*)state)->seqEntryIndex = sq[((BaddieState*)state)->seqEntryIndex].next;
        }
    }
    pw = powfBitEstimate(((BaddieState*)state)->unk304, timeDelta);
    ((GameObject*)obj)->anim.rotY = (f32)((GameObject*)obj)->anim.rotY * pw;
    pw = powfBitEstimate(((BaddieState*)state)->unk304, timeDelta);
    ((GameObject*)obj)->anim.rotZ = (f32)((GameObject*)obj)->anim.rotZ * pw;
    if (((FCVars*)state)->engineTimer < lbl_803E2C70)
    {
        ((FCVars*)state)->engineTimer = lbl_803E2C54 * timeDelta + ((FCVars*)state)->engineTimer;
    }
    else
    {
        ((FCVars*)state)->engineTimer = lbl_803E2C70;
    }
    *(s16*)obj = ((FCVars*)state)->engineTimer * timeDelta + (f32)(int)*obj;
    ((FCVars*)state)->emergeTimer = lbl_803E2C38;
    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_PATH_FOLLOW) != 0)
    {
        f32* dp = d;
        dp[0] = base->posX - ((GameObject*)obj)->anim.worldPosX;
        dp[1] = base->posY - ((GameObject*)obj)->anim.worldPosY;
        dp[2] = base->posZ - ((GameObject*)obj)->anim.worldPosZ;
        ((FCVars*)state)->distToCurve = sqrtf(dp[2] * dp[2] + (dp[0] * dp[0] + dp[1] * dp[1]));
        if (((FCVars*)state)->distToCurve > lbl_803E2C40)
        {
            *(u32*)&((BaddieState*)state)->unk2E4 |= 0x10000LL;
            ((FCVars*)state)->warpTimer = lbl_803E2C30;
        }
    }
    if (((FCVars*)state)->engineTimer > lbl_803E2C30)
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_baddie_rach_death);
        {
            f32 t = ((FCVars*)state)->engineTimer;
            Sfx_SetObjectSfxVolumeU32IntLegacy((u32)obj, SFXTRIG_baddie_rach_death,
                                               (int)((gCrawlerSfxVolMax127 * t) / lbl_803E2C70),
                                               t / *(f32*)&lbl_803E2C70);
        }
    }
    else
    {
        Sfx_StopFromObject((int)obj, SFXTRIG_baddie_rach_death);
    }
    if (((FCVars*)state)->linkedObj != NULL && (((GameObject*)((FCVars*)state)->linkedObj)->anim.seqId == 0x1f ||
                                                ((GameObject*)((FCVars*)state)->linkedObj)->anim.seqId == 0))
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_fball2_c);
    }
}

#pragma opt_common_subs off
void crawler_initTailModel(int* obj, int* st)
{
    u8* tab;
    ((BaddieState*)st)->speedScale = lbl_803E2C7C;
    *(u32*)&((BaddieState*)st)->unk2E4 = 0x405009;
    ((BaddieState*)st)->unk304 = lbl_803E2C80;
    *((u8*)st + 0x320) = 0;
    {
        f32 d1 = lbl_803E2C84;
        *(f32*)&((BaddieState*)st)->eventFlags = d1;
        *((u8*)st + 0x321) = 0;
        ((BaddieState*)st)->unk318 = lbl_803E2C3C;
        *((u8*)st + 0x322) = 0;
        ((BaddieState*)st)->unk31C = d1;
    }
    ((BaddieState*)st)->pathStep = ((BaddieState*)st)->pathStep * lbl_803E2C88;
    {
        f32* fbase = (f32*)gCrawlerSeqTable;
        u8* bbase = gCrawlerSeqTable;
        u32 idx = ((BaddieState*)st)->seqEntryIndex;
        u32 off = idx * 0xc;
        Baddie_SetMove(obj, st, bbase[off + 8], *(f32*)((char*)fbase + off), 0, 0);
    }
    ((FCVars*)st)->emergeTimer = lbl_803E2C58;
    ObjHits_SetHitVolumeMasks((ObjAnimComponent*)obj, 0xe, 1, 0xfff);
    ((FireCrawlerState*)st)->tailModelChain = ObjModelChain_Alloc(gCrawlerModelChainIds, 5);
    ObjModelChain_SetOrigin(((FireCrawlerState*)st)->tailModelChain, lbl_803E2C8C, lbl_803E2C90, lbl_803E2C94);
    ((BaddieState*)st)->reactionFlags = ((BaddieState*)st)->reactionFlags | 0x100;
    *(int*)((char*)obj + 0x108) = (int)&baddieAfterUpdateBonesCb;
}
#pragma opt_common_subs reset
