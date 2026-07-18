/*
 * snowworm - the snowworm baddie plus the shared crawler-family reaction and
 * variant helpers that live in the same original translation unit:
 *   fn_8015A52C                 per-frame body-segment placement helper.
 *   snowworm_updateWhileFrozen  freeze-event handler.
 *   crawler_playReactionEffects hit-reaction particle/sfx playback.
 *   snowworm_update             per-frame update: advances the curve walk and
 *                               drives the emerge/burrow timers.
 *   snowworm_applyReactionState applies the queued reaction to the actor.
 *   crawler_initVariant         seeds the per-variant scratch fields.
 *   whirlpool_updateWhileFrozen freeze-event stub.
 */
/*
 * firecrawler - state-handler TU for a group of class-0x1C ground/air enemies
 * in the enemy mega-DLL (0x0C9). (The SmallBasket container is the unrelated
 * DLL 0x104.) The enemies handled here were
 * identified from the retail OBJECTS.bin (object name at def+0x91) cross-
 * referenced with the dispatch in dll_00C9_enemy.c:
 *
 *   anim.seqId  enemy          handler(s)               shipped?
 *   0x6a2       FireCrawler    crawler_update/B/C        yes (dragrock, moonpass) - has firepipe
 *   0x6a3       RedEye         crawler_update/B/C        yes (wallcity)
 *   0x6a4       ShadowHunter   crawler_update/B/C        dynamic-only (e.g. Krazoa test)
 *   0x6a5       SwampStrider   crawler_update/B/C        dynamic-only
 *   0x4ac       HoodedZyck     hoodedZyck_update/B       dynamic-only
 *   0x7c8       HagabonMK2     hagabonMK2_update/B          yes
 *   0x842/0x84b snowworm(_baby) snowworm_update         yes
 *
 * The 0x6a2-0x6a5 crawler family shares one AI (crawler_initModelVariant sets
 * per-variant speed/health/model). Behaviour: follows ROM curve paths
 * (RomCurveWalker / gRomCurveInterface), tracks the player, reacts to hits
 * (crawler_onHit), FireCrawler spawns a linked "firepipe" projectile
 * (firecrawler_spawnFirepipe), and HagabonMK2 flies with a dynamic light +
 * looping engine SFX (0x3e8). Move/sequence sub-tables live at gCrawlerDescriptorTable
 * (CrawlerSeq12 / CrawlerSeq16 / CrawlerDescriptor). controlFlags bits
 * 0x80000000 (just-triggered) and 0x40000000 (active) gate the move dispatch.
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
#include "main/dll/snowworm.h"

typedef struct CrawlerModelChainList
{
    u8* modelIds;
    s32 count;
} CrawlerModelChainList;

STATIC_ASSERT(sizeof(CrawlerModelChainList) == 8);

extern u8 lbl_803DBD30[4];

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
extern u8* gCrawlerReactionTables[];

extern f32 lbl_803E2C98;
extern f32 lbl_803E2C9C;
extern f32 gCrawlerPi;
extern f32 gCrawlerHalfCircleBams;
extern f32 lbl_803E2CA8;
void fn_80157B58(int* obj, u8* state);

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


void fn_8015A52C(s16* obj)
{
    u8 locked = Obj_IsLoadingLocked();
    if (locked != 0)
    {
        int* setup = (int*)Obj_AllocObjectSetup(0x24, 0x51b);
        ((GameObject*)setup)->anim.rootMotionScale = ((GameObject*)obj)->anim.localPosX;
        ((GameObject*)setup)->anim.localPosX = lbl_803E2C98 + ((GameObject*)obj)->anim.localPosY;
        ((GameObject*)setup)->anim.localPosY = ((GameObject*)obj)->anim.localPosZ;
        ((ObjPlacement*)setup)->color[0] = 1;
        ((ObjPlacement*)setup)->color[1] = 4;
        ((ObjPlacement*)setup)->color[3] = 0xff;
        setup = (int*)Obj_SetupObject((ObjPlacement*)setup, 5, -1, -1, 0);
        if (setup != NULL)
        {
            ((GameObject*)setup)->anim.velocityX =
                lbl_803E2C9C * -mathSinf((gCrawlerPi * (f32)*obj) / gCrawlerHalfCircleBams);
            ((GameObject*)setup)->anim.velocityY = lbl_803E2CA8;
            ((GameObject*)setup)->anim.velocityZ =
                lbl_803E2C9C * -mathCosf((gCrawlerPi * (f32)*obj) / gCrawlerHalfCircleBams);
        }
    }
}


void snowworm_updateWhileFrozen(int obj, int* st, int p3, int cmd, int p5, int sub, void* wpad0, int wpad1)
{
    u8* base;
    u32 r;

    {
        u8* bbase;
        u32 idx;
        bbase = (u8*)gCrawlerReactionTables;
        idx = ((FCVars*)st)->turnDelta;
        bbase = bbase + idx * 8;
        base = *(u8**)(bbase + 4);
    }

    if (cmd == 0x11)
    {
        return;
    }
    if (cmd == 0x10)
    {
        ((BaddieState*)st)->reactionFlags |= 0x20;
        return;
    }
    if (((FCVars*)st)->moveTableIndex > 3)
    {
        Baddie_SetMove((int*)obj, st, 6, 0.5f, 0, 0);
    }
    else
    {
        Baddie_SetMove((int*)obj, st, 5, 0.5f, 0, 0);
    }
    r = randomGetRange(0, 3);
    ((BaddieState*)st)->userData1 = base[r];
    ((BaddieState*)st)->reactionFlags |= 0x8;
    if (sub > (int)((BaddieState*)st)->hitCounter)
    {
        ((BaddieState*)st)->hitCounter = 0;
    }
    else
    {
        ((BaddieState*)st)->hitCounter = (u16)(((BaddieState*)st)->hitCounter - sub);
    }
    if (((BaddieState*)st)->hitCounter == 0)
    {
        Sfx_PlayFromObject(obj, SFXTRIG_baddie_eggsnatch_carry2);
    }
    if (cmd == 0x1a)
        return;
    Sfx_PlayFromObject(obj, SFXTRIG_stftest);
}

void crawler_playReactionEffects(int* obj, int* st)
{
    u16 flag = 0;
    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 2:
        if (((FCVars*)st)->moveEventMask != 0)
        {
            Sfx_PlayFromObjectLimited((u32)obj, SFXTRIG_baddie_blooplaugh3, 2);
        }
        flag = 1;
        break;
    case 3:
        if (((FCVars*)st)->moveEventMask != 0)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_baddie_haga_death);
        }
        break;
    case 4:
        if (((FCVars*)st)->moveEventMask != 0)
        {
            if (((GameObject*)obj)->anim.currentMoveProgress < 0.15f)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_baddie_blooplaugh1);
            }
            else
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_baddie_rach_call1);
            }
        }
        break;
    case 5:
        if (((FCVars*)st)->moveEventMask != 0)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_baddie_eggsnatch);
        }
        break;
    case 6:
        if (((FCVars*)st)->moveEventMask != 0)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_baddie_eggsnatch);
        }
        break;
    case 7:
        if (((FCVars*)st)->moveEventMask != 0)
        {
            Sfx_PlayFromObjectLimited((u32)obj, SFXTRIG_baddie_eggsnatch_movelp, 2);
        }
        flag = 1;
        break;
    case 9:
        if (((FCVars*)st)->moveEventMask != 0)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_baddie_blooplaugh2);
        }
        break;
    }
    if (flag != 0)
    {
        if (((FCVars*)st)->turnDelta != 0)
        {
            (*gPartfxInterface)->spawnObject(obj, FIRECRAWLER_PARTFX_MOVE_TURN, NULL, 2, -1, NULL);
        }
        else
        {
            (*gPartfxInterface)->spawnObject(obj, FIRECRAWLER_PARTFX_MOVE_STRAIGHT, NULL, 2, -1, NULL);
        }
    }
}

void snowworm_update(int* obj, u8* state)
{
    u8* tbl = *(u8**)((char*)gCrawlerReactionTables + ((FCVars*)state)->turnDelta * 8);
    int i;

    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumePriority = 10;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumeId = 1;
    if (((GameObject*)obj)->anim.currentMove == 0)
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED;
        ObjHits_DisableObject((GameObject*)obj);
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode =
            *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED;
        ObjHits_EnableObject((GameObject*)obj);
    }

    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_JUST_TRIGGERED) != 0 &&
        ((BaddieState*)state)->userData1 <= 1)
    {
        if (((FCVars*)state)->turnDelta != 0 || (int)randomGetRange(0, 0x14) < 10)
        {
            ((BaddieState*)state)->userData1 = 1;
        }
        else
        {
            ((BaddieState*)state)->userData1 = 7;
        }
        ((BaddieState*)state)->controlFlags |= (u64)BADDIE_CONTROL_SEQUENCE_DRIVEN;
    }

    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        *(char*)&((BaddieState*)state)->userData1 += 1;
        if (((BaddieState*)state)->userData1 > gSnowwormSeqIndexMax[((FCVars*)state)->turnDelta])
        {
            ((BaddieState*)state)->userData1 = gSnowwormSeqIndexReset[((FCVars*)state)->turnDelta];
        }
        if (((FCVars*)state)->moveTableIndex < 4)
        {
            i = ((BaddieState*)state)->userData1 * 0xc;
            Baddie_SetMove(obj, state, (tbl + i)[8], *(f32*)((int)tbl + i), 0, 0);
        }
        else
        {
            i = ((BaddieState*)state)->userData1 * 0xc;
            Baddie_SetMove(obj, state, (tbl + i)[9], *(f32*)((int)tbl + i), 0, 0);
        }
        if (((GameObject*)obj)->anim.currentMove == 9)
        {
            fn_8015A52C((s16*)obj);
        }
        else if (((GameObject*)obj)->anim.currentMove == 1)
        {
            int r = randomGetRange(0, ((BaddieState*)state)->userData2);
            s16 a = randomGetRange(-0x8000, 0x7fff);
            f32 angle = (gCrawlerPi * a) / gCrawlerHalfCircleBams;
            ((GameObject*)obj)->anim.localPosX =
                r * mathSinf(angle) + *(f32*)(*(int*)&((GameObject*)obj)->anim.placementData + 8);
            ((GameObject*)obj)->anim.localPosZ =
                r * mathCosf(angle) + ((GameObject*)((GameObject*)obj)->anim.placementData)->anim.localPosY;
            baddieTurnTowardPoint((GameObject*)obj, (int)state, ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosX,
                        ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosZ, 1, 0);
        }
    }

    baddieTurnTowardPoint((GameObject*)obj, (int)state, ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosX,
                ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosZ,
                lbl_803DBD30[((FCVars*)state)->turnDelta], 0);
    crawler_playReactionEffects(obj, (int*)state);
}

void snowworm_applyReactionState(int* obj, int* st)
{
    u8* t1 = *(u8**)((char*)gCrawlerReactionTables + ((FCVars*)st)->turnDelta * 8);
    *((u8*)obj + 0xaf) = (u8)(*((u8*)obj + 0xaf) | 0x8);
    if ((((BaddieState*)st)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        s16 a = ((GameObject*)obj)->anim.currentMove;
        if (a == 7)
        {
            ((BaddieState*)st)->userData1 = 1;
        }
        else if (a != 0)
        {
            ((BaddieState*)st)->userData1 = 0;
        }
        {
            u8* bbase = t1;
            f32* fbase = (f32*)t1;
            u32 idx2 = ((BaddieState*)st)->userData1;
            u32 off = idx2 * 0xc;
            Baddie_SetMove(obj, st, bbase[off + 8], *(f32*)((char*)fbase + off), 0, 0);
        }
    }
    crawler_playReactionEffects(obj, st);
}

void crawler_initVariant(int* obj, int* st)
{
    ((BaddieState*)st)->speedScale = 60.0f;
    /* 0x33b: crawler variant selector (shares slot with BaddieState.userData2);
     * kept raw - single site, member spelling off u8* st is byte-risky. */
    *((u8*)st + 0x33b) = ((BaddieState*)st)->unk2A8;
    ((BaddieState*)st)->unk2A8 = 160.0f;
    *(u32*)&((BaddieState*)st)->unk2E4 = 0x42003;
    ((BaddieState*)st)->unk308 = 0.01f;
    ((BaddieState*)st)->animDeltaScale = 0.006f;
    ((BaddieState*)st)->unk304 = 0.95f;
    *((u8*)st + 0x320) = 0;
    {
        f32 d = 1.0f;
        *(f32*)&((BaddieState*)st)->eventFlags = d;
        *((u8*)st + 0x321) = 0xa;
        ((BaddieState*)st)->unk318 = d;
        *((u8*)st + 0x322) = 7;
        ((BaddieState*)st)->unk31C = d;
    }
    ((BaddieState*)st)->userData1 = 1;
    ((FCVars*)st)->turnDelta = (u16)(((GameObject*)obj)->anim.seqId == 0x84b);
}

void whirlpool_updateWhileFrozen(int wpad0, void* wpad1, int wpad2, int wpad3, int wpad4, int wpad5, void* wpad6, int wpad7)
{
}
