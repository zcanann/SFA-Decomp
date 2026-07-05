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
#include "main/camera_interface.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/model.h"
#include "main/gamebits.h"
#include "main/dll/baddie_state.h"
#include "main/dll/baddie_setmove.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/effect_interfaces.h"
#include "main/objhits.h"
#include "main/dll/modgfx.h"
#include "main/sfa_extern_decls.h"
#include "main/dll/firecrawler.h"
#include "main/dll/objfsa.h"
#include "main/audio/sfx_trigger_ids.h"
#define FIRECRAWLER_OBJFLAG_RENDERED 0x800
#define FIRECRAWLER_OBJFLAG_PARENT_SLACK 0x1000

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
extern int ObjGroup_FindNearestObject();
extern u32 ObjLink_AttachChild();
extern u64 ObjPath_GetPointWorldPosition();
extern int Obj_GetYawDeltaToObject();
extern f32 lbl_803E2CC0;
extern f32 lbl_803E2CC4;
extern f32 lbl_803E2CC8;
extern f32 lbl_803E2CCC;
extern f32 lbl_803E2CD0;
extern f32 lbl_803E2CD4;
extern u8 Obj_IsLoadingLocked(void);
extern void* Obj_AllocObjectSetup(int size, int b);
extern int* Obj_SetupObject(int* obj, int p1, int p2, int p3, int p4);
extern void firepipe_setLinkedUpdateFlag(int* obj);
extern void firepipe_clearLinkedUpdateFlag(int);
extern f32 lbl_803E2B18;
extern f32 lbl_803E2B38;
extern f32 lbl_803E2B40;
extern f32 lbl_803E2B4C;
extern f32 lbl_803E2B64;
extern f32 lbl_803E2B68;
extern f32 lbl_803E2B6C;
extern f32 lbl_803E2B70;
extern f32 lbl_803E2B74;
extern f32 lbl_803E2B78;
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
extern f32 lbl_803E2CBC;
extern u8* gCrawlerReactionTables[];

extern f32 lbl_803E2CB8;
extern f32 lbl_803E2C1C;
extern f32 lbl_803E2C20;
extern f32 lbl_803E2C24;
extern float fn_802943F4(float x);
extern void PSMTXRotRad(f32* mtx, int axis, f32 angle);
extern void PSMTXMultVecSR(f32 * mtx, f32 * in, f32 * out);
extern f32 lbl_803E2BB8;
extern f32 lbl_803E2BD4;
extern f32 lbl_803E2BE4;
extern const f32 lbl_803E2BE8;
extern f32 lbl_803E2BEC;
extern f32 lbl_803E2BF0;
extern f32 lbl_803E2BF4;
extern f32 lbl_803E2BF8;
extern f32 lbl_803E2BFC;
extern f32 lbl_803E2C00;
extern f32 lbl_803E2C04;
extern f32 lbl_803E2C08;
extern f32 gCrawlerS8Norm127;
extern int fn_8014C11C(int obj, f32 dist, u8 flag, int maxCount, void* buf);
extern int gCrawlerNearbyObjectBuffer[];
extern f32 lbl_803E2B80;
extern float mathSinf(float x);
extern float mathCosf(float x);
extern f32 lbl_803E2C98;
extern f32 lbl_803E2C9C;
extern f32 gCrawlerPi;
extern f32 gCrawlerHalfCircleBams;
extern f32 lbl_803E2CA8;
extern f32 lbl_803E2B84;
extern f32 lbl_803E2B88;
extern void fn_8014CF7C(int* obj, u8* state, f32 x, f32 z, int p5, int p6);
extern u8 gSnowwormSeqIndexReset[4];
extern u8 gSnowwormSeqIndexMax[4];
extern u8 lbl_803DBD30[4];
extern int getAngle(float y, float x);
extern f32 timeDelta;
extern f32 lbl_803E2B2C;
extern f32 lbl_803E2B28;
extern f32 lbl_803E2B34;
extern f32 lbl_803E2B30;
extern f32 lbl_803E2B44;
extern f32 lbl_803E2B60;
extern f32 lbl_803DBCE0;
extern f32 lbl_803DBCE4;
extern f32 lbl_803DBCEC;

extern f32 lbl_803E2BA8;
extern int objCreateLight(int a, int b);
extern void modelLightStruct_setLightKind();
extern void modelLightStruct_setPosition();
extern void modelLightStruct_setDiffuseColor();
extern void modelLightStruct_setSpecularColor();
extern void modelLightStruct_setDistanceAttenuation();
extern void lightSetField4D();
extern void modelLightStruct_setEnabled();
extern void modelLightStruct_startColorFade();
extern void modelLightStruct_setAffectsAabbLightSelection();
extern void sidekickToy_accelerateTowardTarget3D(s16* obj, f32 x, f32 y, f32 z, f32 a, f32 b, f32 c, f32 spd);
extern float powfBitEstimate(float x, float y);
extern f32 sqrtf(f32 x);
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
extern int objBboxFn_800640cc(f32* from, f32* to, f32 h, int n, void* buf, s16* obj, u8 p7, int p8, int p9, int p10);
extern int fn_80295C88(void* player);
extern void* Obj_GetPlayerObject(void);
extern f32 lbl_803E2B3C;
extern f32 lbl_803E2B48;
extern f32 lbl_803E2B50;
extern f32 lbl_803DBCE8;
extern f32 gCrawlerHitSfxTimer;
extern f32 lbl_803E2BAC;
extern f32 lbl_803E2BB0;
extern f32 lbl_803E2BB4;
extern char lbl_803DBCF0;

extern u8 gCrawlerSpeedThresholds[];
extern f32 lbl_803E2BA0;
extern f32 lbl_803E2BA4;
extern f32 lbl_803E2BBC;
extern f32 lbl_803E2BC0;
extern f32 lbl_803E2BC4;
extern f32 lbl_803E2BC8;
extern f32 lbl_803E2BCC;
extern f32 lbl_803E2BD0;
extern f32 lbl_803E2BD8;
extern f32 lbl_803E2BDC;
extern f32 lbl_803E2BE0;
extern f32 lbl_803E2C44;
extern f32 lbl_803E2C4C;
extern f32 lbl_803E2C5C;
extern f32 lbl_803E2C60;
extern f32 lbl_803E2C64;
extern f32 lbl_803E2C68;
extern char lbl_803DBCF8;
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
typedef struct FCVars {
    u8 pad000[0x2a0];
    u16 moveTableIndex; /* 0x2a0: reaction/move sub-table index (*0xc stride) */
    u8 pad2a2[0x2a4 - 0x2a2];
    u16 projectileTimer;/* 0x2a4: firepipe launch timing counter (>=0x50 gate) */
    u8 pad2a6[0x2ec - 0x2a6];
    u16 hitCountScalar; /* 0x2ec: hit-count scalar folded into emergeTimer */
    u8 pad2ee[0x2f1 - 0x2ee];
    u8 hitConfigFlags;  /* 0x2f1: bit 0x40 = group-0 hit-immunity config */
    u8 pad2f2[0x2f8 - 0x2f2];
    u16 moveEventMask;  /* 0x2f8: per-frame move-progress event bitmask (bit 1<<i) */
    u8 pad2fa[0x310 - 0x2fa];
    f32 pathSpeed;      /* 0x310: per-frame curve-advance speed */
    u8 pad314[0x323 - 0x314];
    u8 moveStartFlags;  /* 0x323: bit 8 = move suppresses target-facing */
    f32 engineTimer;    /* 0x324: engine-sfx / spin-down timer (dt-decremented) */
    f32 emergeTimer;    /* 0x328: emerge/burrow fade timer */
    f32 distToCurve;    /* 0x32c: distance from object to its curve point */
    f32 warpTimer;      /* 0x330: HagabonMK2 warp/teleport cooldown timer */
    u8 pad334[0x338 - 0x334];
    u16 turnDelta;      /* 0x338: signed turn amount / variant index (dual use) */
    u8 pad33a[0x33c - 0x33a];
    u8 flagsC;          /* 0x33c: bit1 hitVolumeIndex, bit4 invuln */
    u8 flagsD;          /* 0x33d: move/link state bits (0x8/0x10/0x18/0x20/0x30/0x40) */
    u8 moveChainIndex;  /* 0x33e: index into the chained-move table (tbl4) */
    u8 reactStep;       /* 0x33f: reaction/hit sequence step (indexes seq/CrawlerSeq16) */
    void *linkedObj;    /* 0x340: linked/tracked object pointer (HagabonMK2, hoodedZyck) */
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

void crawler_nop(void)
{
}

void hagabonMK2_stopLoopSfx(int x) { Sfx_StopFromObject(x, SFXTRIG_baddie_rach_death); }

void firecrawler_spawnFirepipe(int* obj)
{
    int* child;
    if (Obj_IsLoadingLocked() != 0)
    {
        child = Obj_AllocObjectSetup(0x24, 0x710);
        ObjPath_GetPointWorldPosition(obj, 0, (char*)child + 0x8, (char*)child + 0xc, (char*)child + 0x10, 0);
        ((FirepipeSetup*)child)->head.color[0] = 1;
        ((FirepipeSetup*)child)->head.color[1] = 4;
        ((FirepipeSetup*)child)->head.color[2] = 0xff;
        ((FirepipeSetup*)child)->head.color[3] = 0xff;
        ((FirepipeSetup*)child)->unk18 = 0;
        ((FirepipeSetup*)child)->unk19 = 0;
        ((FirepipeSetup*)child)->unk1A = 0;
        ((FirepipeSetup*)child)->unk1C = 0xa;
        ((FirepipeSetup*)child)->unk1E = 0;
        ((FirepipeSetup*)child)->unk20 = 0;
        ((FirepipeSetup*)child)->unk22 = 3;
        ((FirepipeSetup*)child)->unk23 = 0;
        child = Obj_SetupObject(child, 5, -1, -1, 0);
        if (child != 0)
        {
            ObjLink_AttachChild(obj, child, 0);
            firepipe_setLinkedUpdateFlag(child);
            ((GameObject*)child)->anim.flags = (s16)(((GameObject*)child)->anim.flags | OBJANIM_FLAG_HIDDEN);
        }
    }
}

void crawler_handleReactionEvent(int obj, int* st, int p3, int cmd, int p5, int sub)
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
        Baddie_SetMove((int*)obj, st, 6, lbl_803E2CB8, 0, 0);
    }
    else
    {
        Baddie_SetMove((int*)obj, st, 5, lbl_803E2CB8, 0, 0);
    }
    r = randomGetRange(0, 3);
    ((BaddieState*)st)->seqEntryIndex = base[r];
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
    if (cmd == 0x1a) return;
    Sfx_PlayFromObject(obj, SFXen_blkscrp6);
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
            ((BaddieState*)st)->seqEntryIndex = 1;
        }
        else if (a != 0)
        {
            ((BaddieState*)st)->seqEntryIndex = 0;
        }
        {
            u8* bbase = t1;
            f32* fbase = (f32*)t1;
            u32 idx2 = ((BaddieState*)st)->seqEntryIndex;
            u32 off = idx2 * 0xc;
            Baddie_SetMove(obj, st, bbase[off + 8],
                        *(f32*)((char*)fbase + off), 0, 0);
        }
    }
    crawler_playReactionEffects(obj, st);
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
            if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2CBC)
            {
                Sfx_PlayFromObject((int)obj, SFXTRIG_baddie_blooplaugh1);
            }
            else
            {
                Sfx_PlayFromObject((int)obj, SFXfox_fightbreath4);
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
            (*gPartfxInterface)->spawnObject(obj, 0x802, NULL, 2, -1, NULL);
        }
        else
        {
            (*gPartfxInterface)->spawnObject(obj, 0x809, NULL, 2, -1, NULL);
        }
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
        Baddie_SetMove(obj, st, bbase[off + 8],
                    *(f32*)((char*)fbase + off), 0, 0);
    }
    ((FCVars*)st)->emergeTimer = lbl_803E2C58;
    ObjHits_SetHitVolumeMasks((int)obj, 0xe, 1, 0xfff);
    ((FireCrawlerState*)st)->tailModelChain = ObjModelChain_Alloc(gCrawlerModelChainIds, 5);
    ObjModelChain_SetOrigin(((FireCrawlerState*)st)->tailModelChain, lbl_803E2C8C, lbl_803E2C90, lbl_803E2C94);
    ((BaddieState*)st)->reactionFlags = ((BaddieState*)st)->reactionFlags | 0x100;
    *(int*)((char*)obj + 0x108) = (int)&baddieAfterUpdateBonesCb;
}
#pragma opt_common_subs reset


void crawler_initScaledVariant(int* obj, int* st)
{
    f32 ratio;
    f32 base_v;
    u32 v;
    u32 amt;
    amt = *((u8*)((int*)*(int*)&((GameObject*)obj)->anim.placementData) + 0x2f);
    ratio = amt;
    if (lbl_803E2B18 == amt)
    {
        ratio = lbl_803E2B38;
    }
    ratio = ratio / lbl_803E2B38;
    ((BaddieState*)st)->speedScale = lbl_803E2B64;
    *(u32*)&((BaddieState*)st)->unk2E4 = 0x8b;
    v = *(u32*)&((BaddieState*)st)->unk2E4;
    *(u32*)&((BaddieState*)st)->unk2E4 = v | 0x20;
    ((BaddieState*)st)->unk308 = lbl_803E2B68 * ratio;
    base_v = lbl_803E2B40;
    ((BaddieState*)st)->animDeltaScale = base_v;
    ((BaddieState*)st)->unk304 = lbl_803E2B6C;
    *((u8*)st + 0x320) = 0;
    *(f32*)&((BaddieState*)st)->eventFlags = lbl_803E2B70;
    *((u8*)st + 0x321) = 3;
    {
        f32 d2 = lbl_803E2B4C;
        ((BaddieState*)st)->unk318 = d2;
        *((u8*)st + 0x322) = 5;
        ((BaddieState*)st)->unk31C = d2;
    }
    ((FCVars*)st)->turnDelta = 0;
    ((FCVars*)st)->engineTimer = lbl_803E2B74;
    ((FCVars*)st)->emergeTimer = base_v;
    ((GameObject*)obj)->anim.alpha = 0;
    ((BaddieState*)st)->pathStep = lbl_803E2B78 * ratio;
    ((BaddieState*)st)->reactionFlags = 0;
    ObjHits_EnableObject((int)obj);
}

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

void crawler_handleHitStateEvent(int obj, int* st, int unused, int cmd)
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

void crawler_initVariant(int* obj, int* st)
{
    ((BaddieState*)st)->speedScale = lbl_803E2CC0;
    /* 0x33b: crawler variant selector (shares slot with BaddieState.inWhirlpoolGroup);
     * kept raw - single site, member spelling off u8* st is byte-risky. */
    *((u8*)st + 0x33b) = ((BaddieState*)st)->unk2A8;
    ((BaddieState*)st)->unk2A8 = lbl_803E2CC4;
    *(u32*)&((BaddieState*)st)->unk2E4 = 0x42003;
    ((BaddieState*)st)->unk308 = lbl_803E2CC8;
    ((BaddieState*)st)->animDeltaScale = lbl_803E2CCC;
    ((BaddieState*)st)->unk304 = lbl_803E2CD0;
    *((u8*)st + 0x320) = 0;
    {
        f32 d = lbl_803E2CD4;
        *(f32*)&((BaddieState*)st)->eventFlags = d;
        *((u8*)st + 0x321) = 0xa;
        ((BaddieState*)st)->unk318 = d;
        *((u8*)st + 0x322) = 7;
        ((BaddieState*)st)->unk31C = d;
    }
    ((BaddieState*)st)->seqEntryIndex = 1;
    ((FCVars*)st)->turnDelta = (u16)(((GameObject*)obj)->anim.seqId == 0x84b);
}

void fn_80157CDC(int obj, int state)
{
    extern void CameraShake_ApplyRadial(f32, f32, f32, f32, f32);
    extern f32 Vec_distance(int, int);
    extern void doRumble(f32 duration);
    extern void firecrawler_spawnFirepipe(int, int);
    extern void fn_80157B58(int, int);
    extern void firepipe_setLinkedUpdateFlag(int);
    extern f32 lbl_803E2BA0;
    extern f32 lbl_803E2BA4;
    typedef struct
    {
        u8 pad[4];
        u32 sfxId;   /* 0x4 */
        u8 pad2;
        u8 shakeAmt; /* 0x9 */
        u8 rumbleAmt;/* 0xa */
        u8 flags;    /* 0xb */
    } CrawlerSubDesc;
    typedef struct
    {
        u8 pad[0x1c];
        CrawlerSubDesc* p;
    } CrawlerDescE;
    CrawlerDescE* d = (CrawlerDescE*)gCrawlerDescriptorTable;
    CrawlerSubDesc* entry = d[((BaddieState*)state)->inWhirlpoolGroup].p;
    u8 i;

    gCrawlerHitSfxTimer = gCrawlerHitSfxTimer - timeDelta;

    for (i = 0; i <= 12; i++)
    {
        if ((((FCVars*)state)->moveEventMask & (1 << i)) != 0)
        {
            CrawlerSubDesc* sub = &entry[i];
            if (sub->sfxId != 0)
            {
                Sfx_PlayFromObject(obj, (u16)sub->sfxId);
            }
            if (sub->shakeAmt != 0)
            {
                CameraShake_ApplyRadial(((GameObject*)obj)->anim.localPosX, ((GameObject*)obj)->anim.localPosY,
                                        ((GameObject*)obj)->anim.localPosZ, lbl_803E2BA0, (f32)(u32)sub->shakeAmt);
            }
            if (sub->rumbleAmt != 0)
            {
                void* player = Obj_GetPlayerObject();
                if ((((GameObject*)player)->objectFlags & FIRECRAWLER_OBJFLAG_PARENT_SLACK) == 0)
                {
                    f32 dist = Vec_distance(obj + 0x18, (int)player + 0x18);
                    if (dist <= lbl_803E2B80)
                    {
                        f32 amt = lbl_803E2BA4 - dist / lbl_803E2B80;
                        doRumble(amt * (f32)(u32)sub->rumbleAmt);
                    }
                }
            }
            if (sub->flags != 0)
            {
                if ((sub->flags & 1) != 0)
                {
                    ((FCVars*)state)->flagsD = (u8)(((FCVars*)state)->flagsD ^ 0x40);
                    if ((((FCVars*)state)->flagsD & 0x40) != 0)
                    {
                        if (((GameObject*)obj)->childObjs[0] == NULL)
                        {
                            firecrawler_spawnFirepipe(obj, state);
                        }
                        else
                        {
                            firepipe_setLinkedUpdateFlag(*(int*)&((GameObject*)obj)->childObjs[0]);
                        }
                    }
                    else if (((GameObject*)obj)->childObjs[0] != NULL)
                    {
                        firepipe_clearLinkedUpdateFlag(*(int*)&((GameObject*)obj)->childObjs[0]);
                    }
                }
                if ((sub->flags & 2) != 0)
                {
                    fn_80157B58(obj, state);
                }
            }
        }
    }
}

/* crawler_initModelVariant: crawler-family variant init. Dispatches on obj->modelType
 * (offset 0x46): values 0x6a2/0x6a3/0x6a4 each pick a different float +
 * byte tuple to seed state[0x2a8..0x322]. The trailing block sets
 * shared state floats and computes obj[0x8] from params[0x28]. */
void crawler_initModelVariant(s16* obj, u8* state)
{
    u8* params = *(u8**)&((GameObject*)obj)->anim.placementData;
    *(u32*)&((BaddieState*)state)->unk2E4 = 0xb;
    *(u32*)&((BaddieState*)state)->unk2E4 |= 0x400b0LL;
    *(u32*)&((BaddieState*)state)->unk2E4 |= 0x40001040LL;
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x6a3:
        ((BaddieState*)state)->speedScale = lbl_803E2BE4;
        ((BaddieState*)state)->unk2A8 = lbl_803E2BB8;
        ((BaddieState*)state)->hitCounter = 0x1e;
        state[0x33b] = 0;
        state[0x320] = 9;
        *(f32*)&((BaddieState*)state)->eventFlags = lbl_803E2BE8;
        state[0x321] = 0xc;
        ((BaddieState*)state)->unk318 = lbl_803E2BEC;
        state[0x322] = 9;
        ((BaddieState*)state)->unk31C = lbl_803E2BE8;
        *(u32*)&((BaddieState*)state)->unk2E4 |= 0x400;
        break;
    case 0x6a2:
        ((BaddieState*)state)->speedScale = lbl_803E2BF0;
        ((BaddieState*)state)->unk2A8 = lbl_803E2BB8;
        ((BaddieState*)state)->hitCounter = 0x32;
        state[0x33b] = 1;
        state[0x320] = 0xe;
        *(f32*)&((BaddieState*)state)->eventFlags = lbl_803E2BE8;
        state[0x321] = 0xd;
        ((BaddieState*)state)->unk318 = lbl_803E2BEC;
        state[0x322] = 0xe;
        ((BaddieState*)state)->unk31C = lbl_803E2BE8;
        *(u32*)&((BaddieState*)state)->unk2E4 |= 0xc00;
        break;
    case 0x6a4:
        ((BaddieState*)state)->speedScale = lbl_803E2BF4;
        ((BaddieState*)state)->unk2A8 = lbl_803E2BF8;
        ((BaddieState*)state)->hitCounter = 0xf;
        state[0x33b] = 2;
        state[0x320] = 0xd;
        *(f32*)&((BaddieState*)state)->eventFlags = lbl_803E2BE8;
        state[0x321] = 0x10;
        ((BaddieState*)state)->unk318 = lbl_803E2BEC;
        state[0x322] = 0xd;
        ((BaddieState*)state)->unk31C = lbl_803E2BE8;
        *(u32*)&((BaddieState*)state)->unk2E4 |= 0xc00;
        break;
    }
    *(f32*)(state + 0x308) = lbl_803E2BD4;
    ((BaddieState*)state)->animDeltaScale = lbl_803E2BFC;
    ((BaddieState*)state)->unk304 = lbl_803E2C00;
    ((BaddieState*)state)->pathStep = ((BaddieState*)state)->pathStep * lbl_803E2C04;
    if ((s8)params[0x2e] != -1)
    {
        ((BaddieState*)state)->controlFlags |= 1;
    }
    ((GameObject*)obj)->anim.rootMotionScale = lbl_803E2C08 + ((f32)(s32)(s8)params[0x28] / gCrawlerS8Norm127);
}

/* Nearby-object scan. Asks fn_8014C11C for up to 40 objects
 * within lbl_803E2B80, walks the result array of (obj, ?) pairs, and if
 * any entry's modelType is 0x6a3 with state[0x2dc] bit 0x20000000 set
 * AND bits 0x1800 clear, latches "found" and exits. If nothing matched,
 * loads the default triggered camera action. */
#pragma dont_inline on
void crawler_checkNearbyActive(int obj, u8* state)
{
    u8 count = fn_8014C11C(obj, lbl_803E2B80, 0, 0x28, gCrawlerNearbyObjectBuffer);
    u8 noMatch = 1;
    if (count >= 1)
    {
        u8 i;
        for (i = 0; i < count; i++)
        {
            u32 objectIndex = (u8)i;
            int e = gCrawlerNearbyObjectBuffer[objectIndex * 2];
            if (((GameObject*)e)->anim.seqId == 0x6a3)
            {
                u32 flags = *(u32*)((char*)((GameObject*)e)->extra + 0x2dc);
                if ((flags & 0x20000000) != 0 && (flags & 0x1800) == 0)
                {
                    i = count;
                    noMatch = 0;
                }
            }
        }
    }
    if (noMatch != 0)
    {
        (*gCameraInterface)->loadTriggeredCamAction(0, 0, 0);
    }
}
#pragma dont_inline reset

#pragma dont_inline on
void fn_8015A52C(s16* obj)
{
    u8 locked = Obj_IsLoadingLocked();
    if (locked != 0)
    {
        int* setup = Obj_AllocObjectSetup(0x24, 0x51b);
        ((GameObject*)setup)->anim.rootMotionScale = ((GameObject*)obj)->anim.localPosX;
        ((GameObject*)setup)->anim.localPosX = lbl_803E2C98 + ((GameObject*)obj)->anim.localPosY;
        ((GameObject*)setup)->anim.localPosY = ((GameObject*)obj)->anim.localPosZ;
        ((ObjPlacement*)setup)->color[0] = 1;
        ((ObjPlacement*)setup)->color[1] = 4;
        ((ObjPlacement*)setup)->color[3] = 0xff;
        setup = Obj_SetupObject(setup, 5, -1, -1, 0);
        if (setup != NULL)
        {
            ((GameObject*)setup)->anim.velocityX = lbl_803E2C9C * -mathSinf(
                (gCrawlerPi * (f32) * obj) / gCrawlerHalfCircleBams);
            ((GameObject*)setup)->anim.velocityY = lbl_803E2CA8;
            ((GameObject*)setup)->anim.velocityZ = lbl_803E2C9C * -mathCosf(
                (gCrawlerPi * (f32) * obj) / gCrawlerHalfCircleBams);
        }
    }
}
#pragma dont_inline reset

void fn_80157B58(int* obj, u8* state)
{
    u8 locked = Obj_IsLoadingLocked();
    if (locked != 0)
    {
        int child;
        int setup = (int)Obj_AllocObjectSetup(0x24, 0x869);
        ObjPath_GetPointWorldPosition(obj, 0, setup + 8, setup + 0xc, setup + 0x10, 0);
        ((ObjPlacement*)setup)->color[0] = 1;
        ((ObjPlacement*)setup)->color[1] = 4;
        ((ObjPlacement*)setup)->color[2] = 0xff;
        ((ObjPlacement*)setup)->color[3] = 0xff;
        child = (int)Obj_SetupObject((int*)setup, 5, -1, -1, 0);
        if ((u32)child != 0)
        {
            f32 dur = lbl_803E2B84 * ((f32) ((FCVars*)state)->projectileTimer / ((BaddieState*)state)->unk2A8);
            ((GameObject*)child)->anim.velocityX =
                (((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosX - ((GameObject*)setup)->anim.rootMotionScale)
                / dur;
            ((GameObject*)child)->anim.velocityY =
                ((lbl_803E2B88 + ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosY + (f32)(int)
            randomGetRange(-10, 10)
            )
            -((GameObject*)setup)->anim.localPosX
            )
            /
            dur;
            ((GameObject*)child)->anim.velocityZ =
                (((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosZ - ((GameObject*)setup)->anim.localPosY) /
                dur;
        }
        Sfx_PlayFromObject((int)obj, SFXTRIG_en_cvdrip1c_4ae);
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
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode | INTERACT_FLAG_DISABLED;
        ObjHits_DisableObject((int)obj);
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode = *(u8*)&((GameObject*)obj)->anim.resetHitboxMode & ~INTERACT_FLAG_DISABLED;
        ObjHits_EnableObject((int)obj);
    }

    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_JUST_TRIGGERED) != 0 && ((BaddieState*)state)->seqEntryIndex <= 1)
    {
        if (((FCVars*)state)->turnDelta != 0 || (int)randomGetRange(0, 0x14) < 10)
        {
            ((BaddieState*)state)->seqEntryIndex = 1;
        }
        else
        {
            ((BaddieState*)state)->seqEntryIndex = 7;
        }
        ((BaddieState*)state)->controlFlags |= (u64)BADDIE_CONTROL_SEQUENCE_DRIVEN;
    }

    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        *(char*)&((BaddieState*)state)->seqEntryIndex += 1;
        if (((BaddieState*)state)->seqEntryIndex > gSnowwormSeqIndexMax[((FCVars*)state)->turnDelta])
        {
            ((BaddieState*)state)->seqEntryIndex = gSnowwormSeqIndexReset[((FCVars*)state)->turnDelta];
        }
        if (((FCVars*)state)->moveTableIndex < 4)
        {
            i = ((BaddieState*)state)->seqEntryIndex * 0xc;
            Baddie_SetMove(obj, state, (tbl + i)[8], *(f32*)((int)tbl + i), 0, 0);
        }
        else
        {
            i = ((BaddieState*)state)->seqEntryIndex * 0xc;
            Baddie_SetMove(obj, state, (tbl + i)[9], *(f32*)((int)tbl + i), 0, 0);
        }
        if (((GameObject*)obj)->anim.currentMove == 9)
        {
            fn_8015A52C((s16*)obj);
        }
        else if (((GameObject*)obj)->anim.currentMove == 1)
        {
            int r = randomGetRange(0, ((BaddieState*)state)->inWhirlpoolGroup);
            s16 a = randomGetRange(-0x8000, 0x7fff);
            f32 angle = (gCrawlerPi * a) / gCrawlerHalfCircleBams;
            ((GameObject*)obj)->anim.localPosX = r * mathSinf(angle) + *(f32*)(*(int*)&((GameObject*)obj)->anim.
                placementData + 8);
            ((GameObject*)obj)->anim.localPosZ = r * mathCosf(angle) + ((GameObject*)((GameObject*)obj)->anim.
                placementData)->anim.localPosY;
            fn_8014CF7C(obj, state, ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosX,
                        ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosZ, 1, 0);
        }
    }

    fn_8014CF7C(obj, state, ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosX,
                ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosZ, lbl_803DBD30[((FCVars*)state)->turnDelta], 0);
    crawler_playReactionEffects(obj, (int*)state);
}

void hoodedZyck_update(s16* obj, u8* state)
{
    int moved;
    int turnRaw;
    u16 mag;
    u32 grabbed;

    ((FCVars*)state)->engineTimer = ((FCVars*)state)->engineTimer - timeDelta;
    if (((FCVars*)state)->engineTimer <= lbl_803E2B18)
    {
        ((FCVars*)state)->engineTimer = (f32)(int)randomGetRange(0x3c, 0x78);
    }

    if (lbl_803E2B18 != ((FCVars*)state)->emergeTimer)
    {
        ObjHits_DisableObject((int)obj);
        if (((GameObject*)obj)->anim.currentMove != 5)
        {
            Baddie_SetMove((int*)obj, state, 5, lbl_803DBCEC, 0, 0);
        }
        else if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
        {
            ObjHits_EnableObject((int)obj);
            ((FCVars*)state)->emergeTimer = lbl_803E2B18;
        }
        ((GameObject*)obj)->anim.alpha = 0xff;
        moved = 1;
    }
    else
    {
        moved = 0;
    }

    if (moved == 0)
    {
        f32 diff;
        f32 z;
        u32 ang;
        *(s16*)obj = (f32)((FCVars*)state)->turnDelta * timeDelta + (f32)(int) * obj;
        z = lbl_803E2B18;
        ((GameObject*)obj)->anim.velocityX = z;
        ((GameObject*)obj)->anim.velocityY = z;
        ((GameObject*)obj)->anim.velocityZ = z;
        ObjHits_SetHitVolumeSlot((int)obj, 9, 1, -1);
        ang = getAngle(((GameObject*)obj)->anim.localPosX - ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosX,
                       ((GameObject*)obj)->anim.localPosZ - ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosZ) &
            0xffff;
        diff = (f32)(int)(ang - ((int)*(s16*)obj & 0xffffu));
        if (diff > lbl_803E2B2C)
        {
            diff = lbl_803E2B28 + diff;
        }
        if (diff < lbl_803E2B34)
        {
            diff = lbl_803E2B30 + diff;
        }
        turnRaw = diff;
        {
            int t = (s16)turnRaw;
            mag = (u16)(t >= 0 ? t : -t);
        }
        ObjHits_EnableObject((int)obj);
        grabbed = ((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN;
        if (grabbed != 0 && ((GameObject*)obj)->anim.currentMove == 6)
        {
            Baddie_SetMove((int*)obj, state, 4, lbl_803DBCE0, 0, 1);
        }
        else
        {
            if (grabbed != 0
                || (mag < 1000
                    && ((GameObject*)obj)->anim.currentMove != 2
                    && ((GameObject*)obj)->anim.currentMove != 4
                    && ((GameObject*)obj)->anim.currentMove != 6))
            {
                if (mag < 1000)
                {
                    if (((BaddieState*)state)->speedScale < lbl_803E2B60)
                    {
                        Baddie_SetMove((int*)obj, state, 2, lbl_803E2B44, 0, 0);
                    }
                    else
                    {
                        Baddie_SetMove((int*)obj, state, 6, lbl_803DBCE4, 0, 0);
                    }
                    ((FCVars*)state)->turnDelta = 0;
                }
                else
                {
                    Baddie_SetMove((int*)obj, state, 1, lbl_803E2B44, 0, 0);
                    if ((s16)turnRaw < 0)
                    {
                        ((FCVars*)state)->turnDelta = 0xfed4;
                    }
                    else
                    {
                        ((FCVars*)state)->turnDelta = 300;
                    }
                }
            }
            ((GameObject*)obj)->anim.rotY = ((BaddieState*)state)->spawnRotY;
            ((GameObject*)obj)->anim.rotZ = ((BaddieState*)state)->spawnRotZ;
        }
    }
}

typedef struct
{
    f32 spd;     /* 0x0 */
    u32 mask;    /* 0x4 */
    u8 moveId;   /* 0x8 */
    u8 next;     /* 0x9 */
    u8 mode;     /* 0xa */
    u8 pad;
} CrawlerSeq12;

typedef struct
{
    f32 spd;     /* 0x0 */
    u32 mask;    /* 0x4 */
    u8 moveId;   /* 0x8 */
    u8 next9;    /* 0x9 */
    u8 nextA;    /* 0xa */
    u8 pad;
    int flagC;   /* 0xc */
} CrawlerSeq16;

void crawler_update(int* obj, u8* state)
{
    typedef struct
    {
        u8 pad[0xc];
        u8* tC;
        CrawlerSeq12* t10;
        CrawlerSeq16* t14;
        u8* t18;
        u8 pad2[4];
    } CrawlerDescL;
    CrawlerDescL* d = (CrawlerDescL*)gCrawlerDescriptorTable;
    CrawlerSeq12* t9 = d[((BaddieState*)state)->inWhirlpoolGroup].t10;
    u8* t8 = d[((BaddieState*)state)->inWhirlpoolGroup].t18;
    u8* t7 = d[((BaddieState*)state)->inWhirlpoolGroup].tC;
    CrawlerSeq16* t6 = d[((BaddieState*)state)->inWhirlpoolGroup].t14;
    f32 cap;
    int i;
    u8* p;
    int j;
    int n;

    if (((BaddieState*)state)->trackedObj != NULL && ((GameObject*)((BaddieState*)state)->trackedObj)->anim.classId == 1)
    {
        fn_8001FE90();
    }

    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_JUST_TRIGGERED) != 0)
    {
        if (((BaddieState*)state)->inWhirlpoolGroup == 0)
        {
            (*gCameraInterface)->loadTriggeredCamAction(0, 0x6c, 0);
        }
        if (((GameObject*)obj)->anim.seqId == 0x6a2 && ((GameObject*)obj)->childObjs[0] != NULL)
        {
            firepipe_clearLinkedUpdateFlag(*(int*)&((GameObject*)obj)->childObjs[0]);
        }
        ((FCVars*)state)->flagsD = ((FCVars*)state)->flagsD | 0x10;
    }

    if (((FCVars*)state)->emergeTimer != *(f32*)&lbl_803E2BA8 && ((FCVars*)state)->reactStep != 0)
    {
        cap = lbl_803E2BA8;
        ((FCVars*)state)->emergeTimer -= timeDelta;
        if (((FCVars*)state)->emergeTimer <= cap)
        {
            ((FCVars*)state)->emergeTimer = cap;
            ((BaddieState*)state)->controlFlags |= (u64)BADDIE_CONTROL_SEQUENCE_DRIVEN;
            ((FCVars*)state)->flagsC = t6[((FCVars*)state)->reactStep].flagC;
            ((GameObject*)obj)->hitVolumeIndex = ((FCVars*)state)->flagsC & 1;
            ((FCVars*)state)->reactStep = t6[((FCVars*)state)->reactStep].nextA;
        }
    }

    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
    {
        ((FCVars*)state)->flagsD = ((FCVars*)state)->flagsD & ~0x30;
        if (((GameObject*)obj)->anim.seqId == 0x6a2 && ((GameObject*)obj)->childObjs[0] != NULL)
        {
            firepipe_clearLinkedUpdateFlag(*(int*)&((GameObject*)obj)->childObjs[0]);
        }
        if (((FCVars*)state)->reactStep != 0)
        {
            Baddie_SetMove(obj, state, t6[((FCVars*)state)->reactStep].moveId,
                        t6[((FCVars*)state)->reactStep].spd, 0, t6[((FCVars*)state)->reactStep].mask & 0xff);
            ((FCVars*)state)->flagsC = t6[((FCVars*)state)->reactStep].flagC;
            ((GameObject*)obj)->hitVolumeIndex = ((FCVars*)state)->flagsC & 1;
            ((FCVars*)state)->reactStep = t6[((FCVars*)state)->reactStep].next9;
        }
        else
        {
            i = ((FCVars*)state)->moveTableIndex * 0xc;
            if (*(u8*)(t7 + i + 8) == 0)
            {
                if (((FCVars*)state)->projectileTimer >= 0x50)
                {
                    ((BaddieState*)state)->seqEntryIndex = 0;
                }
                fn_8014C11C((int)obj, lbl_803E2BB8, 6, 0x28, gCrawlerNearbyObjectBuffer);
                if ((((BaddieState*)state)->controlFlags &
                     t9[((BaddieState*)state)->seqEntryIndex].mask) == 0
                    && t9[((BaddieState*)state)->seqEntryIndex].next != 0)
                {
                    ((BaddieState*)state)->seqEntryIndex =
                        t9[((BaddieState*)state)->seqEntryIndex].next;
                }
                Baddie_SetMove(obj, state, t9[((BaddieState*)state)->seqEntryIndex].moveId,
                            t9[((BaddieState*)state)->seqEntryIndex].spd, 0,
                            t9[((BaddieState*)state)->seqEntryIndex].mode);
                ((BaddieState*)state)->seqEntryIndex = t9[((BaddieState*)state)->seqEntryIndex].next;
            }
            else
            {
                Baddie_SetMove(obj, state, *(u8*)(t7 + i + 8), *(f32*)((int)t7 + i), 0,
                            *(u8*)(t7 + i + 0xa));
            }
        }
    }

    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumePriority = 0;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumeId = 0;
    j = 1;
    p = t8 + 0xc;
    n = *(u8*)(t8 + 8);
    for (; j <= n; j++)
    {
        if (((GameObject*)obj)->anim.currentMove == *(u8*)(p + 8))
        {
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumePriority = (s8) * (int*)(t8 + j * 0xc + 4);
            ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumeId = (s8) * (u8*)(t8 + j * 0xc + 9);
            if (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumePriority == 0x1f)
            {
                ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x40;
            }
            else
            {
                ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags & ~0x40LL;
            }
            break;
        }
        p += 0xc;
    }

    if ((((FCVars*)state)->moveStartFlags & 8) == 0 && (((FCVars*)state)->flagsD & 0x10) == 0)
    {
        fn_8014CF7C(obj, state, ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosX,
                    ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosZ, 0x1e, 0);
    }
    fn_80157CDC((int)obj, (int)state);
}

typedef struct
{
    u8 pad[6];
    u16 sfxId;   /* 0x6 */
    f32 vol;     /* 0x8 */
    f32 x;       /* 0xc */
    f32 y;       /* 0x10 */
    f32 z;       /* 0x14 */
} CrawlerSfxParams;

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
                ((FireCrawlerState*)state)->engineLight = (void*)objCreateLight(0, 1);
            }
            if (((FireCrawlerState*)state)->engineLight != NULL)
            {
                modelLightStruct_setLightKind(((FireCrawlerState*)state)->engineLight, 2);
                modelLightStruct_setPosition(((FireCrawlerState*)state)->engineLight, ((GameObject*)obj)->anim.localPosX,
                                             ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ);
                modelLightStruct_setDiffuseColor(((FireCrawlerState*)state)->engineLight, 0xc0, 0x40, 0xff, 0xff);
                modelLightStruct_setSpecularColor(((FireCrawlerState*)state)->engineLight, 0xc0, 0x40, 0xff, 0xff);
                modelLightStruct_setDistanceAttenuation(((FireCrawlerState*)state)->engineLight, lbl_803E2C10, lbl_803E2C14);
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
    sidekickToy_accelerateTowardTarget3D(obj, ((GameObject*)((BaddieState*)state)->trackedObj)->anim.worldPosX,
                                         lbl_803E2C48 + ((GameObject*)((BaddieState*)state)->trackedObj)->anim.worldPosY,
                                         ((GameObject*)((BaddieState*)state)->trackedObj)->anim.worldPosZ,
                                         *(f32*)&lbl_803E2C48, lbl_803E2C78, lbl_803E2C50, ((BaddieState*)state)->unk304);
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
    *(s16*)obj = ((FCVars*)state)->engineTimer * timeDelta + (f32)(int) * obj;
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
        extern void Sfx_SetObjectSfxVolume(u32 obj, u32 sfx, int vol, f32 v);
        Sfx_PlayFromObject((int)obj, SFXTRIG_baddie_rach_death);
        {
            f32 t = ((FCVars*)state)->engineTimer;
            Sfx_SetObjectSfxVolume((u32)obj, SFXTRIG_baddie_rach_death, (int)((gCrawlerSfxVolMax127 * t) / lbl_803E2C70),
                                   t / *(f32*)&lbl_803E2C70);
        }
    }
    else
    {
        Sfx_StopFromObject((int)obj, SFXTRIG_baddie_rach_death);
    }
    if (((FCVars*)state)->linkedObj != NULL
        && (((GameObject*)((FCVars*)state)->linkedObj)->anim.seqId == 0x1f
            || ((GameObject*)((FCVars*)state)->linkedObj)->anim.seqId == 0))
    {
        Sfx_PlayFromObject((int)obj, SFXTRIG_fball2_c);
    }
}

void hoodedZyck_updateB(s16* obj, u8* state)
{
    f32 scale;
    int moved;
    u8 noHit;
    int turnRaw;
    u32 mag;
    u8 bufA[88];
    u8 bufB[84];
    f32 tgtA[3];
    f32 posA[3];
    f32 tgtB[3];
    f32 posB[3];
    f32 range;
    f32 cosA;
    f32 sinA;
    f32 cosB;
    f32 sinB;

    {
        u8 n = *(u8*)(*(int*)&((GameObject*)obj)->anim.placementData + 0x2f);
        scale = n;
        if (lbl_803E2B18 == n)
        {
            scale = lbl_803E2B38;
        }
        scale = scale / lbl_803E2B38;
    }

    ((FCVars*)state)->engineTimer = ((FCVars*)state)->engineTimer - timeDelta;
    if (((FCVars*)state)->engineTimer <= lbl_803E2B18)
    {
        ((FCVars*)state)->engineTimer = (f32)(int)randomGetRange(0x3c, 0x78);
    }

    if (lbl_803E2B18 != ((FCVars*)state)->emergeTimer)
    {
        ObjHits_DisableObject((int)obj);
        if (((GameObject*)obj)->anim.currentMove != 5)
        {
            Baddie_SetMove((int*)obj, state, 5, lbl_803DBCEC, 0, 0);
        }
        else if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
        {
            ObjHits_EnableObject((int)obj);
            ((FCVars*)state)->emergeTimer = lbl_803E2B18;
        }
        ((GameObject*)obj)->anim.alpha = 0xff;
        moved = 1;
    }
    else
    {
        moved = 0;
    }

    if (moved == 0)
    {
        u32 ang;
        f32 diff;
        void* other;

        *(s16*)obj = *(s16*)obj + ((FCVars*)state)->turnDelta;
        posA[0] = ((GameObject*)obj)->anim.localPosX;
        posA[1] = ((GameObject*)obj)->anim.localPosY;
        posA[2] = ((GameObject*)obj)->anim.localPosZ;
        fn_80292E20((u16)((GameObject*)obj)->anim.rotX, &sinA, &cosA);
        tgtA[0] = -(lbl_803E2B38 * sinA - ((GameObject*)obj)->anim.localPosX);
        tgtA[1] = lbl_803E2B3C + ((GameObject*)obj)->anim.localPosY;
        tgtA[2] = -(lbl_803E2B38 * cosA - ((GameObject*)obj)->anim.localPosZ);
        /* 0x261 = BaddieState.contactSfxFlags; kept raw - typed member as a
         * call arg shifts arg emission bytes here. */
        noHit = !(u8)objBboxFn_800640cc(posA, tgtA, lbl_803E2B18, 3, bufA, obj, *(u8*)(state + 0x261), -1, 0xff, 0);
        ang = getAngle(((GameObject*)obj)->anim.localPosX - ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosX,
                       ((GameObject*)obj)->anim.localPosZ - ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosZ) &
            0xffff;
        diff = (f32)(int)(ang - ((int)*(s16*)obj & 0xffffu));
        if (diff > lbl_803E2B2C)
        {
            diff = lbl_803E2B28 + diff;
        }
        if (diff < lbl_803E2B34)
        {
            diff = lbl_803E2B30 + diff;
        }
        turnRaw = diff;
        {
            s16 t = turnRaw;
            mag = (u16)(t >= 0 ? t : -t);
        }
        if (fn_80295C88(Obj_GetPlayerObject()) != 0)
        {
            range = lbl_803E2B48;
            other = (void*)ObjGroup_FindNearestObject(0x30, obj, &range);
            if (other != NULL)
            {
                s16 yaw = Obj_GetYawDeltaToObject(obj, other, &range);
                int t;
                if (yaw < -300)
                {
                    yaw = -300;
                }
                else if (yaw > 300)
                {
                    yaw = 300;
                }
                t = yaw;
                ((FCVars*)state)->turnDelta = t;
                t = yaw >= 0 ? yaw : -yaw;
                if (t < 0x4000)
                {
                    *(s16*)obj = -*(s16*)obj;
                    posB[0] = ((GameObject*)obj)->anim.localPosX;
                    posB[1] = ((GameObject*)obj)->anim.localPosY;
                    posB[2] = ((GameObject*)obj)->anim.localPosZ;
                    fn_80292E20((u16)((GameObject*)obj)->anim.rotX, &sinB, &cosB);
                    tgtB[0] = -(lbl_803E2B38 * sinB - ((GameObject*)obj)->anim.localPosX);
                    tgtB[1] = lbl_803E2B3C + ((GameObject*)obj)->anim.localPosY;
                    tgtB[2] = -(lbl_803E2B38 * cosB - ((GameObject*)obj)->anim.localPosZ);
                    if ((u8)objBboxFn_800640cc(posB, tgtB, lbl_803E2B18, 3, bufB, obj, *(u8*)(state + 0x261), -1, 0xff,
                                               0) == 0)
                    {
                        if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
                        {
                            Baddie_SetMove((int*)obj, state, 7, lbl_803E2B40 / (lbl_803E2B4C * scale), 0, 1);
                        }
                        ((GameObject*)obj)->anim.rotY = ((BaddieState*)state)->spawnRotY;
                        ((GameObject*)obj)->anim.rotZ = ((BaddieState*)state)->spawnRotZ;
                    }
                    *(s16*)obj = -*(s16*)obj;
                }
                return;
            }
        }
        if (((BaddieState*)state)->trackedObj != NULL && ((GameObject*)((BaddieState*)state)->trackedObj)->anim.hitboxScale >
            lbl_803E2B50)
        {
            ((BaddieState*)state)->speedScale = lbl_803DBCE8;
        }
        if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0 || noHit == 0
            || (mag < 3000 && noHit != 0 && ((GameObject*)obj)->anim.currentMove != 0))
        {
            if (noHit != 0 && mag < 3000)
            {
                ((FCVars*)state)->turnDelta = 0;
                Baddie_SetMove((int*)obj, state, 0, lbl_803E2B40 / scale, 0, 1);
            }
            else
            {
                Baddie_SetMove((int*)obj, state, 1, lbl_803E2B44 / scale, 0, 0);
                {
                    f32 z = lbl_803E2B18;
                    ((GameObject*)obj)->anim.velocityX = z;
                    ((GameObject*)obj)->anim.velocityY = z;
                    ((GameObject*)obj)->anim.velocityZ = z;
                }
                if (mag < 3000)
                {
                    ((FCVars*)state)->turnDelta = (randomGetRange(0, 1) - 1) * 300;
                }
                else if ((s16)turnRaw < 0)
                {
                    ((FCVars*)state)->turnDelta = 0xfed4;
                }
                else
                {
                    ((FCVars*)state)->turnDelta = 300;
                }
            }
        }
        ((GameObject*)obj)->anim.rotY = ((BaddieState*)state)->spawnRotY;
        ((GameObject*)obj)->anim.rotZ = ((BaddieState*)state)->spawnRotZ;
    }
}

void crawler_onHit(int obj, u8* state, u8* attacker, int cmd, int p5, int damage)
{
    typedef struct
    {
        u8 pad[0x14];
        CrawlerSeq16* seq; // 0x14
        u8 pad2[8];
    } CrawlerDesc;
    u8 idx;
    CrawlerDesc* d = (CrawlerDesc*)gCrawlerDescriptorTable;
    CrawlerSeq16* tbl = d[(idx = ((BaddieState*)state)->inWhirlpoolGroup)].seq;

    if (cmd == 0xe)
    {
        damage = damage << 3;
    }
    if (idx == 0 && cmd == 5)
    {
        damage = damage << 2;
    }
    if (idx == 1
        && (((GameObject*)attacker)->anim.seqId == 0x1b5 || ((GameObject*)attacker)->anim.classId == 0x1c || cmd ==
            0x1f))
    {
        return;
    }
    if ((((FCVars*)state)->flagsC & 4) != 0 || (idx == 0 && (((FCVars*)state)->hitConfigFlags & 0x40) != 0))
    {
        if (cmd == 0x11)
        {
            return;
        }
        if (((GameObject*)obj)->anim.seqId == 0x6a2)
        {
            if (gCrawlerHitSfxTimer <= lbl_803E2BA8 && attacker != NULL)
            {
                switch (((GameObject*)attacker)->anim.seqId)
                {
                case 0x416:
                    Sfx_PlayFromObject(obj, SFXTRIG_snort);
                    break;
                case 0:
                case 0x69:
                    Sfx_PlayFromObject(obj, SFXTRIG_stftest);
                    break;
                }
                gCrawlerHitSfxTimer = lbl_803E2BAC;
            }
        }
        else
        {
            Sfx_PlayFromObject(obj, SFXTRIG_swd_var);
        }
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x10;
        return;
    }

    if (idx == 1 && ((GameObject*)obj)->childObjs[0] != NULL)
    {
        firepipe_clearLinkedUpdateFlag(*(int*)&((GameObject*)obj)->childObjs[0]);
    }
    ((FCVars*)state)->flagsD = ((FCVars*)state)->flagsD & ~0x40;
    ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags & ~0x40LL;
    if (cmd == 0x10 && ((BaddieState*)state)->inWhirlpoolGroup != 0)
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x20;
        return;
    }

    if (((FCVars*)state)->reactStep != 0)
    {
        u8 step;
        if (((BaddieState*)state)->inWhirlpoolGroup == 0)
        {
            step = 4;
        }
        else
        {
            step = 3;
        }
        Baddie_SetMove((int*)obj, state, tbl[step].moveId, tbl[step].spd, 0,
                    tbl[step].mask & 0xff);
        ((FCVars*)state)->flagsC = tbl[step].flagC;
        ((GameObject*)obj)->hitVolumeIndex = ((FCVars*)state)->flagsC & 1;
        ((FCVars*)state)->reactStep = tbl[step].next9;
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 8;
        if (((GameObject*)obj)->anim.seqId == 0x6a2)
        {
            if (gCrawlerHitSfxTimer <= lbl_803E2BA8 && attacker != NULL)
            {
                switch (((GameObject*)attacker)->anim.seqId)
                {
                case 0x416:
                    Sfx_PlayFromObject(obj, SFXTRIG_snort);
                    break;
                case 0:
                case 0x69:
                    Sfx_PlayFromObject(obj, SFXTRIG_stftest);
                    break;
                }
                Sfx_PlayFromObject(obj, SFXTRIG_baddie_var);
                gCrawlerHitSfxTimer = lbl_803E2BAC;
            }
        }
        else
        {
            Sfx_PlayFromObject(obj, SFXTRIG_stftest_var);
        }
        if (damage > ((BaddieState*)state)->hitCounter)
        {
            ((BaddieState*)state)->hitCounter = 0;
        }
        else
        {
            ((BaddieState*)state)->hitCounter = ((BaddieState*)state)->hitCounter - damage;
        }
        if (((BaddieState*)state)->hitCounter == 0 && ((BaddieState*)state)->inWhirlpoolGroup == 0)
        {
            crawler_checkNearbyActive(obj, state);
        }
        return;
    }

    if ((((BaddieState*)state)->inWhirlpoolGroup == 0 && cmd == 0x11 && GameBit_Get(0xc55) != 0)
        || ((BaddieState*)state)->inWhirlpoolGroup == 1)
    {
        u8 v;
        Baddie_SetMove((int*)obj, state, tbl[1].moveId, tbl[1].spd, 0, tbl[1].mask & 0xff);
        ((FCVars*)state)->flagsC = tbl[1].flagC;
        ((GameObject*)obj)->hitVolumeIndex = ((FCVars*)state)->flagsC & 1;
        ((FCVars*)state)->reactStep = tbl[1].next9;
        v = ((BaddieState*)state)->inWhirlpoolGroup;
        if (v == 0)
        {
            ((FCVars*)state)->emergeTimer = lbl_803E2BB0 * (f32) ((FCVars*)state)->hitCountScalar;
            ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 8;
            if (((GameObject*)obj)->anim.seqId == 0x6a2)
            {
                if (gCrawlerHitSfxTimer <= lbl_803E2BA8 && attacker != NULL)
                {
                    switch (((GameObject*)attacker)->anim.seqId)
                    {
                    case 0x416:
                        Sfx_PlayFromObject(obj, SFXTRIG_snort);
                        break;
                    case 0:
                    case 0x69:
                        Sfx_PlayFromObject(obj, SFXTRIG_stftest);
                        break;
                    }
                    Sfx_PlayFromObject(obj, SFXTRIG_baddie_var);
                    gCrawlerHitSfxTimer = lbl_803E2BAC;
                }
            }
            else
            {
                Sfx_PlayFromObject(obj, SFXTRIG_stftest_var);
            }
            return;
        }
        if (v == 1)
        {
            ((FCVars*)state)->emergeTimer = lbl_803E2BB4 * (f32) ((FCVars*)state)->hitCountScalar;
            if (((GameObject*)obj)->anim.seqId == 0x6a2)
            {
                if (gCrawlerHitSfxTimer <= lbl_803E2BA8 && attacker != NULL)
                {
                    switch (((GameObject*)attacker)->anim.seqId)
                    {
                    case 0x416:
                        Sfx_PlayFromObject(obj, SFXTRIG_snort);
                        break;
                    case 0:
                    case 0x69:
                        Sfx_PlayFromObject(obj, SFXTRIG_stftest);
                        break;
                    }
                    Sfx_PlayFromObject(obj, SFXTRIG_baddie_var);
                    gCrawlerHitSfxTimer = lbl_803E2BAC;
                }
            }
            else
            {
                Sfx_PlayFromObject(obj, SFXTRIG_swd_var);
            }
            ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x10;
        }
        return;
    }

    if (cmd != 0x11)
    {
        if (((GameObject*)obj)->anim.seqId == 0x6a2)
        {
            if (gCrawlerHitSfxTimer <= lbl_803E2BA8 && attacker != NULL)
            {
                switch (((GameObject*)attacker)->anim.seqId)
                {
                case 0x416:
                    Sfx_PlayFromObject(obj, SFXTRIG_snort);
                    break;
                case 0:
                case 0x69:
                    Sfx_PlayFromObject(obj, SFXTRIG_stftest);
                    break;
                }
                Sfx_PlayFromObject(obj, SFXTRIG_baddie_var);
                gCrawlerHitSfxTimer = lbl_803E2BAC;
            }
        }
        else
        {
            Sfx_PlayFromObject(obj, SFXTRIG_swd_var);
        }
    }
    ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x10;
}

typedef struct
{
    u8* tbl0; // 0x0  anim move ids
    u8* tbl4; // 0x4  chained move table (stride 0xc)
    u8* tbl8; // 0x8  random move table (stride 0xc)
    u8* tblC; // 0xc  octant move table (stride 0xc)
    u8* tbl10; // 0x10 single move entry
    CrawlerSeq16* seq; // 0x14
    u8* tbl18; // 0x18 anim-id loop table (stride 0xc)
    u8 pad1C[4];
} CrawlerDescriptor;

void crawler_updateC(s16* obj, u8* state)
{
    CrawlerDescriptor* d = (CrawlerDescriptor*)gCrawlerDescriptorTable;
    u8* t8 = d[((BaddieState*)state)->inWhirlpoolGroup].tbl8;
    u8* t0 = d[((BaddieState*)state)->inWhirlpoolGroup].tbl0;
    CrawlerSeq16* seq = d[((BaddieState*)state)->inWhirlpoolGroup].seq;
    u8* tC = d[((BaddieState*)state)->inWhirlpoolGroup].tblC;
    RomCurveWalker* base = *(RomCurveWalker**)state;
    f32 scale = lbl_803E2BA4;
    f32 cap;
    int i;
    f32 dv[3];

    ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags & ~0x40LL;
    if (((GameObject*)obj)->childObjs[0] != NULL)
    {
        firepipe_clearLinkedUpdateFlag(*(int*)&((GameObject*)obj)->childObjs[0]);
    }

    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_JUST_TRIGGERED) != 0)
    {
        ((FCVars*)state)->flagsD = ((FCVars*)state)->flagsD | 8;
        if ((*gRomCurveInterface)->initCurve(*(RomCurveWalker**)state, obj, lbl_803E2BA8,
                                             (int*)&lbl_803DBCF0, -1) != 0)
        {
            ((BaddieState*)state)->controlFlags = ((BaddieState*)state)->controlFlags & ~(u64)BADDIE_CONTROL_PATH_FOLLOW;
        }
        if (((BaddieState*)state)->inWhirlpoolGroup == 0)
        {
            crawler_checkNearbyActive((int)obj, state);
        }
        ((BaddieState*)state)->seqEntryIndex = 0;
    }

    if (((FCVars*)state)->emergeTimer != *(f32*)&lbl_803E2BA8 && ((FCVars*)state)->reactStep != 0)
    {
        cap = lbl_803E2BA8;
        ((FCVars*)state)->emergeTimer = ((FCVars*)state)->emergeTimer - timeDelta;
        if (((FCVars*)state)->emergeTimer <= cap)
        {
            ((FCVars*)state)->emergeTimer = cap;
            ((BaddieState*)state)->controlFlags |= (u64)BADDIE_CONTROL_SEQUENCE_DRIVEN;
            ((FCVars*)state)->flagsC = seq[((FCVars*)state)->reactStep].flagC;
            ((GameObject*)obj)->hitVolumeIndex = ((FCVars*)state)->flagsC & 1;
            ((FCVars*)state)->reactStep = seq[((FCVars*)state)->reactStep].nextA;
        }
        if ((((BaddieState*)state)->controlFlags & (BADDIE_CONTROL_JUST_TRIGGERED | BADDIE_CONTROL_SEQUENCE_DRIVEN)) == 0)
        {
            return;
        }
    }

    {
        u32 flags = ((BaddieState*)state)->controlFlags;
        if ((flags & BADDIE_CONTROL_PATH_FOLLOW) != 0)
        {
            int count = fn_8014C11C((int)obj, lbl_803E2BB8, 1, 0x28, gCrawlerNearbyObjectBuffer);
            if (count >= 1 && (f32) * (u16*)((char*)gCrawlerNearbyObjectBuffer + 4) <= lbl_803E2BB8)
            {
                f32* dp = dv;
                int rel;
                u16 oct;
                dp[0] = ((GameObject*)obj)->anim.worldPosX - *(f32*)(gCrawlerNearbyObjectBuffer[0] + 0x18);
                dp[1] = ((GameObject*)obj)->anim.worldPosY - *(f32*)(gCrawlerNearbyObjectBuffer[0] + 0x1c);
                dp[2] = ((GameObject*)obj)->anim.worldPosZ - *(f32*)(gCrawlerNearbyObjectBuffer[0] + 0x20);
                rel = (getAngle(-dp[0], -dp[2]) & 0xffff) - ((int)*(s16*)obj & 0xffffu);
                if (rel > 0x8000)
                {
                    rel = rel - 0xffff;
                }
                if (rel < -0x8000)
                {
                    rel = rel + 0xffff;
                }
                oct = ((u32)rel & 0xffff) >> 13;
                if (oct == 3 || oct == 4)
                {
                    scale = (f32) * (u16*)((char*)gCrawlerNearbyObjectBuffer + 4) / lbl_803E2BB8;
                }
                else if (oct == 0 || oct == 7)
                {
                    scale = lbl_803E2BB4 * (lbl_803E2BA4 - (f32) * (u16*)((char*)gCrawlerNearbyObjectBuffer + 4) / lbl_803E2BB8) +
                        lbl_803E2BA4;
                }
            }
            {
                f32 dx = base->posX - ((GameObject*)obj)->anim.localPosX;
                f32 dz = base->posZ - ((GameObject*)obj)->anim.localPosZ;
                f32 dist = sqrtf(dx * dx + dz * dz);
                if (dist > lbl_803E2BA0)
                {
                    dist = lbl_803E2BA0;
                }
                ((FCVars*)state)->pathSpeed = scale * (((lbl_803E2BA0 - dist) / lbl_803E2BA0) * ((BaddieState*)state)->pathStep);
                if (((FCVars*)state)->pathSpeed < lbl_803E2BBC)
                {
                    ((FCVars*)state)->pathSpeed = *(f32 *)&lbl_803E2BBC;
                }
            }
            if ((Curve_AdvanceAlongPath(base, ((FCVars*)state)->pathSpeed) != 0 || base->atSegmentEnd != 0)
                && (*gRomCurveInterface)->goNextPoint(base) != 0
                && (*gRomCurveInterface)->initCurve(*(RomCurveWalker**)state, obj, lbl_803E2BC0,
                                                    (int*)&lbl_803DBCF0, -1) != 0)
            {
                ((BaddieState*)state)->controlFlags = ((BaddieState*)state)->controlFlags & ~(u64)BADDIE_CONTROL_PATH_FOLLOW;
            }
            if ((((FCVars*)state)->flagsD & 0xa) == 0)
            {
                f32 diff;
                f32 t;
                f32 a;
                diff = (f32)(int)(((getAngle(base->tangentX, base->tangentZ) & 0xffff) + 0x8000)
                    - ((int)*(s16*)obj & 0xffffu));
                if (diff > lbl_803E2BC8)
                {
                    diff = lbl_803E2BC4 + diff;
                }
                if (diff < lbl_803E2BD0)
                {
                    diff = lbl_803E2BCC + diff;
                }
                t = (((BaddieState*)state)->pathStep * scale - ((FCVars*)state)->pathSpeed) / lbl_803E2B84;
                a = diff >= lbl_803E2BA8 ? diff : -diff;
                /* 0x308 = BaddieState.unk308; kept raw here - the typed
                 * member spelling shifts bytes off the u8* state param. */
                *(f32*)(state + 0x308) = t * (lbl_803E2BA4 - a / lbl_803E2BCC);
                if (*(f32*)(state + 0x308) < lbl_803E2BD4)
                {
                    *(f32*)(state + 0x308) = lbl_803E2BD4;
                }
                else if (*(f32*)(state + 0x308) > lbl_803E2BD8)
                {
                    *(f32*)(state + 0x308) = lbl_803E2BD8;
                }
            }
            if ((((BaddieState*)state)->controlFlags & (BADDIE_CONTROL_JUST_TRIGGERED | BADDIE_CONTROL_SEQUENCE_DRIVEN)) != 0)
            {
                ((FCVars*)state)->flagsD = ((FCVars*)state)->flagsD & ~0x20;
                if (((FCVars*)state)->reactStep != 0)
                {
                    i = ((FCVars*)state)->reactStep * 0x10;
                    Baddie_SetMove((int*)obj, state, *(u8*)((char*)seq + i + 8), *(f32*)((int)seq + i), 0,
                                *(int*)((char*)seq + i + 4) & 0xff);
                    ((FCVars*)state)->flagsC = seq[((FCVars*)state)->reactStep].flagC;
                    ((GameObject*)obj)->hitVolumeIndex = ((FCVars*)state)->flagsC & 1;
                    ((FCVars*)state)->reactStep = seq[((FCVars*)state)->reactStep].next9;
                }
                else
                {
                    f32* dp2 = dv;
                    int rel2;
                    u16 oct2;
                    u8 mv;
                    dp2[0] = ((GameObject*)obj)->anim.worldPosX - base->posX;
                    dp2[1] = ((GameObject*)obj)->anim.worldPosY - base->posY;
                    dp2[2] = ((GameObject*)obj)->anim.worldPosZ - base->posZ;
                    rel2 = (getAngle(-dp2[0], -dp2[2]) & 0xffff) - ((int)*(s16*)obj & 0xffffu);
                    if (rel2 > 0x8000)
                    {
                        rel2 = rel2 - 0xffff;
                    }
                    if (rel2 < -0x8000)
                    {
                        rel2 = rel2 + 0xffff;
                    }
                    oct2 = ((u32)rel2 & 0xffff) >> 13;
                    i = oct2 * 0xc;
                    mv = *(u8*)((char*)tC + i + 8);
                    if (mv == 0)
                    {
                        ((FCVars*)state)->flagsD = ((FCVars*)state)->flagsD & ~0x18;
                        {
                            f32 v = ((FCVars*)state)->pathSpeed;
                            int j = ((BaddieState*)state)->inWhirlpoolGroup * 0xc;
                            if (v > *(f32*)((int)gCrawlerSpeedThresholds + j))
                            {
                                ((FCVars*)state)->moveStartFlags = 1;
                                ObjAnim_SetCurrentMove((int)obj, *(u8*)(t0 + 0x2c), lbl_803E2BA8, 0);
                            }
                            else if (v > *(f32*)((char*)gCrawlerSpeedThresholds + j + 4))
                            {
                                ((FCVars*)state)->moveStartFlags = 1;
                                ObjAnim_SetCurrentMove((int)obj, *(u8*)(t0 + 0x20), lbl_803E2BA8, 0);
                            }
                            else if (v > *(f32*)((char*)gCrawlerSpeedThresholds + j + 8))
                            {
                                ((FCVars*)state)->moveStartFlags = 1;
                                ObjAnim_SetCurrentMove((int)obj, *(u8*)(t0 + 0x14), lbl_803E2BA8, 0);
                            }
                            else
                            {
                                ((FCVars*)state)->moveStartFlags = 1;
                                *(f32*)(state + 0x308) = lbl_803E2BDC;
                                ObjAnim_SetCurrentMove((int)obj, *(u8*)(t0 + 8), lbl_803E2BA8, 0);
                                ((FCVars*)state)->pathSpeed = lbl_803E2BA8;
                            }
                        }
                    }
                    else
                    {
                        Baddie_SetMove((int*)obj, state, mv, *(f32*)((int)tC + i), 0,
                                    *(u8*)((char*)tC + i + 0xa));
                        ((FCVars*)state)->flagsD = ((FCVars*)state)->flagsD | 8;
                    }
                }
            }
            if ((((FCVars*)state)->moveStartFlags & 8) == 0 && (((FCVars*)state)->flagsD & 0x10) == 0)
            {
                fn_8014CF7C((int*)obj, state, base->posX, base->posZ, 0xf, 0);
            }
        }
        else if ((flags & 0xc0000000) != 0)
        {
            i = (randomGetRange(1, *(u8*)(t8 + 8)) & 0xff) * 0xc;
            Baddie_SetMove((int*)obj, state, *(u8*)((char*)t8 + i + 8), *(f32*)((int)t8 + i), 0,
                        *(u8*)((char*)t8 + i + 0xa));
        }
    }
    fn_80157CDC((int)obj, (int)state);
}

void crawler_updateB(s16* obj, u8* state)
{
    CrawlerDescriptor* d = (CrawlerDescriptor*)gCrawlerDescriptorTable;
    u8* t8 = d[((BaddieState*)state)->inWhirlpoolGroup].tbl8;
    u8* tC = d[((BaddieState*)state)->inWhirlpoolGroup].tblC;
    CrawlerSeq16* seq = d[((BaddieState*)state)->inWhirlpoolGroup].seq;
    u8* t4 = d[((BaddieState*)state)->inWhirlpoolGroup].tbl4;
    u8* t18 = d[((BaddieState*)state)->inWhirlpoolGroup].tbl18;
    u8* t10 = d[((BaddieState*)state)->inWhirlpoolGroup].tbl10;
    f32 cap;
    int count;
    int i;
    f32 dv[3];

    if (((BaddieState*)state)->trackedObj != NULL && ((GameObject*)((BaddieState*)state)->trackedObj)->anim.classId == 1)
    {
        fn_8001FE90();
    }

    if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_JUST_TRIGGERED) != 0)
    {
        if (((BaddieState*)state)->inWhirlpoolGroup == 0)
        {
            (*gCameraInterface)->loadTriggeredCamAction(0, 0x6c, 0);
        }
        ((FCVars*)state)->flagsD = ((FCVars*)state)->flagsD | 0x10;
        ((BaddieState*)state)->seqEntryIndex = 0;
        if (((GameObject*)obj)->anim.seqId == 0x6a2)
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_baddie_eggsnatch_var);
            if (((GameObject*)obj)->childObjs[0] != NULL)
            {
                firepipe_clearLinkedUpdateFlag(*(int*)&((GameObject*)obj)->childObjs[0]);
            }
        }
    }

    if (((FCVars*)state)->emergeTimer != *(f32*)&lbl_803E2BA8 && ((FCVars*)state)->reactStep != 0)
    {
        cap = lbl_803E2BA8;
        ((FCVars*)state)->emergeTimer = ((FCVars*)state)->emergeTimer - timeDelta;
        if (((FCVars*)state)->emergeTimer <= cap)
        {
            ((FCVars*)state)->emergeTimer = cap;
            ((BaddieState*)state)->controlFlags |= (u64)BADDIE_CONTROL_SEQUENCE_DRIVEN;
            ((FCVars*)state)->flagsC = seq[((FCVars*)state)->reactStep].flagC;
            ((GameObject*)obj)->hitVolumeIndex = ((FCVars*)state)->flagsC & 1;
            ((FCVars*)state)->reactStep = seq[((FCVars*)state)->reactStep].nextA;
        }
    }

    count = fn_8014C11C((int)obj, lbl_803E2BE0, 1, 0x28, gCrawlerNearbyObjectBuffer);
    if (count >= 1)
    {
        if ((((FCVars*)state)->flagsD & 0x20) == 0 || (((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
        {
            if (((FCVars*)state)->reactStep != 0)
            {
                Baddie_SetMove((int*)obj, state, seq[((FCVars*)state)->reactStep].moveId,
                            seq[((FCVars*)state)->reactStep].spd, 0,
                            seq[((FCVars*)state)->reactStep].mask & 0xff);
                ((FCVars*)state)->flagsC = seq[((FCVars*)state)->reactStep].flagC;
                ((GameObject*)obj)->hitVolumeIndex = ((FCVars*)state)->flagsC & 1;
                ((FCVars*)state)->reactStep = seq[((FCVars*)state)->reactStep].next9;
            }
            else
            {
                f32* dp = dv;
                int rel;
                u16 oct;
                dp[0] = ((GameObject*)obj)->anim.worldPosX - *(f32*)(gCrawlerNearbyObjectBuffer[0] + 0x18);
                dp[1] = ((GameObject*)obj)->anim.worldPosY - *(f32*)(gCrawlerNearbyObjectBuffer[0] + 0x1c);
                dp[2] = ((GameObject*)obj)->anim.worldPosZ - *(f32*)(gCrawlerNearbyObjectBuffer[0] + 0x20);
                rel = (getAngle(-dp[0], -dp[2]) & 0xffff) - ((int)*(s16*)obj & 0xffffu);
                if (rel > 0x8000)
                {
                    rel = rel - 0xffff;
                }
                if (rel < -0x8000)
                {
                    rel = rel + 0xffff;
                }
                oct = ((u32)rel & 0xffff) >> 13;
                if (oct != 0 && oct < 7)
                {
                    if (oct < 3 || oct > 4)
                    {
                        u8 mv;
                        i = ((FCVars*)state)->moveTableIndex * 0xc;
                        mv = *(u8*)((char*)tC + i + 8);
                        if (mv == 0)
                        {
                            int i2 = ((FCVars*)state)->moveChainIndex * 0xc;
                            u8* p9 = (u8*)t4 + 9;
                            Baddie_SetMove((int*)obj, state, *(u8*)((char*)t4 + i2 + 8), *(f32*)((int)t4 + i2), 0,
                                        *(u8*)((char*)t4 + i2 + 0xa));
                            ((FCVars*)state)->moveChainIndex = p9[((FCVars*)state)->moveChainIndex * 0xc];
                        }
                        else
                        {
                            Baddie_SetMove((int*)obj, state, mv, *(f32*)((int)tC + i), 0,
                                        *(u8*)((char*)tC + i + 0xa));
                        }
                    }
                    else
                    {
                        i = (randomGetRange(1, *(u8*)(t8 + 8)) & 0xff) * 0xc;
                        Baddie_SetMove((int*)obj, state, *(u8*)((char*)t8 + i + 8), *(f32*)((int)t8 + i), 0,
                                    *(u8*)((char*)t8 + i + 0xa));
                    }
                }
                else
                {
                    Baddie_SetMove((int*)obj, state, *(u8*)(t10 + 8), *(f32*)t10, 0, *(u8*)(t10 + 0xa));
                }
                ((FCVars*)state)->flagsD = ((FCVars*)state)->flagsD | 0x20;
                ((FCVars*)state)->flagsD = ((FCVars*)state)->flagsD & ~0x10;
            }
        }
    }
    else
    {
        if ((((BaddieState*)state)->controlFlags & BADDIE_CONTROL_SEQUENCE_DRIVEN) != 0)
        {
            ((FCVars*)state)->flagsD = ((FCVars*)state)->flagsD & ~0x30;
            if (((GameObject*)obj)->anim.seqId == 0x6a2 && ((GameObject*)obj)->childObjs[0] != NULL)
            {
                firepipe_clearLinkedUpdateFlag(*(int*)&((GameObject*)obj)->childObjs[0]);
            }
            if (((FCVars*)state)->reactStep != 0)
            {
                Baddie_SetMove((int*)obj, state, seq[((FCVars*)state)->reactStep].moveId,
                            seq[((FCVars*)state)->reactStep].spd, 0,
                            seq[((FCVars*)state)->reactStep].mask & 0xff);
                ((FCVars*)state)->flagsC = seq[((FCVars*)state)->reactStep].flagC;
                ((GameObject*)obj)->hitVolumeIndex = ((FCVars*)state)->flagsC & 1;
                ((FCVars*)state)->reactStep = seq[((FCVars*)state)->reactStep].next9;
            }
            else
            {
                int i2 = ((FCVars*)state)->moveChainIndex * 0xc;
                if ((((BaddieState*)state)->controlFlags & *(u32*)((char*)t4 + i2 + 4)) != 0)
                {
                    u8 mv;
                    i = ((FCVars*)state)->moveTableIndex * 0xc;
                    mv = *(u8*)((char*)tC + i + 8);
                    if (mv == 0)
                    {
                        Baddie_SetMove((int*)obj, state, *(u8*)((char*)t4 + i2 + 8), *(f32*)((int)t4 + i2), 0,
                                    *(u8*)((char*)t4 + i2 + 0xa));
                    }
                    else
                    {
                        Baddie_SetMove((int*)obj, state, mv, *(f32*)((int)tC + i), 0,
                                    *(u8*)((char*)tC + i + 0xa));
                    }
                }
                else
                {
                    u8 mv;
                    i = ((FCVars*)state)->moveTableIndex * 0xc;
                    mv = *(u8*)((char*)tC + i + 8);
                    if (mv == 0)
                    {
                        int i4 = (randomGetRange(1, *(u8*)(t8 + 8)) & 0xff) * 0xc;
                        Baddie_SetMove((int*)obj, state, *(u8*)((char*)t8 + i4 + 8), *(f32*)((int)t8 + i4), 0,
                                    *(u8*)((char*)t8 + i4 + 0xa));
                    }
                    else
                    {
                        Baddie_SetMove((int*)obj, state, mv, *(f32*)((int)tC + i), 0,
                                    *(u8*)((char*)tC + i + 0xa));
                    }
                }
                {
                    u8* p9 = (u8*)t4 + 9;
                    ((FCVars*)state)->moveChainIndex = p9[((FCVars*)state)->moveChainIndex * 0xc];
                }
            }
        }
    }

    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumePriority = 0;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumeId = 0;
    {
        int j = 1;
        u8* p = t18 + 0xc;
        int c;
        for (c = *(u8*)(t18 + 8); c >= 1; c--)
        {
            if (((GameObject*)obj)->anim.currentMove == *(u8*)(p + 8))
            {
                ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumePriority = (s8) * (int*)((char*)t18 + j * 0xc + 4);
                ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumeId = (s8) * (u8*)((char*)t18 + j * 0xc + 9);
                if (((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumePriority == 0x1f)
                {
                    ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x40;
                }
                else
                {
                    ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags & ~0x40LL;
                }
                break;
            }
            p += 0xc;
            j += 1;
        }
    }

    if ((((FCVars*)state)->moveStartFlags & 8) == 0 && (((FCVars*)state)->flagsD & 0x10) == 0)
    {
        fn_8014CF7C((int*)obj, state, ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosX,
                    ((GameObject*)((BaddieState*)state)->trackedObj)->anim.localPosZ, 0x1e, 0);
    }
    fn_80157CDC((int)obj, (int)state);
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
                ((FireCrawlerState*)state)->engineLight = (void*)objCreateLight(0, 1);
            }
            if (((FireCrawlerState*)state)->engineLight != NULL)
            {
                modelLightStruct_setLightKind(((FireCrawlerState*)state)->engineLight, 2);
                modelLightStruct_setPosition(((FireCrawlerState*)state)->engineLight, ((GameObject*)obj)->anim.localPosX,
                                             ((GameObject*)obj)->anim.localPosY, ((GameObject*)obj)->anim.localPosZ);
                modelLightStruct_setDiffuseColor(((FireCrawlerState*)state)->engineLight, 0xc0, 0x40, 0xff, 0xff);
                modelLightStruct_setSpecularColor(((FireCrawlerState*)state)->engineLight, 0xc0, 0x40, 0xff, 0xff);
                modelLightStruct_setDistanceAttenuation(((FireCrawlerState*)state)->engineLight, lbl_803E2C10, lbl_803E2C14);
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
        if ((Curve_AdvanceAlongPath(base, ((BaddieState*)state)->pathStep * t) != 0 || base->atSegmentEnd != 0)
            && (*gRomCurveInterface)->goNextPoint(base) != 0
            && (*gRomCurveInterface)->initCurve(*(RomCurveWalker**)state, obj, lbl_803E2C44,
                                                (int*)&lbl_803DBCF8, -1) != 0)
        {
            ((BaddieState*)state)->controlFlags = ((BaddieState*)state)->controlFlags & ~(u64)BADDIE_CONTROL_PATH_FOLLOW;
        }
        sidekickToy_accelerateTowardTarget3D(obj, base->posX, base->posY,
                                             base->posZ, lbl_803E2C48, lbl_803E2C4C, lbl_803E2C50,
                                             ((BaddieState*)state)->unk304);
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
        *(s16*)obj = ((FCVars*)state)->engineTimer * timeDelta + (f32)(int) * obj;
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
        ratio = sqrtf(((GameObject*)obj)->anim.velocityX * ((GameObject*)obj)->anim.velocityX
            + ((GameObject*)obj)->anim.velocityZ * ((GameObject*)obj)->anim.velocityZ) / lbl_803E2C48;
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
        extern void Sfx_SetObjectSfxVolume(u32 obj, u32 sfx, int vol, f32 v);
        Sfx_PlayFromObject((int)obj, SFXTRIG_baddie_rach_death);
        {
            f32 t = ((FCVars*)state)->engineTimer;
            Sfx_SetObjectSfxVolume((u32)obj, SFXTRIG_baddie_rach_death, (int)((gCrawlerSfxVolMax127 * t) / lbl_803E2C70),
                                   t / *(f32*)&lbl_803E2C70);
        }
    }
    else
    {
        Sfx_StopFromObject((int)obj, SFXTRIG_baddie_rach_death);
    }

    {
        s16 t;
        if (((FCVars*)state)->linkedObj != NULL
            && ((t = ((GameObject*)((FCVars*)state)->linkedObj)->anim.seqId) == 0x1f || t == 0))
        {
            Sfx_PlayFromObject((int)obj, SFXTRIG_fball2_c);
        }
    }
}

extern u8 lbl_8031F3A0[];
extern u8 lbl_8031F3D0[];
extern u8 lbl_8031F424[];
extern u8 lbl_8031F46C[];
extern u8 lbl_8031F4CC[];
extern u8 lbl_8031F52C[];
extern u8 lbl_8031F5EC[];
extern u8 lbl_8031F65C[];
extern u8 lbl_8031F6F8[];
extern u8 lbl_8031F728[];
extern u8 lbl_8031F788[];
extern u8 lbl_8031F7AC[];
extern u8 lbl_8031F7D0[];
extern u8 lbl_8031F86C[];
extern u8 lbl_8031F8BC[];
extern u8 lbl_8031F958[];
extern u8 lbl_8031F988[];
extern u8 lbl_8031F9E8[];
extern u8 lbl_8031FA18[];
extern u8 lbl_8031FA3C[];
extern u8 lbl_8031FA78[];
extern u8 lbl_8031FAA8[];

void* gCrawlerDescriptorTable[24] = {
    lbl_8031F3A0, lbl_8031F46C, lbl_8031F3D0, lbl_8031F4CC,
    lbl_8031F424, lbl_8031F5EC, lbl_8031F52C, lbl_8031F65C,
    lbl_8031F6F8, lbl_8031F7AC, lbl_8031F788, lbl_8031F728,
    lbl_8031F7AC, lbl_8031F86C, lbl_8031F7D0, lbl_8031F8BC,
    lbl_8031F958, lbl_8031FA18, lbl_8031F9E8, lbl_8031F988,
    lbl_8031FA3C, lbl_8031FAA8, lbl_8031FA78, lbl_8031F65C,
};

u8 gCrawlerSpeedThresholds[] = {
    0x3F, 0x99, 0x99, 0x9A, 0x3F, 0x4C, 0xCC, 0xCD, 0x38, 0xD1, 0xB7, 0x17,
    0x3F, 0x99, 0x99, 0x9A, 0x3F, 0x4C, 0xCC, 0xCD, 0x38, 0xD1, 0xB7, 0x17,
    0x3F, 0x99, 0x99, 0x9A, 0x3F, 0x4C, 0xCC, 0xCD, 0x38, 0xD1, 0xB7, 0x17,
    0x00, 0x00, 0x00, 0x00,
};

u8 gCrawlerSeqTable[] = {
    0x40, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
    0x3F, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x02, 0x00,
    0x3F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x04, 0x04, 0x00,
    0x3F, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x04, 0x05, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00,
};

extern u8 lbl_803DBD00[];
extern u8 lbl_803DBD08[];
extern u8 lbl_803DBD10[];
extern u8 lbl_803DBD18[];
extern u8 lbl_803DBD20[];
extern u8 lbl_803DBD34[];
extern u8 lbl_803DBD38[];
extern u8 lbl_8031FC40[];
extern u8 lbl_8031FCE8[];

void* gCrawlerModelChainIds[] = {
    lbl_803DBD00, lbl_803DBD08, lbl_803DBD10, lbl_803DBD18, lbl_803DBD20,
};

u8* gCrawlerReactionTables[] = {
    lbl_8031FC40, lbl_803DBD34, lbl_8031FCE8, lbl_803DBD38,
};
u8 lbl_8031FBB8[0x18] = { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x06 };
u8 lbl_8031FBD0[0x18] = { 0x00, 0x00, 0x00, 0x0c, 0x00, 0x00, 0x00, 0x0d, 0x00, 0x00, 0x00, 0x0e, 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x11 };
u8 lbl_8031FBE8[0x18] = { 0x00, 0x00, 0x00, 0x12, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x16, 0x00, 0x00, 0x00, 0x17 };
u8 lbl_8031FC00[0x18] = { 0x00, 0x00, 0x00, 0x18, 0x00, 0x00, 0x00, 0x19, 0x00, 0x00, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x1b, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x1d };
u8 lbl_8031FC18[0x14] = { 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x0b };
u8 lbl_8031FC40[0xa8] = { 0x3f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x07, 0x07, 0x07, 0x00, 0x40, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0xcc, 0xcc, 0xcd, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x3e, 0xcc, 0xcc, 0xcd, 0x00, 0x00, 0x00, 0x01, 0x02, 0x02, 0x02, 0x00, 0x3f, 0x33, 0x33, 0x33, 0x00, 0x00, 0x00, 0x03, 0x03, 0x03, 0x09, 0x00, 0x3f, 0x33, 0x33, 0x33, 0x00, 0x00, 0x00, 0x03, 0x08, 0x08, 0x08, 0x00, 0x3f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x07, 0x07, 0x07, 0x00, 0x40, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0xcc, 0xcc, 0xcd, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x3e, 0xcc, 0xcc, 0xcd, 0x00, 0x00, 0x00, 0x01, 0x02, 0x02, 0x02, 0x00, 0x3f, 0xa6, 0x66, 0x66, 0x00, 0x00, 0x00, 0x03, 0x04, 0x04, 0x09, 0x00, 0x3f, 0x33, 0x33, 0x33, 0x00, 0x00, 0x00, 0x03, 0x08, 0x08, 0x08, 0x00, 0x3f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x07, 0x07, 0x07, 0x00, 0x40, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
u8 lbl_8031FCE8[0x60] = { 0x3f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x07, 0x07, 0x07, 0x00, 0x40, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3e, 0xcc, 0xcc, 0xcd, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00, 0x3f, 0x19, 0x99, 0x9a, 0x00, 0x00, 0x00, 0x01, 0x02, 0x02, 0x02, 0x00, 0x3f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x09, 0x09, 0x09, 0x00, 0x3f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x08, 0x08, 0x08, 0x00, 0x3f, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x07, 0x07, 0x07, 0x00, 0x40, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
