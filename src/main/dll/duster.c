/*
 * duster - a baddie-AI DLL hosting several creature behaviours that all
 * drive the shared BaddieState control record (obj+0xB8 extra block,
 * accessed via gBaddieControlInterface). Each creature contributes its
 * own init/update/freeze-event handlers:
 *   - rachnop (rachnopInit / fn_801557D4 / fn_80155884 / fn_80155948 /
 *     rachnopUpdateWhileFrozen): wall-crawling spider; fn_801554B4 probes
 *     the surrounding geometry (objBboxFn_800640cc) to find a wall face,
 *     then drives roll/charge moves toward the tracked player.
 *   - pollen spit (pollenFn_80155b10): spawns a projectile setup object
 *     (Obj_AllocObjectSetup/Obj_SetupObject, type 0x47b) aimed at the
 *     tracked target with randomised speed.
 *   - day/night gated mover (baddieInit_80156188 / fn_80155F20 /
 *     fn_80156010 / timeOfDayFn_80155cf8 / baddieUpdateWhileFrozen_80155e10):
 *     switches move sets by sky time-of-day.
 *   - whirlpool/water creature (wbInit / fn_8015625C / fn_8015652C /
 *     wbUpdateWhileFrozen): path-following (RomCurveWalker) flyer/swimmer
 *     with buoyancy clamping and periodic decoy sfx.
 *   - mutated EBA (mutatedEbaInit / fn_80156B0C / fn_80156C34 / fn_80156950
 *     / mutatedEbaUpdateWhileFrozen): move-table sequenced attacker
 *     (gDusterEbaMoveTable entries, 0xC bytes each).
 *   - hooded Zyck flyer (fn_80156DA0 / hoodedZyckUpdateWhileFrozen):
 *     line-probes the ground each frame and toggles its move/visibility.
 *
 * Shared idioms: controlFlags bit 0x40000000 = "move just landed / can
 * react this frame"; unk2E4 bit 0x10000 = facing/tracking latch;
 * seqEntryIndex is the per-creature phase counter. SFX ids identify each
 * creature's voice set (fox_*, en_*, watery_*, foxcom_*).
 */
#include "main/audio/sfx_ids.h"
#include "main/audio/sfx.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/dll/baddie_state.h"
#include "main/dll/baddie_setmove.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objhits.h"
#include "main/sky_interface.h"
#include "main/gameplay_runtime.h"
#include "main/dll/dll_00C9_enemy.h"
#include "main/dll/objfsa.h"

/*
 * DusterState - file-local overlay naming the PER-FAMILY scratch that
 * baddie_state.h leaves raw for the duster creatures. phaseTimer/decoyTimer
 * are f32 per-frame countdown timers; turnDelta is the hooded-zyck per-frame
 * rotY step.
 */
typedef struct DusterState {
    u8 pad00[0x2F8];
    u16 moveEventFired; /* 0x2F8 nonzero = current move fired its progress event this frame */
    u8 pad2FA[0x324 - 0x2FA];
    f32 phaseTimer;   /* 0x324 */
    f32 decoyTimer;   /* 0x328 */
    u8 pad32C[0x338 - 0x32C];
    u16 turnDelta;    /* 0x338 hooded-zyck per-frame rotY step */
    /*
     * 0x344..0x364: the wall/plane block fn_801554B4 writes from a bbox probe
     * hit and the crawl helpers read back. planeNormal (0x344) is passed by
     * address to the PSVEC helpers, so it stays raw; the rest are scalar-only.
     */
    u8 pad33A[0x350 - 0x33A];
    f32 planeNormalW;   /* 0x350 4th probe component (hit[10]) */
    f32 planeAxisRatio; /* 0x354 anchor->plane projection ratio */
    f32 planeAnchorY;   /* 0x358 max(hit[3],hit[4]) */
    f32 planeBoundMin;  /* 0x35C min(hit[15],hit[16]) */
    f32 planeAnchorX;   /* 0x360 hit[1] */
    f32 planeAnchorZ;   /* 0x364 hit[5] */
} DusterState;

#pragma dont_inline on

extern int getAngle(float y, float x);
extern void* Obj_AllocObjectSetup(int size, int b);
extern int Obj_SetupObject();
extern int Obj_IsLoadingLocked(void);
extern int objBboxFn_800640cc();
extern void fn_8014CD1C(int obj, int state, int moveId, f32 a, f32 b, int c);

extern char lbl_803DBCD8;
extern void fn_80154D0C(int, int, u16*, float*);
extern u32 fn_80154FB4(short*, int, u32, double);
extern int fn_80169EF4(float* src, float* dst, f32 speed, char flag, f32 arc);
extern void PSVECSubtract(f32 *a, f32 *b, f32 *out);
extern void PSVECNormalize(f32 *in, f32 *out);
extern f32 PSVECDotProduct(f32 * a, f32 * b);
extern void PSVECCrossProduct(f32 *a, f32 *b, f32 *out);
extern u32 fn_80295CBC();
extern f32 gDusterWallProbeOffsets[];
extern u8 gDusterEbaMoveTable[];
extern f32 timeDelta;
extern f32 lbl_803E2A00;
extern f32 lbl_803E2A04;
extern const f32 lbl_803E2A20;
extern const f32 lbl_803E2A24;
extern const f32 lbl_803E2A28;
extern const f32 lbl_803E2A2C;
extern const f32 lbl_803E2A30;
extern const f32 lbl_803E2A34;
extern const f32 lbl_803E2A38;
extern const f32 lbl_803E2A3C;
extern const f32 lbl_803E2A40;
extern const f32 lbl_803E2A48;
extern const f32 lbl_803E2A4C;
extern const f32 lbl_803E2A50;
extern const f32 lbl_803E2A54;
extern const f32 lbl_803E2A58;
extern const f32 lbl_803E2A60;
extern const f32 gDusterDayStartSeconds;
extern const f32 gDusterDayEndSeconds;
extern const f32 lbl_803E2A78;
extern const f32 lbl_803E2A7C;
extern const f32 lbl_803E2A80;
extern f32 lbl_803E2B18;
extern const f32 lbl_803E2A5C;
extern const f32 lbl_803E2A84;
extern const f32 lbl_803E2A88;
extern const f32 lbl_803E2A8C;
extern const f32 lbl_803E2A90;
extern const f32 lbl_803E2A98;
extern const f32 lbl_803E2AA8;
extern const f32 lbl_803E2AAC;
extern const f32 lbl_803E2AB0;
extern const f32 lbl_803E2AB4;
extern const f32 lbl_803E2AB8;
extern const f32 lbl_803E2ABC;
extern const f32 lbl_803E2AC0;
extern const f32 lbl_803E2AC4;
extern const f32 lbl_803E2AC8;
extern const f32 lbl_803E2ACC;
extern const f32 lbl_803E2AD0;
extern const f32 lbl_803E2AD4;
extern const f32 lbl_803E2AD8;
extern const f32 lbl_803E2ADC;
extern f32 lbl_803E2AE0;
extern const f32 lbl_803E2AE4;
extern const f32 lbl_803E2AE8;
extern const f32 lbl_803E2AEC;
extern const f32 lbl_803E2AF0;
extern const f32 lbl_803E2AF4;
extern const f32 lbl_803E2AF8;
extern const f32 lbl_803E2AFC;
extern const f32 lbl_803E2B00;
extern const f32 lbl_803E2B04;
extern const f32 lbl_803E2B38;
extern const f32 lbl_803E2B3C;
extern const f32 lbl_803E2B40;
extern const f32 lbl_803E2B44;
extern f32 lbl_803DBCEC;

#pragma opt_common_subs off
void fn_8015536C(float* outPos, float* anchor, float lateral, float height)
{
    float hi;
    float lo;
    float sideAxis[3];
    float up[3];
    float upConst;
    float scale;

    hi = anchor[6] - lbl_803E2A20;
    if (height > hi)
    {
        height = hi;
    }
    else
    {
        lo = lbl_803E2A24 + anchor[5];
        if (height < lo)
        {
            height = lo;
        }
    }
    if (anchor[4] > lbl_803E2A00)
    {
        hi = anchor[4] - lbl_803E2A20;
        lo = lbl_803E2A20;
    }
    else
    {
        hi = lbl_803E2A28;
        lo = lbl_803E2A20 + anchor[4];
    }
    if (lateral > hi)
    {
        lateral = hi;
    }
    else
    {
        if (lateral < lo)
        {
            lateral = lo;
        }
    }
    outPos[1] = height;
    upConst = lbl_803E2A00;
    up[0] = upConst;
    up[1] = lbl_803E2A04;
    up[2] = upConst;
    PSVECCrossProduct(up, anchor, sideAxis);
    PSVECNormalize(sideAxis, sideAxis);
    *outPos = lateral * sideAxis[0] + anchor[7];
    outPos[2] = lateral * sideAxis[2] + anchor[8];
    scale = lbl_803E2A2C;
    *outPos = scale * *anchor + *outPos;
    outPos[1] = scale * anchor[1] + outPos[1];
    outPos[2] = scale * anchor[2] + outPos[2];
}
#pragma opt_common_subs reset

void fn_801554B4(int* obj, int state)
{
    u8 didHit;
    float* probeOffsets;
    int i;
    f32 dot;
    float maxv[3];
    float minv[3];
    float sideAxis0[3];
    float cv[3];
    float av[3];
    float toAnchor[3];
    float bv[3];
    float sideAxis[3];
    float dv[3];
    float hit[18];

    didHit = 0;
    probeOffsets = gDusterWallProbeOffsets;
    for (i = 0; didHit == 0 && i < 4; i++)
    {
        maxv[0] = ((GameObject*)obj)->anim.localPosX + probeOffsets[i * 2 + 0];
        maxv[1] = ((GameObject*)obj)->anim.localPosY;
        maxv[2] = ((GameObject*)obj)->anim.localPosZ + probeOffsets[i * 2 + 1];
        minv[0] = ((GameObject*)obj)->anim.localPosX - probeOffsets[i * 2 + 0];
        minv[1] = ((GameObject*)obj)->anim.localPosY;
        minv[2] = ((GameObject*)obj)->anim.localPosZ - probeOffsets[i * 2 + 1];
        didHit = objBboxFn_800640cc(maxv, minv, lbl_803E2A00, 3, hit, obj, 5, 3, 0xff, 0);
    }
    if (didHit != 0)
    {
        ((GameObject*)obj)->anim.localPosX = (hit[17] - lbl_803E2A20) * ((minv[0] - maxv[0]) / lbl_803E2A24) + maxv[0];
        ((GameObject*)obj)->anim.localPosZ = (hit[17] - lbl_803E2A20) * ((minv[2] - maxv[2]) / lbl_803E2A24) + maxv[2];
        *(float*)(state + 0x344) = hit[7];
        *(float*)(state + 0x348) = hit[8];
        *(float*)(state + 0x34c) = hit[9];
        ((DusterState*)state)->planeNormalW = hit[10];
        ((DusterState*)state)->planeAnchorY = (hit[3] > hit[4]) ? hit[3] : hit[4];
        ((DusterState*)state)->planeBoundMin = (hit[15] < hit[16]) ? hit[15] : hit[16];
        av[0] = lbl_803E2A00;
        av[1] = lbl_803E2A04;
        av[2] = lbl_803E2A00;
        PSVECCrossProduct(av, (float*)(state + 0x344), sideAxis0);
        PSVECNormalize(sideAxis0, sideAxis0);
        ((DusterState*)state)->planeAnchorX = hit[1];
        ((DusterState*)state)->planeAnchorZ = hit[5];
        cv[0] = hit[2];
        cv[2] = hit[6];
        bv[0] = ((DusterState*)state)->planeAnchorX;
        bv[1] = ((DusterState*)state)->planeAnchorY;
        bv[2] = ((DusterState*)state)->planeAnchorZ;
        PSVECSubtract(bv, cv, toAnchor);
        dot = PSVECDotProduct(toAnchor, (float*)(state + 0x344));
        bv[0] = *(float*)(state + 0x344) * dot + cv[0];
        bv[1] = *(float*)(state + 0x348) * dot + cv[1];
        bv[2] = *(float*)(state + 0x34c) * dot + cv[2];
        dv[0] = lbl_803E2A00;
        dv[1] = lbl_803E2A04;
        dv[2] = lbl_803E2A00;
        PSVECCrossProduct(dv, (float*)(state + 0x344), sideAxis);
        PSVECNormalize(sideAxis, sideAxis);
        if (lbl_803E2A00 != sideAxis[0])
        {
            ((DusterState*)state)->planeAxisRatio = (cv[0] - ((DusterState*)state)->planeAnchorX) / sideAxis[0];
        }
        else
        {
            ((DusterState*)state)->planeAxisRatio = (cv[2] - ((DusterState*)state)->planeAnchorZ) / sideAxis[2];
        }
        ((BaddieState*)state)->seqEntryIndex = 1;
    }
}

void rachnopUpdateWhileFrozen(u32 obj, int state, u32 unused, int eventKind)
{
    if (eventKind == 0x10)
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x20;
    }
    else if (eventKind != 0x11)
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 8;
        Sfx_PlayFromObject(obj, SFXfox_runbreath2);
        ((BaddieState*)state)->hitCounter = 0;
    }
    return;
}

void fn_801557D4(int* obj, int state)
{
    int cond;

    if (((BaddieState*)state)->seqEntryIndex == 0)
    {
        fn_801554B4(obj, state);
    }
    else
    {
        if ((((GameObject*)((BaddieState*)state)->trackedObj)->anim.classId == 1) &&
            (cond = fn_80295CBC(*(int*)&((BaddieState*)state)->trackedObj), cond != 0))
        {
            *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 & ~0x10000LL;
        }
        if ((((BaddieState*)state)->controlFlags & 0x40000000) != 0)
        {
            Sfx_PlayFromObject((u32)obj, SFXfox_runbreath1);
            Baddie_SetMove((int)obj, state, 2, lbl_803E2A04, 0, 0);
        }
    }
    return;
}

void fn_80155884(int* obj, int state)
{
    int cond;

    if (((BaddieState*)state)->seqEntryIndex == 0)
    {
        fn_801554B4(obj, state);
    }
    else if ((((GameObject*)((BaddieState*)state)->trackedObj)->anim.classId == 1) &&
        (cond = fn_80295CBC(*(int*)&((BaddieState*)state)->trackedObj), cond != 0))
    {
        fn_80154FB4((short*)obj, state, 0x19, (double)lbl_803E2A30);
        if ((((BaddieState*)state)->controlFlags & 0x40000000) != 0)
        {
            Baddie_SetMove((int)obj, state, 0, lbl_803E2A30, 0, 0);
            Sfx_PlayFromObject((u32)obj, SFXfox_roll4);
        }
    }
    else
    {
        *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 | 0x10000LL;
    }
    return;
}

#pragma opt_common_subs off
void fn_80155948(int* obj, int state)
{
    short move;
    int cond;
    u16 outIds[2];
    float outVec[3];

    if (((BaddieState*)state)->seqEntryIndex == 0)
    {
        fn_801554B4(obj, state);
    }
    else if ((((GameObject*)((BaddieState*)state)->trackedObj)->anim.classId == 1) &&
        (cond = fn_80295CBC(*(int*)&((BaddieState*)state)->trackedObj), cond != 0))
    {
        ObjHits_SetHitVolumeSlot((int)obj, 10, 1, 0);
        move = *(short*)(obj + 0x28);
        if (move == 3)
        {
            fn_80154FB4((short*)obj, state, 0x19, (double)lbl_803E2A00);
        }
        else if ((move == 0) || (move == 1))
        {
            fn_80154FB4((short*)obj, state, 0x19, (double)lbl_803E2A30);
        }
        fn_80154D0C((int)obj, state, outIds, outVec);
        if (((((BaddieState*)state)->controlFlags & 0x40000000) != 0) ||
            ((outIds[0] < 0x5dc && (*(short*)(obj + 0x28) != 1))))
        {
            if (outIds[0] < 0x5dc)
            {
                Sfx_PlayFromObject((u32)obj, SFXfox_roll3);
                Baddie_SetMove((int)obj, state, 1, lbl_803E2A30, 0, 0);
            }
            else
            {
                Baddie_SetMove((int)obj, state, 3, lbl_803E2A30, 0, 0);
            }
        }
    }
    else
    {
        *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 | 0x10000LL;
    }
    return;
}
#pragma opt_common_subs reset


void rachnopInit(u32 unused, int state)
{
    float fa;
    float fb;

    ((BaddieState*)state)->speedScale = lbl_803E2A34;
    *(u32*)&((BaddieState*)state)->unk2E4 = 1;
    fa = lbl_803E2A38;
    ((BaddieState*)state)->unk308 = lbl_803E2A38;
    ((BaddieState*)state)->animDeltaScale = fa;
    ((BaddieState*)state)->unk304 = lbl_803E2A3C;
    ((BaddieState*)state)->unk320 = 0;
    fb = lbl_803E2A40;
    *(float*)&((BaddieState*)state)->eventFlags = lbl_803E2A40;
    ((BaddieState*)state)->unk321 = 4;
    fa = lbl_803E2A04;
    ((BaddieState*)state)->unk318 = lbl_803E2A04;
    ((BaddieState*)state)->unk322 = 0;
    ((BaddieState*)state)->unk31C = fb;
    ((DusterState*)state)->phaseTimer = lbl_803E2A00;
    ((BaddieState*)state)->seqEntryIndex = 0;
    ((BaddieState*)state)->inWhirlpoolGroup = 0;
    ((BaddieState*)state)->pathStep = fa;
    return;
}

void pollenFn_80155b10(u32 obj, int state)
{
    u32 loadLocked;
    int ref;
    u16* setup;
    f32 spd;
    f32 t;
    f32 dx;
    f32 dz;
    f32 a[3];
    f32 b[3];
    float velXZ;
    float cosVal;
    float velY;
    float cosPitch;

    loadLocked = Obj_IsLoadingLocked();
    if ((loadLocked & 0xff) != 0)
    {
        a[0] = ((GameObject*)obj)->anim.localPosX;
        a[1] = lbl_803E2A48 + ((GameObject*)obj)->anim.localPosY;
        a[2] = ((GameObject*)obj)->anim.localPosZ;
        ref = *(int*)&((BaddieState*)state)->trackedObj;
        b[0] = ((GameObject*)ref)->anim.localPosX;
        b[1] = lbl_803E2A4C + ((GameObject*)ref)->anim.localPosY;
        b[2] = ((GameObject*)ref)->anim.localPosZ;
        spd = lbl_803E2A50 *
            (lbl_803E2A58 * (f32)(int)
        randomGetRange(-10, 10) + lbl_803E2A54
        )
        ;
        ref = fn_80169EF4(a, b, spd, 1, lbl_803E2A5C);
        fn_80293018(ref, &cosVal, &velXZ);
        velXZ = velXZ * spd;
        cosVal = cosVal * spd;
        dx = b[0] - ((GameObject*)obj)->anim.localPosX;
        dz = b[2] - ((GameObject*)obj)->anim.localPosZ;
        if (lbl_803E2A60 != dz)
        {
            ref = getAngle(dx, dz);
            fn_80293018(ref, &cosPitch, &velY);
            t = velXZ;
            velY = velY * t;
            velXZ = t * cosPitch;
        }
        else
        {
            velY = lbl_803E2A60;
        }
        setup = Obj_AllocObjectSetup(0x24, 0x47b);
        ((ObjPlacement*)setup)->posX = a[0];
        ((ObjPlacement*)setup)->posY = a[1];
        ((ObjPlacement*)setup)->posZ = a[2];
        ((ObjPlacement*)setup)->color[0] = 1;
        ((ObjPlacement*)setup)->color[1] = 1;
        ((ObjPlacement*)setup)->color[2] = 0xff;
        ((ObjPlacement*)setup)->color[3] = 0xff;
        ref = Obj_SetupObject(setup, 5, -1, -1, 0);
        if ((void*)ref != NULL)
        {
            ((GameObject*)ref)->anim.velocityX = velXZ;
            ((GameObject*)ref)->anim.velocityY = cosVal;
            ((GameObject*)ref)->anim.velocityZ = velY;
            *(u32*)&((GameObject*)ref)->ownerObj = obj;
            Sfx_PlayFromObject(obj, SFXfox_climbgrunt2);
        }
    }
    return;
}

void timeOfDayFn_80155cf8(int obj, int state)
{
    u8 isDaytime;
    float timeInfo[4];

    (*gSkyInterface)->getTimeOfDay(timeInfo);
    if ((timeInfo[0] >= gDusterDayStartSeconds) && (timeInfo[0] <= gDusterDayEndSeconds))
    {
        isDaytime = 1;
    }
    else
    {
        isDaytime = 0;
    }
    if ((isDaytime != 0) && (((BaddieState*)state)->seqEntryIndex == 0))
    {
        ((BaddieState*)state)->seqEntryIndex = 1;
        *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 | 0x10000LL;
        Baddie_SetMove(obj, state, 1, lbl_803E2A78, 0, 0);
    }
    else if ((isDaytime == 0) && (((BaddieState*)state)->seqEntryIndex == 2))
    {
        ((BaddieState*)state)->seqEntryIndex = 1;
        *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 | 0x10000LL;
        Baddie_SetMove(obj, state, 3, lbl_803E2A78, 0, 0);
    }
    return;
}

void baddieUpdateWhileFrozen_80155e10(u32 obj, int state, u32 unused1, int eventKind, u32 unused2,
                                      int damage)
{
    if (eventKind == 0x10)
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x20;
    }
    else if (eventKind == 0x11)
    {
        if ((((BaddieState*)state)->seqEntryIndex == 2) && (((GameObject*)obj)->anim.currentMove != 5))
        {
            Baddie_SetMove(obj, state, 5, lbl_803E2A7C, 0, 0);
        }
    }
    else if ((((GameObject*)obj)->anim.currentMove == 5) || (((GameObject*)obj)->anim.currentMove == 4))
    {
        if (damage > (int)(u32)((BaddieState*)state)->hitCounter)
        {
            ((BaddieState*)state)->hitCounter = 0;
            Sfx_PlayFromObject(obj, SFXfox_climbgrunt1);
            Sfx_PlayFromObject(obj, SFXen_blkscrp6);
        }
        else
        {
            ((BaddieState*)state)->hitCounter = ((BaddieState*)state)->hitCounter - damage;
            Sfx_PlayFromObject(obj, SFXfox_roll1);
            Sfx_PlayFromObject(obj, SFXen_blkscrp6);
        }
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 8;
    }
    else
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x10;
        Sfx_PlayFromObject(obj, SFXfox_roll2);
    }
    return;
}

void fn_80155F20(int obj, int state)
{
    ((DusterState*)state)->phaseTimer = lbl_803E2A60;
    if ((((BaddieState*)state)->controlFlags & 0x40000000) != 0)
    {
        if (((BaddieState*)state)->seqEntryIndex == 1)
        {
            if (((GameObject*)obj)->anim.currentMove == 1)
            {
                ((BaddieState*)state)->seqEntryIndex = 2;
                *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 & ~0x10000LL;
            }
            else if (((GameObject*)obj)->anim.currentMove == 3)
            {
                ((BaddieState*)state)->seqEntryIndex = 0;
                *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 | 0x10000LL;
                Baddie_SetMove(obj, state, 0, lbl_803E2A54, 0, 0);
            }
        }
        else if ((((BaddieState*)state)->seqEntryIndex == 2) && (((GameObject*)obj)->anim.currentMove != 2))
        {
            Baddie_SetMove(obj, state, 2, lbl_803E2A54, 0, 0);
        }
    }
    timeOfDayFn_80155cf8(obj, state);
    return;
}

void fn_80156010(u32 obj, int state)
{
    u8 timerExpired;

    timerExpired = 0;
    ((DusterState*)state)->phaseTimer = ((DusterState*)state)->phaseTimer - timeDelta;
    if (((DusterState*)state)->phaseTimer <= lbl_803E2A60)
    {
        timerExpired = 1;
        ((DusterState*)state)->phaseTimer = *(f32 *)&lbl_803E2A60;
    }
    if ((((BaddieState*)state)->controlFlags & 0x40000000) != 0)
    {
        if (((GameObject*)obj)->anim.currentMove == 4)
        {
            pollenFn_80155b10(obj, state);
            ((DusterState*)state)->phaseTimer = lbl_803E2A80;
            Baddie_SetMove(obj, state, 5, lbl_803E2A54, 0, 0);
        }
        else if ((((GameObject*)obj)->anim.currentMove == 5) && (timerExpired))
        {
            Baddie_SetMove(obj, state, 6, lbl_803E2A54, 0, 0);
            Sfx_PlayFromObject(obj, SFXfox_fightbreath2);
        }
        else if (((GameObject*)obj)->anim.currentMove == 6)
        {
            Baddie_SetMove(obj, state, 2, lbl_803E2A54, 0, 0);
            ((DusterState*)state)->phaseTimer = lbl_803E2A80;
        }
        else if ((((GameObject*)obj)->anim.currentMove == 2) && (timerExpired) && ((((BaddieState*)state)->controlFlags & 0x4000000) != 0))
        {
            Baddie_SetMove(obj, state, 4, lbl_803E2A54, 0, 0);
            Sfx_PlayFromObject(obj, SFXfox_fightbreath1);
        }
    }
    timeOfDayFn_80155cf8(obj, state);
    return;
}

void baddieInit_80156188(u32 unused, int state)
{
    float fa;
    float fb;

    ((BaddieState*)state)->speedScale = lbl_803E2A84;
    *(u32*)&((BaddieState*)state)->unk2E4 = 1;
    ((BaddieState*)state)->unk308 = lbl_803E2A58;
    ((BaddieState*)state)->animDeltaScale = lbl_803E2A88;
    ((BaddieState*)state)->unk304 = lbl_803E2A8C;
    ((BaddieState*)state)->unk320 = 0;
    fb = lbl_803E2A90;
    *(float*)&((BaddieState*)state)->eventFlags = lbl_803E2A90;
    ((BaddieState*)state)->unk321 = 7;
    fa = lbl_803E2A54;
    ((BaddieState*)state)->unk318 = lbl_803E2A54;
    ((BaddieState*)state)->unk322 = 0;
    ((BaddieState*)state)->unk31C = fb;
    ((BaddieState*)state)->seqEntryIndex = 0;
    ((DusterState*)state)->phaseTimer = lbl_803E2A60;
    ((BaddieState*)state)->pathStep = fa;
    return;
}

void wbUpdateWhileFrozen(u32 obj, int state, u32 unused, int eventKind)
{
    if (eventKind != 0x11)
    {
        if (eventKind == 0x10)
        {
            ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x20;
        }
        else
        {
            Sfx_PlayFromObject(obj, SFXfox_cough3);
            ((BaddieState*)state)->hitCounter = 0;
            *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 | 0x20;
            ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 8;
        }
    }
    return;
}

void fn_8015625C(u32 obj, int state)
{
    u32 randVal;
    GameObject* tracked;
    f32 moveSpeed;
    ObjHitsPriorityState* hitState;

    if (((DusterState*)state)->decoyTimer > lbl_803E2AA8)
    {
        ((DusterState*)state)->decoyTimer = lbl_803E2AAC;
    }
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->suppressOutgoingHits = 0;
    ObjHits_SetHitVolumeSlot(obj, 10, 1, 0);
    if ((((BaddieState*)state)->controlFlags & 0x40000000) != 0)
    {
        Sfx_PlayFromObject(obj, SFXfox_cough4);
    }
    ((DusterState*)state)->decoyTimer = ((DusterState*)state)->decoyTimer - timeDelta;
    if (((DusterState*)state)->decoyTimer <= lbl_803E2A98)
    {
        if ((((BaddieState*)state)->controlFlags & 0x600) != 0)
        {
            randVal = randomGetRange(0x96, 0xfa);
            ((DusterState*)state)->decoyTimer = (float)(int)randVal;
        }
        else
        {
            randVal = randomGetRange(600, 0x352);
            ((DusterState*)state)->decoyTimer = (float)(int)randVal;
        }
        Sfx_PlayFromObject(obj, SFXfoxcom_decoy);
    }
    if ((((BaddieState*)state)->controlFlags & 0x40000000) != 0)
    {
        ObjAnim_SetCurrentMove(obj, 3, lbl_803E2A98, *(u8*)(state + 0x323));
    }
    if (((DusterState*)state)->phaseTimer > lbl_803E2A98)
    {
        ((DusterState*)state)->phaseTimer = ((DusterState*)state)->phaseTimer - timeDelta;
        if (((DusterState*)state)->phaseTimer <= lbl_803E2A98)
        {
            ((DusterState*)state)->phaseTimer = lbl_803E2AB0;
            *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 | 0x10000LL;
        }
    }
    else if ((((BaddieState*)state)->controlFlags & 0x400) != 0)
    {
        ((DusterState*)state)->phaseTimer = lbl_803E2AB0;
    }
    if ((((BaddieState*)state)->controlFlags & 0x8000000) != 0)
    {
        moveSpeed = lbl_803E2AB4;
    }
    else
    {
        tracked = (GameObject*)((BaddieState*)state)->trackedObj;
        moveSpeed = sidekickToy_accelerateTowardTargetXZ(obj, tracked->anim.worldPosX,
                                                         lbl_803E2AB8 + tracked->anim.worldPosY,
                                                         tracked->anim.worldPosZ,
                                                         lbl_803E2ABC, lbl_803E2AC0, lbl_803E2AC4,
                                                         ((BaddieState*)state)->unk304);
    }
    if (((moveSpeed > lbl_803E2A98) && (((GameObject*)obj)->anim.velocityY < lbl_803E2AC8)) ||
        ((((BaddieState*)state)->controlFlags & 0x8000000) != 0))
    {
        ((BaddieState*)state)->seqEntryIndex = 1;
    }
    if ((((BaddieState*)state)->seqEntryIndex != 0) && (moveSpeed > lbl_803E2A98))
    {
        ((BaddieState*)state)->unk308 = lbl_803E2ACC;
        if (((BaddieState*)state)->hitCounter != 0)
        {
            ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY + lbl_803E2AD0;
        }
        if (((GameObject*)obj)->anim.velocityY < lbl_803E2AD4)
        {
            ((GameObject*)obj)->anim.velocityY = lbl_803E2AD4;
        }
        else if (((GameObject*)obj)->anim.velocityY > lbl_803E2AD8)
        {
            ((GameObject*)obj)->anim.velocityY = lbl_803E2AD8;
        }
    }
    else
    {
        ((BaddieState*)state)->seqEntryIndex = 0;
        if (((BaddieState*)state)->unk308 > lbl_803E2ADC)
        {
            ((BaddieState*)state)->unk308 = -(lbl_803E2AE0 * timeDelta - ((BaddieState*)state)->unk308);
        }
    }
    fn_8014CD1C(obj, state, 0x2d, lbl_803E2A98, *(f32*)&lbl_803E2A98, 0);
}

void fn_8015652C(u32 obj, int state)
{
    u32 randVal;
    RomCurveWalker* route;
    ObjPlacement* placement;
    f32 moveSpeed;
    ObjHitsPriorityState* hitState;

    route = *(RomCurveWalker**)state;
    placement = ((GameObject*)obj)->anim.placement;
    hitState = (ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState;
    hitState->suppressOutgoingHits = 0;
    ObjHits_SetHitVolumeSlot(obj, 10, 1, 0);
    if ((((BaddieState*)state)->controlFlags & 0x40000000) != 0)
    {
        Sfx_PlayFromObject(obj, SFXfox_cough4);
    }
    ((DusterState*)state)->decoyTimer = ((DusterState*)state)->decoyTimer - timeDelta;
    if (((DusterState*)state)->decoyTimer <= lbl_803E2A98)
    {
        if ((((BaddieState*)state)->controlFlags & 0x600) != 0)
        {
            randVal = randomGetRange(0x96, 0xfa);
            ((DusterState*)state)->decoyTimer = (float)(int)randVal;
        }
        else
        {
            randVal = randomGetRange(600, 0x352);
            ((DusterState*)state)->decoyTimer = (float)(int)randVal;
        }
        Sfx_PlayFromObject(obj, SFXfoxcom_decoy);
    }
    if ((((BaddieState*)state)->controlFlags & 0x40000000) != 0)
    {
        ObjAnim_SetCurrentMove(obj, 0, lbl_803E2A98, *(u8*)(state + 0x323));
    }
    if (((DusterState*)state)->phaseTimer > lbl_803E2A98)
    {
        ((DusterState*)state)->phaseTimer = ((DusterState*)state)->phaseTimer - timeDelta;
        if (((DusterState*)state)->phaseTimer <= lbl_803E2A98)
        {
            ((DusterState*)state)->phaseTimer = lbl_803E2A98;
        }
    }
    else
    {
        *(u32*)&((BaddieState*)state)->unk2E4 = *(u32*)&((BaddieState*)state)->unk2E4 & ~0x10000LL;
    }
    if ((((BaddieState*)state)->controlFlags & 0x2000) != 0)
    {
        if (((Curve_AdvanceAlongPath(route, ((BaddieState*)state)->pathStep) != 0 ||
                    route->atSegmentEnd != 0) &&
                (*gRomCurveInterface)->goNextPoint(route) != 0) &&
            (*gRomCurveInterface)->initCurve(*(RomCurveWalker**)state, (void*)obj, lbl_803E2AE4,
                                             (int*)&lbl_803DBCD8, -1) != 0)
        {
            ((BaddieState*)state)->controlFlags = ((BaddieState*)state)->controlFlags & ~0x2000LL;
        }
        if ((((BaddieState*)state)->controlFlags & 0x8000000) != 0)
        {
            moveSpeed = lbl_803E2ABC;
        }
        else
        {
            moveSpeed = sidekickToy_accelerateTowardTargetXZ(obj, route->posX, route->posY, route->posZ,
                                                             lbl_803E2ABC, lbl_803E2AC0, lbl_803E2AC4,
                                                             ((BaddieState*)state)->unk304);
        }
    }
    else if ((((BaddieState*)state)->controlFlags & 0x8000000) != 0)
    {
        moveSpeed = lbl_803E2ABC;
    }
    else
    {
        moveSpeed = sidekickToy_accelerateTowardTargetXZ(obj, placement->posX, placement->posY,
                                                         placement->posZ, lbl_803E2ABC, lbl_803E2AC0,
                                                         lbl_803E2AC4,
                                                         ((BaddieState*)state)->unk304);
    }
    if (((moveSpeed > lbl_803E2A98) && (((GameObject*)obj)->anim.velocityY < lbl_803E2AC8)) ||
        ((((BaddieState*)state)->controlFlags & 0x8000000) != 0))
    {
        ((BaddieState*)state)->seqEntryIndex = 1;
    }
    if ((((BaddieState*)state)->seqEntryIndex != 0) && (moveSpeed > lbl_803E2A98))
    {
        ((BaddieState*)state)->unk308 = lbl_803E2ACC;
        if (((BaddieState*)state)->hitCounter != 0)
        {
            ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY + lbl_803E2AD0;
        }
        if (((GameObject*)obj)->anim.velocityY < lbl_803E2AD4)
        {
            ((GameObject*)obj)->anim.velocityY = lbl_803E2AD4;
        }
        else if (((GameObject*)obj)->anim.velocityY > lbl_803E2AD8)
        {
            ((GameObject*)obj)->anim.velocityY = lbl_803E2AD8;
        }
    }
    else
    {
        ((BaddieState*)state)->seqEntryIndex = 0;
        if (((BaddieState*)state)->unk308 > lbl_803E2ADC)
        {
            ((BaddieState*)state)->unk308 = -(lbl_803E2AE0 * timeDelta - ((BaddieState*)state)->unk308);
        }
    }
    fn_8014CD1C(obj, state, 0x2d, lbl_803E2A98, *(f32*)&lbl_803E2A98, 0);
}

void wbInit(u32 unused, int state)
{
    float fa;
    u32 ua;

    ((BaddieState*)state)->speedScale = lbl_803E2AE8;
    *(u32*)&((BaddieState*)state)->unk2E4 = 0x2002b029;
    ((BaddieState*)state)->unk308 = lbl_803E2ACC;
    ((BaddieState*)state)->animDeltaScale = lbl_803E2AEC;
    ((BaddieState*)state)->unk304 = lbl_803E2AF0;
    ((BaddieState*)state)->unk320 = 0;
    fa = lbl_803E2AF4;
    *(float*)&((BaddieState*)state)->eventFlags = lbl_803E2AF4;
    ((BaddieState*)state)->unk321 = 1;
    ((BaddieState*)state)->unk318 = fa;
    ((BaddieState*)state)->unk322 = 2;
    ((BaddieState*)state)->unk31C = fa;
    ua = randomGetRange(0x78, 0x1e0);
    ((DusterState*)state)->decoyTimer =
        (float)(int)ua;
    return;
}

void fn_80156950(u32 obj, int state)
{
    switch (((GameObject*)obj)->anim.currentMove)
    {
    case 5:
        if (((DusterState*)state)->moveEventFired != 0)
        {
            Sfx_PlayFromObject(obj, SFXfox_fightbreath3);
        }
        break;
    case 6:
        if (((DusterState*)state)->moveEventFired != 0)
        {
            Sfx_PlayFromObject(obj, SFXfox_fightbreath3);
        }
        break;
    case 7:
        if (((DusterState*)state)->moveEventFired != 0)
        {
            if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2AF8)
            {
                Sfx_PlayFromObject(obj, SFXfox_fightbreath3);
            }
            else
            {
                Sfx_PlayFromObject(obj, SFXfox_fightbreath2);
            }
        }
        break;
    case 8:
        if (((DusterState*)state)->moveEventFired != 0)
        {
            if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2AFC)
            {
                Sfx_PlayFromObject(obj, SFXfox_fightbreath1);
            }
            else if (((GameObject*)obj)->anim.currentMoveProgress < lbl_803E2B00)
            {
                Sfx_PlayFromObject(obj, SFXfox_fightbreath4);
            }
            else
            {
                Sfx_PlayFromObject(obj, SFXfox_fightbreath2);
            }
        }
        break;
    }
    return;
}

void mutatedEbaUpdateWhileFrozen(u32 obj, int state, u32 unused, int eventKind)
{
    int move;

    if (eventKind != 0x11)
    {
        if (eventKind == 0x10)
        {
            ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x20;
        }
        else
        {
            if ((((move = ((GameObject*)obj)->anim.currentMove) == 0) || (move == 1)) || (move == 3) || (move == 4))
            {
                Sfx_PlayFromObject(obj, SFXfox_roll2);
                ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x10;
            }
            else
            {
                Baddie_SetMove(obj, state, 4, lbl_803E2B04, 0, 0);
                ((BaddieState*)state)->seqEntryIndex = 0;
                Sfx_PlayFromObject(obj, SFXfox_roll1);
                ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 8;
            }
        }
    }
    return;
}

void fn_80156B0C(u32 obj, int state)
{
    int tblOff;

    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumePriority = 10;
    ((ObjHitsPriorityState*)((GameObject*)obj)->anim.hitReactState)->hitVolumeId = 1;
    if (((((BaddieState*)state)->controlFlags & 0x80000000) != 0) && (((BaddieState*)state)->seqEntryIndex <= 1))
    {
        ((BaddieState*)state)->seqEntryIndex = 1;
        ((BaddieState*)state)->controlFlags = ((BaddieState*)state)->controlFlags | 0x40000000LL;
    }
    if ((((BaddieState*)state)->controlFlags & 0x40000000) != 0)
    {
        ((BaddieState*)state)->seqEntryIndex += 1;
        if (10 < ((BaddieState*)state)->seqEntryIndex)
        {
            ((BaddieState*)state)->seqEntryIndex = 3;
        }
        if (*(u16*)(state + 0x2a0) < 4)
        {
            tblOff = (u32)((BaddieState*)state)->seqEntryIndex * 0xc;
            Baddie_SetMove(obj, state, gDusterEbaMoveTable[tblOff + 8],
                        *(float*)(gDusterEbaMoveTable + tblOff), 0, 0);
        }
        else
        {
            tblOff = (u32)((BaddieState*)state)->seqEntryIndex * 0xc;
            Baddie_SetMove(obj, state, gDusterEbaMoveTable[tblOff + 9],
                        *(float*)(gDusterEbaMoveTable + tblOff), 0, 0);
        }
    }
    fn_80156950(obj, state);
    return;
}

void fn_80156C34(u32 obj, int state)
{
    int tblOff;
    u32 phase;

    if ((((BaddieState*)state)->controlFlags & 0x40000000) != 0)
    {
        phase = ((BaddieState*)state)->seqEntryIndex;
        if (phase == 0)
        {
            ((BaddieState*)state)->seqEntryIndex += 1;
        }
        else if (phase >= 2)
        {
            ((BaddieState*)state)->seqEntryIndex = 0;
        }
        tblOff = (u32)((BaddieState*)state)->seqEntryIndex * 0xc;
        Baddie_SetMove(obj, state, gDusterEbaMoveTable[tblOff + 8],
                    *(float*)(gDusterEbaMoveTable + tblOff), 0, 0);
    }
    fn_80156950(obj, state);
    return;
}

void mutatedEbaInit(u32 unused, int state)
{
    float fa;

    ((BaddieState*)state)->speedScale = lbl_803E2A84;
    *(u32*)&((BaddieState*)state)->unk2E4 = 0x46001;
    ((BaddieState*)state)->unk308 = lbl_803E2A58;
    ((BaddieState*)state)->animDeltaScale = lbl_803E2A88;
    ((BaddieState*)state)->unk304 = lbl_803E2A8C;
    ((BaddieState*)state)->unk320 = 0;
    fa = lbl_803E2A54;
    *(float*)&((BaddieState*)state)->eventFlags = lbl_803E2A54;
    ((BaddieState*)state)->unk321 = 4;
    ((BaddieState*)state)->unk318 = fa;
    ((BaddieState*)state)->unk322 = 3;
    ((BaddieState*)state)->unk31C = fa;
    ((BaddieState*)state)->seqEntryIndex = 1;
    ((BaddieState*)state)->hitCounter = 0xa;
    return;
}

void hoodedZyckUpdateWhileFrozen(u32 obj, int state, u32 unused, int eventKind)
{
    if (eventKind == 0x10)
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 0x20;
    }
    else
    {
        ((BaddieState*)state)->reactionFlags = ((BaddieState*)state)->reactionFlags | 8;
        Sfx_PlayFromObject(obj, SFXwatery_bubble2);
        ((BaddieState*)state)->hitCounter = 0;
    }
    return;
}

void fn_80156DA0(int obj, int state)
{
    bool resetting;
    int groundHit;
    u8 noHit;
    int randBit;
    float toPos[3];
    float fromPos[3];
    float cosYaw;
    float sinYaw;
    float hitOut[22];

    ((DusterState*)state)->phaseTimer = ((DusterState*)state)->phaseTimer - timeDelta;
    if (((DusterState*)state)->phaseTimer <= lbl_803E2B18)
    {
        ((DusterState*)state)->phaseTimer = (float)(int)randomGetRange(0x3c, 0x78);
    }
    if (lbl_803E2B18 != ((DusterState*)state)->decoyTimer)
    {
        ObjHits_DisableObject(obj);
        if (((GameObject*)obj)->anim.currentMove != 5)
        {
            Baddie_SetMove(obj, state, 5, lbl_803DBCEC, 0, 0);
        }
        else if ((((BaddieState*)state)->controlFlags & 0x40000000) != 0)
        {
            ObjHits_EnableObject(obj);
            ((DusterState*)state)->decoyTimer = lbl_803E2B18;
        }
        ((GameObject*)obj)->anim.alpha = 0xff;
        resetting = true;
    }
    else
    {
        resetting = false;
    }
    if (!resetting)
    {
        ((GameObject*)obj)->anim.rotX =
            (short)(((GameObject*)obj)->anim.rotX + ((DusterState*)state)->turnDelta);
        fromPos[0] = ((GameObject*)obj)->anim.localPosX;
        fromPos[1] = ((GameObject*)obj)->anim.localPosY;
        fromPos[2] = ((GameObject*)obj)->anim.localPosZ;
        fn_80292E20((u32)(u16)((GameObject*)obj)->anim.rotX, &sinYaw, &cosYaw);
        toPos[0] = ((GameObject*)obj)->anim.localPosX - lbl_803E2B38 * sinYaw;
        toPos[1] = lbl_803E2B3C + ((GameObject*)obj)->anim.localPosY;
        toPos[2] = ((GameObject*)obj)->anim.localPosZ - lbl_803E2B38 * cosYaw;
        groundHit = objBboxFn_800640cc(fromPos, toPos, lbl_803E2B18, 3, hitOut, obj,
                                   (u32) * (u8*)(state + 0x261), 0xffffffff, 0xff, 0);
        noHit = !(groundHit & 0xff);
        if (!noHit || ((((BaddieState*)state)->controlFlags & 0x40000000) != 0))
        {
            if (noHit && ((GameObject*)obj)->anim.currentMove != 0)
            {
                ((DusterState*)state)->turnDelta = 0;
                Baddie_SetMove(obj, state, 0, lbl_803E2B40, 0, 1);
            }
            else
            {
                float fz;
                Baddie_SetMove(obj, state, 1, lbl_803E2B44, 0, 0);
                fz = lbl_803E2B18;
                ((GameObject*)obj)->anim.velocityX = fz;
                ((GameObject*)obj)->anim.velocityY = fz;
                ((GameObject*)obj)->anim.velocityZ = fz;
                randBit = randomGetRange(0, 1);
                ((DusterState*)state)->turnDelta = (u16)((randBit - 1) * 0x12c);
            }
        }
        ((GameObject*)obj)->anim.rotY = ((BaddieState*)state)->spawnRotY;
        ((GameObject*)obj)->anim.rotZ = ((BaddieState*)state)->spawnRotZ;
    }
    return;
}

u8 gDusterEbaMoveTable[] = {
    0x3F, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x03, 0x03, 0x00,
    0x40, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x3E, 0xCC, 0xCC, 0xCD, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0x01, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x07, 0x07, 0x07, 0x00,
    0x40, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x08, 0x08, 0x08, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x02, 0x02, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x05, 0x06, 0x05, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x07, 0x07, 0x07, 0x00,
    0x40, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x08, 0x08, 0x08, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x05, 0x06, 0x06, 0x00,
    0x00, 0x00, 0x00, 0x00,
};
