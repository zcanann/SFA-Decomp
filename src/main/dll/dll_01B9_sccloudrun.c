/* === moved from main/dll/CR/CRsnowbike.c [801DBFA0-801DC310) (TU re-split, docs/boundary_audit.md) === */
#include "main/obj_placement.h"
#include "main/game_object.h"


typedef struct ScMusictreePlacement
{
    u8 pad0[0x20 - 0x0];
    u8 unk20;
    u8 unk21;
    u8 unk22;
    u8 pad23[0x28 - 0x23];
} ScMusictreePlacement;




typedef struct ScMusictreeSpawnAmbientEffectPlacement
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
    u8 pad8[0x20 - 0x8];
    u8 unk20;
    u8 unk21;
    u8 unk22;
    u8 pad23[0x28 - 0x23];
} ScMusictreeSpawnAmbientEffectPlacement;


/* sc_levelcontrol_getExtraSize == 0x24 (CloudRunner race level control). */
typedef struct ScLevelControlState
{
    f32 fogNear; /* 0x00: enableHeavyFog base */
    f32 fog04; /* 0x04 */
    f32 fog08; /* 0x08 */
    f32 fog0C; /* 0x0c */
    f32 timer10; /* 0x10 */
    f32 fadeTimer; /* 0x14 */
    u8 pad18[4];
    u8 musicStep; /* 0x1c: index into the lbl_803DC060 cue table */
    u8 mode; /* 0x1d: anim-event mode latch */
    u8 areaCell; /* 0x1e: 0xff until the player enters map 0xe */
    u8 flags1F; /* 0x1f */
    u8 musicTrack; /* 0x20 */
    s8 unk21; /* 0x21 */
    u8 flags22; /* 0x22: SnowFlags22 overlay (bit 7) */
    u8 pad23;
} ScLevelControlState;





/*
 * --INFO--
 *
 * Function: sh_emptytumblew_init
 * EN v1.0 Address: 0x801DAFDC
 * EN v1.0 Size: 1440b
 * EN v1.1 Address: 0x801DB048
 * EN v1.1 Size: 1080b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */



/*
 * --INFO--
 *
 * Function: FUN_801db580
 * EN v1.0 Address: 0x801DB580
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x801DB594
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/*
 * --INFO--
 *
 * Function: sc_levelcontrol_processAnimEvents
 * EN v1.0 Address: 0x801DB670
 * EN v1.0 Size: 324b
 * EN v1.1 Address: 0x801DB688
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: sc_levelcontrol_setAnimEventState
 * EN v1.0 Address: 0x801DB7B4
 * EN v1.0 Size: 272b
 * EN v1.1 Address: 0x801DB7E8
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_801db8c4
 * EN v1.0 Address: 0x801DB8C4
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x801DB904
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
#pragma peephole off


/*
 * --INFO--
 *
 * Function: FUN_801db924
 * EN v1.0 Address: 0x801DB924
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801DB964
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling on
#pragma peephole on


/* Trivial 4b 0-arg blr leaves. */
#pragma scheduling off
#pragma peephole off



void sc_musictree_free(void);

void sc_musictree_hitDetect(void);

/* 8b "li r3, N; blr" returners. */
int sc_musictree_getExtraSize(void);
int sc_musictree_getObjectTypeId(void);

/* Pattern wrappers. */

/* render-with-objRenderFn_8003b8f4 pattern. */
extern void objRenderFn_8003b8f4(f32);


extern void fn_8003B608(int a, int b, int c);
extern int ObjPath_GetPointWorldPosition(int obj, int idx, f32* x, f32* y, f32* z, int p6);
extern f32 lbl_803E558C;

typedef struct SCMusicTreeState
{
    int ambientEffect[3];
    f32 pathPoint[3][3];
    f32 proximityBurstTimer;
    f32 animSpeed;
    f32 scale;
    f32 proximityCooldown;
    f32 hitCooldown;
    int hitCooldownState;
    u16 hearRadius;
    s16 previousDistance;
    u8 flags;
    u8 pad4D[0x50 - 0x4D];
} SCMusicTreeState;

void sc_musictree_render(int obj, int p2, int p3, int p4, int p5, s8 visible);



extern void GameBit_Set(int bit, int val);
extern void Sfx_PlayFromObject(int a, int b);



extern void enableHeavyFog(f32 a, f32 b, f32 c, f32 d, f32 e, int f);

typedef struct
{
    u8 bit7 : 1;
    u8 lo : 7;
} SnowFlags22;


extern u8 Obj_IsLoadingLocked(void);
extern int Obj_AllocObjectSetup(int a, int b);
extern int Obj_SetupObject(int setup, int a, int b, int c, int d);

#pragma dont_inline on
void sc_musictree_spawnAmbientEffect(int obj, int p2, int p3, s8 idx);
#pragma dont_inline reset

extern f32 lbl_803E5588;

#pragma dont_inline on
void sc_musictree_handleHitObject(int p1, int p2, int effectType);
#pragma dont_inline reset

extern u16 lbl_803DC060[4];

/* EN v1.0 0x801DB3A8  size: 2732b  SnowBike Race level controller per-frame
 * driver: replays the env-fx set on map (re)entry, latches the race
 * GameBits, runs the two race countdown timers, eases the heavy fog level,
 * tracks the totem combo code (bits 0x7d..0x7f), and keeps the area music
 * in sync with the Thorntail animation state. */

/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset
#pragma peephole reset

#include "main/dll/DR/cloudrunner_state.h"
#include "main/game_object.h"
#include "main/obj_placement.h"
#include "main/objfx.h"
#include "main/objseq.h"

typedef struct ScCloudrunneraPlacement
{
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    u8 pad1A[0x20 - 0x1A];
} ScCloudrunneraPlacement;


typedef struct ScMusictreeState
{
    u8 pad0[0x30 - 0x0];
    f32 unk30;
    f32 moveStepScale;
    u8 pad38[0x48 - 0x38];
    u16 unk48;
    u16 unk4A;
    u8 unk4C;
    u8 pad4D[0x50 - 0x4D];
} ScMusictreeState;


extern void GameBit_Set(int id, int value);
extern void Sfx_PlayFromObject(int obj, int sfxId);
extern void ObjHitbox_SetCapsuleBounds(int obj, int radius, int a, int b);
extern int ObjHits_GetPriorityHitWithPosition(int obj, int* type, int* a, int* b, f32* x, f32* y, f32* z);
extern int ObjHits_PollPriorityHitEffectWithCooldown(int obj, int a, int b, int c, int d, int e, int* state);
extern void ObjHits_RecordObjectHit(int target, int src, int a, int b, int c);
extern int* ObjList_GetObjects(int* startIndex, int* objectCount);
extern int Obj_SetupObject(int s, int a, int b, int c, int d);
extern int ObjLink_AttachChild(int parent, int child, int a);
extern int ObjLink_DetachChild(int parent, int child);
extern void cmbsrc_setExternalActive(int obj, int active);
extern void Obj_FreeObject(int obj);
extern void* Obj_GetPlayerObject(void);
extern void objSetSlot(int obj, int slot);
extern void Obj_SetModelColorFadeRecursive(int obj, int r, int g, int b, int a, int frames);
extern void objfx_spawnRandomBurst(int obj, int mode, int p3, void* vec, f32 f, int flag);
extern void vecRotateZXY(int obj, void* vec);
extern f32 sqrtf(f32 x);
extern f32 fn_8001461C(void);


extern ObjectTriggerInterface** gObjectTriggerInterface;
extern int* gTitleMenuControlInterface;

extern f32 timeDelta;
extern u8 framesThisStep;
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;

extern u8 lbl_803DB411;
extern int lbl_803DC068;
extern int lbl_803DDC08;
extern f32 lbl_803E5590;
extern f32 lbl_803E5594;
extern f32 lbl_803E5598;
extern f32 lbl_803E559C;
extern f32 lbl_803E55A0;
extern f32 lbl_803E55A4;
extern f32 lbl_803E55A8;
extern f32 lbl_803E55AC;
extern f32 lbl_803E55B0;
extern f32 lbl_803E55B4;
extern f32 lbl_803E55B8;
extern f32 lbl_803E55BC;
extern f32 lbl_803E55C0;
extern f32 lbl_803E55D0;
extern f32 lbl_803E55D4;
extern f32 lbl_803E55D8;
extern f32 lbl_803E55DC;
extern f32 lbl_803E55E0;


typedef struct SCMusicTreeSetup
{
    ObjPlacement base;
    u8 rotXByte;
    u8 rotZByte;
    u8 yawByte;
    u8 hearRadiusHalf;
    f32 scale;
    u8 pad20[0x23 - 0x20];
    u8 flags;
} SCMusicTreeSetup;

STATIC_ASSERT(sizeof(SCMusicTreeSetup) == 0x24);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, rotXByte) == 0x18);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, rotZByte) == 0x19);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, yawByte) == 0x1A);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, hearRadiusHalf) == 0x1B);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, scale) == 0x1C);
STATIC_ASSERT(offsetof(SCMusicTreeSetup, flags) == 0x23);

void sc_musictree_update(int obj);

void sc_musictree_init(int obj, SCMusicTreeSetup* setup);

void sc_musictree_release(void);

void sc_musictree_initialise(void);

typedef struct SCTotemPoleState
{
    u16 gameBit;
    u8 currentState;
    u8 previousState;
    f32 animSpeed;
} SCTotemPoleState;

#define SC_TOTEMPOLE_OBJECT_TYPE 0x282
#define SC_TOTEMPOLE_GAMEBIT_FRONT 0x81
#define SC_TOTEMPOLE_GAMEBIT_LEFT 0x82
#define SC_TOTEMPOLE_GAMEBIT_RIGHT 0x83
#define SC_TOTEMPOLE_GAMEBIT_REAR 0x84
#define SC_TOTEMPOLE_SETUP_REAR 0x44916
#define SC_TOTEMPOLE_SETUP_RIGHT 0x44909
#define SC_TOTEMPOLE_SETUP_FRONT 0x4490C
#define SC_TOTEMPOLE_SETUP_LEFT 0x4490F

int sc_totempole_sortCompletionGameBits(u16* bits, u16 param2);

int sc_totempole_getExtraSize(void);
int sc_totempole_getObjectTypeId(void);

void sc_totempole_free(void);

void sc_totempole_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void sc_totempole_hitDetect(void);

void sc_totempole_update(int obj);

void sc_totempole_init(int obj, int p2);

void sc_totempole_release(void);

void sc_totempole_initialise(void);

int sc_cloudrunnera_getExtraSize(void) { return 0x140; }
int sc_cloudrunnera_getObjectTypeId(void) { return 0xb; }

void sc_cloudrunnera_free(int* obj)
{
    void* inner = ((GameObject*)obj)->extra;
    (*gObjectTriggerInterface)->freeState(inner);
    ((void (*)(int*, int, int, int, int))(*(int*)(*gTitleMenuControlInterface + 0x8)))(obj, 0xffff, 0, 0, 0);
}

void sc_cloudrunnera_render(int p1, int p2, int p3, int p4, int p5, s8 visible)
{
    s32 v = visible;
    if (v != 0) objRenderFn_8003b8f4(lbl_803E55E0);
}

void sc_cloudrunnera_hitDetect(void)
{
}

void sc_cloudrunnera_update(int obj)
{
    int i;
    ObjSeqState* seq = ((GameObject*)obj)->extra;
    void* sub;
    int idx, count;

    sub = ((GameObject*)obj)->anim.placementData;
    if (sub == NULL) return;
    if (((ScCloudrunneraPlacement*)sub)->unk18 == -1) return;
    idx = (*gObjectTriggerInterface)->update((u8*)obj, (f32)(u32)lbl_803DB411);
    if (idx != 0 && ((GameObject*)obj)->seqIndex == -2)
    {
        int found;
        register s32 mark = *(s8*)&seq->slot;
        int* arr;
        int n;
        int markCopy;
        int matchCount;

        found = 0;
        arr = ObjList_GetObjects(&idx, &count);
        matchCount = 0;
        idx = 0;
        markCopy = mark;
        n = count;
        for (; idx < n; idx++)
        {
            int o = *arr;
            s16 t = ((GameObject*)o)->seqIndex;
            if (t == mark)
            {
                found = o;
            }
            if (t == -2 && ((GameObject*)o)->anim.classId == 0x10)
            {
                seq = *(ObjSeqState**)&((GameObject*)o)->extra;
                if (markCopy == (s8)seq->slot)
                {
                    matchCount++;
                }
            }
            arr++;
        }
        if (matchCount <= 1 && (u32)found != 0 && *(s16*)(found + 0xb4) != -1)
        {
            *(s16*)(found + 0xb4) = -1;
            (*gObjectTriggerInterface)->endSequence(markCopy);
        }
        ((GameObject*)obj)->seqIndex = -1;
    }

    for (i = 0; i < seq->eventCount; i++)
    {
        switch (seq->eventIds[i])
        {
        case 0:
            {
                int setup;
                int newObj;
                if (*(void**)&((GameObject*)obj)->childObjs[0] != NULL)
                {
                    break;
                }
                if (Obj_IsLoadingLocked() == 0)
                {
                    break;
                }
                setup = Obj_AllocObjectSetup(0x30, 0x6e8);
                *(u8*)(setup + 0x1b) = 0x9;
                *(u8*)(setup + 0x1c) = 0;
                *(u8*)(setup + 0x1d) = 0;
                *(f32*)(setup + 0x20) = lbl_803E55E0;
                *(u8*)(setup + 0x26) = 0xff;
                *(u8*)(setup + 0x27) = 0xff;
                *(u8*)(setup + 0x28) = 0xff;
                *(s16*)(setup + 0x24) = -1;
                *(u8*)(setup + 0x4) = 2;
                *(u8*)(setup + 0x5) = 1;
                *(u8*)(setup + 0x6) = 0xff;
                *(u8*)(setup + 0x7) = 0xff;
                *(u8*)(setup + 0x29) = 1;
                *(u8*)(setup + 0x2a) = 0;
                newObj = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                         *(int*)&((GameObject*)obj)->anim.parent);
                ((GameObject*)newObj)->anim.flags = (s16)(((GameObject*)newObj)->anim.flags | 0x4000);
                ObjLink_AttachChild(obj, newObj, 0);
                Sfx_PlayFromObject(obj, 0x10f);
                break;
            }
        case 1:
            {
                if (*(void**)&((GameObject*)obj)->childObjs[0] != NULL)
                {
                    cmbsrc_setExternalActive(*(int*)&((GameObject*)obj)->childObjs[0], 0);
                }
                break;
            }
        case 2:
            {
                int innerSlot = *(int*)&((GameObject*)obj)->childObjs[0];
                if ((u32)innerSlot != 0)
                {
                    ObjLink_DetachChild(obj, innerSlot);
                    Obj_FreeObject(innerSlot);
                }
                break;
            }
        }
    }
    {
        int t = *(int*)&((GameObject*)obj)->childObjs[0];
        if ((u32)t != 0)
        {
            *(s16*)(t + 4) = ((GameObject*)obj)->anim.rotZ;
            *(s16*)(*(int*)&((GameObject*)obj)->childObjs[0] + 2) = (s16)(((GameObject*)obj)->anim.rotY + 0xe38);
            *(s16*)(*(int*)&((GameObject*)obj)->childObjs[0] + 0) = (s16)(((GameObject*)obj)->anim.rotX + -0x8000);
        }
    }
}

void sc_cloudrunnera_init(int obj, int p2)
{
    ObjSeqState* seq;
    f32 base;

    objSetSlot(obj, 0x64);
    seq = ((GameObject*)obj)->extra;
    seq->unk6A = *(s16*)(p2 + 0x1a);
    seq->flags = -1;
    base = lbl_803E55E0;
    seq->posOffsetDecay = base / (base + (f32)(u32) * (u8*)(p2 + 0x24));
    seq->curveId = -1;
    ((GameObject*)obj)->unkF8 = 0;

    if (*(int*)(obj + 0xf4) == 0 && *(s16*)(p2 + 0x18) != 1)
    {
        (*gObjectTriggerInterface)
            ->loadAnimData((u8*)seq, (u8*)p2);
        ((GameObject*)obj)->unkF4 = *(s16*)(p2 + 0x18) + 1;
    }
    else if (*(int*)(obj + 0xf4) != 0 && *(s16*)(p2 + 0x18) != *(int*)(obj + 0xf4) - 1)
    {
        (*gObjectTriggerInterface)->freeState((u8*)seq);
        if (*(s16*)(p2 + 0x18) != -1)
        {
            (*gObjectTriggerInterface)
                ->loadAnimData((u8*)seq, (u8*)p2);
        }
        ((GameObject*)obj)->unkF4 = *(s16*)(p2 + 0x18) + 1;
    }
    if (((GameObject*)obj)->anim.modelState != NULL)
    {
        ((GameObject*)obj)->anim.modelState->shadowTintA = 0x64;
        ((GameObject*)obj)->anim.modelState->shadowTintB = 0x96;
    }
}

void sc_cloudrunnera_release(void)
{
}

void sc_cloudrunnera_initialise(void)
{
}

int fn_801DD170(void);
