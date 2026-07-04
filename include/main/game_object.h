#ifndef MAIN_GAME_OBJECT_H_
#define MAIN_GAME_OBJECT_H_

#include "global.h"
#include "main/objanim_internal.h"

/*
 * GameObject - the engine-wide object record passed around as "obj" /
 * "int obj" / "u8 *obj" throughout src/main and the DLLs. Its head
 * (0x00..0xAF) is exactly ObjAnimComponent (rot @0/2/4, localPos
 * @0xC/10/14, worldPos @0x18/1C/20, velocity @0x24/28/2C, classId @0x44,
 * placementData @0x4C, modelInstance @0x50, ... - see
 * objanim_internal.h, layout STATIC_ASSERTed there). The tail below is
 * named from engine-side evidence only:
 *  - 0xB0 u16: anim.c/audio.c/backpack.c (*(u16 *)(obj + 0xb0), 74 sites)
 *  - 0xB4 s16: baddieControl.c/object.c/objseq.c
 *  - 0xB8 ptr: the per-class extra state block (BaddieState /
 *    ObjSeqState / GroundBaddieState live here - see baddie_state.h)
 *  - 0xBC..0xC8 ptrs: anim.c/object.c/objseq.c list links + callbacks
 *  - 0xE4/0xE5/0xE6/0xEB: object.c bookkeeping bytes
 *  - 0xF4/0xF8 s32: anim.c/campfire.c flag words (*(int *) sites)
 *  - 0xFC/0x100/0x104 f32: object.c
 * The record extends past 0x108; total size unverified - do not take
 * sizeof(GameObject) or index arrays of it.
 *
 * Width discipline (per CLAUDE.md recipe #77): the pointer fields here
 * are routinely null-tested through *(int *) in matched code (cmpwi).
 * Keep those spellings via launders - *(int *)&obj->extra != 0 - rather
 * than retyping the test to a pointer compare.
 */
typedef struct GameObject {
    ObjAnimComponent anim;
    u16 objectFlags; /* obj+0xB0 flag word; 9 object families STATIC_ASSERT
        this name (Checkpoint4/CmbSrc/EnemyMushroom/Laser/MagicPlant/...) */
    u8 unkB2[2];
    s16 seqIndex; /* obj+0xB4 trigger-sequence index (-1 = none, -2 = pending);
        passed to ObjectTriggerInterface.endSequence(seqIndex) */
    u8 unkB6[2];
    void *extra; /* per-class state block */
    void *animEventCallback; /* obj+0xBC anim-event callback slot;
        LinkALevelControlObject/EarthWalkerObject STATIC_ASSERT this at 0xBC */
    void *pendingParentObj; /* obj+0xC0: object whose anim.parent this object
        inherits in Obj_ApplyPendingParentLinks (set by objseq, cleared after) */
    void *ownerObj; /* obj+0xC4 owner-ward chain link (newObj->ownerObj = obj at
        spawn; objprint walks it to the chain root for shadow state; some DLL
        classes reuse the slot as f32 scratch via launders) */
    void *childObjs[5]; /* obj+0xC8..0xD8 child-object slots, childCount used;
        Obj_*ModelColorFadeRecursive walks them (childScan += 4 loop) */
    void *unkDC;
    u8 unkE0[4];
    u8 hitVolumeIndex; /* index into anim.hitVolumeBounds/hitVolumeTransforms +
        modelInstance->hitVolumes (active hit-volume node) */
    u8 colorFadeFlags; /* obj+0xE5 bits 1/2 queried by getters, 4 toggled, 8
        suppresses the fade tick (Obj_*ModelColorFade* family) */
    s16 colorFadeFrames; /* obj+0xE6 frames left; -= framesThisStep, <=0 with
        no ownerObj -> Obj_ClearModelColorFadeRecursive */
    u8 paletteIndex; /* obj+0xE8 (objprint: paletteIdx = target->...) */
    s8 unkE9;
    u8 unkEA;
    u8 childCount;
    u8 unkEC[3];
    s8 colorFadeAlpha; /* obj+0xEF written from the fade alpha each tick */
    u8 fadeCounter; /* obj+0xF0 ++ toward the fade limit each tick */
    u8 unkF1[3];
    s32 unkF4;
    s32 unkF8;
    f32 externalVelX; /* obj+0xFC..0x104: velocity imparted externally
        (carrier object's velocity / move-data velocity), added to
        anim.velocity in the localPos integration */
    f32 externalVelY;
    f32 externalVelZ;
} GameObject;

STATIC_ASSERT(offsetof(GameObject, objectFlags) == 0xB0);

/*
 * GameObject.objectFlags (obj+0xB0 u16) bit names. Values are the
 * engine-wide consensus recovered from the per-class file-local
 * *_OBJFLAG_* defines that name the identical bit across dozens of
 * consumers (SET-condition + READ-behavior agree on the meaning):
 *  - 0x2000 HITDETECT_DISABLED: cleared for collision; class init OR's it
 *    in to suppress hit detection (object.c hitdetect gate, 100+ sites).
 *  - 0x4000 HIDDEN: suppresses render; paired with HITDETECT_DISABLED on
 *    hide (main.c/light.c/many class inits).
 *  - 0x8000 UPDATE_DISABLED: object.c update loop skips the tick when set.
 *  - 0x800 RENDERED: set by the render path, cleared each frame
 *    (objprint/lightmap), queried to know an object drew this frame.
 *  - 0x40 FREED: object freed/pending-free marker.
 * Field is u16, so a bare int constant folds identically for |= / & / &~.
 */
#define OBJECT_OBJFLAG_FREED               0x40
#define OBJECT_OBJFLAG_RENDERED            0x800
#define OBJECT_OBJFLAG_HITDETECT_DISABLED  0x2000
#define OBJECT_OBJFLAG_HIDDEN              0x4000
#define OBJECT_OBJFLAG_UPDATE_DISABLED     0x8000

STATIC_ASSERT(offsetof(GameObject, extra) == 0xB8);
STATIC_ASSERT(offsetof(GameObject, hitVolumeIndex) == 0xE4);
STATIC_ASSERT(offsetof(GameObject, colorFadeAlpha) == 0xEF);
STATIC_ASSERT(offsetof(GameObject, unkF4) == 0xF4);
STATIC_ASSERT(offsetof(GameObject, externalVelZ) == 0x104);

void Obj_SetActiveHitVolumeBounds(GameObject *obj, int xBound, int zBound, int yBound,
                                  u8 radiusOrHeight, u8 flags);


/* extern-cleanup: consolidated prototypes */
void disableHeavyFog(void);
void subtitleFn_8001b700(void);
void trickyReportError(const char* fmt, ...);
u8 fn_801334E0(void);
int dbstealerworm_stateHandlerA0F(int obj, int p2, f32 t);
void renderResetFn_8003fc60(void);
void modelLightChannels_applyGXControls(void);
void __GXAbortWaitPECopyDone(void);
void gameUiResetMenuState(void);
int atan2_8002178c(f32 dx, f32 dz);
void mapBlockFn_80059c2c(u8 * outFlags);
void fn_8003A230(int obj, void* p, f32 f);
int isInBounds(f32 x, f32 z);
void skeetlawall_setScale(int* obj, f32* outVec, u8* outByte);
void objSetHintTextIdx(int obj, u16 idx);
void DBstealerwo_setFuncPtrs_80203c78(void);
int dbstealerworm_stateHandlerA07(int obj, int p2, f32 t);
int dbstealerworm_stateHandlerA08(int obj, int p2, f32 t);
int dbstealerworm_stateHandlerA0B(int obj, int p2, f32 t);
int dbstealerworm_stateHandlerA0C(int obj, int p2, f32 t);


/* extern-cleanup: consolidated prototypes (true-def sigs) */
void* textureIdxToPtr(int idx);
void trickyDebugPrint(const char* fmt, ...);
void resetLotsOfRenderVars(void);
void textureFn_800528bc(void);
void showHelpText(s16 val);
void* gameTextGetPhrase(int textId, int phraseIndex);
void modelLightChannels_reset(u8 v);
void modelLightChannel_configure(int i, int a, int b);
void lightGetColor(int i, u8* a, u8* b, u8* c);
void gxColorFn_800523d0(void);
void fn_8004D230(void);
void fn_8004D928(void);
void texFlagFn_80023cbc(int v);
void texRestructRefs(int mode);
int testAndSet_onlyUseHeaps1and2(int v);
int mmGetRegionForPtr(u8* ptr);
int getHeapItemSize(void* ptr);
void debugPrintfxy(int x, int y, char* fmt, ...);
void gxTextureFn_8004bf88(void* bufp, u8 flag1, u8 flag2, int* out1, int* out2);
u8 fn_8012DDAC(void);
void gameTextResetCursor(int flags);
int atan2i(int y, int x);

#endif
