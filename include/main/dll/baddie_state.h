#ifndef MAIN_DLL_BADDIE_STATE_H_
#define MAIN_DLL_BADDIE_STATE_H_

#include "ghidra_import.h"
#include "global.h"

/*
 * BaddieState - the engine-wide actor-control record that lives at the
 * head of the obj+0xB8 extra block for objects driven through
 * gBaddieControlInterface / gPlayerInterface (the name follows the
 * gBaddieControlInterface linkage; ActorControlState was the considered
 * alternative since the player shares it - cheap to rename later).
 *
 * Shared layout evidence:
 * - scarab.c (dll_CA/CB/CE: extraSizes 0x458/0x41c/0x410 - this struct is
 *   the common 0x410 prefix; nothing past 0x40C is referenced there) and
 *   mediumbasket.c (dll_CA family straddles both TUs) - converted.
 * - player.c's "inner" is the SAME record (0x274 mode compares, 0x27A
 *   just-started flag, 0x346 latch, ...) - adoption left to Zac/future.
 * - treasurechest.c / dll_01B5_lightfoot.c reference the same offsets -
 *   future passes.
 * - DR_CloudRunner's 0xBC8 extra block EMBEDS this record as its prefix
 *   (0x25F/0x28C/0x314/0x354 head + private tail from ~0x410) - layout
 *   evidence; not converted this round.
 *
 * Only fields with read/write evidence in scarab.c/mediumbasket.c are
 * named; everything else is padded. The engine-side writers (the
 * interface implementations) own most of the unobserved head.
 */
typedef struct BaddieState {
    u8 unk00[0x14];
    f32 posX; /* copied into spawned contact objects as position */
    f32 posY;
    f32 posZ;
    u8 unk20[0x38 - 0x20];
    f32 velX; /* copied into spawned contact objects as velocity */
    f32 velY;
    f32 velZ;
    u8 unk44[0xB8 - 0x44];
    s8 surfaceSoundIndex; /* 0..0x22 index into the per-type contact-sfx tables (intersect.c objAudioFn_8006ef38) */
    u8 padB9[0xBC - 0xB9];
    u8 paletteSlot; /* indexes the palette table (paletteIndex = gIceBaddiePaletteIndexTable[slot]) */
    u8 unkBD[0xC4 - 0xBD];
    void *contactObj; /* GameObject*; its anim.seqId (0x5d/0x99/0x1db/0x223) switches a sfx override (intersect.c) */
    u8 unkC8[0x19C - 0xC8];
    s16 spawnRotY; /* pair copied into the spawn-setup shorts; restored into anim.rotY */
    s16 spawnRotZ; /* restored into anim.rotZ */
    u8 unk1A0[0x1B4 - 0x1A0];
    f32 waterDepth; /* compared > threshold to fire the waterfx splash path (intersect.c) */
    u8 unk1B8[0x25B - 0x1B8];
    s8 contactSfxMuted; /* nonzero suppresses contact sfx unless contactSfxFlags bit 0x10 (intersect.c) */
    u8 unk25C[0x25F - 0x25C];
    u8 physicsActive; /* enables the free-fall physics path: gravity integration (velY -= g*dt), floor bounce response; set when thrown/spat */
    s8 contactSfxFlags; /* bit 0x10 allows contact sfx while contactSfxMuted is set (intersect.c) */
    u8 unk261[0x270 - 0x261];
    s16 substate; /* CA-family substate 0..5; gates the map-event re-register when != 3 */
    s16 prevSubstate; /* latched from substate for change detection (prevSubstate = startState in objseq) */
    s16 controlMode; /* current control move/mode; gPlayerInterface[5](obj,state,N) requests N */
    s16 unk276; /* compared != 4 */
    u8 unk278[2];
    u8 moveJustStartedA; /* one-shot, tested at SeqFn entry */
    u8 moveJustStartedB; /* one-shot, secondary channel (death/cleanup handlers) */
    u8 unk27C[0x280 - 0x27C];
    f32 animSpeedA; /* anim blend speed pair */
    f32 animSpeedB;
    u8 unk288[4];
    f32 moveInputZ;
    f32 moveInputX;
    f32 animSpeedC; /* third of the animSpeed family - stored in lockstep with animSpeedB (z = K; animSpeedC = z; animSpeedB = z), scaled with animSpeedA and obj+0x28 */
    f32 inputMagnitude;
    void *trackedObj; /* current target/player object (5-family census: lwz 668) */
    /* 0x2A0-0x2A7 is a PER-FAMILY UNION (lead-arbitrated): scarab and
     * mediumbasket targets store f32 here (stfs f0,672(rN) at 4+ sites
     * each -- the published types below), but the smallbasket family's
     * target reads u16 (lhz r0,672(r30) in smallbasket_handleReactionEvent
     * /fn_8015A924, lhz r0,676(r29) in fn_80157B58: a *0xc move-table
     * index and a u16->f32 duration). smallbasket keeps RAW spellings at
     * these offsets -- do NOT launder through these names there (a u16
     * index read through "moveSpeed" would be semantically false). */
    f32 moveSpeed; /* per-mode movement speed */
    f32 gravity;
    f32 unk2A8; /* mediumbasket whirlpool block 0x2A8..0x33B */
    f32 speedScale;
    u16 hitCounter; /* hit/impact counter (lhz-only reads in all families; sth stores) */
    u8 pad2B2[0x2B8 - 0x2B2];
    f32 velSmoothTime; /* first-order velocity smoothing divisor: vel += t * (target - vel) / velSmoothTime */
    u8 pad2BC[0x2C0 - 0x2BC];
    f32 targetDistance; /* sqrtf dist to targetObj (scarab/campfire/anim/mediumbasket); also (s32)-compared */
    u8 unk2C4[0x2D0 - 0x2C4];
    void *targetObj; /* current attack/aggro target */
    u8 pad2D4[0x2DC - 0x2D4];
/* controlFlags bit: baddie is currently driven by the sequence-object / script
 * move system (set by newseqobj.c when a seq timer expires; gates the scripted
 * anim-chain moves, and makes the defeat handler skip the death gamebits so
 * scripted/cutscene deaths don't count). */
#define BADDIE_CONTROL_SEQUENCE_DRIVEN 0x40000000
/* controlFlags bit: baddie follows its ROM curve path (RomCurveWalker). Gates
 * the path-tracking branches; cleared on hit/redirect. */
#define BADDIE_CONTROL_PATH_FOLLOW 0x2000
/* controlFlags bit: scripted move was just triggered this frame (the newseqobj
 * move system latches it before it promotes to SEQUENCE_DRIVEN). */
#define BADDIE_CONTROL_JUST_TRIGGERED 0x80000000
    u32 controlFlags; /* control flag word: 0x2000 path-follow, 0x2000_0000/0x4000_0000/0x8000_0000 move gates */
    u8 pad2E0[4];
    int unk2E4; /* whirlpool: 0x42001 flag word */
    u32 reactionFlags; /* event/reaction flag word: bits 8/0x10/0x20/0x28/0x80 */
    u8 pad2EC[0x2FC - 0x2EC];
    f32 pathStep; /* path-advance step (lfs/stfs 764; fed to Curve_AdvanceAlongPath) */
    f32 animDeltaScale;
    f32 unk304;
    f32 unk308;
    u8 unk30C[8];
/* eventFlags bit: anim-event footstep - the anim/event stream latches it, and
 * the per-family update readers test-then-clear it to fire the footstep/climb
 * contact SFX. */
#define BADDIE_EVENT_FOOTSTEP 0x1
/* eventFlags bit: anim-event landing/impact - latched on a landing anim event,
 * test-then-cleared by the readers to fire the land sound / rumble / waterfx
 * splash. */
#define BADDIE_EVENT_LANDING 0x200
    u32 eventFlags; /* bits 1/0x200 observed; whirlpool states store an f32 here (union via launder) */
    f32 unk318;
    f32 unk31C;
    u8 unk320;
    u8 unk321;
    u8 unk322;
    /* 0x323-0x345 is largely PER-FAMILY scratch: magicPlant/duster/seqObj11E
     * targets use f32 timers at 0x324/0x328/0x32C/0x330/0x334 and a u16 angle
     * at 0x338 where the published s16 fields below (mediumbasket whirlpool
     * evidence) overlap them; those families keep RAW spellings here. */
    u8 unk323[0x32E - 0x323];
    s16 stateTimer; /* count-up dt-accumulating timer, gated > 0x78, reset to 0 on state entry */
    s16 cameraYaw;
    u8 unk332[4];
    s16 turnRate; /* s16 angle units/sec: *yaw += k * (turnRate * timeDelta / speed) */
    u8 unk338[2];
    u8 seqEntryIndex; /* indexes the 16B SeqEntry anim table (entry + i*16), wraps to 1 past the count */
    u8 inWhirlpoolGroup; /* ObjGroup 80 membership latch */
    u8 unk33C[0x346 - 0x33C]; /* incl. 0x340: ptr in smallbasket, u32-tested in magicPlant - thin/conflicting, left raw */
    u8 moveDone; /* set when the current move completes; SeqFns chain the next mode off it */
    u8 unk347[2];
    u8 hasTarget; /* cleared with death/reset */
    u8 unk34A[3];
    u8 stateTag; /* per-tick state/mode index (written each tick; compared ==1/==3 across the baddie cluster + player) */
    u8 unk34E[6];
    u8 hitPoints; /* decremented on hit, (s8) < 1 = dead (anim.c/kt_rex pattern) */
    u8 unk355;
    u8 moveEventFlags; /* one-shot move-progress event latches (bit1/bit2: SFX fired once past a progress threshold) */
    u8 unk357[0x35C - 0x357];
} BaddieState;

STATIC_ASSERT(sizeof(BaddieState) == 0x35C);
STATIC_ASSERT(offsetof(BaddieState, controlMode) == 0x274);
STATIC_ASSERT(offsetof(BaddieState, moveJustStartedB) == 0x27B);
STATIC_ASSERT(offsetof(BaddieState, trackedObj) == 0x29C);
STATIC_ASSERT(offsetof(BaddieState, moveSpeed) == 0x2A0);
STATIC_ASSERT(offsetof(BaddieState, targetObj) == 0x2D0);
STATIC_ASSERT(offsetof(BaddieState, controlFlags) == 0x2DC);
STATIC_ASSERT(offsetof(BaddieState, pathStep) == 0x2FC);
STATIC_ASSERT(offsetof(BaddieState, eventFlags) == 0x314);
STATIC_ASSERT(offsetof(BaddieState, moveDone) == 0x346);
STATIC_ASSERT(offsetof(BaddieState, hitPoints) == 0x354);

/*
 * GroundBaddieState - BaddieState plus the route/config tail shared by the
 * ground-bug baddie cluster (scarab dll_CA/CB/CE, mediumbasket; treasurechest
 * and lightfoot reference the same tail offsets). The 0x35C+ region is
 * PER-FAMILY in general: the dll_2E look-controller block sits at 0x35C for
 * DRpushcart/DIMSnowHorn1, 0x3EC for hightop, 0x4C4 for DR_CloudRunner -
 * which is why it is not part of BaddieState itself.
 */
typedef struct GroundBaddieState {
    BaddieState baddie;
    u8 route35C[0x3DC - 0x35C]; /* route/voxmap buffer handed to gBaddieControlInterface[10] */
    void *path; /* rom-curve/path record */
    int savedObjC0; /* obj+0xC0 swap slot around the player-interface update */
    u8 unk3E4[4];
    f32 glowAlpha; /* 0x3e8: alpha of the red glow tint RGBA(200,0,0,glowAlpha), passed to fn_8003B5E0 + objParticleFn alpha arg in baddie render */
    u8 unk3EC[4];
    s16 triggerId; /* config-sourced id (loaded from config+0x22) handed to gBaddieControlInterface[19]/+0x4C when a move/landing event fires */
    s16 gameBitA; /* set 1 on trigger */
    s16 gameBitB; /* set 1 / cleared 0; also passed to interface[10] */
    s16 gameBitC; /* gate; checked != -1 + GameBit_Get */
    u8 unk3F8[2];
    s16 unk3FA; /* pair passed to the interface with unk3FC */
    s16 unk3FC;
    u16 aggroRange; /* target-acquire radius passed to interface+0x48; (f32)(u32) conversions */
/* flags400 bit: baddie is advancing along its ROM curve path. Set once the
 * RomCurveWalker is successfully initialised (dll19func0), then each update
 * step calls Curve_AdvanceAlongPath while it is set and clears it at the end
 * of the path (dllcb). u16 field - no LL form needed. */
#define BADDIE_FLAG400_PATH_ACTIVE 0x8
    u16 flags400; /* bit flags 2/8/0x100; &flags400 also passed as a buffer base */
    s16 targetState; /* 0 = no target; tryAcquireTarget vs updateTargetMotion */
    u8 configFlags; /* bits 1/2/0x10 */
    u8 unk405; /* small mode 0..2 */
    u8 aggression; /* percent-ish; randomGetRange(0, x), > 50 compares */
    u8 unk407[0x40C - 0x407];
    void *control; /* per-family control/extra record (engine-allocated; treasurechest casts its slot to LandedArwingState*) */
} GroundBaddieState;

STATIC_ASSERT(sizeof(GroundBaddieState) == 0x410);
STATIC_ASSERT(offsetof(GroundBaddieState, targetState) == 0x402);
STATIC_ASSERT(offsetof(GroundBaddieState, control) == 0x40C);


/* extern-cleanup: consolidated prototypes */
void fn_8001FEA8(void);


/* extern-cleanup: consolidated prototypes (true-def sigs) */
float fn_80293DA4(float x);

#endif /* MAIN_DLL_BADDIE_STATE_H_ */
