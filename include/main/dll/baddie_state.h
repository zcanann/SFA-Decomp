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
    u8 unk44[0xBC - 0x44];
    u8 unkBC;
    u8 unkBD[0x19C - 0xBD];
    s16 unk19C; /* pair copied into the spawn-setup shorts */
    s16 unk19E;
    u8 unk1A0[0x25F - 0x1A0];
    u8 unk25F;
    u8 unk260[0x270 - 0x260];
    s16 unk270; /* CA-family substate 0..5; gates the map-event re-register when != 3 */
    s16 unk272;
    s16 controlMode; /* current control move/mode; gPlayerInterface[5](obj,state,N) requests N */
    s16 unk276; /* compared != 4 */
    u8 unk278[2];
    u8 moveJustStartedA; /* one-shot, tested at SeqFn entry */
    u8 moveJustStartedB; /* one-shot, secondary channel (death/cleanup handlers) */
    u8 unk27C[0x280 - 0x27C];
    f32 animSpeedA; /* anim blend speed pair */
    f32 animSpeedB;
    u8 unk288[4];
    f32 unk28C;
    f32 unk290;
    f32 unk294; /* scaled together with animSpeedA and obj+0x28 */
    u8 unk298[0x2A0 - 0x298];
    f32 moveSpeed; /* per-mode movement speed */
    f32 unk2A4;
    f32 unk2A8; /* mediumbasket whirlpool block 0x2A8..0x33B */
    f32 unk2AC;
    u8 unk2B0[0x2C0 - 0x2B0];
    f32 unk2C0; /* frame-counter-ish; compared (s32) > 0x37 */
    u8 unk2C4[0x2D0 - 0x2C4];
    void *targetObj; /* current attack/aggro target */
    u8 unk2D4[0x2E4 - 0x2D4];
    int unk2E4; /* whirlpool: 0x42001 flag word */
    u8 unk2E8[0x300 - 0x2E8];
    f32 unk300;
    f32 unk304;
    f32 unk308;
    u8 unk30C[8];
    u32 eventFlags; /* bits 1/0x200 observed; whirlpool states store an f32 here (union via launder) */
    f32 unk318;
    f32 unk31C;
    u8 unk320;
    u8 unk321;
    u8 unk322;
    u8 unk323[0x32E - 0x323];
    s16 unk32E; /* compared > 0x78 */
    s16 unk330;
    u8 unk332[4];
    s16 unk336; /* (f32)-scaled by timeDelta */
    u8 unk338[2];
    u8 unk33A;
    u8 inWhirlpoolGroup; /* ObjGroup 80 membership latch */
    u8 unk33C[0x346 - 0x33C];
    u8 moveDone; /* set when the current move completes; SeqFns chain the next mode off it */
    u8 unk347[2];
    u8 unk349; /* cleared with death/reset */
    u8 unk34A[3];
    u8 unk34D; /* 0/1/3 */
    u8 unk34E[6];
    u8 unk354; /* (s8)-compared counter */
    u8 unk355;
    u8 unk356; /* bit flags 1|2 */
    u8 unk357[0x35C - 0x357];
    u8 unk35C[0x3DC - 0x35C]; /* buffer handed to gBaddieControlInterface[10] */
    void *path; /* rom-curve/path record */
    int savedObjC0; /* obj+0xC0 swap slot around the player-interface update */
    u8 unk3E4[4];
    f32 unk3E8; /* CE render: forwarded to fn_8003B5E0(0xC8,...) */
    u8 unk3EC[4];
    s16 unk3F0; /* id passed to gBaddieControlInterface[19]/+0x4C */
    s16 gameBitA; /* set 1 on trigger */
    s16 gameBitB; /* set 1 / cleared 0; also passed to interface[10] */
    s16 gameBitC; /* gate; checked != -1 + GameBit_Get */
    u8 unk3F8[2];
    s16 unk3FA; /* pair passed to the interface with unk3FC */
    s16 unk3FC;
    u16 unk3FE; /* distance config; (f32)(u32) conversions */
    u16 flags400; /* bit flags 2/8/0x100; &flags400 also passed as a buffer base */
    s16 targetState; /* 0 = no target; tryAcquireTarget vs updateTargetMotion */
    u8 configFlags; /* bits 1/2/0x10 */
    u8 unk405; /* small mode 0..2 */
    u8 aggression; /* percent-ish; randomGetRange(0, x), > 50 compares */
    u8 unk407[0x40C - 0x407];
    void *control; /* per-family control/extra record (engine-allocated; treasurechest casts its slot to LandedArwingState*) */
} BaddieState;

STATIC_ASSERT(sizeof(BaddieState) == 0x410);
STATIC_ASSERT(offsetof(BaddieState, controlMode) == 0x274);
STATIC_ASSERT(offsetof(BaddieState, moveSpeed) == 0x2A0);
STATIC_ASSERT(offsetof(BaddieState, eventFlags) == 0x314);
STATIC_ASSERT(offsetof(BaddieState, moveDone) == 0x346);
STATIC_ASSERT(offsetof(BaddieState, targetState) == 0x402);
STATIC_ASSERT(offsetof(BaddieState, control) == 0x40C);

#endif /* MAIN_DLL_BADDIE_STATE_H_ */
