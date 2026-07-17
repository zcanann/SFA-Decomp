/*
 * mikaladon - spawn-time setup for the mikaladon enemy, dispatched by object
 * seqId from the tricky (DLL 0x00C4) and enemy (DLL 0x00C9) object DLLs.
 * Seeds the per-instance speed/anim scales and the curve-path step, then
 * places the actor at its initial position along the path.
 */
#include "main/dll/partfx_interface.h"
#include "main/audio/sfx_ids.h"
#include "dolphin/MSL_C/PPCEABI/bare/H/trig_float_helpers.h"
#include "dolphin/mtx/mtx_legacy.h"
#include "main/audio/sfx.h"
#include "main/dll/baddie_state.h"
#include "main/game_object.h"
#include "main/object.h"
#include "main/obj_placement.h"
#include "main/dll/curve_walker.h"
#include "main/dll/rom_curve_interface.h"
#include "main/objhits.h"
#include "main/dll/objfsa.h"
#include "main/audio/sfx_trigger_ids.h"
#include "main/frame_timing.h"
#include "main/voxmaps.h"

extern u8 gMagicPlantSeqEntryTable[8];

#define MAGICPLANT_OBJFLAG_PARENT_SLACK 0x1000

/* DLL-id of the object spawned by fn_80153640 (generic spawn; no cache field /
   named spawn-fn / kind name -> suffixless per role-gate). */
#define MAGICPLANT_CHILD_OBJ 0x51b

/* The magic-plant's one particle-fx effect (spawned per hit-count in the
   attack handler). */
#define MAGICPLANT_PARTFX          0x802
#define MAGICPLANT_HIT_VOLUME_SLOT 0xe

extern f32 lbl_803E286C;
extern f32 lbl_803E2894;
void fn_8014D08C(GameObject* obj, int state, u8 moveId, f32 speed, int p5, int flags);
#define Baddie_SetMove(obj, state, moveId, speed, p5, flags)                                                           \
    fn_8014D08C((GameObject*)(obj), (int)(state), (moveId), (speed), (p5), (flags))
extern void fn_8014CF7C(int obj, int state, f32 f1, f32 f2, int p3, int p4);
extern void fn_8014C678(int obj, int state, void* vec, f32 f1, f32 f2, f32 f3, int p6);
extern void fn_8014CD1C(int obj, int state, int p3, f32 f1, f32 f2, int p6);

void mikaladon_init(GameObject* obj, int state)
{
    f32 zero;
    f32 lblA;
    f32 a, b;

    zero = lbl_803E286C;
    ((BaddieState*)state)->speedScale = zero;
    ((BaddieState*)state)->unk2E4 = 1;
    ((BaddieState*)state)->unk308 = 0.01f;
    ((BaddieState*)state)->animDeltaScale = 0.006f;
    lblA = lbl_803E2894;
    ((BaddieState*)state)->unk304 = lblA;
    ((BaddieState*)state)->unk320 = 1;
    *(f32*)&((BaddieState*)state)->eventFlags = lblA;
    ((BaddieState*)state)->unk321 = 3;
    ((BaddieState*)state)->unk318 = lblA;
    ((BaddieState*)state)->unk322 = 1;
    ((BaddieState*)state)->unk31C = lblA;
    *(f32*)(state + 0x324) = obj->anim.localPosX;
    *(f32*)(state + 0x328) = obj->anim.localPosY;
    *(f32*)(state + 0x32c) = obj->anim.localPosZ;
    ((BaddieState*)state)->seqEntryIndex = 0;
    ((BaddieState*)state)->inWhirlpoolGroup = 0;
    *(s16*)(state + 0x338) = 0;
    *(f32*)(state + 0x330) = zero;
    *(f32*)(state + 0x334) = zero;
    ((BaddieState*)state)->pathStep = 8.0f;

    fn_80293018(*(u16*)(state + 0x338), &a, &b);
    obj->anim.localPosX = a * ((BaddieState*)state)->unk2A8 + *(f32*)(state + 0x324);
    obj->anim.localPosZ = b * ((BaddieState*)state)->unk2A8 + *(f32*)(state + 0x32c);
}
