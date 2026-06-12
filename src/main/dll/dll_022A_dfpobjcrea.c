/* === moved from main/main.c [801FE118-801FEB30) (TU re-split, docs/boundary_audit.md) === */
#pragma scheduling on
#pragma peephole on
#include "main/game_object.h"
#include "main/dll/anim_internal.h"
#include "main/main.h"
#include "main/objlib.h"

extern uint GameBit_Get(int eventId);
extern void GameBit_Set(int eventId, int value);


/*
 * --INFO--
 *
 * Function: FUN_801fd398
 * EN v1.0 Address: 0x801FD398
 * EN v1.0 Size: 852b
 * EN v1.1 Address: 0x801FD3A4
 * EN v1.1 Size: 720b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


#pragma scheduling off
#pragma peephole off
void dbegg_processMessages(int obj);
#pragma peephole reset
#pragma scheduling reset


/* Trivial 4b 0-arg blr leaves. */













/* 8b "li r3, N; blr" returners. */
int dbegg_getExtraSize(void);
int dbegg_getObjectTypeId(void);

/* ObjGroup_RemoveObject(x, N) wrappers. */
#pragma scheduling off
void dbegg_free(int x);
#pragma scheduling reset

/* plain forwarder. */

/* fn_X(lbl); lbl = 0; */
#pragma scheduling off
#pragma scheduling reset

/* dll_224_hitDetect: render iff obj->field_0x74 set. */


/* dll_224_update: dispatch GameEvent id based on vtable[0x40](obj->field_0xac). */
#pragma scheduling off
#pragma peephole off
void dll_224_update(void* param_1);
#pragma peephole reset
#pragma scheduling reset


/* fn_801FD4A8: decrement extra->[4] by x; return whether it reached 0. */
#pragma scheduling off
#pragma scheduling reset

int dbegg_setScale(int obj);

/* dbegg_setupFromDef: set up dbegg from def fields, dispatch on def->_26 mode byte. */
extern f32 lbl_803E61C8;
extern f32 lbl_803E61D0;
extern int fn_801FE560(int obj, f32* out, f32 a, f32 b, int p3);
extern int Obj_SetActiveModelIndex(int obj, int idx);
#pragma scheduling off
#pragma peephole off
void dbegg_setupFromDef(int obj, u8* state);
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
int dbegg_func0B(int obj, f32* v);
#pragma scheduling reset

#pragma scheduling off
#pragma scheduling reset

#pragma scheduling off
#pragma scheduling reset

extern void objRenderFn_8003b8f4(f32);
#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

extern f32 lbl_803E61CC;
#pragma scheduling off
#pragma peephole off
void dbegg_render(int obj, int p1, int p2, int p3, int p4, s8 visible);
#pragma peephole reset
#pragma scheduling reset

/* dll_224_init: init extra-data fields from other; set obj->0xaf bit 3. */
#pragma scheduling off
#pragma peephole off
void dll_224_init(void* obj, void* other);

#pragma peephole reset
#pragma scheduling reset

extern int objBboxFn_800640cc(void* from, void* to, f32 radius, int mode, void* hit, int obj, int p7, int p8, int p9,
                              int p10);
extern f32 lbl_803E6218;
extern f32 lbl_803E621C;

#pragma scheduling off
void dbegg_hitDetect(int obj);
#pragma scheduling reset

/* ==== v1.0 recovered functions (drift additions) ==== */

extern f32 lbl_803E61E0;
extern f32 lbl_803E61E4;
extern f32 lbl_803E61E8;
extern f32 lbl_803E61EC;
extern f32 lbl_803E61F0;
extern f32 lbl_803E61F4;
extern f32 lbl_803E61F8;
extern f32 lbl_803E61FC;
extern f32 lbl_803E6200;
extern f32 lbl_803E6204;
extern f32 lbl_803E6208;
extern f32 mathSinf(f32 x);
extern f32 mathCosf(f32 x);
extern f32 sqrtf(f32 x);
extern int hitDetectFn_80065e50(f32 x, f32 y, f32 z, int obj, int*** listOut, int p6, int p7);

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
#pragma peephole off
#pragma opt_common_subs off
#pragma opt_loop_invariants off
int fn_801FE560(int obj, f32* out, f32 a, f32 b, int flag);
#pragma opt_loop_invariants reset
#pragma opt_common_subs reset
#pragma peephole reset
#pragma scheduling reset

#pragma scheduling off
void fn_801FE774(int cam, f32* vel);
#pragma scheduling reset
#pragma scheduling reset
#pragma peephole reset

#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/dll/anim.h"
#include "main/dll/baddie_state.h"
#include "main/objseq.h"
#include "main/objfx.h"
#include "main/resource.h"

/*
 * DbStealerwormControl - the per-family control record hung off
 * GroundBaddieState.control (state+0x40C) for dbstealerworm
 * (extraSize 0x460 = GroundBaddieState 0x410 + a 0x50 private tail;
 * the control record itself is memset(0x50) in dbstealerworm_init).
 */
typedef struct DbStealerwormControl
{
    int cfg; /* entry in the lbl_80329514 table (stride 8 ints) */
    f32 unk04;
    f32 unk08;
    f32 countdown; /* countdown; init randomGetRange(10, 300) */
    f32 unk10;
    u8 flags14; /* bits 1/2 */
    u8 flags15; /* bits 1/4 */
    u8 unk16[2];
    int linkedObj; /* ObjMsg target object */
    s16 unk1C;
    u8 unk1E[2];
    int unk20; /* cursor into the cfg route list (12-byte entries) */
    int msgStack; /* Stack_* handle; 3-word messages */
    int unk28;
    int unk2C;
    int unk30; /* ObjGroup id */
    u8 unk34;
    u8 unk35[3];
    f32 unk38;
    int unk3C;
    u8 unk40[4];
    u8 flags44; /* bits 0x10/0x20 */
    u8 unk45[3];
    f32 randomTimer48; /* RandomTimer_UpdateRangeTrigger slots */
    f32 randomTimer4C;
} DbStealerwormControl;

STATIC_ASSERT(sizeof(DbStealerwormControl) == 0x50);

/* dfplevelcontrol extra block (extraSize 0xC). */
typedef struct DfpLevelControlState
{
    s16 timer; /* counts down by timeDelta; set 300 on gamebit 1509 */
    s16 mode; /* 1..2, from def+0x1A */
    u8 unk04[2];
    u8 sfxLatch; /* gamebit-1589 one-shot latch */
    u8 flags07; /* DfpFlags7 bitfield overlay */
    u8 unk08[4];
} DfpLevelControlState;

STATIC_ASSERT(sizeof(DfpLevelControlState) == 0xC);

/* dfpobjcreator extra block (extraSize 0x1C). */
typedef struct DfpObjCreatorState
{
    int spawnedObj;
    u8 unk04[8];
    s16 gameBit; /* 0x0C: spawn gate */
    s16 spawnPeriod; /* 0x0E */
    s16 spawnTimer; /* 0x10 */
    s16 unk12;
    s16 unk14;
    s16 unk16;
    u8 unk18[4];
} DfpObjCreatorState;

STATIC_ASSERT(sizeof(DfpObjCreatorState) == 0x1C);

/* DFP_Torch extra block (extraSize 0x10). */
typedef struct DfpTorchState
{
    int gameBit; /* lit-state gamebit, -1 = none (def+0x1E) */
    s16 flickerTimer; /* 0x04 */
    s16 litTimer; /* 0x06: 0x7D0 countdown while lit */
    u8 visibleLatch; /* 0x08 */
    u8 mode; /* 0x09: def+0x19 */
    u8 lit; /* 0x0A */
    u8 sfxPending; /* 0x0B */
    u8 prevLit; /* 0x0C */
    u8 colorIdx; /* 0x0D: def+0x1C */
    u8 unk0E[2];
} DfpTorchState;

STATIC_ASSERT(sizeof(DfpTorchState) == 0x10);

/* dll_22C (raising platform) extra block (extraSize 0x10). */
typedef struct Dll22CState
{
    f32 raiseHeight; /* def+0x1A */
    s16 mode; /* 0x04 */
    s16 gameBit; /* 0x06: def+0x20 */
    s16 gameBit2; /* 0x08: def+0x1E */
    s16 pauseTimer; /* 0x0A: 100 between moves */
    u8 unk0C; /* def+0x1C */
    u8 sfxLatch; /* 0x0D */
    u8 unk0E[2];
} Dll22CState;

STATIC_ASSERT(sizeof(Dll22CState) == 0x10);

/* dbegg extra block: rom-curve walker + egg mode machine. */
typedef struct DbEggState
{
    f32 waterOffset; /* float-height offset above water */
    u8 curveWalker[0x10]; /* 0x004: rom-curve walker record (state+4 to gRomCurveInterface) */
    int unk14;
    u8 unk18[0x6C - 0x18];
    f32 curvePosX; /* 0x06C: walker sample position */
    f32 curvePosY;
    f32 curvePosZ;
    u8 unk78[0x118 - 0x78];
    u8 mode; /* 0x118 */
    u8 flags119; /* bits 1/2/4/8/0x10 */
    u8 unk11A[2];
    s16 msg11C; /* 0x11C: 3-word message payload sent via ObjMsg */
    s16 msg11E;
    f32 msg120;
} DbEggState;

STATIC_ASSERT(offsetof(DbEggState, mode) == 0x118);

/* dfpseqpoint extra block (extraSize 0x10). */
typedef struct DfpSeqPointState
{
    f32 triggerRadius; /* def+0x1A */
    s16 gameBitGate; /* 0x04: def+0x1E */
    s16 gameBitDone; /* 0x06: def+0x20 */
    s16 triggerId; /* 0x08: def+0x1C */
    u8 unk0A[3];
    u8 doneLatch; /* 0x0D */
    u8 triggerMode; /* 0x0E: def+0x19 */
    u8 flags0F; /* DfpFlags7-style bit 0x80 */
} DfpSeqPointState;

typedef struct DfpFlags7
{
    u8 b80 : 1;
    u8 b40 : 1;
    u8 b20 : 1;
    u8 rest : 5;
} DfpFlags7;

STATIC_ASSERT(sizeof(DfpSeqPointState) == 0x10);

/* drakorenergy extra block (extraSize 0xC). */
typedef struct DrakorEnergyState
{
    f32 startY; /* spawn height; bounce threshold in mode 1 */
    int phase; /* += framesThisStep * 0x500; drives glow color/bob */
    u8 mode; /* 0x08: 0 idle, 1 falling, 2 bobbing, 3 chasing, 4 collected, 5 reset */
    u8 unk09[3];
} DrakorEnergyState;

STATIC_ASSERT(sizeof(DrakorEnergyState) == 0xC);

/* chuka extra block (extraSize 0xC). */
#include "main/dll/baddie/chuka.h"

typedef struct DfpseqpointPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    s32 unk14;
    u8 pad18[0x19 - 0x18];
    u8 unk19;
    u8 pad1A[0x1E - 0x1A];
    s8 unk1E;
    u8 pad1F[0x24 - 0x1F];
    s16 unk24;
    u8 pad26[0x2B - 0x26];
    u8 unk2B;
    u8 pad2C[0x2E - 0x2C];
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} DfpseqpointPlacement;


typedef struct DrakorenergyPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    s32 unk14;
    u8 pad18[0x19 - 0x18];
    u8 unk19;
    u8 pad1A[0x1E - 0x1A];
    s8 unk1E;
    u8 pad1F[0x20 - 0x1F];
    s16 gameBitId;
    u8 pad22[0x24 - 0x22];
    s16 unk24;
    u8 pad26[0x2B - 0x26];
    u8 unk2B;
    u8 pad2C[0x2E - 0x2C];
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} DrakorenergyPlacement;




typedef struct DfpobjcreatorObjectDef
{
    u8 pad0[0x18 - 0x0];
    s16 gameBit;
    u8 pad1A[0x1C - 0x1A];
    s16 spawnPeriod;
    u8 pad1E[0x24 - 0x1E];
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} DfpobjcreatorObjectDef;


typedef struct Dbholecontrol1Placement
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    s32 unk14;
    s16 unk18;
    u8 pad1A[0x1C - 0x1A];
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x24 - 0x22];
    s16 unk24;
    u8 pad26[0x2B - 0x26];
    u8 unk2B;
    u8 pad2C[0x2E - 0x2C];
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} Dbholecontrol1Placement;


typedef struct ChukaPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    s32 unk14;
    u8 pad18[0x19 - 0x18];
    u8 unk19;
    u8 pad1A[0x1C - 0x1A];
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x24 - 0x22];
    s16 unk24;
    u8 pad26[0x2B - 0x26];
    u8 unk2B;
    u8 pad2C[0x2E - 0x2C];
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} ChukaPlacement;


typedef struct DfpobjcreatorPlacement
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
    f32 posX;
    f32 posY;
    f32 posZ;
    s32 unk14;
    u8 pad18[0x19 - 0x18];
    u8 unk19;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x24 - 0x22];
    s16 unk24;
    u8 pad26[0x2B - 0x26];
    u8 unk2B;
    u8 pad2C[0x2E - 0x2C];
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} DfpobjcreatorPlacement;


typedef struct DbstealerwormPlacement
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u32 eventConfigId;
    s16 incrementGameBit;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x24 - 0x22];
    s16 unk24;
    u8 pad26[0x2B - 0x26];
    u8 unk2B;
    s16 unk2C;
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} DbstealerwormPlacement;


typedef struct DbeggPlacement
{
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
    f32 targetPosX;
    f32 targetPosY;
    f32 targetPosZ;
    u32 unk14;
    s16 unk18;
    s16 unk1A;
    s16 triggerGameBit;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x24 - 0x22];
    s16 unk24;
    u8 pad26[0x2B - 0x26];
    u8 unk2B;
    s16 unk2C;
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} DbeggPlacement;


/* GCRobotBlast extra block (extraSize 0x8). */
typedef struct GCRobotBlastState
{
    int mode; /* def+0x19 */
    u8 flags04; /* bit 0x80 = blast fired (BlastFlags4 overlay) */
    u8 unk05[3];
} GCRobotBlastState;

STATIC_ASSERT(sizeof(GCRobotBlastState) == 0x8);

/* dbholecontrol1 extra block (extraSize 0xC). */
typedef struct DbHoleControl1State
{
    int gameBitA; /* def+0x1A */
    int gameBitB; /* def+0x1C */
    u8 unk08[4];
} DbHoleControl1State;

STATIC_ASSERT(sizeof(DbHoleControl1State) == 0xC);

extern undefined4 getLActions();
extern undefined4 FUN_80006824();
extern uint FUN_80006ab8();
extern undefined8 FUN_80006ac4();
extern u32 randomGetRange(int min, int max);
extern int FUN_80017a98();
extern undefined8 FUN_800305f8();
extern int ObjHits_GetPriorityHit();
extern uint ObjGroup_ContainsObject();
extern int ObjGroup_FindNearestObjectForObject();
extern int ObjGroup_FindNearestObject();
extern undefined4 ObjMsg_SendToObject();
extern int Obj_GetYawDeltaToObject();
extern undefined4 FUN_8003b818();
extern double FUN_80293900();

extern undefined4 DAT_8032a290;
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern ModgfxInterface** gModgfxInterface;
extern EffectInterface** gPartfxInterface;
extern f64 DOUBLE_803e6f78;
extern f64 DOUBLE_803e7000;
extern f32 lbl_803DC074;
extern f32 lbl_803E6F40;
extern f32 lbl_803E6F50;
extern f32 lbl_803E6F60;
extern f32 lbl_803E6F80;
extern f32 lbl_803E6F84;
extern f32 lbl_803E6F88;
extern f32 lbl_803E6F8C;
extern f32 lbl_803E6F90;
extern f32 lbl_803E6F94;
extern f32 lbl_803E6FD8;
extern f32 lbl_803E6FDC;
extern f32 lbl_803E6FE0;
extern f32 lbl_803E6FE4;
extern f32 lbl_803E7008;
extern f32 lbl_803E700C;
extern f32 lbl_803E7010;


int GCRobotBlast_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);


int dbstealerworm_stateHandlerB04(int obj, int p);

int dbstealerworm_stateHandlerB02(int obj, int p);


/*
 * --INFO--
 *
 * Function: FUN_80200558
 * EN v1.0 Address: 0x80200558
 * EN v1.0 Size: 488b
 * EN v1.1 Address: 0x80200D88
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80200558(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int iVar1;

    iVar1 = *(int*)(*(int*)&((GameObject*)param_9)->extra + 0x40c);
    *(byte*)(iVar1 + 0x14) = *(byte*)(iVar1 + 0x14) | 2;
    *(byte*)(iVar1 + 0x15) = *(byte*)(iVar1 + 0x15) | 4;
    *(float*)(param_10 + 0x2a0) = lbl_803E6F80;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        param_1 = FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7,
                               param_8, param_9, 0x11, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    *(undefined*)(param_10 + 0x34d) = 0x1f;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        *(undefined4*)(iVar1 + 0x18) = *(undefined4*)(param_10 + 0x2d0);
        *(undefined2*)(iVar1 + 0x1c) = 0x24;
        *(undefined4*)(iVar1 + 0x2c) = 0;
        ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                            *(int*)(iVar1 + 0x18), 0x11, param_9, 0x12, param_13, param_14, param_15, param_16);
        FUN_80006824(param_9, SFXfoot_ice_run_3);
    }
    if (lbl_803E6F84 < ((GameObject*)param_9)->anim.currentMoveProgress)
    {
        *(undefined*)(iVar1 + 0x34) = 1;
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80200740
 * EN v1.0 Address: 0x80200740
 * EN v1.0 Size: 556b
 * EN v1.1 Address: 0x80200E88
 * EN v1.1 Size: 544b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80200740(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    float fVar1;
    uint uVar2;
    int iVar3;
    short* psVar4;
    int iVar5;
    double dVar6;
    undefined4 local_48;
    undefined4 local_44;
    undefined4 local_40;
    undefined4 local_3c;
    undefined4 local_38;
    undefined4 local_34;
    undefined4 local_30;
    undefined4 local_2c;
    undefined4 local_28;
    float local_24;
    float local_20;
    float local_1c;

    iVar5 = *(int*)(*(int*)&((GameObject*)param_9)->extra + 0x40c);
    *(byte*)(iVar5 + 0x14) = *(byte*)(iVar5 + 0x14) | 2;
    *(byte*)(iVar5 + 0x15) = *(byte*)(iVar5 + 0x15) & 0xfb;
    fVar1 = lbl_803E6F88;
    *(float*)(param_10 + 0x280) = *(float*)(param_10 + 0x280) / lbl_803E6F88;
    *(float*)(param_10 + 0x284) = *(float*)(param_10 + 0x284) / fVar1;
    *(float*)(param_10 + 0x2a0) = lbl_803E6F8C;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 0x11, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    *(undefined*)(param_10 + 0x34d) = 0x1f;
    if ((((GameObject*)param_9)->anim.currentMoveProgress <= lbl_803E6F84) ||
        (((GameObject*)param_9)->anim.localPosY < *(float*)(*(int*)(param_10 + 0x2d0) + 0x10) - lbl_803E6F90))
    {
        iVar3 = *(int*)(param_10 + 0x2d0);
        local_24 = *(float*)(iVar3 + 0xc) - ((GameObject*)param_9)->anim.localPosX;
        local_20 = *(float*)(iVar3 + 0x10) - (((GameObject*)param_9)->anim.localPosY + lbl_803E6F94);
        local_1c = *(float*)(iVar3 + 0x14) - ((GameObject*)param_9)->anim.localPosZ;
        dVar6 = FUN_80293900((double)(local_1c * local_1c + local_24 * local_24 + local_20 * local_20));
        if (dVar6 < (double)lbl_803E6F50)
        {
            local_40 = *(undefined4*)(param_10 + 0x2d0);
            psVar4 = *(short**)(iVar5 + 0x24);
            local_48 = 0xe;
            local_44 = 1;
            uVar2 = FUN_80006ab8(psVar4);
            if (uVar2 == 0)
            {
                FUN_80006ac4(psVar4, (uint) & local_48);
            }
            *(undefined*)(iVar5 + 0x34) = 1;
        }
    }
    else
    {
        psVar4 = *(short**)(iVar5 + 0x24);
        local_30 = 9;
        local_2c = 0;
        local_28 = 0x24;
        uVar2 = FUN_80006ab8(psVar4);
        if (uVar2 == 0)
        {
            FUN_80006ac4(psVar4, (uint) & local_30);
        }
        *(undefined*)(iVar5 + 0x34) = 1;
        local_34 = *(undefined4*)(param_10 + 0x2d0);
        psVar4 = *(short**)(iVar5 + 0x24);
        local_3c = 7;
        local_38 = 1;
        uVar2 = FUN_80006ab8(psVar4);
        if (uVar2 == 0)
        {
            FUN_80006ac4(psVar4, (uint) & local_3c);
        }
        *(undefined*)(iVar5 + 0x34) = 1;
    }
    return 0;
}


/*
 * --INFO--
 *
 * Function: FUN_80201260
 * EN v1.0 Address: 0x80201260
 * EN v1.0 Size: 616b
 * EN v1.1 Address: 0x802028CC
 * EN v1.1 Size: 404b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80201260(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, uint param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    int iVar1;
    uint uVar2;
    short* psVar3;
    int iVar4;
    undefined4 local_28;
    undefined4 local_24;
    undefined4 local_20;

    iVar4 = *(int*)(*(int*)&((GameObject*)param_9)->extra + 0x40c);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        param_1 = FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7,
                               param_8, param_9, 0, 0, param_12, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        *(undefined4*)(param_10 + 0x2d0) = 0;
        if (*(int*)(iVar4 + 0x18) != 0)
        {
            ObjMsg_SendToObject(param_1, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                                *(int*)(iVar4 + 0x18), 0x11, param_9, 0x10, param_13, param_14, param_15, param_16);
            *(undefined4*)(iVar4 + 0x18) = 0;
        }
        iVar1 = FUN_80017a98();
        iVar1 = (**(code**)(**(int**)(*(int*)(iVar1 + 200) + 0x68) + 0x44))();
        if (iVar1 == 0)
        {
            uVar2 = randomGetRange(0, 2);
            FUN_80006824(param_9, (ushort) * (undefined4*)(&DAT_8032a290 + uVar2 * 4));
        }
        else
        {
            uVar2 = randomGetRange(3, 4);
            FUN_80006824(param_9, (ushort) * (undefined4*)(&DAT_8032a290 + uVar2 * 4));
        }
        local_20 = *(undefined4*)(iVar4 + 0x30);
        local_24 = *(undefined4*)(iVar4 + 0x2c);
        psVar3 = *(short**)(iVar4 + 0x24);
        local_28 = *(undefined4*)(iVar4 + 0x28);
        uVar2 = FUN_80006ab8(psVar3);
        if (uVar2 == 0)
        {
            FUN_80006ac4(psVar3, (uint) & local_28);
        }
        *(undefined4*)(iVar4 + 0x3c) = 0;
    }
    *(undefined*)(param_10 + 0x34d) = 0x10;
    *(float*)(param_10 + 0x2a0) = lbl_803E6FD8;
    *(float*)(param_10 + 0x280) = lbl_803E6F40;
    if (*(char*)(param_10 + 0x346) != '\0')
    {
        *(undefined*)(iVar4 + 0x34) = 1;
    }
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802014c8
 * EN v1.0 Address: 0x802014C8
 * EN v1.0 Size: 400b
 * EN v1.1 Address: 0x80202A60
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_802014c8(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    extern undefined4 ObjHits_EnableObject(); /* #57 */
    extern undefined4 ObjHits_SetHitVolumeSlot(); /* #57 */
    undefined4 uVar1;
    int iVar2;

    iVar2 = *(int*)&((GameObject*)param_9)->extra;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    uVar1 = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    *(float*)(param_10 + 0x2a0) = lbl_803E6F8C;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 10, 0, uVar1, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    *(undefined*)(param_10 + 0x34d) = 1;
    iVar2 = *(int*)(iVar2 + 0x40c);
    *(byte*)(iVar2 + 0x14) = *(byte*)(iVar2 + 0x14) | 2;
    if ((*(uint*)(param_10 + 0x314) & 1) != 0)
    {
        *(uint*)(param_10 + 0x314) = *(uint*)(param_10 + 0x314) & ~1;
        *(byte*)(iVar2 + 0x14) = *(byte*)(iVar2 + 0x14) | 1;
    }
    if (*(char*)(param_10 + 0x346) != '\0')
    {
        *(undefined*)(iVar2 + 0x34) = 1;
    }
    return 0;
}

int dbstealerworm_stateHandlerA09(int obj, int p);

/*
 * --INFO--
 *
 * Function: FUN_80201658
 * EN v1.0 Address: 0x80201658
 * EN v1.0 Size: 328b
 * EN v1.1 Address: 0x80202B5C
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80201658(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    extern undefined4 ObjHits_EnableObject(); /* #57 */
    extern undefined4 ObjHits_SetHitVolumeSlot(); /* #57 */
    undefined4 uVar1;

    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    uVar1 = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    *(float*)(param_10 + 0x2a0) = lbl_803E6F8C;
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                     param_9, 5, 0, uVar1, param_13, param_14, param_15, param_16);
        *(undefined*)(param_10 + 0x346) = 0;
    }
    *(undefined*)(param_10 + 0x34d) = 1;
    return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_802017a0
 * EN v1.0 Address: 0x802017A0
 * EN v1.0 Size: 568b
 * EN v1.1 Address: 0x80202BF8
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_802017a0(undefined8 param_1, double param_2, double param_3, undefined8 param_4, undefined8 param_5,
             undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9, int param_10,
             undefined4 param_11, undefined4 param_12, undefined4 param_13, undefined4 param_14,
             undefined4 param_15, undefined4 param_16)
{
    extern undefined4 ObjHits_EnableObject(); /* #57 */
    extern undefined4 ObjHits_SetHitVolumeSlot(); /* #57 */
    uint uVar1;
    undefined4 uVar2;
    int iVar3;
    int iVar4;

    iVar3 = *(int*)&((GameObject*)param_9)->extra;
    iVar4 = *(int*)(iVar3 + 0x40c);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        ObjHits_EnableObject(param_9);
    }
    uVar2 = 0xffffffff;
    ObjHits_SetHitVolumeSlot(param_9, 10, 1, -1);
    if (*(char*)(param_10 + 0x27a) != '\0')
    {
        uVar1 = randomGetRange(0, 1);
        if (uVar1 == 0)
        {
            if (*(char*)(param_10 + 0x27a) != '\0')
            {
                FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                             param_9, 7, 0, uVar2, param_13, param_14, param_15, param_16);
                *(undefined*)(param_10 + 0x346) = 0;
            }
        }
        else if (*(char*)(param_10 + 0x27a) != '\0')
        {
            FUN_800305f8((double)lbl_803E6F40, param_2, param_3, param_4, param_5, param_6, param_7, param_8,
                         param_9, 6, 0, uVar2, param_13, param_14, param_15, param_16);
            *(undefined*)(param_10 + 0x346) = 0;
        }
        *(undefined*)(param_10 + 0x34d) = 1;
        *(float*)(param_10 + 0x2a0) =
            lbl_803E6FDC +
            (float)((double)CONCAT44(0x43300000, (uint) * (byte*)(iVar3 + 0x406)) - DOUBLE_803e6f78) /
            lbl_803E6FE0;
    }
    *(float*)(param_10 + 0x280) = lbl_803E6F40;
    if (*(char*)(param_10 + 0x346) != '\0')
    {
        *(undefined*)(iVar4 + 0x34) = 1;
    }
    *(byte*)(iVar4 + 0x14) = *(byte*)(iVar4 + 0x14) | 2;
    return 0;
}


/*
 * --INFO--
 *
 * Function: FUN_80202004
 * EN v1.0 Address: 0x80202004
 * EN v1.0 Size: 300b
 * EN v1.1 Address: 0x802032B0
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80202004(double param_1, double param_2, undefined8 param_3, double param_4, ushort* param_5,
             int param_6)
{
    int iVar1;
    undefined4 uVar2;
    int iVar3;
    double dVar4;
    double dVar5;
    float local_48[5];

    iVar3 = *(int*)(param_5 + 0x5c);
    iVar1 = Obj_GetYawDeltaToObject(param_5, param_6, local_48);
    if ((double)lbl_803E6F40 == param_4)
    {
        uVar2 = 0;
    }
    else
    {
        dVar5 = (double)(float)((double)(float)((double)local_48[0] - param_1) / param_4);
        dVar4 = dVar5;
        if (dVar5 < (double)lbl_803E6F40)
        {
            dVar4 = -dVar5;
        }
        if ((double)lbl_803E7008 <= dVar4)
        {
            if (dVar5 < (double)lbl_803E6F40)
            {
                param_2 = -param_2;
            }
            *(float*)(iVar3 + 0x280) =
                lbl_803DC074 * lbl_803E6FE4 *
                ((float)(param_2 *
                    (double)(lbl_803E6F60 -
                        (float)((double)CONCAT44(0x43300000, (int)(short)iVar1 ^ 0x80000000) -
                            DOUBLE_803e7000) / lbl_803E700C)) - *(float*)(iVar3 + 0x280)) +
                *(float*)(iVar3 + 0x280);
            *(float*)(iVar3 + 0x284) = lbl_803E6F40;
            uVar2 = 0;
        }
        else
        {
            uVar2 = 1;
        }
    }
    return uVar2;
}

int dbstealerworm_stateHandlerA06(int obj, int p2);

/*
 * --INFO--
 *
 * Function: FUN_80202130
 * EN v1.0 Address: 0x80202130
 * EN v1.0 Size: 312b
 * EN v1.1 Address: 0x802033DC
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_80202130(double param_1, double param_2, undefined8 param_3, double param_4, ushort* param_5,
             int param_6)
{
    int iVar1;
    int iVar2;
    double dVar3;
    float local_58[7];

    iVar2 = *(int*)(param_5 + 0x5c);
    if ((param_5 != (ushort*)0x0) && (param_6 != 0))
    {
        iVar1 = Obj_GetYawDeltaToObject(param_5, param_6, local_58);
        if ((double)lbl_803E6F40 != param_4)
        {
            if ((double)local_58[0] < param_1)
            {
                dVar3 = (double)(*(float*)(param_5 + 8) - *(float*)(param_6 + 0x10));
                if (dVar3 < (double)lbl_803E6F40)
                {
                    dVar3 = -dVar3;
                }
                if (dVar3 < (double)lbl_803E7010)
                {
                    return 1;
                }
            }
            *(float*)(iVar2 + 0x280) =
                lbl_803DC074 * lbl_803E6FE4 *
                ((float)(param_2 *
                    (double)(lbl_803E6F60 -
                        (float)((double)CONCAT44(0x43300000, (int)(short)iVar1 ^ 0x80000000) -
                            DOUBLE_803e7000) / lbl_803E700C)) - *(float*)(iVar2 + 0x280)) +
                *(float*)(iVar2 + 0x280);
            *(float*)(iVar2 + 0x284) = lbl_803E6F40;
        }
    }
    return 0;
}


int dbstealerworm_stateHandlerA05(int obj, int p);


int dbstealerworm_stateHandlerA03(int obj, int p);


int dbstealerworm_stateHandlerA01(int obj, int p);


/*
 * --INFO--
 *
 * Function: FUN_80204320
 * EN v1.0 Address: 0x80204320
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x802051FC
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80204320(int param_1, int param_2, int param_3, int param_4, int param_5, s8 visible)
{
    if (visible != 0)
    {
        FUN_8003b818(param_1);
    }
    return;
}

void fn_80204320(int obj);


void dll_22C_init(int obj, char* p);


/* Trivial 4b 0-arg blr leaves. */
void dbegg_release(void);

void dbegg_initialise(void);

void GCRobotBlast_free(void);

void GCRobotBlast_render(void);

void GCRobotBlast_hitDetect(void);

void GCRobotBlast_update(void);

void GCRobotBlast_release(void);

void GCRobotBlast_initialise(void);

void DrakorEnergy_func0B_nop(void);

void drakorenergy_free(void);

void drakorenergy_hitDetect(void);

void drakorenergy_release(void);

void drakorenergy_initialise(void);

extern f32 lbl_803E627C;
extern f32 lbl_803E62A0;

void drakorenergy_init(int* obj, u8* init);

void dbstealerworm_release(void);

void dbholecontrol1_hitDetect(void);

void dbholecontrol1_release(void);

void dbholecontrol1_initialise(void);

extern void Obj_RemoveFromUpdateList(int* obj);

void dbholecontrol1_update(int* obj);

extern void Stack_Free(int* stack);
extern void Obj_FreeObject(int obj);
extern void** gBaddieControlInterface;
extern int* gPlayerInterface;
extern f32 lbl_803E62A8;
extern f32 lbl_803E62FC;
extern u8 lbl_80329514[];
extern void* memset(void* dst, int v, int n);

void dbstealerworm_init(int* obj, u8* def, int param3);

void dbstealerworm_free(int* obj);

void dbholecontrol1_init(int* obj, u8* params);

void dfplevelcontrol_render(void);

void dfplevelcontrol_hitDetect(void);

void dfplevelcontrol_release(void);

void dfpobjcreator_hitDetect(void)
{
}

void dfpobjcreator_release(void)
{
}

void dfpobjcreator_initialise(void)
{
}

void dll_22C_hitDetect_nop(void);

void dll_22C_release_nop(void);

void dll_22C_initialise_nop(void);

void doorswitch_render(void);

void doorswitch_hitDetect(void);

void doorswitch_release(void);

void doorswitch_initialise(void);

void dfpseqpoint_free(void);

void dfpseqpoint_hitDetect(void);

void dfpseqpoint_release(void);

void dfpseqpoint_initialise(void);

void dfpseqpoint_init(int* obj, u8* init);

void DFP_Torch_hitDetect(void);

void DFP_Torch_release(void);

void DFP_Torch_initialise(void);

void chuka_render(void);

/* 8b "li r3, N; blr" returners. */
int GCRobotBlast_getExtraSize(void);
int GCRobotBlast_getObjectTypeId(void);
int drakorenergy_getExtraSize(void);
int drakorenergy_getObjectTypeId(void);
int dbstealerworm_getExtraSize(void);
int dbstealerworm_getObjectTypeId(void);
int dbholecontrol1_getExtraSize(void);
int dbholecontrol1_getObjectTypeId(void);
int dfplevelcontrol_getExtraSize(void);
int dfplevelcontrol_getObjectTypeId(void);
int dfpobjcreator_getExtraSize(void) { return 0x1c; }
int dfpobjcreator_getObjectTypeId(void) { return 0x0; }
int dll_22C_SeqFn(void);
int dll_22C_getExtraSize_ret_16(void);
int dll_22C_getObjectTypeId(void);
int doorswitch_getExtraSize(void);
int doorswitch_getObjectTypeId(void);
int dfpseqpoint_getExtraSize(void);
int dfpseqpoint_getObjectTypeId(void);
int DFP_Torch_getExtraSize(void);
int DFP_Torch_getObjectTypeId(void);
int chuka_SeqFn(void);
int chuka_getExtraSize(void);
int chuka_getObjectTypeId(void);

/* Pattern wrappers. */
s16 DBstealerworm_setScale(int* obj);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E6390;
extern f32 lbl_803E6398;
extern f32 lbl_803E63B8;

void dbholecontrol1_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void dll_22C_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void dfpseqpoint_render(int p1, int p2, int p3, int p4, int p5, s8 visible);

void dfpobjcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

extern f32 lbl_803E6278;

void drakorenergy_render(int obj, int p1, int p2, int p3, int p4, s8 visible);

extern int gDBStealerWormStateHandlersA[];

void chuka_free(int obj);

void chuka_hitDetect(int obj);

void dbstealerworm_hitDetect(int obj);

void GCRobotBlast_init(int obj, s8* p);

/* ObjGroup_RemoveObject(x, N) wrappers. */
void dbholecontrol1_free(int x);
void dfplevelcontrol_free(int x);

/* plain forwarder. */
extern void DBstealerwo_setFuncPtrs_80203c78(void);
void dbstealerworm_initialise(void);

/* OSReport(string) wrappers. */
extern void OSReport(const char* fmt, ...);
void doorswitch_free(void);
void doorswitch_update(void);
void doorswitch_init(void);

int DrakorEnergy_setScale(int* obj);

/* alpha-flag predicate: returns 7 on fire/clear, 0 on idle */
int dbstealerworm_stateHandlerB00(int p1, int p2);

/* baddie anim update: fires vtable[0x13] when flag set */
int dbstealerworm_stateHandlerB03(int p1, int p2);

/* anim progress accumulator */
extern f32 lbl_803E62BC;

int dbstealerworm_stateHandlerB01(int p1, int p2);

/* clear list-actions wrapper: notifies vtable[6] then resets getLActions */
void fn_80204B6C(int p1);

/* timed counter: decrement (p1->b8)->0 by timeDelta, then notify */
extern void fn_802960E8(void* playerObj, int p2);
extern f32 timeDelta;

int dfplevelcontrol_SeqFn(int p1);

extern s16 lbl_80329848[];

void dfplevelcontrol_initialise(void);

void dfpobjcreator_free(int obj, int flag)
{
    DfpObjCreatorState* state = ((GameObject*)obj)->extra;
    if (flag == 0)
    {
        if (*(void**)&state->spawnedObj != NULL)
        {
            Obj_FreeObject(state->spawnedObj);
            state->spawnedObj = 0;
        }
    }
}


void dbegg_init(int obj);

void DFP_Torch_free(int obj);

void dfpobjcreator_init(int obj, s8* def)
{
    DfpObjCreatorState* state = ((GameObject*)obj)->extra;
    *(s16*)obj = (s16)((s32)def[0x1E] << 8);
    state->gameBit = ((DfpobjcreatorObjectDef*)def)->gameBit;
    state->spawnPeriod = ((DfpobjcreatorObjectDef*)def)->spawnPeriod;
    state->spawnTimer = state->spawnPeriod;
    state->unk12 = (s16)(s32)
    def[0x1F];
    state->unk14 = (s16)((s32)(u8)def[0x20] << 1);
    state->unk16 = 100;
}

void dfplevelcontrol_setScale(int unused, u8* out);

int dbstealerworm_stateHandlerA00(int obj, int p2);

int dbholecontrol1_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate);

int dbstealerworm_func0B(int obj, u8 msg, int* out);

extern int gDBStealerWormStateHandlersB[];
extern int dbstealerworm_stateHandlerA02();
extern int dbstealerworm_stateHandlerA04();
extern int dbstealerworm_stateHandlerA07(int obj, int p2, f32 t);
extern int dbstealerworm_stateHandlerA08(int obj, int p2, f32 t);
extern int dbstealerworm_stateHandlerA0A();
extern int dbstealerworm_stateHandlerA0B(int obj, int p2, f32 t);
extern int dbstealerworm_stateHandlerA0C(int obj, int p2, f32 t);
extern int dbstealerworm_stateHandlerA0D();
extern int dbstealerworm_stateHandlerA0E();
extern int dbstealerworm_stateHandlerA0F(int obj, int p2, f32 t);
extern int dbstealerworm_stateHandlerB05();
extern int dbstealerworm_stateHandlerB06();

void DBstealerwo_setFuncPtrs_80203c78(void);

extern void fn_80202EF0(int obj, int p2);

#pragma dont_inline on
void fn_80203000(int obj, int param2);
#pragma dont_inline reset

extern void unlockLevel(int a, int b, int c);
extern void Music_Trigger(int a, int b);


void dfplevelcontrol_init(int obj, int param2);

extern f32 lbl_803E62F4;

int dbstealerworm_stateHandlerA04(int obj, int param2);

extern f32 lbl_803E62E8;
extern f32 lbl_803E62EC;

int dbstealerworm_stateHandlerA0E(int obj, int param2);

extern f64 lbl_803E63F0;
extern f32 lbl_803E63E4;
extern f32 lbl_803E63E8;
extern f32 lbl_803E63E0;

void DFP_Torch_init(int obj, int param2);

void fn_80202EF0(int obj, int p2);

#pragma opt_common_subs off
#pragma dont_inline on
int fn_80202C78(int obj, int p6, f32 p1, f32 p2, f32 p3, f32 p4);
#pragma dont_inline reset
#pragma opt_common_subs reset

#pragma dont_inline on
int fn_80202DA4(u8* obj, u8* p6, f32 p1, f32 p2, f32 p3, f32 p4);

void dfpobjcreator_update(int obj)
{
    extern u8 Obj_IsLoadingLocked(void);
    extern uint GameBit_Get(int);
    extern u8*Obj_AllocObjectSetup(int, int);
    extern u8*Obj_SetupObject(u8*, int, int, int, int);
    extern f32 timeDelta;
    int data = *(int*)&((GameObject*)obj)->anim.placementData;
    DfpObjCreatorState* state = ((GameObject*)obj)->extra;
    u8* setup;
    u8* newObj;

    if (Obj_IsLoadingLocked() != 0)
    {
        switch (((DfpobjcreatorPlacement*)data)->unk1A)
        {
        case 7:
            state->spawnTimer -= (s16)timeDelta;
            if (state->spawnTimer <= 0 && GameBit_Get(state->gameBit) != 0)
            {
                state->spawnTimer = state->spawnPeriod;
                setup = Obj_AllocObjectSetup(0x24, 0x71b);
                ((ObjPlacement*)setup)->posX = ((DfpobjcreatorPlacement*)data)->posX;
                ((ObjPlacement*)setup)->posY = ((DfpobjcreatorPlacement*)data)->posY;
                ((ObjPlacement*)setup)->posZ = ((DfpobjcreatorPlacement*)data)->posZ;
                setup[4] = ((DfpobjcreatorPlacement*)data)->unk4;
                setup[5] = ((DfpobjcreatorPlacement*)data)->unk5;
                setup[6] = ((DfpobjcreatorPlacement*)data)->unk6;
                setup[7] = ((DfpobjcreatorPlacement*)data)->unk7;
                *(s16*)(setup + 0x1e) = -1;
                *(s16*)(setup + 0x20) = -1;
                *(s16*)(setup + 0x1a) = 0xdc;
                newObj = Obj_SetupObject(setup, 5, ((GameObject*)obj)->anim.mapEventSlot, -1,
                                         *(int*)&((GameObject*)obj)->anim.parent);
                ((GameObject*)newObj)->unkF4 = *(s8*)(data + 0x1e);
            }
            break;
        }
    }
}
#pragma dont_inline reset

int dbstealerworm_stateHandlerA02(int obj, int p2);

void dbstealerworm_render(int obj, int p2, int p3, int p4, int p5, s8 visible);

int dbstealerworm_stateHandlerA0D(int obj, int p2);

typedef struct
{
    u8 flag80 : 1;
    u8 flag40 : 1;
    u8 flag20 : 1;
    u8 flag10 : 1;
} AnimFlags44;

int dbstealerworm_stateHandlerB05(int obj, int p2);

void fn_80203144(int obj, int p2, int p3);

void dfplevelcontrol_update(int obj);

int fn_80202A2C(int obj, int* objs, f32* weights, int n, f32 limit);

void DFP_Torch_render(int obj, int p2, int p3, int p4, int p5, s8 visible);

void fn_80204098(int obj);

int dbstealerworm_stateHandlerB06(int obj, int p2);

int dbstealerworm_stateHandlerA0A(int obj, int p2);

int dbstealerworm_stateHandlerA0B(int obj, int p2, f32 t);

int dbstealerworm_stateHandlerA07(int obj, int p2, f32 t);

#pragma opt_loop_invariants off
void dbstealerworm_update(u8* objp);
#pragma opt_loop_invariants reset

int dbstealerworm_stateHandlerA08(int obj, int p2, f32 t);

void fn_80204BF8(int obj);

int dbstealerworm_stateHandlerA0C(int obj, int p2, f32 t);

void chuka_update(int obj);

void DFP_Torch_update(int obj);

void drakorenergy_update(int obj);

int dfpseqpoint_SeqFn(int obj, int p2, ObjAnimUpdateState* animUpdate);

void dfpseqpoint_update(int obj);

int dbstealerworm_stateHandlerA0F(int obj, int p2, f32 t);

void dbegg_update(int obj);

/* === moved from main/dll/baddie/chuka.c [8020637C-80206474) (TU re-split, docs/boundary_audit.md) === */
#include "main/dll/baddie/chuka.h"
#include "main/effect_interfaces.h"
#include "main/dll_000A_expgfx.h"
#include "main/game_object.h"

extern u8 gChukaModeTable[9];
extern f32 lbl_803E63F8;
extern f32 lbl_803E63FC;

/*
 * --INFO--
 *
 * Function: chuka_init
 * EN v1.0 Address: 0x8020637C
 * EN v1.0 Size: 240b
 * EN v1.1 Address: 0x80206444
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void chuka_init(int obj, int params);

/*
 * --INFO--
 *
 * Function: dfpfloorbar_free
 * EN v1.0 Address: 0x80206480
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80206590
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/* EN v1.0 0x80206474  size: 8b   trivial 0-returner. */

/* EN v1.0 0x80206484  size: 8b   trivial 0-returner. */

/*
 * --INFO--
 *
 * Function: chuka_release
 * EN v1.0 Address: 0x8020646C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void chuka_release(void);

/*
 * --INFO--
 *
 * Function: chuka_initialise
 * EN v1.0 Address: 0x80206470
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void chuka_initialise(void);

/*
 * --INFO--
 *
 * Function: dfpfloorbar_getExtraSize
 * EN v1.0 Address: 0x8020647C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

extern f32 lbl_803E6408;

/* EN v1.0 0x802064D0  size: 48b   if (p6) objRenderFn_8003b8f4(lbl_803E6408).
 * Logic-only (~91%): retail uses extsb+cmpwi, MWCC -O4,p folds to extsb.
 */

/* EN v1.0 0x80206500  size: 44b   if (b->_8 && (b->_8->_6 & 0x40)) clear. */
