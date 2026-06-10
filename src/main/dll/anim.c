#include "ghidra_import.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/rom_curve_interface.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/mapEventTypes.h"
#include "main/dll/anim.h"
#include "main/dll/baddie_state.h"
#include "main/objanim_internal.h"
#include "main/objhits_types.h"
#include "main/objseq.h"
#include "main/objfx.h"
#include "main/resource.h"

/*
 * DbStealerwormControl - the per-family control record hung off
 * GroundBaddieState.control (state+0x40C) for dbstealerworm
 * (extraSize 0x460 = GroundBaddieState 0x410 + a 0x50 private tail;
 * the control record itself is memset(0x50) in dbstealerworm_init).
 */
typedef struct DbStealerwormControl {
    int cfg; /* entry in the lbl_80329514 table (stride 8 ints) */
    f32 unk04;
    f32 unk08;
    f32 unk0C; /* countdown; init randomGetRange(10, 300) */
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
typedef struct DfpLevelControlState {
    s16 timer; /* counts down by timeDelta; set 300 on gamebit 1509 */
    s16 mode; /* 1..2, from def+0x1A */
    u8 unk04[2];
    u8 sfxLatch; /* gamebit-1589 one-shot latch */
    u8 flags07; /* DfpFlags7 bitfield overlay */
    u8 unk08[4];
} DfpLevelControlState;

STATIC_ASSERT(sizeof(DfpLevelControlState) == 0xC);

/* dfpobjcreator extra block (extraSize 0x1C). */
typedef struct DfpObjCreatorState {
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
typedef struct DfpTorchState {
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
typedef struct Dll22CState {
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
typedef struct DbEggState {
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
typedef struct DfpSeqPointState {
    f32 triggerRadius; /* def+0x1A */
    s16 gameBitGate; /* 0x04: def+0x1E */
    s16 gameBitDone; /* 0x06: def+0x20 */
    s16 triggerId; /* 0x08: def+0x1C */
    u8 unk0A[3];
    u8 doneLatch; /* 0x0D */
    u8 triggerMode; /* 0x0E: def+0x19 */
    u8 flags0F; /* DfpFlags7-style bit 0x80 */
} DfpSeqPointState;

typedef struct DfpFlags7 {
    u8 b80 : 1;
    u8 b40 : 1;
    u8 b20 : 1;
    u8 rest : 5;
} DfpFlags7;

STATIC_ASSERT(sizeof(DfpSeqPointState) == 0x10);

/* drakorenergy extra block (extraSize 0xC). */
typedef struct DrakorEnergyState {
    f32 startY; /* spawn height; bounce threshold in mode 1 */
    int phase; /* += framesThisStep * 0x500; drives glow color/bob */
    u8 mode; /* 0x08: 0 idle, 1 falling, 2 bobbing, 3 chasing, 4 collected, 5 reset */
    u8 unk09[3];
} DrakorEnergyState;

STATIC_ASSERT(sizeof(DrakorEnergyState) == 0xC);

/* chuka extra block (extraSize 0xC). */
#include "main/dll/baddie/chuka.h"

typedef struct DfpseqpointPlacement {
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


typedef struct DrakorenergyPlacement {
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
    s16 unk20;
    u8 pad22[0x24 - 0x22];
    s16 unk24;
    u8 pad26[0x2B - 0x26];
    u8 unk2B;
    u8 pad2C[0x2E - 0x2C];
    s8 unk2E;
    u8 pad2F[0x30 - 0x2F];
} DrakorenergyPlacement;


typedef struct DbstealerwormState {
    u8 pad0[0xC - 0x0];
    f32 unkC;
    f32 unk10;
    f32 unk14;
    s32 unk18;
    u8 pad1C[0xC8 - 0x1C];
    s32 unkC8;
    u8 padCC[0x280 - 0xCC];
    f32 unk280;
    f32 unk284;
    u8 pad288[0x40C - 0x288];
    s32 unk40C;
    u8 pad410[0x460 - 0x410];
} DbstealerwormState;


typedef struct DfpobjcreatorObjectDef {
    u8 pad0[0x18 - 0x0];
    s16 unk18;
    u8 pad1A[0x1C - 0x1A];
    s16 unk1C;
    u8 pad1E[0x24 - 0x1E];
    s16 unk24;
    u8 pad26[0x28 - 0x26];
} DfpobjcreatorObjectDef;


typedef struct Dbholecontrol1Placement {
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


typedef struct ChukaPlacement {
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


typedef struct DfpobjcreatorPlacement {
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
    f32 unk8;
    f32 unkC;
    f32 unk10;
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


typedef struct DbstealerwormPlacement {
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
    f32 posX8;
    f32 posY8;
    f32 posZ8;
    u32 unk14;
    s16 unk18;
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


typedef struct DbeggPlacement {
    u8 pad0[0x4 - 0x0];
    u8 unk4;
    u8 unk5;
    u8 unk6;
    u8 unk7;
    f32 posX8;
    f32 posY8;
    f32 posZ8;
    u32 unk14;
    s16 unk18;
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
} DbeggPlacement;


/* GCRobotBlast extra block (extraSize 0x8). */
typedef struct GCRobotBlastState {
    int mode; /* def+0x19 */
    u8 flags04; /* bit 0x80 = blast fired (BlastFlags4 overlay) */
    u8 unk05[3];
} GCRobotBlastState;

STATIC_ASSERT(sizeof(GCRobotBlastState) == 0x8);

/* dbholecontrol1 extra block (extraSize 0xC). */
typedef struct DbHoleControl1State {
    int gameBitA; /* def+0x1A */
    int gameBitB; /* def+0x1C */
    u8 unk08[4];
} DbHoleControl1State;

STATIC_ASSERT(sizeof(DbHoleControl1State) == 0xC);

extern undefined4 FUN_800033a8();
extern undefined8 FUN_80003494();
extern undefined4 getLActions();
extern undefined4 FUN_800067c0();
extern bool FUN_800067f0();
extern undefined4 FUN_8000680c();
extern undefined4 FUN_80006824();
extern undefined4 FUN_800068c4();
extern void* FUN_800069a8();
extern int FUN_80006a10();
extern int FUN_80006a64();
extern undefined8 FUN_80006a68();
extern uint FUN_80006ab0();
extern uint FUN_80006ab8();
extern undefined4 FUN_80006ac0();
extern undefined8 FUN_80006ac4();
extern undefined8 FUN_80006ac8();
extern undefined4 FUN_80006acc();
extern undefined4 FUN_80006b0c();
extern undefined4 FUN_80006b14();
extern uint FUN_80006c00();
extern undefined4 FUN_80017688();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern undefined4 FUN_80017710();
extern double FUN_80017714();
extern undefined4 FUN_8001771c();
extern uint FUN_80017758();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017784();
extern undefined4 FUN_80017a5c();
extern undefined4 FUN_80017a88();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined4 FUN_80017ac8();
extern undefined4 FUN_80017ad0();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 FUN_8002f6ac();
extern undefined8 FUN_800305f8();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_DisableObject();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHit();
extern uint ObjGroup_ContainsObject();
extern int ObjGroup_FindNearestObjectForObject();
extern int ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_SendToObjects();
extern undefined4 ObjMsg_SendToObject();
extern undefined4 ObjMsg_AllocQueue();
extern undefined4 ObjPath_GetPointWorldPosition();
extern int Obj_GetYawDeltaToObject();
extern void* FUN_80039518();
extern undefined4 FUN_8003964c();
extern undefined4 FUN_8003b540();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80042b9c();
extern undefined4 FUN_80042bec();
extern undefined4 FUN_80044404();
extern undefined4 FUN_80053c98();
extern undefined4 FUN_80057690();
extern undefined4 FUN_8005b024();
extern int FUN_8005b398();
extern uint FUN_8005b54c();
extern undefined4 FUN_800723a0();
extern undefined4 FUN_800810f4();
extern undefined4 FUN_8008110c();
extern undefined4 FUN_8008111c();
extern undefined8 FUN_80081120();
extern undefined4 FUN_80135814();
extern undefined4 SH_LevelControl_runBloopEvent();
extern undefined4 FUN_801d8480();
extern undefined4 FUN_801fe3b0();
extern undefined4 FUN_801fe540();
extern int FUN_801fe750();
extern undefined4 FUN_801fe924();
extern undefined4 FUN_8020a488();
extern undefined4 FUN_80247eb8();
extern undefined4 FUN_80247edc();
extern undefined4 FUN_80247ef8();
extern double SeekTwiceBeforeRead();
extern undefined8 FUN_80286830();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined8 FUN_80286840();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern undefined4 FUN_80294c44();
extern undefined4 FUN_80294d60();
extern undefined4 SUB42();

extern undefined4 DAT_802c2c90;
extern undefined4 DAT_802c2c94;
extern undefined4 DAT_802c2c98;
extern undefined4 DAT_802c2c9c;
extern undefined4 DAT_8032a158;
extern undefined4 DAT_8032a274;
extern undefined4 DAT_8032a280;
extern undefined4 DAT_8032a284;
extern undefined4 DAT_8032a290;
extern undefined4 DAT_8032a2a4;
extern undefined4 DAT_8032a31c;
extern undefined4 DAT_8032a33c;
extern undefined4 DAT_8032a34c;
extern undefined4 DAT_8032a35c;
extern undefined4 DAT_8032a36c;
extern undefined4 DAT_8032a37c;
extern undefined4 DAT_8032a38c;
extern undefined2 DAT_8032a488;
extern undefined4 DAT_8032a494;
extern undefined4 DAT_8032a496;
extern undefined4 DAT_8032a498;
extern undefined4 DAT_803add20;
extern undefined4 DAT_803add2c;
extern undefined4 DAT_803add30;
extern undefined4 DAT_803add34;
extern undefined4 DAT_803add38;
extern undefined4 DAT_803add3c;
extern undefined4 DAT_803add40;
extern undefined4 DAT_803add44;
extern undefined4 DAT_803add48;
extern undefined4 DAT_803add4c;
extern undefined4 DAT_803add50;
extern undefined4 DAT_803add54;
extern undefined4 DAT_803add58;
extern undefined4 DAT_803add5c;
extern undefined4 DAT_803add60;
extern undefined4 DAT_803add64;
extern undefined4 DAT_803add68;
extern undefined4 DAT_803add6c;
extern undefined4 DAT_803add70;
extern undefined4 DAT_803add74;
extern undefined4 DAT_803add78;
extern undefined4 DAT_803add7c;
extern undefined4 DAT_803add80;
extern undefined4 DAT_803add84;
extern undefined4 DAT_803add88;
extern undefined4 DAT_803add8c;
extern undefined4 DAT_803add90;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dcdd8;
extern undefined4 DAT_803dcde0;
extern undefined4 DAT_803dcde8;
extern undefined4 DAT_803dcdea;
extern undefined4 DAT_803dcdeb;
extern ObjectTriggerInterface **gObjectTriggerInterface;
extern ModgfxInterface **gModgfxInterface;
extern EffectInterface **gPartfxInterface;
extern undefined4* DAT_803dd70c;
extern undefined4* DAT_803dd718;
extern undefined4* DAT_803dd71c;
extern MapEventInterface **gMapEventInterface;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803de960;
extern undefined4 DAT_803de968;
extern undefined4 DAT_803e6e58;
extern undefined4 DAT_803e6e5c;
extern f64 DOUBLE_803e6ea8;
extern f64 DOUBLE_803e6f78;
extern f64 DOUBLE_803e7000;
extern f64 DOUBLE_803e7048;
extern f64 DOUBLE_803e7058;
extern f32 lbl_803DC074;
extern f32 lbl_803DC078;
extern f32 lbl_803DCDC8;
extern f32 lbl_803DCDCC;
extern f32 lbl_803DCDD0;
extern f32 lbl_803DCDD4;
extern f32 playerMapOffsetZ;
extern f32 lbl_803E6E60;
extern f32 lbl_803E6E64;
extern f32 lbl_803E6E7C;
extern f32 lbl_803E6E84;
extern f32 lbl_803E6E98;
extern f32 lbl_803E6EB8;
extern f32 lbl_803E6EBC;
extern f32 lbl_803E6EC0;
extern f32 lbl_803E6EC4;
extern f32 lbl_803E6EC8;
extern f32 lbl_803E6ECC;
extern f32 lbl_803E6ED0;
extern f32 lbl_803E6ED4;
extern f32 lbl_803E6ED8;
extern f32 lbl_803E6EDC;
extern f32 lbl_803E6EE0;
extern f32 lbl_803E6EE4;
extern f32 lbl_803E6EE8;
extern f32 lbl_803E6EEC;
extern f32 lbl_803E6EF0;
extern f32 lbl_803E6EF4;
extern f32 lbl_803E6EF8;
extern f32 lbl_803E6EFC;
extern f32 lbl_803E6F00;
extern f32 lbl_803E6F08;
extern f32 lbl_803E6F0C;
extern f32 lbl_803E6F14;
extern f32 lbl_803E6F18;
extern f32 lbl_803E6F1C;
extern f32 lbl_803E6F20;
extern f32 lbl_803E6F2C;
extern f32 lbl_803E6F38;
extern f32 lbl_803E6F40;
extern f32 lbl_803E6F44;
extern f32 lbl_803E6F48;
extern f32 lbl_803E6F4C;
extern f32 lbl_803E6F50;
extern f32 lbl_803E6F58;
extern f32 lbl_803E6F5C;
extern f32 lbl_803E6F60;
extern f32 lbl_803E6F64;
extern f32 lbl_803E6F68;
extern f32 lbl_803E6F6C;
extern f32 lbl_803E6F70;
extern f32 lbl_803E6F80;
extern f32 lbl_803E6F84;
extern f32 lbl_803E6F88;
extern f32 lbl_803E6F8C;
extern f32 lbl_803E6F90;
extern f32 lbl_803E6F94;
extern f32 lbl_803E6F98;
extern f32 lbl_803E6F9C;
extern f32 lbl_803E6FA0;
extern f32 lbl_803E6FA4;
extern f32 lbl_803E6FA8;
extern f32 lbl_803E6FAC;
extern f32 lbl_803E6FB0;
extern f32 lbl_803E6FB4;
extern f32 lbl_803E6FB8;
extern f32 lbl_803E6FBC;
extern f32 lbl_803E6FC0;
extern f32 lbl_803E6FC4;
extern f32 lbl_803E6FC8;
extern f32 lbl_803E6FCC;
extern f32 lbl_803E6FD0;
extern f32 lbl_803E6FD4;
extern f32 lbl_803E6FD8;
extern f32 lbl_803E6FDC;
extern f32 lbl_803E6FE0;
extern f32 lbl_803E6FE4;
extern f32 lbl_803E6FE8;
extern f32 lbl_803E6FEC;
extern f32 lbl_803E6FF0;
extern f32 lbl_803E6FF4;
extern f32 lbl_803E7008;
extern f32 lbl_803E700C;
extern f32 lbl_803E7010;
extern f32 lbl_803E7014;
extern f32 lbl_803E7018;
extern f32 lbl_803E701C;
extern f32 lbl_803E7020;
extern f32 lbl_803E7034;
extern f32 lbl_803E7038;
extern f32 lbl_803E703C;
extern f32 lbl_803E7040;
extern f32 lbl_803E7060;
extern f32 lbl_803E7064;
extern f32 lbl_803E7068;
extern f32 lbl_803E706C;
extern f32 lbl_803E7070;
extern f32 lbl_803E7074;
extern f32 lbl_803E7078;
extern undefined4 PTR_DAT_8032a154;


int GCRobotBlast_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate)
{
  extern void objfx_spawnDirectionalBurst(int, int, f32, int, int, int, f32, int, int);
  extern f32 lbl_803E6270;
  extern f32 lbl_803E6274;
  typedef struct {
    u8 b80 : 1;
  } BlastFlags4;
  int sub = *(int *)&((GameObject *)obj)->extra;
  int i;

  for (i = 0; i < animUpdate->eventCount; i++) {
    ((BlastFlags4 *)&((GCRobotBlastState *)sub)->flags04)->b80 = animUpdate->eventIds[i];
  }
  if (((u32)((GCRobotBlastState *)sub)->flags04 >> 7 & 1) != 0) {
    switch (((GCRobotBlastState *)sub)->mode) {
    case 0:
    case 1:
      objfx_spawnDirectionalBurst(obj, 7, lbl_803E6270, 5, 6, 0x64, lbl_803E6274, 0, 0x200000);
      objfx_spawnDirectionalBurst(obj, 6, lbl_803E6270, 1, 6, 0x64, lbl_803E6274, 0, 0x200000);
      break;
    }
  }
  return 0;
}


int dbstealerworm_stateHandlerB04(int obj, int p)
{
  extern int *gPlayerInterface;
  extern f32 lbl_803E62A8;
  float fz;
  int b8;

  b8 = *(int *)&((GameObject *)obj)->extra;
  if (*(char *)&((BaddieState *)p)->moveJustStartedB != '\0') {
    (**(void (**)(int, int, int))(*gPlayerInterface + 0x14))(obj, p, 1);
    b8 = *(int *)&((GroundBaddieState *)b8)->control;
    fz = lbl_803E62A8;
    ((DbStealerwormControl *)b8)->unk0C = lbl_803E62A8;
    ((DbStealerwormControl *)b8)->unk10 = fz;
    ((DbStealerwormControl *)b8)->unk04 = fz;
  }
  return 0;
}

int dbstealerworm_stateHandlerB02(int obj, int p)
{
  extern int *gPlayerInterface;
  extern f32 lbl_803E62A8;
  int b8;
  float fz;
  s8 flag2;

  b8 = *(int *)&((GameObject *)obj)->extra;
  if (*(char *)&((BaddieState *)p)->moveJustStartedB != '\0') {
    b8 = *(int *)&((GroundBaddieState *)b8)->control;
    fz = lbl_803E62A8;
    ((DbStealerwormControl *)b8)->unk0C = lbl_803E62A8;
    ((DbStealerwormControl *)b8)->unk10 = fz;
    ((DbStealerwormControl *)b8)->unk04 = fz;
    (**(void (**)(int, int, int))(*gPlayerInterface + 0x14))(obj, p, 6);
  } else {
    flag2 = *(char *)&((BaddieState *)p)->moveDone;
    if (flag2 != 0) {
      if (((GameObject *)obj)->anim.alpha == 0) {
        if (flag2 != 0) {
          return 7;
        }
      }
    }
  }
  return 0;
}


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
FUN_80200558(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  
  iVar1 = *(int *)(*(int *)&((GameObject *)param_9)->extra + 0x40c);
  *(byte *)(iVar1 + 0x14) = *(byte *)(iVar1 + 0x14) | 2;
  *(byte *)(iVar1 + 0x15) = *(byte *)(iVar1 + 0x15) | 4;
  *(float *)(param_10 + 0x2a0) = lbl_803E6F80;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    param_1 = FUN_800305f8((double)lbl_803E6F40,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,param_9,0x11,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 0x1f;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(undefined4 *)(iVar1 + 0x18) = *(undefined4 *)(param_10 + 0x2d0);
    *(undefined2 *)(iVar1 + 0x1c) = 0x24;
    *(undefined4 *)(iVar1 + 0x2c) = 0;
    ObjMsg_SendToObject(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 *(int *)(iVar1 + 0x18),0x11,param_9,0x12,param_13,param_14,param_15,param_16);
    FUN_80006824(param_9,SFXfoot_ice_run_3);
  }
  if (lbl_803E6F84 < ((GameObject *)param_9)->anim.currentMoveProgress) {
    *(undefined *)(iVar1 + 0x34) = 1;
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
FUN_80200740(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  float fVar1;
  uint uVar2;
  int iVar3;
  short *psVar4;
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
  
  iVar5 = *(int *)(*(int *)&((GameObject *)param_9)->extra + 0x40c);
  *(byte *)(iVar5 + 0x14) = *(byte *)(iVar5 + 0x14) | 2;
  *(byte *)(iVar5 + 0x15) = *(byte *)(iVar5 + 0x15) & 0xfb;
  fVar1 = lbl_803E6F88;
  *(float *)(param_10 + 0x280) = *(float *)(param_10 + 0x280) / lbl_803E6F88;
  *(float *)(param_10 + 0x284) = *(float *)(param_10 + 0x284) / fVar1;
  *(float *)(param_10 + 0x2a0) = lbl_803E6F8C;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E6F40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0x11,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 0x1f;
  if ((((GameObject *)param_9)->anim.currentMoveProgress <= lbl_803E6F84) ||
     (((GameObject *)param_9)->anim.localPosY < *(float *)(*(int *)(param_10 + 0x2d0) + 0x10) - lbl_803E6F90))
  {
    iVar3 = *(int *)(param_10 + 0x2d0);
    local_24 = *(float *)(iVar3 + 0xc) - ((GameObject *)param_9)->anim.localPosX;
    local_20 = *(float *)(iVar3 + 0x10) - (((GameObject *)param_9)->anim.localPosY + lbl_803E6F94);
    local_1c = *(float *)(iVar3 + 0x14) - ((GameObject *)param_9)->anim.localPosZ;
    dVar6 = FUN_80293900((double)(local_1c * local_1c + local_24 * local_24 + local_20 * local_20));
    if (dVar6 < (double)lbl_803E6F50) {
      local_40 = *(undefined4 *)(param_10 + 0x2d0);
      psVar4 = *(short **)(iVar5 + 0x24);
      local_48 = 0xe;
      local_44 = 1;
      uVar2 = FUN_80006ab8(psVar4);
      if (uVar2 == 0) {
        FUN_80006ac4(psVar4,(uint)&local_48);
      }
      *(undefined *)(iVar5 + 0x34) = 1;
    }
  }
  else {
    psVar4 = *(short **)(iVar5 + 0x24);
    local_30 = 9;
    local_2c = 0;
    local_28 = 0x24;
    uVar2 = FUN_80006ab8(psVar4);
    if (uVar2 == 0) {
      FUN_80006ac4(psVar4,(uint)&local_30);
    }
    *(undefined *)(iVar5 + 0x34) = 1;
    local_34 = *(undefined4 *)(param_10 + 0x2d0);
    psVar4 = *(short **)(iVar5 + 0x24);
    local_3c = 7;
    local_38 = 1;
    uVar2 = FUN_80006ab8(psVar4);
    if (uVar2 == 0) {
      FUN_80006ac4(psVar4,(uint)&local_3c);
    }
    *(undefined *)(iVar5 + 0x34) = 1;
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
FUN_80201260(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  int iVar1;
  uint uVar2;
  short *psVar3;
  int iVar4;
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  iVar4 = *(int *)(*(int *)&((GameObject *)param_9)->extra + 0x40c);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    param_1 = FUN_800305f8((double)lbl_803E6F40,param_2,param_3,param_4,param_5,param_6,param_7,
                           param_8,param_9,0,0,param_12,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  if (*(char *)(param_10 + 0x27a) != '\0') {
    *(undefined4 *)(param_10 + 0x2d0) = 0;
    if (*(int *)(iVar4 + 0x18) != 0) {
      ObjMsg_SendToObject(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   *(int *)(iVar4 + 0x18),0x11,param_9,0x10,param_13,param_14,param_15,param_16);
      *(undefined4 *)(iVar4 + 0x18) = 0;
    }
    iVar1 = FUN_80017a98();
    iVar1 = (**(code **)(**(int **)(*(int *)(iVar1 + 200) + 0x68) + 0x44))();
    if (iVar1 == 0) {
      uVar2 = randomGetRange(0,2);
      FUN_80006824(param_9,(ushort)*(undefined4 *)(&DAT_8032a290 + uVar2 * 4));
    }
    else {
      uVar2 = randomGetRange(3,4);
      FUN_80006824(param_9,(ushort)*(undefined4 *)(&DAT_8032a290 + uVar2 * 4));
    }
    local_20 = *(undefined4 *)(iVar4 + 0x30);
    local_24 = *(undefined4 *)(iVar4 + 0x2c);
    psVar3 = *(short **)(iVar4 + 0x24);
    local_28 = *(undefined4 *)(iVar4 + 0x28);
    uVar2 = FUN_80006ab8(psVar3);
    if (uVar2 == 0) {
      FUN_80006ac4(psVar3,(uint)&local_28);
    }
    *(undefined4 *)(iVar4 + 0x3c) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 0x10;
  *(float *)(param_10 + 0x2a0) = lbl_803E6FD8;
  *(float *)(param_10 + 0x280) = lbl_803E6F40;
  if (*(char *)(param_10 + 0x346) != '\0') {
    *(undefined *)(iVar4 + 0x34) = 1;
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
FUN_802014c8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = *(int *)&((GameObject *)param_9)->extra;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    ObjHits_EnableObject(param_9);
  }
  uVar1 = 0xffffffff;
  ObjHits_SetHitVolumeSlot(param_9,10,1,-1);
  *(float *)(param_10 + 0x2a0) = lbl_803E6F8C;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E6F40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,10,0,uVar1,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 1;
  iVar2 = *(int *)(iVar2 + 0x40c);
  *(byte *)(iVar2 + 0x14) = *(byte *)(iVar2 + 0x14) | 2;
  if ((*(uint *)(param_10 + 0x314) & 1) != 0) {
    *(uint *)(param_10 + 0x314) = *(uint *)(param_10 + 0x314) & ~1;
    *(byte *)(iVar2 + 0x14) = *(byte *)(iVar2 + 0x14) | 1;
  }
  if (*(char *)(param_10 + 0x346) != '\0') {
    *(undefined *)(iVar2 + 0x34) = 1;
  }
  return 0;
}

int dbstealerworm_stateHandlerA09(int obj, int p)
{
  extern int Stack_IsFull(int sp);
  extern void Stack_Push(int sp, int *args);
  extern f32 lbl_803E62A8;
  BaddieState *bs = (BaddieState *)p;
  DbStealerwormControl *sub_40c;
  int sub_40c_30;
  int frame[3];
  int frame2[3];
  f32 resetValue;

  sub_40c = (DbStealerwormControl *)(*(GroundBaddieState **)&((GameObject *)obj)->extra)->control;
  sub_40c_30 = sub_40c->unk30;
  sub_40c->flags14 |= 0x2;
  resetValue = lbl_803E62A8;
  bs->animSpeedA = resetValue;
  bs->animSpeedB = resetValue;
  {
    void *p2d0 = *(void **)&bs->targetObj;
    if (p2d0 == NULL || (**(int (**)(void *))(*(int *)(*(int *)((char *)p2d0 + 0x68)) + 0x20))(p2d0) == 0) {
      sub_40c->unk34 = 1;
    }
  }
  if (*(void **)&sub_40c->linkedObj == NULL) {
    s16 r26 = sub_40c->unk1C;
    if (r26 != -1) {
      int sp_handle;
      int v2c;
      int v30;
      v30 = sub_40c->unk30;
      v2c = sub_40c->unk2C;
      sp_handle = sub_40c->msgStack;
      frame[0] = sub_40c->unk28;
      frame[1] = v2c;
      frame[2] = v30;
      if (Stack_IsFull(sp_handle) == 0) Stack_Push(sp_handle, frame);
      sp_handle = sub_40c->msgStack;
      frame2[0] = 7;
      frame2[1] = 0;
      frame2[2] = r26;
      if (Stack_IsFull(sp_handle) == 0) Stack_Push(sp_handle, frame2);
      sub_40c->unk34 = 1;
      sub_40c->unk1C = -1;
    }
  }
  if ((s32)(bs->eventFlags & 0x200) != 0) {
    sub_40c->linkedObj = *(int *)&bs->targetObj;
    sub_40c->unk1C = (s16)sub_40c_30;
    sub_40c->unk2C = 0;
    ObjMsg_SendToObject(sub_40c->linkedObj, 17, obj, 18);
    Sfx_PlayFromObject(obj, SFXfoot_ice_run_3);
  }
  *(s8 *)&bs->unk34D = 18;
  if (*(char *)&bs->moveJustStartedA != '\0') {
    ObjAnim_SetCurrentMove((int)obj, 16, lbl_803E62A8, 0);
    *(s8 *)&bs->moveDone = 0;
  }
  if (*(s8 *)&bs->moveDone != 0) {
    sub_40c->unk34 = 1;
  }
  return 0;
}

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
FUN_80201658(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  undefined4 uVar1;
  
  if (*(char *)(param_10 + 0x27a) != '\0') {
    ObjHits_EnableObject(param_9);
  }
  uVar1 = 0xffffffff;
  ObjHits_SetHitVolumeSlot(param_9,10,1,-1);
  *(float *)(param_10 + 0x2a0) = lbl_803E6F8C;
  if (*(char *)(param_10 + 0x27a) != '\0') {
    FUN_800305f8((double)lbl_803E6F40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,5,0,uVar1,param_13,param_14,param_15,param_16);
    *(undefined *)(param_10 + 0x346) = 0;
  }
  *(undefined *)(param_10 + 0x34d) = 1;
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
FUN_802017a0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,int param_9,int param_10,
            undefined4 param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
            undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  int iVar4;
  
  iVar3 = *(int *)&((GameObject *)param_9)->extra;
  iVar4 = *(int *)(iVar3 + 0x40c);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    ObjHits_EnableObject(param_9);
  }
  uVar2 = 0xffffffff;
  ObjHits_SetHitVolumeSlot(param_9,10,1,-1);
  if (*(char *)(param_10 + 0x27a) != '\0') {
    uVar1 = randomGetRange(0,1);
    if (uVar1 == 0) {
      if (*(char *)(param_10 + 0x27a) != '\0') {
        FUN_800305f8((double)lbl_803E6F40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     param_9,7,0,uVar2,param_13,param_14,param_15,param_16);
        *(undefined *)(param_10 + 0x346) = 0;
      }
    }
    else if (*(char *)(param_10 + 0x27a) != '\0') {
      FUN_800305f8((double)lbl_803E6F40,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,6,0,uVar2,param_13,param_14,param_15,param_16);
      *(undefined *)(param_10 + 0x346) = 0;
    }
    *(undefined *)(param_10 + 0x34d) = 1;
    *(float *)(param_10 + 0x2a0) =
         lbl_803E6FDC +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar3 + 0x406)) - DOUBLE_803e6f78) /
         lbl_803E6FE0;
  }
  *(float *)(param_10 + 0x280) = lbl_803E6F40;
  if (*(char *)(param_10 + 0x346) != '\0') {
    *(undefined *)(iVar4 + 0x34) = 1;
  }
  *(byte *)(iVar4 + 0x14) = *(byte *)(iVar4 + 0x14) | 2;
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
FUN_80202004(double param_1,double param_2,undefined8 param_3,double param_4,ushort *param_5,
            int param_6)
{
  int iVar1;
  undefined4 uVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  float local_48 [5];
  
  iVar3 = *(int *)(param_5 + 0x5c);
  iVar1 = Obj_GetYawDeltaToObject(param_5,param_6,local_48);
  if ((double)lbl_803E6F40 == param_4) {
    uVar2 = 0;
  }
  else {
    dVar5 = (double)(float)((double)(float)((double)local_48[0] - param_1) / param_4);
    dVar4 = dVar5;
    if (dVar5 < (double)lbl_803E6F40) {
      dVar4 = -dVar5;
    }
    if ((double)lbl_803E7008 <= dVar4) {
      if (dVar5 < (double)lbl_803E6F40) {
        param_2 = -param_2;
      }
      *(float *)(iVar3 + 0x280) =
           lbl_803DC074 * lbl_803E6FE4 *
           ((float)(param_2 *
                   (double)(lbl_803E6F60 -
                           (float)((double)CONCAT44(0x43300000,(int)(short)iVar1 ^ 0x80000000) -
                                  DOUBLE_803e7000) / lbl_803E700C)) - *(float *)(iVar3 + 0x280)) +
           *(float *)(iVar3 + 0x280);
      *(float *)(iVar3 + 0x284) = lbl_803E6F40;
      uVar2 = 0;
    }
    else {
      uVar2 = 1;
    }
  }
  return uVar2;
}

int dbstealerworm_stateHandlerA06(int obj, int p2)
{
  extern void ObjHits_DisableObject(int);
  extern void ObjGroup_RemoveObject(int, int);
  extern int gameBitIncrement(int);
  extern void Obj_FreeObject(int);
  extern void Stack_Pop(int, int *);
  extern int Stack_IsEmpty(int);
  extern MapEventInterface **gMapEventInterface;
  extern int *gPlayerInterface;
  extern int lbl_80329634[];
  extern int lbl_80329640[];
  extern f32 lbl_803E62A8;
  extern f32 lbl_803E6334;
  extern f32 lbl_803E6338;
  extern f32 lbl_803E633C;

  GroundBaddieState *sub = ((GameObject *)obj)->extra;
  int data = *(int *)&((GameObject *)obj)->anim.placementData;
  DbStealerwormControl *sub_40c = (DbStealerwormControl *)sub->control;
  BaddieState *bs = (BaddieState *)p2;

  *(s8 *)&bs->unk34D = 0x11;

  if ((s32)(s8)bs->moveJustStartedA != 0) {
    f32 fz = lbl_803E62A8;
    bs->animSpeedB = fz;
    bs->animSpeedA = fz;
    *(int *)&bs->targetObj = 0;
    bs->unk25F = 1;
    bs->unk349 = 0;
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 0x8);
    ObjHits_DisableObject(obj);
    ObjGroup_RemoveObject(obj, 3);
    if (*(void **)&sub_40c->linkedObj != NULL) {
      ObjMsg_SendToObject((void *)sub_40c->linkedObj, 17, obj, 16);
      sub_40c->unk1C = -1;
      sub_40c->linkedObj = 0;
    }
  }
  if ((s32)(s8)bs->moveJustStartedA != 0) {
    ObjAnim_SetCurrentMove((int)obj, 1, lbl_803E62A8, 0);
    bs->moveDone = 0;
  }
  bs->moveSpeed = lbl_803E6334;
  if (((GameObject *)obj)->anim.currentMoveProgress > lbl_803E6338) {
    int local;
    gameBitIncrement(((DbstealerwormPlacement *)data)->unk18);
    if ((((DbstealerwormPlacement *)data)->unk14 + 0x10000) == 0xffff) {
      Obj_FreeObject(obj);
      return 0;
    }
    while (Stack_IsEmpty(sub_40c->msgStack) == 0) {
      Stack_Pop(sub_40c->msgStack, &local);
    }
    if (((DbstealerwormPlacement *)data)->unk2C == 0) {
      (*gMapEventInterface)->startTimedEvent(*(int *)&((DbstealerwormPlacement *)data)->unk14, lbl_803E633C);
    }
    sub->configFlags |= ((DbstealerwormPlacement *)data)->unk2B;
  }
  (**(void (**)(int, int, int, int, int *))((char *)(*gPlayerInterface) + 0x34))(obj, p2, 0, 2, lbl_80329634);
  (**(void (**)(int, int, int, int, int *))((char *)(*gPlayerInterface) + 0x34))(obj, p2, 7, 0, lbl_80329640);
  return 0;
}

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
FUN_80202130(double param_1,double param_2,undefined8 param_3,double param_4,ushort *param_5,
            int param_6)
{
  int iVar1;
  int iVar2;
  double dVar3;
  float local_58 [7];
  
  iVar2 = *(int *)(param_5 + 0x5c);
  if ((param_5 != (ushort *)0x0) && (param_6 != 0)) {
    iVar1 = Obj_GetYawDeltaToObject(param_5,param_6,local_58);
    if ((double)lbl_803E6F40 != param_4) {
      if ((double)local_58[0] < param_1) {
        dVar3 = (double)(*(float *)(param_5 + 8) - *(float *)(param_6 + 0x10));
        if (dVar3 < (double)lbl_803E6F40) {
          dVar3 = -dVar3;
        }
        if (dVar3 < (double)lbl_803E7010) {
          return 1;
        }
      }
      *(float *)(iVar2 + 0x280) =
           lbl_803DC074 * lbl_803E6FE4 *
           ((float)(param_2 *
                   (double)(lbl_803E6F60 -
                           (float)((double)CONCAT44(0x43300000,(int)(short)iVar1 ^ 0x80000000) -
                                  DOUBLE_803e7000) / lbl_803E700C)) - *(float *)(iVar2 + 0x280)) +
           *(float *)(iVar2 + 0x280);
      *(float *)(iVar2 + 0x284) = lbl_803E6F40;
    }
  }
  return 0;
}


int dbstealerworm_stateHandlerA05(int obj, int p)
{
  extern void *Obj_GetPlayerObject(void);
  extern int lbl_80329650[];
  extern int Stack_IsFull(int sp);
  extern void Stack_Push(int sp, int *args);
  extern f32 lbl_803E62A8;
  extern f32 lbl_803E6340;
  BaddieState *bs = (BaddieState *)p;
  DbStealerwormControl *sub_40c;
  int frame[3];

  sub_40c = (DbStealerwormControl *)(*(GroundBaddieState **)&((GameObject *)obj)->extra)->control;
  if (*(char *)&bs->moveJustStartedA != '\0') {
    ObjAnim_SetCurrentMove((int)obj, 0, lbl_803E62A8, 0);
    *(s8 *)&bs->moveDone = 0;
  }
  if (*(char *)&bs->moveJustStartedA != '\0') {
    int r;
    int player_c8;
    *(u32 *)&bs->targetObj = 0;
    if (*(void **)&sub_40c->linkedObj != NULL) {
      ObjMsg_SendToObject(sub_40c->linkedObj, 17, obj, 16);
      sub_40c->linkedObj = 0;
    }
    player_c8 = *(int *)((char *)Obj_GetPlayerObject() + 0xc8);
    r = (**(int (**)(int))(*(int *)(*(int *)(player_c8 + 0x68)) + 0x44))(player_c8);
    if (r != 0) {
      Sfx_PlayFromObject(obj, (u16)lbl_80329650[randomGetRange(3, 4)]);
    } else {
      Sfx_PlayFromObject(obj, (u16)lbl_80329650[randomGetRange(0, 2)]);
    }
    {
      int frame1;
      int frame2;
      int sp_handle;
      int frame0;
      frame2 = sub_40c->unk30;
      frame1 = sub_40c->unk2C;
      sp_handle = sub_40c->msgStack;
      frame0 = sub_40c->unk28;
      frame[0] = frame0;
      frame[1] = frame1;
      frame[2] = frame2;
      if (Stack_IsFull(sp_handle) == 0) {
        Stack_Push(sp_handle, frame);
      }
    }
    sub_40c->unk3C = 0;
  }
  *(s8 *)&bs->unk34D = 16;
  bs->moveSpeed = lbl_803E6340;
  bs->animSpeedA = lbl_803E62A8;
  if (*(s8 *)&bs->moveDone != 0) {
    sub_40c->unk34 = 1;
  }
  return 0;
}


int dbstealerworm_stateHandlerA03(int obj, int p)
{
  extern void ObjHits_EnableObject(int obj);
  extern void ObjHits_SetHitVolumeSlot(int obj, int slot, int a, int b);
  extern f32 lbl_803E62A8;
  extern f32 lbl_803E62F4;

  if (*(char *)&((BaddieState *)p)->moveJustStartedA != '\0') {
    ObjHits_EnableObject(obj);
  }
  ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
  ((BaddieState *)p)->moveSpeed = lbl_803E62F4;
  if (*(char *)&((BaddieState *)p)->moveJustStartedA != '\0') {
    ObjAnim_SetCurrentMove((int)obj, 5, lbl_803E62A8, 0);
    *(s8 *)&((BaddieState *)p)->moveDone = 0;
  }
  *(s8 *)&((BaddieState *)p)->unk34D = 1;
  return 0;
}


int dbstealerworm_stateHandlerA01(int obj, int p)
{
  extern int *gPlayerInterface;
  extern int lbl_80329640[];
  extern f32 lbl_803E62A8;
  extern f32 lbl_803E62C8;
  extern f32 lbl_803E62F4;
  extern f32 lbl_803E634C;
  BaddieState *bs = (BaddieState *)p;
  GroundBaddieState *sub;
  DbStealerwormControl *sub_40c;
  int p4c;

  sub = ((GameObject *)obj)->extra;
  p4c = *(int *)&((GameObject *)obj)->anim.placementData;
  sub_40c = (DbStealerwormControl *)sub->control;
  if (*(char *)&bs->moveJustStartedA != '\0') {
    ObjAnim_SetCurrentMove((int)obj, 14, lbl_803E62A8, 0);
    *(s8 *)&bs->moveDone = 0;
  }
  *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 0x8;
  if (((GameObject *)obj)->anim.currentMoveProgress > lbl_803E634C) {
    sub_40c->flags14 |= 0x2;
    ObjHits_DisableObject(obj);
  }
  if (*(char *)&bs->moveJustStartedA != '\0') {
    bs->moveSpeed = lbl_803E62F4;
    bs->animSpeedA = lbl_803E62A8;
  }
  if (*(s8 *)&bs->moveDone != 0) {
    Sfx_PlayFromObject(obj, SFXfoot_ice_run_2);
    sub_40c->unk04 = lbl_803E62C8;
    ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E62A8, 0);
    *(u32 *)&bs->targetObj = 0;
    bs->unk25F = 0;
    bs->unk349 = 0;
    sub->targetState = 0;
    sub->configFlags |= ((DbstealerwormPlacement *)p4c)->unk2B;
    if (*(void **)&sub_40c->linkedObj != NULL) {
      ObjMsg_SendToObject(sub_40c->linkedObj, 17, obj, 19);
      sub_40c->linkedObj = 0;
      sub_40c->unk1C = -1;
    }
    if ((sub_40c->flags15 & 0x2) == 0) {
      *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 0x8;
    }
    sub_40c->unk34 = 1;
  }
  (**(int (**)(int, int, int, int, int *))(*gPlayerInterface + 0x34))(obj, p, 7, 0, lbl_80329640);
  return 0;
}


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
void FUN_80204320(int param_1,int param_2,int param_3,int param_4,int param_5,s8 visible)
{
  if (visible != 0) {
    FUN_8003b818(param_1);
  }
  return;
}

void fn_80204320(int obj)
{
  extern void *Obj_GetPlayerObject(void);
  extern uint GameBit_Get(int);
  extern u8 lbl_803DC182;
  extern s16 lbl_80329848[];
  DfpLevelControlState *sub;
  void *player;

  sub = ((GameObject *)obj)->extra;
  player = Obj_GetPlayerObject();
  if (lbl_803DC182 != 0) {
    s16 i;
    s16 *arr = (s16 *)((char *)lbl_80329848 + 12);
    arr[0] = 0;
    arr[1] = 0;
    arr[2] = 0;
    arr = lbl_80329848;
    for (i = 0; i < 6; i++) {
      *arr = (s16)randomGetRange(1, 4);
      arr++;
    }
    GameBit_Set(1508, 0);
    sub->timer = 0;
    lbl_803DC182 = 0;
  }
  if (GameBit_Get(1507) == 0) {
    if (GameBit_Get(1504) != 0 && GameBit_Get(1505) != 0) {
      GameBit_Set(1507, 1);
    }
  }
  if (GameBit_Get(3671) == 0) {
    if (GameBit_Get(1589) != 0 && sub->sfxLatch == 0) {
      s16 i;
      s16 *arr;
      Sfx_PlayFromObject(0, 1095);
      arr = lbl_80329848;
      for (i = 0; i < 6; i++) {
        *arr = (s16)randomGetRange(1, 4);
        arr++;
      }
      GameBit_Set(1508, 1);
      sub->sfxLatch = 1;
    } else if (GameBit_Get(1589) == 0 && sub->sfxLatch == 1) {
      sub->sfxLatch = 0;
      GameBit_Set(1508, 0);
    }
    if (GameBit_Get(1509) != 0) {
      sub->timer = 300;
      ObjMsg_SendToObject(player, 0x60005, obj, 1);
    }
  }
}


void dll_22C_init(int obj, char *p)
{
  extern f32 lbl_803E63A8;
  int b8;

  b8 = *(int *)&((GameObject *)obj)->extra;
  ((GameObject *)obj)->animEventCallback = (void *)dll_22C_SeqFn;
  ((GameObject *)obj)->anim.rotX = (s16)(*(char *)(p + 0x18) << 8);
  ((Dll22CState *)b8)->mode = 0;
  ((Dll22CState *)b8)->gameBit = *(s16 *)(p + 0x20);
  ((Dll22CState *)b8)->gameBit2 = *(s16 *)(p + 0x1e);
  ((Dll22CState *)b8)->raiseHeight = (f32)*(s16 *)(p + 0x1a);
  ((Dll22CState *)b8)->unk0C = (u8)*(s16 *)(p + 0x1c);
  ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.localPosY - lbl_803E63A8;
  ((GameObject *)obj)->objectFlags = ((GameObject *)obj)->objectFlags | 0x2000;
}



/* Trivial 4b 0-arg blr leaves. */
void dbegg_release(void) {}
void dbegg_initialise(void) {}
void GCRobotBlast_free(void) {}
void GCRobotBlast_render(void) {}
void GCRobotBlast_hitDetect(void) {}
void GCRobotBlast_update(void) {}
void GCRobotBlast_release(void) {}
void GCRobotBlast_initialise(void) {}
void DrakorEnergy_func0B_nop(void) {}
void drakorenergy_free(void) {}
void drakorenergy_hitDetect(void) {}
void drakorenergy_release(void) {}
void drakorenergy_initialise(void) {}

extern f32 lbl_803E627C;
extern f32 lbl_803E62A0;

void drakorenergy_init(int *obj, u8 *init) {
    extern uint GameBit_Get(int);
    DrakorEnergyState *sub;
    f32 fz;
    sub = ((GameObject *)obj)->extra;
    sub->mode = 5;
    ((GameObject *)obj)->anim.localPosX = *(f32*)(init + 8);
    ((GameObject *)obj)->anim.localPosY = *(f32*)(init + 0xc);
    ((GameObject *)obj)->anim.localPosZ = *(f32*)(init + 0x10);
    fz = lbl_803E627C;
    ((GameObject *)obj)->anim.velocityZ = fz;
    ((GameObject *)obj)->anim.velocityX = fz;
    ((GameObject *)obj)->anim.velocityY = lbl_803E62A0;
    sub->phase = randomGetRange(0, 0xffff);
    if (GameBit_Get(*(s16*)(init + 0x20)) != 0) {
        sub->mode = 4;
    }
}
void dbstealerworm_release(void) {}
void dbholecontrol1_hitDetect(void) {}
void dbholecontrol1_release(void) {}
void dbholecontrol1_initialise(void) {}

extern void Obj_RemoveFromUpdateList(int *obj);

void dbholecontrol1_update(int *obj) {
    extern uint GameBit_Get(int);
    u8 *def;
    def = *(u8**)&((GameObject *)obj)->anim.placementData;
    if (GameBit_Get(((Dbholecontrol1Placement *)def)->unk1E) != 0) {
        Obj_RemoveFromUpdateList(obj);
        ((GameObject *)obj)->anim.flags = (s16)(((GameObject *)obj)->anim.flags | OBJANIM_FLAG_HIDDEN);
    } else if (GameBit_Get(((Dbholecontrol1Placement *)def)->unk20) != 0) {
        (*gObjectTriggerInterface)->runSequence(*(s8 *)(def + 0x19), obj, -1);
    }
}

extern void Stack_Free(int *stack);
extern void Obj_FreeObject(int obj);
extern void **gBaddieControlInterface;
extern int *gPlayerInterface;
extern f32 lbl_803E62A8;
extern f32 lbl_803E62FC;
extern u8 lbl_80329514[];
extern void *memset(void *dst, int v, int n);
void dbstealerworm_init(int *obj, u8 *def, int param3) {
    u8 *sub;
    int *p40c;
    int mode;
    int r;

    sub = ((GameObject *)obj)->extra;
    mode = 6;
    if (param3 != 0) {
        mode = (u8)(mode | 1);
    }
    ((void(*)(int*, u8*, u8*, int, int, int, u8, f32))((void**)*gBaddieControlInterface)[22])(obj, def, sub, 0x10, 7, 0x10a, mode, lbl_803E62FC);
    ObjGroup_AddObject(obj, 3);
    ((GameObject *)obj)->animEventCallback = NULL;
    p40c = *(int**)&((GroundBaddieState *)sub)->control;
    memset(p40c, 0, 0x50);
    ((DbStealerwormControl *)p40c)->unk08 = lbl_803E62FC;
    ((DbStealerwormControl *)p40c)->cfg = (int)&lbl_80329514[((s16)*(s16*)(def + 0x24)) * 8];
    r = randomGetRange(0xa, 0x12c);
    ((DbStealerwormControl *)p40c)->unk0C = (f32)(s32)r;
    ((DbStealerwormControl *)p40c)->flags44 = (u8)((((DbStealerwormControl *)p40c)->flags44 & ~0x20) | ((def[0x2b] & 1) << 5));
    ((DbStealerwormControl *)p40c)->flags44 = (u8)(((DbStealerwormControl *)p40c)->flags44 | 0x10);
    ((DbStealerwormControl *)p40c)->linkedObj = 0;
    ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E62A8, 0);
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode | 0x8);
    ((void(*)(int*, u8*, int))((void**)*gPlayerInterface)[5])(obj, sub, 3);
    ((GroundBaddieState *)sub)->baddie.unk270 = 0;
    ((GroundBaddieState *)sub)->baddie.unk25F = 1;
    ObjHits_EnableObject(obj);
    ObjMsg_AllocQueue(obj, 4);
    if (((GameObject *)obj)->anim.modelState != NULL) {
        ((GameObject *)obj)->anim.modelState->flags |= 0x4008;
    }
}

void dbstealerworm_free(int *obj) {
    u8 *sub = ((GameObject *)obj)->extra;
    int *p40c = *(int**)&((GroundBaddieState *)sub)->control;
    ObjGroup_RemoveObject(obj, 3);
    Stack_Free((int*)((DbStealerwormControl *)p40c)->msgStack);
    if (((GameObject *)obj)->unkC8 != NULL) {
        Obj_FreeObject(*(int *)&((GameObject *)obj)->unkC8);
        *(int *)&((GameObject *)obj)->unkC8 = 0;
    }
    ((void(*)(int*, u8*, int))((void**)*gBaddieControlInterface)[16])(obj, sub, 3);
}

void dbholecontrol1_init(int *obj, u8 *params) {
    DbHoleControl1State *sub = ((GameObject *)obj)->extra;
    ObjGroup_AddObject(obj, 0x1e);
    *(s16*)obj = (s16)((s8)params[0x18] << 8);
    ((GameObject *)obj)->animEventCallback = (void *)dbholecontrol1_SeqFn;
    sub->gameBitA = *(s16*)(params + 0x1a);
    sub->gameBitB = *(s16*)(params + 0x1c);
}
void dfplevelcontrol_render(void) {}
void dfplevelcontrol_hitDetect(void) {}
void dfplevelcontrol_release(void) {}
void dfpobjcreator_hitDetect(void) {}
void dfpobjcreator_release(void) {}
void dfpobjcreator_initialise(void) {}
void dll_22C_hitDetect_nop(void) {}
void dll_22C_release_nop(void) {}
void dll_22C_initialise_nop(void) {}
void doorswitch_render(void) {}
void doorswitch_hitDetect(void) {}
void doorswitch_release(void) {}
void doorswitch_initialise(void) {}
void dfpseqpoint_free(void) {}
void dfpseqpoint_hitDetect(void) {}
void dfpseqpoint_release(void) {}
void dfpseqpoint_initialise(void) {}

void dfpseqpoint_init(int *obj, u8 *init) {
    DfpSeqPointState *sub;
    sub = ((GameObject *)obj)->extra;
    ((GameObject *)obj)->animEventCallback = (void *)dfpseqpoint_SeqFn;
    *(s16*)obj = (s16)((s8)init[0x18] << 8);
    sub->triggerRadius = (f32)(s32)*(s16*)(init + 0x1a);
    sub->triggerId = *(s16*)(init + 0x1c);
    sub->triggerMode = init[0x19];
    sub->gameBitGate = *(s16*)(init + 0x1e);
    sub->gameBitDone = *(s16*)(init + 0x20);
    ((GameObject *)obj)->objectFlags = (u16)(((GameObject *)obj)->objectFlags | 0x2000);
    ((DfpFlags7 *)&sub->flags0F)->b80 = 0;
}
void DFP_Torch_hitDetect(void) {}
void DFP_Torch_release(void) {}
void DFP_Torch_initialise(void) {}
void chuka_render(void) {}

/* 8b "li r3, N; blr" returners. */
int GCRobotBlast_getExtraSize(void) { return 0x8; }
int GCRobotBlast_getObjectTypeId(void) { return 0x0; }
int drakorenergy_getExtraSize(void) { return 0xc; }
int drakorenergy_getObjectTypeId(void) { return 0x0; }
int dbstealerworm_getExtraSize(void) { return 0x460; }
int dbstealerworm_getObjectTypeId(void) { return 0x49; }
int dbholecontrol1_getExtraSize(void) { return 0xc; }
int dbholecontrol1_getObjectTypeId(void) { return 0x0; }
int dfplevelcontrol_getExtraSize(void) { return 0xc; }
int dfplevelcontrol_getObjectTypeId(void) { return 0x0; }
int dfpobjcreator_getExtraSize(void) { return 0x1c; }
int dfpobjcreator_getObjectTypeId(void) { return 0x0; }
int dll_22C_SeqFn(void) { return 0x0; }
int dll_22C_getExtraSize_ret_16(void) { return 0x10; }
int dll_22C_getObjectTypeId(void) { return 0x0; }
int doorswitch_getExtraSize(void) { return 0x0; }
int doorswitch_getObjectTypeId(void) { return 0x0; }
int dfpseqpoint_getExtraSize(void) { return 0x10; }
int dfpseqpoint_getObjectTypeId(void) { return 0x0; }
int DFP_Torch_getExtraSize(void) { return 0x10; }
int DFP_Torch_getObjectTypeId(void) { return 0x1; }
int chuka_SeqFn(void) { return 0x0; }
int chuka_getExtraSize(void) { return 0xc; }
int chuka_getObjectTypeId(void) { return 0x0; }

/* Pattern wrappers. */
s16 DBstealerworm_setScale(int *obj) { return ((BaddieState *)((int**)obj)[0xb8/4])->controlMode; }

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E6390;
extern void objRenderFn_8003b8f4(f32);
extern f32 lbl_803E6398;
extern f32 lbl_803E63B8;
void dbholecontrol1_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E6390); }
void dll_22C_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E6398); }
void dfpseqpoint_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { s32 v = visible; if (v != 0) objRenderFn_8003b8f4(lbl_803E63B8); }
void dfpobjcreator_render(int p1, int p2, int p3, int p4, int p5, s8 visible) { if (visible == 0) return; }

extern f32 lbl_803E6278;
void drakorenergy_render(int obj, int p1, int p2, int p3, int p4, s8 visible) {
    DrakorEnergyState *inner = ((GameObject *)obj)->extra;
    u32 t = inner->mode;
    if (t != 0 && t != 4) {
        ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p1, p2, p3, p4, lbl_803E6278);
    }
}
extern int gDBStealerWormStateHandlersA[];
void chuka_free(int obj) {
    (*gExpgfxInterface)->freeSource2((u32)obj);
}
void chuka_hitDetect(int obj) {
    int *light;
    int *inner = ((GameObject *)obj)->extra;
    light = (int *)inner[1];
    if (light == NULL) return;
    if ((*(s16 *)((char *)light + 6) & 0x40) == 0) return;
    inner[1] = 0;
}
void dbstealerworm_hitDetect(int obj) {
    int *inner = ((GameObject *)obj)->extra;
    (*(void (*)(int, int *, int *))(*(int *)(*gPlayerInterface + 0xc)))(obj, inner, gDBStealerWormStateHandlersA);
}
void GCRobotBlast_init(int obj, s8 *p) {
    typedef struct {
        u8 b80 : 1;
    } BlastFlags4;
    char *inner = ((GameObject *)obj)->extra;
    ((GCRobotBlastState *)inner)->mode = (s8)p[0x19];
    ((BlastFlags4 *)&((GCRobotBlastState *)inner)->flags04)->b80 = 0;
    ((GameObject *)obj)->animEventCallback = (void *)GCRobotBlast_SeqFn;
}

/* ObjGroup_RemoveObject(x, N) wrappers. */
void dbholecontrol1_free(int x) { ObjGroup_RemoveObject(x, 0x1e); }
void dfplevelcontrol_free(int x) { ObjGroup_RemoveObject(x, 0x9); }

/* plain forwarder. */
extern void DBstealerwo_setFuncPtrs_80203c78(void);
void dbstealerworm_initialise(void) { DBstealerwo_setFuncPtrs_80203c78(); }

/* OSReport(string) wrappers. */
extern void OSReport(const char *fmt, ...);
void doorswitch_free(void) { OSReport(sDoorswitchInitNoLongerSupported); }
void doorswitch_update(void) { OSReport(sDoorswitchInitNoLongerSupported); }
void doorswitch_init(void) { OSReport(sDoorswitchInitNoLongerSupported); }

int DrakorEnergy_setScale(int *obj) { return ((DrakorEnergyState *)((int**)obj)[0xb8/4])->mode == 0; }

/* alpha-flag predicate: returns 7 on fire/clear, 0 on idle */
int dbstealerworm_stateHandlerB00(int p1, int p2)
{
  BaddieState *p = (BaddieState *)p2;
  f32 fz;
  if (*(void **)&p->targetObj != NULL) {
    if ((s8)p->moveJustStartedB != 0) {
      fz = lbl_803E62A8;
      p->animSpeedB = fz;
      p->animSpeedA = fz;
      return 7;
    }
    if ((s8)p->moveDone != 0) return 7;
  }
  return 0;
}

/* baddie anim update: fires vtable[0x13] when flag set */
int dbstealerworm_stateHandlerB03(int p1, int p2)
{
  GroundBaddieState *state = ((GameObject *)p1)->extra;
  if ((s8)((BaddieState *)p2)->moveJustStartedB != 0) {
    (*(void (**)(int, s16, int, int))((char *)*gBaddieControlInterface + 0x4c))(
        p1, state->unk3F0, -1, 0);
  }
  return 0;
}

/* anim progress accumulator */
extern f32 lbl_803E62BC;
int dbstealerworm_stateHandlerB01(int p1, int p2)
{
  GroundBaddieState *state = ((GameObject *)p1)->extra;
  if ((s8)((BaddieState *)p2)->hitPoints < 1) return 3;
  if ((s8)((BaddieState *)p2)->moveDone != 0) {
    ((DbStealerwormControl *)state->control)->unk38 += lbl_803E62BC;
    return 7;
  }
  return 0;
}

/* clear list-actions wrapper: notifies vtable[6] then resets getLActions */
void fn_80204B6C(int p1)
{
  (*gExpgfxInterface)->freeSource2((u32)p1);
  getLActions(p1, p1, 0, 0, 0, 0);
}

/* timed counter: decrement (p1->b8)->0 by timeDelta, then notify */
extern void *Obj_GetPlayerObject(void);
extern void fn_802960E8(void *playerObj, int p2);
extern f32 timeDelta;
int dfplevelcontrol_SeqFn(int p1)
{
  DfpLevelControlState *p_b8 = ((GameObject *)p1)->extra;
  void *player = Obj_GetPlayerObject();
  s16 v = p_b8->timer;
  if (v > 0) {
    p_b8->timer = v - (int)timeDelta;
    fn_802960E8(player, 0x51e);
  }
  return 0;
}

extern s16 lbl_80329848[];
void dfplevelcontrol_initialise(void) {
    s16 *p = lbl_80329848;
    p[0] = 1;
    p[1] = 2;
    p[2] = 3;
    p[3] = 0;
    p[4] = 0;
    p[5] = 0;
    p[6] = 0;
    p[7] = 0;
    p[8] = 0;
}

void dfpobjcreator_free(int obj, int flag) {
    DfpObjCreatorState *state = ((GameObject *)obj)->extra;
    if (flag == 0) {
        if (*(void **)&state->spawnedObj != NULL) {
            Obj_FreeObject(state->spawnedObj);
            state->spawnedObj = 0;
        }
    }
}

extern void dbegg_setupFromDef(int obj, int *state);
void dbegg_init(int obj) {
    ObjModelState *modelState;
    dbegg_setupFromDef(obj, ((GameObject *)obj)->extra);
    ObjMsg_AllocQueue(obj, 8);
    modelState = ((GameObject *)obj)->anim.modelState;
    if (modelState != NULL) {
        modelState->flags |= 0x4008;
    }
}

void DFP_Torch_free(int obj) {
    (*gModgfxInterface)->detachSource((void *)obj);
    (*gExpgfxInterface)->freeSource2((u32)obj);
}

void dfpobjcreator_init(int obj, s8 *def) {
    DfpObjCreatorState *state = ((GameObject *)obj)->extra;
    *(s16 *)obj = (s16)((s32)def[0x1E] << 8);
    state->gameBit = ((DfpobjcreatorObjectDef *)def)->unk18;
    state->spawnPeriod = ((DfpobjcreatorObjectDef *)def)->unk1C;
    state->spawnTimer = state->spawnPeriod;
    state->unk12 = (s16)(s32)def[0x1F];
    state->unk14 = (s16)((s32)(u8)def[0x20] << 1);
    state->unk16 = 100;
}

void dfplevelcontrol_setScale(int unused, u8 *out) {
    s16 i = 0;
    s16 *p = lbl_80329848;
    for (; i < 9; i += 3) {
        out[i] = p[0];
        out[(s16)(i + 1)] = p[1];
        out[(s16)(i + 2)] = p[2];
        p += 3;
    }
}

int dbstealerworm_stateHandlerA00(int obj, int p2)
{
  extern void ObjHits_EnableObject(int);
  extern void ObjHits_SetHitVolumeSlot(int, int, int, int);
  extern int *gPlayerInterface;
  extern int lbl_80329640[];
  extern f32 lbl_803E6350;
  extern f32 lbl_803E6354;
  extern f32 lbl_803E6358;
  GroundBaddieState *sub = ((GameObject *)obj)->extra;
  DbStealerwormControl *sub_40c = (DbStealerwormControl *)sub->control;
  BaddieState *bs = (BaddieState *)p2;

  if ((s32)(s8)bs->moveJustStartedA != 0) {
    bs->unk25F = 1;
    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode = (u8)(*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & ~0x8);
    ((GameObject *)obj)->anim.alpha = 255;
    bs->unk34D = 1;
    bs->moveSpeed = lbl_803E6350 + (f32)(u32)sub->aggression / lbl_803E6354;
    ObjHits_EnableObject(obj);
    sub_40c->linkedObj = 0;
    sub_40c->unk1C = -1;
  } else {
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
  }

  if ((s32)(s8)bs->moveDone != 0) {
    sub->targetState = 1;
    sub_40c->unk34 = 1;
  }

  if ((*(int *)&bs->eventFlags & 0x200) != 0) {
    *(int *)&bs->eventFlags = *(int *)&bs->eventFlags & ~0x200;
    sub_40c->flags14 = (u8)(sub_40c->flags14 | 0x4);
  }

  if (((GameObject *)obj)->anim.currentMoveProgress < lbl_803E6358) {
    sub_40c->flags14 = (u8)(sub_40c->flags14 | 0x2);
  }

  (**(void (**)(int, int, int, int, int *))((char *)(*gPlayerInterface) + 0x34))(obj, p2, 7, 0, lbl_80329640);
  return 0;
}

int dbholecontrol1_SeqFn(int obj, int unused, ObjAnimUpdateState *animUpdate)
{
  extern u8 Obj_IsLoadingLocked(void);
  extern void *mapRomListFindItem(int, int, int, int, int);
  extern int Obj_AllocObjectSetup(int, int);
  extern void memcpy(int, void *, int);
  extern void loadObjectAtObject(int, int);
  extern int *ObjGroup_GetObjects(int, int *);
  extern void ObjGroup_RemoveObject(int, int);
  extern void ObjMsg_SendToObjects(int, int, int, int, int);
  extern int lbl_803DDCE0;
  int data = *(int *)&((GameObject *)obj)->anim.placementData;
  int i;

  for (i = 0; i < animUpdate->eventCount; i++) {
    void *res;
    int newObj;
    if (animUpdate->eventIds[i] != 1) continue;
    if (GameBit_Get((s32)(s8)*(u8 *)(data + 0x19) + 2601) != 0) continue;
    if (Obj_IsLoadingLocked() == 0) continue;
    res = mapRomListFindItem(0x4658A, 0, 0, 0, 0);
    if (res == NULL) continue;
    newObj = Obj_AllocObjectSetup(56, 1337);
    memcpy(newObj, res, 56);
    ((GameObject *)newObj)->anim.rootMotionScale = ((GameObject *)obj)->anim.localPosX;
    ((GameObject *)newObj)->anim.localPosX = ((GameObject *)obj)->anim.localPosY;
    ((GameObject *)newObj)->anim.localPosY = ((GameObject *)obj)->anim.localPosZ;
    *(int *)&((GameObject *)newObj)->anim.localPosZ = -1;
    *(s16 *)(newObj + 26) = 149;
    loadObjectAtObject(obj, newObj);
  }

  if (GameBit_Get(((Dbholecontrol1Placement *)data)->unk1E) != 0 || lbl_803DDCE0 != 0) {
    int count;
    int *objs = ObjGroup_GetObjects(36, &count);
    ObjMsg_SendToObjects(0, 3, obj, 17, 0);
    while (count != 0) {
      ObjGroup_RemoveObject(*objs, 36);
      objs++;
      count--;
    }
    return 4;
  }
  return 0;
}

int dbstealerworm_func0B(int obj, u8 msg, int *out)
{
    GroundBaddieState *state = ((GameObject *)obj)->extra;
    DbStealerwormControl *sub = (DbStealerwormControl *)state->control;
    int result = 0;
    u8 b;
    switch (msg) {
    case 0x80:
        break;
    case 0x81:
        b = state->configFlags;
        if ((b & 2) == 0) {
            break;
        }
        state->configFlags = b & ~2;
        if (out != 0) {
            *out = 1;
        }
        result = 1;
        break;
    case 0x82:
        if (state->baddie.controlMode != 0xb) {
            break;
        }
        if (out == 0) {
            break;
        }
        sub->unk3C = (int)out;
        result = 1;
        break;
    case 0x83:
        result = sub->unk3C;
        break;
    }
    return result;
}

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

void DBstealerwo_setFuncPtrs_80203c78(void)
{
    gDBStealerWormStateHandlersA[0] = (int)dbstealerworm_stateHandlerA00;
    gDBStealerWormStateHandlersA[1] = (int)dbstealerworm_stateHandlerA01;
    gDBStealerWormStateHandlersA[2] = (int)dbstealerworm_stateHandlerA02;
    gDBStealerWormStateHandlersA[3] = (int)dbstealerworm_stateHandlerA03;
    gDBStealerWormStateHandlersA[4] = (int)dbstealerworm_stateHandlerA04;
    gDBStealerWormStateHandlersA[5] = (int)dbstealerworm_stateHandlerA05;
    gDBStealerWormStateHandlersA[6] = (int)dbstealerworm_stateHandlerA06;
    gDBStealerWormStateHandlersA[7] = (int)dbstealerworm_stateHandlerA07;
    gDBStealerWormStateHandlersA[8] = (int)dbstealerworm_stateHandlerA08;
    gDBStealerWormStateHandlersA[9] = (int)dbstealerworm_stateHandlerA09;
    gDBStealerWormStateHandlersA[10] = (int)dbstealerworm_stateHandlerA0A;
    gDBStealerWormStateHandlersA[11] = (int)dbstealerworm_stateHandlerA0B;
    gDBStealerWormStateHandlersA[12] = (int)dbstealerworm_stateHandlerA0C;
    gDBStealerWormStateHandlersA[13] = (int)dbstealerworm_stateHandlerA0D;
    gDBStealerWormStateHandlersA[14] = (int)dbstealerworm_stateHandlerA0E;
    gDBStealerWormStateHandlersA[15] = (int)dbstealerworm_stateHandlerA0F;
    gDBStealerWormStateHandlersB[0] = (int)dbstealerworm_stateHandlerB00;
    gDBStealerWormStateHandlersB[1] = (int)dbstealerworm_stateHandlerB01;
    gDBStealerWormStateHandlersB[2] = (int)dbstealerworm_stateHandlerB02;
    gDBStealerWormStateHandlersB[3] = (int)dbstealerworm_stateHandlerB03;
    gDBStealerWormStateHandlersB[4] = (int)dbstealerworm_stateHandlerB04;
    gDBStealerWormStateHandlersB[5] = (int)dbstealerworm_stateHandlerB05;
    gDBStealerWormStateHandlersB[6] = (int)dbstealerworm_stateHandlerB06;
}

extern void fn_80202EF0(int obj, int p2);

#pragma dont_inline on
void fn_80203000(int obj, int param2)
{
    int i;
    int state = *(int *)(param2 + 0x40c);
    if ((*(u8 *)(state + 0x14) & 1) && *(void **)&((GroundBaddieState *)param2)->baddie.targetObj != 0) {
        fn_80202EF0(obj, param2);
    }
    if (*(u8 *)(state + 0x14) & 2) {
        (*gPartfxInterface)->spawnObject((void *)obj, 0x345, NULL, 2, -1, NULL);
        (*gPartfxInterface)->spawnObject((void *)obj, 0x345, NULL, 2, -1, NULL);
        (*gPartfxInterface)->spawnObject((void *)obj, 0x345, NULL, 2, -1, NULL);
    }
    if (*(u8 *)(state + 0x14) & 4) {
        for (i = 0; i < 0xa; i++) {
            (*gPartfxInterface)->spawnObject((void *)obj, 0x343, NULL, 1, -1, NULL);
        }
    }
    *(u8 *)(state + 0x14) = 0;
}
#pragma dont_inline reset

extern void unlockLevel(int a, int b, int c);
extern void Music_Trigger(int a, int b);


void dfplevelcontrol_init(int obj, int param2)
{
    DfpLevelControlState *state = ((GameObject *)obj)->extra;
    int v;
    ObjGroup_AddObject(obj, 9);
    ((DfpFlags7 *)&state->flags07)->b80 = GameBit_Get(0xd5d);
    ((DfpFlags7 *)&state->flags07)->b40 = GameBit_Get(0xd59);
    ((DfpFlags7 *)&state->flags07)->b20 = GameBit_Get(0xd5a);
    ((GameObject *)obj)->animEventCallback = (void *)dfplevelcontrol_SeqFn;
    state->mode = 1;
    v = *(s16 *)(param2 + 0x1a);
    if (v != 0 && v <= 2) {
        state->mode = v;
    }
    (*gMapEventInterface)->getMode(((GameObject *)obj)->anim.mapEventSlot);
    unlockLevel(0, 0, 1);
    ((GameObject *)obj)->objectFlags = ((GameObject *)obj)->objectFlags | 0x4000;
    if (((GameObject *)obj)->anim.mapEventSlot == 0x15) {
        GameBit_Set(0xdce, 0);
    }
    if ((u32)GameBit_Get(0xdce) != 0) {
        Music_Trigger(0x37, 0);
        Music_Trigger(0xe4, 0);
    }
}

extern f32 lbl_803E62F4;

int dbstealerworm_stateHandlerA04(int obj, int param2)
{
    GroundBaddieState *state = ((GameObject *)obj)->extra;
    BaddieState *bs = (BaddieState *)param2;
    u32 v;
    DbStealerwormControl *sub;
    if (*(s8 *)&bs->moveJustStartedA != 0) {
        ObjHits_EnableObject(obj);
    }
    ObjHits_SetHitVolumeSlot(obj, 0xa, 1, -1);
    bs->moveSpeed = lbl_803E62F4;
    if (*(s8 *)&bs->moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove((int)obj, 0xa, lbl_803E62A8, 0);
        bs->moveDone = 0;
    }
    bs->unk34D = 1;
    sub = (DbStealerwormControl *)state->control;
    sub->flags14 = sub->flags14 | 0x2;
    v = bs->eventFlags;
    if (v & 1) {
        bs->eventFlags = v & ~1;
        sub->flags14 = sub->flags14 | 0x1;
    }
    if (*(s8 *)&bs->moveDone != 0) {
        sub->unk34 = 1;
    }
    return 0;
}

extern f32 lbl_803E62E8;
extern f32 lbl_803E62EC;

int dbstealerworm_stateHandlerA0E(int obj, int param2)
{
    DbStealerwormControl *sub = (DbStealerwormControl *)(*(GroundBaddieState **)&((GameObject *)obj)->extra)->control;
    BaddieState *bs = (BaddieState *)param2;
    sub->flags14 = sub->flags14 | 0x2;
    sub->flags15 = sub->flags15 | 0x4;
    bs->moveSpeed = lbl_803E62E8;
    if (*(s8 *)&bs->moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove((int)obj, 0x11, lbl_803E62A8, 0);
        bs->moveDone = 0;
    }
    bs->unk34D = 0x1f;
    if (*(s8 *)&bs->moveJustStartedA != 0) {
        sub->linkedObj = *(int *)&bs->targetObj;
        sub->unk1C = 0x24;
        sub->unk2C = 0;
        ObjMsg_SendToObject(sub->linkedObj, 0x11, obj, 0x12);
        Sfx_PlayFromObject(obj, SFXfoot_ice_run_3);
    }
    if (((GameObject *)obj)->anim.currentMoveProgress > lbl_803E62EC) {
        sub->unk34 = 1;
    }
    return 0;
}

extern f64 lbl_803E63F0;
extern f32 lbl_803E63E4;
extern f32 lbl_803E63E8;
extern f32 lbl_803E63E0;

void DFP_Torch_init(int obj, int param2)
{
    DfpTorchState *state = ((GameObject *)obj)->extra;
    void *res;
    f32 local_18;
    int v;
    *(s16 *)obj = (s16)((*(s8 *)(param2 + 0x18) & 0x3f) << 10);
    v = *(s16 *)(param2 + 0x1a);
    if (v > 0) {
        ((GameObject *)obj)->anim.rootMotionScale = (f32)v / lbl_803E63E4;
    } else {
        ((GameObject *)obj)->anim.rootMotionScale = lbl_803E63E8;
    }
    state->mode = *(u8 *)(param2 + 0x19);
    state->gameBit = *(s16 *)(param2 + 0x1e);
    local_18 = lbl_803E63E0;
    if (state->mode == 0) {
        state->lit = 1;
        res = Resource_Acquire(0x69, 1);
        if (*(s16 *)(param2 + 0x1c) == 0) {
            (*(void (*)(int, int, void *, int, int, int))(*(int *)(*(int *)res + 4)))(obj, 0, &local_18, 0x10004, -1, 0);
        }
    }
    state->colorIdx = (u8)*(s16 *)(param2 + 0x1c);
    ((GameObject *)obj)->objectFlags = ((GameObject *)obj)->objectFlags | 0x2000;
}

void fn_80202EF0(int obj, int p2)
{
    extern u8 Obj_IsLoadingLocked(void);
    extern u8 *Obj_AllocObjectSetup(int, int);
    extern u8 *Obj_SetupObject(u8 *, int, int, int, int);
    extern f32 lbl_803E637C;
    extern f32 lbl_803E62B4;
    extern f32 lbl_803E62B8;
    extern f32 lbl_803E6380;
    u8 *setup;
    u8 *newObj;
    f32 dur;
    f32 t;

    if (Obj_IsLoadingLocked() != 0) {
        setup = Obj_AllocObjectSetup(0x24, 0x30a);
        ((ObjPlacement *)setup)->posX = ((GameObject *)obj)->anim.localPosX;
                ((ObjPlacement *)setup)->posY = lbl_803E637C + ((GameObject *)obj)->anim.localPosY;
                ((ObjPlacement *)setup)->posZ = ((GameObject *)obj)->anim.localPosZ;
                setup[4] = 1;
                setup[5] = 1;
                setup[6] = 0xff;
                setup[7] = 0xff;
        newObj = Obj_SetupObject(setup, 5, ((GameObject *)obj)->anim.mapEventSlot, -1, 0);
        if (newObj != NULL) {
            t = ((BaddieState *)p2)->targetDistance / lbl_803E62B4;
            dur = lbl_803E62B8 * t;
            ((GameObject *)newObj)->anim.velocityX = (*(f32 *)(*(int *)&((BaddieState *)p2)->targetObj + 0xc) - ((GameObject *)obj)->anim.localPosX) / dur;
            ((GameObject *)newObj)->anim.velocityY = ((lbl_803E6380 * t + *(f32 *)(*(int *)&((BaddieState *)p2)->targetObj + 0x10)) - ((GameObject *)obj)->anim.localPosY) / dur;
            ((GameObject *)newObj)->anim.velocityZ = (*(f32 *)(*(int *)&((BaddieState *)p2)->targetObj + 0x14) - ((GameObject *)obj)->anim.localPosZ) / dur;
            *(int *)&((GameObject *)newObj)->unkC4 = obj;
        }
    }
}

#pragma opt_common_subs off
#pragma dont_inline on
int fn_80202C78(int obj, int p6, f32 p1, f32 p2, f32 p3, f32 p4)
{
    extern int Obj_GetYawDeltaToObject(int, int, f32 *);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E6370;
    extern f32 timeDelta;
    extern f32 lbl_803E634C;
    extern f32 lbl_803E62C8;
    extern f32 lbl_803E6374;
    BaddieState *state = ((GameObject *)obj)->extra;
    f32 yawF;
    int yaw;
    f32 zero;
    f32 a;
    f32 ratio;
    f32 k;
    f32 cur;
    f32 prod;

    yaw = Obj_GetYawDeltaToObject(obj, p6, &yawF);
    zero = lbl_803E62A8;
    if (zero == p4) {
        return 0;
    }
    yawF -= p1;
    ratio = yawF / p4;
    yawF = ratio;
    if (ratio >= zero) {
        a = ratio;
    } else {
        a = -ratio;
    }
    if (a < lbl_803E6370) {
        return 1;
    }
    if (ratio < lbl_803E62A8) {
        p2 = -p2;
    }
    cur = state->animSpeedA;
    k = timeDelta * lbl_803E634C;
    prod = p2 * (lbl_803E62C8 - (f32)(s16)yaw / lbl_803E6374);
    state->animSpeedA = k * (prod - cur) + cur;
    state->animSpeedB = lbl_803E62A8;
    return 0;
}
#pragma dont_inline reset
#pragma opt_common_subs reset

#pragma dont_inline on
int fn_80202DA4(u8 *obj, u8 *p6, f32 p1, f32 p2, f32 p3, f32 p4)
{
    extern int Obj_GetYawDeltaToObject(u8 *, u8 *, f32 *);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E6378;
    extern f32 timeDelta;
    extern f32 lbl_803E634C;
    extern f32 lbl_803E62C8;
    extern f32 lbl_803E6374;
    BaddieState *state = ((GameObject *)obj)->extra;
    f32 yawF;
    int yaw;
    f32 dy;
    f32 zero;
    f32 k;
    f32 cur;
    f32 prod;

    if (obj == NULL || p6 == NULL) {
        return 0;
    }
    yaw = Obj_GetYawDeltaToObject(obj, p6, &yawF);
    zero = lbl_803E62A8;
    if (zero == p4) {
        return 0;
    }
    if (yawF < p1) {
        dy = ((GameObject *)obj)->anim.localPosY - *(f32 *)(p6 + 0x10);
        dy = (dy >= zero) ? dy : -dy;
        if (dy < lbl_803E6378) {
            return 1;
        }
    }
    cur = state->animSpeedA;
    k = timeDelta * lbl_803E634C;
    prod = p2 * (lbl_803E62C8 - (f32)(s16)yaw / lbl_803E6374);
    state->animSpeedA = k * (prod - cur) + cur;
    state->animSpeedB = lbl_803E62A8;
    return 0;
}

void dfpobjcreator_update(int obj)
{
    extern u8 Obj_IsLoadingLocked(void);
    extern uint GameBit_Get(int);
    extern u8 *Obj_AllocObjectSetup(int, int);
    extern u8 *Obj_SetupObject(u8 *, int, int, int, int);
    extern f32 timeDelta;
    int data = *(int *)&((GameObject *)obj)->anim.placementData;
    DfpObjCreatorState *state = ((GameObject *)obj)->extra;
    u8 *setup;
    u8 *newObj;

    if (Obj_IsLoadingLocked() != 0) {
        switch (((DfpobjcreatorPlacement *)data)->unk1A) {
        case 7:
            state->spawnTimer -= (s16)timeDelta;
            if (state->spawnTimer <= 0 && GameBit_Get(state->gameBit) != 0) {
                state->spawnTimer = state->spawnPeriod;
                setup = Obj_AllocObjectSetup(0x24, 0x71b);
                ((ObjPlacement *)setup)->posX = ((DfpobjcreatorPlacement *)data)->unk8;
                ((ObjPlacement *)setup)->posY = ((DfpobjcreatorPlacement *)data)->unkC;
                ((ObjPlacement *)setup)->posZ = ((DfpobjcreatorPlacement *)data)->unk10;
                setup[4] = ((DfpobjcreatorPlacement *)data)->unk4;
                setup[5] = ((DfpobjcreatorPlacement *)data)->unk5;
                setup[6] = ((DfpobjcreatorPlacement *)data)->unk6;
                setup[7] = ((DfpobjcreatorPlacement *)data)->unk7;
                *(s16 *)(setup + 0x1e) = -1;
                *(s16 *)(setup + 0x20) = -1;
                *(s16 *)(setup + 0x1a) = 0xdc;
                newObj = Obj_SetupObject(setup, 5, ((GameObject *)obj)->anim.mapEventSlot, -1, *(int *)&((GameObject *)obj)->anim.parent);
                ((GameObject *)newObj)->unkF4 = *(s8 *)(data + 0x1e);
            }
            break;
        }
    }
}
#pragma dont_inline reset

int dbstealerworm_stateHandlerA02(int obj, int p2)
{
    extern void ObjHits_EnableObject(int);
    extern void ObjHits_SetHitVolumeSlot(int, int, int, int);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E6344;
    extern f32 lbl_803E6348;
    GroundBaddieState *state = ((GameObject *)obj)->extra;
    DbStealerwormControl *sub = (DbStealerwormControl *)state->control;
    BaddieState *bs = (BaddieState *)p2;

    if (*(s8 *)&bs->moveJustStartedA != 0) {
        ObjHits_EnableObject(obj);
    }
    ObjHits_SetHitVolumeSlot(obj, 10, 1, -1);
    if (*(s8 *)&bs->moveJustStartedA != 0) {
        if ((int)randomGetRange(0, 1) != 0) {
            if (*(s8 *)&bs->moveJustStartedA != 0) {
                ObjAnim_SetCurrentMove((int)obj, 6, lbl_803E62A8, 0);
                bs->moveDone = 0;
            }
        } else {
            if (*(s8 *)&bs->moveJustStartedA != 0) {
                ObjAnim_SetCurrentMove((int)obj, 7, lbl_803E62A8, 0);
                bs->moveDone = 0;
            }
        }
        bs->unk34D = 1;
        bs->moveSpeed = lbl_803E6344 + (f32)state->aggression / lbl_803E6348;
    }
    bs->animSpeedA = lbl_803E62A8;
    if (*(s8 *)&bs->moveDone != 0) {
        sub->unk34 = 1;
    }
    sub->flags14 |= 2;
    return 0;
}

void dbstealerworm_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    extern void fn_8003B5E0(int, int, int, int);
    extern void objParticleFn_80099d84(int, f32, int, f32, int);
    extern void ObjPath_GetPointWorldPosition(int, int, char *, char *, char *, int);
    extern f32 lbl_803E62D0;
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E62C8;
    DbStealerwormControl *sub;
    GroundBaddieState *state;
    char *path;

    state = ((GameObject *)obj)->extra;
    sub = (DbStealerwormControl *)state->control;
    if (*(void **)&sub->linkedObj != NULL) {
        *(f32 *)(sub->linkedObj + 0xc) = ((GameObject *)obj)->anim.localPosX;
        *(f32 *)(sub->linkedObj + 0x10) = ((GameObject *)obj)->anim.localPosY;
        *(f32 *)(sub->linkedObj + 0x14) = ((GameObject *)obj)->anim.localPosZ;
        *(f32 *)(sub->linkedObj + 0x10) += lbl_803E62D0;
    }
    if (visible != 0 && ((GameObject *)obj)->unkF4 == 0 && state->targetState != 0) {
        {
            if (state->unk3E8 != lbl_803E62A8) {
                fn_8003B5E0(0xc8, 0, 0, (int)state->unk3E8);
            }
            ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(obj, p2, p3, p4, p5, lbl_803E62C8);
            if ((state->flags400 & 0x60) != 0) {
                objParticleFn_80099d84(obj, lbl_803E62C8, 3, state->unk3E8, 0);
            }
            path = *(char **)&sub->linkedObj;
            if (path != NULL && *(void **)(path + 0x50) != NULL) {
                ObjPath_GetPointWorldPosition(obj, 3, path + 0xc, path + 0x10, path + 0x14, 0);
                ((void (*)(int, int, int, int, int, f32))objRenderFn_8003b8f4)(sub->linkedObj, p2, p3, p4, p5, lbl_803E62C8);
            }
        }
    }
}

int dbstealerworm_stateHandlerA0D(int obj, int p2)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int *args);
    extern f32 sqrtf(f32 x);
    extern f32 lbl_803E62F0;
    extern f32 lbl_803E62F4;
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E62EC;
    extern f32 lbl_803E62F8;
    extern f32 lbl_803E62FC;
    extern f32 lbl_803E62B8;
    DbStealerwormControl *sub = (DbStealerwormControl *)(*(GroundBaddieState **)&((GameObject *)obj)->extra)->control;
    BaddieState *bs = (BaddieState *)p2;
    int q;
    int tmp;
    f32 v;
    f32 d;
    struct {
        int msgE[3];
        int msg7[3];
        int msg9[3];
        f32 pos[3];
    } stk;

    sub->flags14 |= 2;
    sub->flags15 &= ~4;
    v = bs->animSpeedA;
    d = lbl_803E62F0;
    bs->animSpeedA = v / d;
    bs->animSpeedB = bs->animSpeedB / d;
    bs->moveSpeed = lbl_803E62F4;
    if (*(s8 *)&bs->moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove((int)obj, 0x11, lbl_803E62A8, 0);
        bs->moveDone = 0;
    }
    bs->unk34D = 0x1f;
    if (((GameObject *)obj)->anim.currentMoveProgress > lbl_803E62EC
        && *(f32 *)(*(int *)&bs->targetObj + 0x10) - lbl_803E62F8 <= ((GameObject *)obj)->anim.localPosY) {
        q = sub->msgStack;
        stk.msg9[0] = 9;
        stk.msg9[1] = 0;
        stk.msg9[2] = 0x24;
        if (Stack_IsFull(q) == 0) {
            Stack_Push(q, stk.msg9);
        }
        sub->unk34 = 1;
        tmp = *(int *)&bs->targetObj;
        q = sub->msgStack;
        stk.msg7[0] = 7;
        stk.msg7[1] = 1;
        stk.msg7[2] = tmp;
        if (Stack_IsFull(q) == 0) {
            Stack_Push(q, stk.msg7);
        }
        sub->unk34 = 1;
    } else {
        stk.pos[0] = ((GameObject *)obj)->anim.localPosX;
        stk.pos[1] = ((GameObject *)obj)->anim.localPosY;
        stk.pos[2] = ((GameObject *)obj)->anim.localPosZ;
        stk.pos[1] = stk.pos[1] + lbl_803E62FC;
        stk.pos[0] = *(f32 *)(*(int *)&bs->targetObj + 0xc) - stk.pos[0];
        stk.pos[1] = *(f32 *)(*(int *)&bs->targetObj + 0x10) - stk.pos[1];
        stk.pos[2] = *(f32 *)(*(int *)&bs->targetObj + 0x14) - stk.pos[2];
        if (sqrtf(stk.pos[2] * stk.pos[2] + (stk.pos[0] * stk.pos[0] + stk.pos[1] * stk.pos[1])) < lbl_803E62B8) {
            tmp = *(int *)&bs->targetObj;
            q = sub->msgStack;
            stk.msgE[0] = 0xe;
            stk.msgE[1] = 1;
            stk.msgE[2] = tmp;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, stk.msgE);
            }
            sub->unk34 = 1;
        }
    }
    return 0;
}

typedef struct {
    u8 flag80 : 1;
    u8 flag40 : 1;
    u8 flag20 : 1;
    u8 flag10 : 1;
} AnimFlags44;

int dbstealerworm_stateHandlerB05(int obj, int p2)
{
    extern int Stack_IsEmpty(int);
    extern void Stack_Pop(int, int *);
    extern int ObjGroup_FindNearestObjectForObject(int, int, f32 *);
    extern int *gPlayerInterface;
    extern int lbl_803296FC[];
    extern f32 lbl_803E62AC;
    extern f32 lbl_803E62B0;
    extern f32 lbl_803E62B4;
    extern f32 lbl_803E62B8;
    GroundBaddieState *tmp = ((GameObject *)obj)->extra;
    DbStealerwormControl *sub;
    int data = *(int *)&((GameObject *)obj)->anim.placementData;
    int base;
    int n;
    u32 found;
    int i;
    int *p;
    u32 o;
    int buf[3];
    f32 range;

    range = lbl_803E62AC;
    sub = (DbStealerwormControl *)tmp->control;
    if (*(s8 *)&((BaddieState *)p2)->moveJustStartedB != 0 || ((u32)sub->flags44 >> 6 & 1) != 0) {
        sub->flags15 &= ~4;
        ((AnimFlags44 *)&sub->flags44)->flag40 = 0;
        if (Stack_IsEmpty(sub->msgStack) == 0) {
            Stack_Pop(sub->msgStack, buf);
        }
        base = sub->cfg;
        n = (sub->unk20 - *(int *)base) / 12;
        if (n >= *(s16 *)(base + 4)) {
            sub->unk20 = 0;
        }
        if (*(void **)&sub->unk20 == NULL) {
            sub->unk20 = *(int *)sub->cfg;
            ((GameObject *)obj)->anim.localPosX = ((DbstealerwormPlacement *)data)->posX8;
            ((GameObject *)obj)->anim.localPosY = ((DbstealerwormPlacement *)data)->posY8;
            ((GameObject *)obj)->anim.localPosZ = ((DbstealerwormPlacement *)data)->posZ8;
        }
        if (*(int *)(sub->unk20 + 4) != 0) {
            *(int *)&((BaddieState *)p2)->targetObj = ObjGroup_FindNearestObjectForObject(*(int *)(sub->unk20 + 4), obj, &range);
        }
        if (*(void **)&((BaddieState *)p2)->targetObj != NULL) {
            (**(void (**)(int, int, int))((char *)(*gPlayerInterface) + 0x14))(obj, p2, *(int *)sub->unk20);
        }
        return 0;
    } else {
        f32 t;
        if (*(void **)&sub->linkedObj == NULL && (t = sub->unk38) > lbl_803E62B0) {
            sub->unk38 = t - lbl_803E62B0;
            range = lbl_803E62B4;
            i = 3;
            found = 0;
            p = &lbl_803296FC[3];
            for (; p--, --i >= 0;) {
                o = ObjGroup_FindNearestObjectForObject(*p, obj, &range);
                if (o != 0) {
                    found = o;
                }
            }
            *(int *)&((BaddieState *)p2)->targetObj = found;
            if (found != 0) {
                if (range < lbl_803E62B8) {
                    (**(void (**)(int, int, int))((char *)(*gPlayerInterface) + 0x14))(obj, p2, 2);
                } else {
                    (**(void (**)(int, int, int))((char *)(*gPlayerInterface) + 0x14))(obj, p2, 4);
                }
            }
        }
    }
    return 0;
}

void fn_80203144(int obj, int p2, int p3)
{
    extern int ObjGroup_FindNearestObject(int, int, f32 *);
    extern void ObjGroup_AddObject(int, int);
    extern void *Obj_GetPlayerObject(void);
    extern void Sfx_PlayFromObject(int, u16);
    extern f32 sqrtf(f32 x);
    extern u32 randomGetRange(int min, int max);
    extern void **gBaddieControlInterface;
    extern int lbl_80329640[];
    extern f32 lbl_803E62B0;
    extern f32 lbl_803E6354;
    extern f32 lbl_803E6384;
    extern f32 timeDelta;
    GroundBaddieState *st = (GroundBaddieState *)p2;
    DbStealerwormControl *sub = (DbStealerwormControl *)st->control;
    u32 near;
    int data;
    char *player;
    f32 dist;
    struct {
        f32 range;
        f32 d[3];
    } stk;

    stk.range = lbl_803E62B0;
    data = *(int *)&((GameObject *)obj)->anim.placementData;
    near = (**(u32 (**)(int, int, f32, int))((char *)*gBaddieControlInterface + 0x48))(obj, p3, (f32)st->aggroRange, 0x8000);
    if (near == 0 && (st->configFlags & 0x10) != 0) {
        near = ObjGroup_FindNearestObject(0x24, obj, &stk.range);
    }
    if (near == 0 && (st->configFlags & 0x10) != 0 && (st->configFlags & 2) == 0 && (*(u8 *)(data + 0x2b) & 2) != 0) {
        near = ObjGroup_FindNearestObject(0x24, obj, 0);
    }
    if (near != 0 && (st->configFlags & 2) == 0) {
        (**(void (**)(int, int, int, int, int, int, int, int, int))((char *)*gBaddieControlInterface + 0x28))(obj, p3, p2 + 0x35c, st->gameBitB, 0, 0, 0, 8, -1);
        *(int *)&((BaddieState *)p3)->targetObj = near;
        ((BaddieState *)p3)->unk349 = 0;
        ObjGroup_AddObject(obj, 3);
        *(u16 *)&st->targetState = 1;
    } else {
        player = Obj_GetPlayerObject();
        if (player != NULL) {
            stk.d[0] = *(f32 *)(player + 0x18) - ((GameObject *)obj)->anim.worldPosX;
            stk.d[1] = *(f32 *)(player + 0x1c) - ((GameObject *)obj)->anim.worldPosY;
            stk.d[2] = *(f32 *)(player + 0x20) - ((GameObject *)obj)->anim.worldPosZ;
            dist = sqrtf(stk.d[2] * stk.d[2] + (stk.d[0] * stk.d[0] + stk.d[1] * stk.d[1]));
        } else {
            dist = lbl_803E6354;
        }
        if (sub->unk0C > sub->unk10 && dist < lbl_803E6384) {
            Sfx_PlayFromObject(obj, (u16)lbl_80329640[1]);
            sub->unk10 = sub->unk10 + (f32)(int)randomGetRange(0x32, 0xfa);
        }
        sub->unk0C += timeDelta;
    }
}

void dfplevelcontrol_update(int obj)
{
    extern void *Obj_GetPlayerObject(void);
    extern uint GameBit_Get(int);
    extern void GameBit_Set(int, int);
    extern void Sfx_PlayFromObject(int, u16);
    extern void coordsToMapCell(f32, f32);
    extern void fn_80204098(int);
    extern void SCGameBitLatch_Update(void *, int, int, int, int, int);
    extern void SCGameBitLatch_UpdateInverted(void *, int, int, int, int, int);
    extern s16 lbl_803DC180;
    extern f32 timeDelta;
    DfpLevelControlState *state = ((GameObject *)obj)->extra;
    char *player;
    u8 b1;
    u8 b2;
    u8 b3;
    int mode;

    player = Obj_GetPlayerObject();
    b1 = GameBit_Get(0xd5d);
    b2 = GameBit_Get(0xd59);
    b3 = GameBit_Get(0xd5a);
    if ((b1 != 0 && ((u32)state->flags07 >> 7 & 1) == 0)
        || (b2 != 0 && ((u32)state->flags07 >> 6 & 1) == 0)
        || (b3 != 0 && ((u32)state->flags07 >> 5 & 1) == 0)) {
        Sfx_PlayFromObject(0, SFXsp_lf_mutter4);
    }
    ((DfpFlags7 *)&state->flags07)->b80 = b1;
    ((DfpFlags7 *)&state->flags07)->b40 = b2;
    ((DfpFlags7 *)&state->flags07)->b20 = b3;
    if (GameBit_Get(0x5e8) == 0 && GameBit_Get(0x5ee) != 0 && GameBit_Get(0x5ef) != 0) {
        GameBit_Set(0x5e8, 1);
    }
    coordsToMapCell(*(f32 *)(player + 0xc), *(f32 *)(player + 0x14));
    mode = (*gMapEventInterface)->getMode(((GameObject *)obj)->anim.mapEventSlot);
    switch (mode) {
    case 1:
        if (lbl_803DC180 != 0) {
            lbl_803DC180 -= (s16)timeDelta;
            if (lbl_803DC180 <= 0) {
                lbl_803DC180 = 0;
            }
        }
        fn_80204320(obj);
        break;
    case 2:
        fn_80204098(obj);
        break;
    case 4:
        break;
    case 0:
        break;
    }
    SCGameBitLatch_Update((void *)state->unk08, 2, -1, -1, 0xdce, 0x95);
    SCGameBitLatch_UpdateInverted((void *)state->unk08, 4, -1, -1, 0xdce, 0x37);
    SCGameBitLatch_UpdateInverted((void *)state->unk08, 1, -1, -1, 0xdce, 0xe4);
    GameBit_Set(0xdcf, 0);
}

int fn_80202A2C(int obj, int *objs, f32 *weights, int n, f32 limit)
{
    extern int ObjGroup_FindNearestObjectForObject(int, int, f32 *);
    extern f32 mathSinf(f32);
    extern f32 mathCosf(f32);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E635C;
    extern f32 lbl_803E62C8;
    extern f32 lbl_803E6360;
    extern f32 lbl_803E6364;
    int *po;
    f32 *pw;
    BaddieState *state = ((GameObject *)obj)->extra;
    int i;
    f32 rangeInit;
    f32 accX;
    f32 accZ;
    u32 o;
    f32 k;
    f32 scale;
    f32 cosv;
    f32 sinv;
    f32 neg;
    f32 v;
    struct {
        f32 range;
        f32 d[3];
    } stk;

    accX = lbl_803E62A8;
    accZ = lbl_803E62A8;
    i = 0;
    po = objs;
    pw = weights;
    rangeInit = lbl_803E635C;
    for (; i < n; i++) {
        stk.range = rangeInit;
        o = ObjGroup_FindNearestObjectForObject(*po, obj, &stk.range);
        if (o != 0) {
            if (stk.range == lbl_803E62A8) {
                return 0;
            }
            k = lbl_803E62C8 - stk.range / lbl_803E635C;
            k = k * k;
            k = k * k;
            stk.d[0] = *(f32 *)(o + 0xc) - ((GameObject *)obj)->anim.localPosX;
            stk.d[1] = *(f32 *)(o + 0x10) - ((GameObject *)obj)->anim.localPosY;
            stk.d[2] = *(f32 *)(o + 0x14) - ((GameObject *)obj)->anim.localPosZ;
            scale = lbl_803E62C8 / stk.range;
            stk.d[0] *= scale;
            stk.d[1] *= scale;
            stk.d[2] *= scale;
            accX = accX - limit * (stk.d[0] * k * *pw);
            accZ = accZ - limit * (stk.d[2] * k * *pw);
        }
        po++;
        pw++;
    }
    cosv = mathSinf(lbl_803E6360 * (f32)((GameObject *)obj)->anim.rotX / lbl_803E6364);
    sinv = mathCosf(lbl_803E6360 * (f32)((GameObject *)obj)->anim.rotX / lbl_803E6364);
    state->animSpeedB = state->animSpeedB + (accX * sinv - accZ * cosv);
    state->animSpeedA = state->animSpeedA + (-accZ * sinv - accX * cosv);
    v = state->animSpeedA;
    neg = -limit;
    if (v < neg) {
        v = neg;
    } else if (v > limit) {
        v = limit;
    }
    state->animSpeedA = v;
    v = state->animSpeedB;
    state->animSpeedB = (v < neg) ? neg : (v > limit) ? limit : v;
    return 0;
}

void DFP_Torch_render(int obj, int p2, int p3, int p4, int p5, s8 visible)
{
    extern char *Camera_GetCurrentViewSlot(void);
    extern void voxmaps_worldToGrid(f32 *, s16 *);
    extern int voxmaps_traceLine(s16 *, s16 *, void *, int, int);
    extern f32 sqrtf(f32 x);
    extern u32 randomGetRange(int min, int max);
    extern f32 lbl_803E63C8;
    extern f32 lbl_803E63CC;
    extern f32 lbl_803E63D0;
    extern f32 lbl_803E63D4;
    extern f32 lbl_803E63D8;
    extern f32 lbl_803E63DC;
    extern f32 timeDelta;
    DfpTorchState *state = ((GameObject *)obj)->extra;
    char *cam;
    f32 dist;
    f32 scale;
    struct {
        u8 pad[12];
        f32 col[3];
    } fx;
    struct {
        s32 out[2];
        s16 g2[4];
        s16 g1[4];
        f32 b[3];
        f32 a[3];
        f32 d[3];
    } stk2;

    if (visible == 0) {
        state->flickerTimer = 0;
        state->visibleLatch = 0;
    } else {
        objRenderFn_8003b8f4(lbl_803E63C8);
        if (state->lit != 0) {
            state->visibleLatch = 1;
            cam = Camera_GetCurrentViewSlot();
            stk2.d[0] = *(f32 *)(cam + 0xc) - ((GameObject *)obj)->anim.localPosX;
            stk2.d[1] = *(f32 *)(cam + 0x10) - ((GameObject *)obj)->anim.localPosY;
            stk2.d[2] = *(f32 *)(cam + 0x14) - ((GameObject *)obj)->anim.localPosZ;
            dist = sqrtf(stk2.d[2] * stk2.d[2] + (stk2.d[0] * stk2.d[0] + stk2.d[1] * stk2.d[1]));
            if (dist > lbl_803E63CC) {
                scale = lbl_803E63C8 / dist;
                stk2.d[0] *= scale;
                stk2.d[1] *= scale;
                stk2.d[2] *= scale;
                stk2.a[0] = lbl_803E63D0 * stk2.d[0];
                stk2.a[1] = lbl_803E63D0 * stk2.d[1];
                stk2.a[2] = lbl_803E63D0 * stk2.d[2];
                stk2.a[0] = stk2.a[0] + ((GameObject *)obj)->anim.localPosX;
                stk2.a[1] = stk2.a[1] + ((GameObject *)obj)->anim.localPosY;
                stk2.a[2] = stk2.a[2] + ((GameObject *)obj)->anim.localPosZ;
                stk2.b[0] = lbl_803E63D4 * stk2.d[0];
                stk2.b[1] = lbl_803E63D4 * stk2.d[1];
                stk2.b[2] = lbl_803E63D4 * stk2.d[2];
                stk2.b[0] = stk2.b[0] + *(f32 *)(cam + 0xc);
                stk2.b[1] = stk2.b[1] + *(f32 *)(cam + 0x10);
                stk2.b[2] = stk2.b[2] + *(f32 *)(cam + 0x14);
                voxmaps_worldToGrid(stk2.a, stk2.g1);
                voxmaps_worldToGrid(stk2.b, stk2.g2);
                if (voxmaps_traceLine(stk2.g1, stk2.g2, stk2.out, 0, 0) == 0) {
                    state->visibleLatch = 0;
                    (*gExpgfxInterface)->freeSource((u32)obj);
                }
            }
            if (state->flickerTimer > 0) {
                state->flickerTimer -= (s16)timeDelta;
            } else {
                if (state->visibleLatch != 0) {
                    fx.col[0] = lbl_803E63D8;
                    fx.col[1] = lbl_803E63DC;
                    fx.col[2] = lbl_803E63D8;
                    (*gPartfxInterface)->spawnObject((void *)obj, 0x1f7, &fx, 0x12, -1,
                                                     NULL);
                }
                state->flickerTimer = (s16)(randomGetRange(-10, 10) + 0x3c);
            }
        }
    }
}

void fn_80204098(int obj)
{
    extern void *Obj_GetPlayerObject(void);
    extern uint GameBit_Get(int);
    extern void GameBit_Set(int, int);
    extern void Sfx_PlayFromObject(int, u16);
    extern void ObjMsg_SendToObject(void *, int, int, int);
    extern u8 lbl_803DC183;
    extern s16 lbl_80329848[];
    DfpLevelControlState *state = ((GameObject *)obj)->extra;
    void *player;
    s16 i;
    s16 *p;

    player = Obj_GetPlayerObject();
    if (lbl_803DC183 != 0) {
        GameBit_Set(0x2d, 1);
        GameBit_Set(0x1d7, 1);
        for (i = 0, p = lbl_80329848; i < 9; i++) {
            *p = (s16)randomGetRange(1, 4);
            p++;
        }
        GameBit_Set(0x5e4, 0);
        state->timer = 0;
        lbl_803DC183 = 0;
    }
    if (GameBit_Get(0x5e3) == 0 && GameBit_Get(0x5e0) != 0 && GameBit_Get(0x5e1) != 0) {
        Sfx_PlayFromObject(obj, SFXmn_spithit6);
        GameBit_Set(0x5e3, 1);
    }
    if (GameBit_Get(0x792) == 0 && GameBit_Get(0xb8c) != 0 && GameBit_Get(0xb8c) != 0) {
        Sfx_PlayFromObject(obj, SFXmn_spithit6);
        GameBit_Set(0x792, 1);
    }
    if (GameBit_Get(0xe58) == 0) {
        if (GameBit_Get(0x635) != 0 && state->sfxLatch == 0) {
            Sfx_PlayFromObject(0, SFXfoot_wood_run_2);
            for (i = 0, p = lbl_80329848; i < 9; i++) {
                *p = (s16)randomGetRange(1, 4);
                p++;
            }
            GameBit_Set(0x5e4, 1);
            state->sfxLatch = 1;
        } else {
            if (GameBit_Get(0x635) == 0 && state->sfxLatch == 1) {
                state->sfxLatch = 0;
                GameBit_Set(0x5e4, 0);
            }
        }
        if (GameBit_Get(0x5e5) != 0) {
            state->timer = 300;
            ObjMsg_SendToObject(player, 0x60005, obj, 0);
        }
    }
    if (GameBit_Get(0x7a1) != 0) {
        if ((*gMapEventInterface)->getAnimEvent(((GameObject *)obj)->anim.mapEventSlot, 6) == 0) {
            (*gMapEventInterface)->setAnimEvent(((GameObject *)obj)->anim.mapEventSlot, 6, 1);
        }
    }
}

int dbstealerworm_stateHandlerB06(int obj, int p2)
{
    extern int Stack_IsEmpty(int);
    extern void Stack_Pop(int, int *);
    extern void Stack_Push(int, int *);
    extern void Obj_FreeObject(int);
    extern int ObjGroup_FindNearestObjectForObject(int, int, f32 *);
    extern int ObjGroup_ContainsObject(int, int);
    extern int *gPlayerInterface;
    extern u8 lbl_80329514[];
    extern f32 lbl_803E62AC;
    extern f32 lbl_803E62A8;
    GroundBaddieState *tmp = ((GameObject *)obj)->extra;
    DbStealerwormControl *sub;
    int data = *(int *)&((GameObject *)obj)->anim.placementData;
    int off;
    int n;
    char *entry;
    char *ptr;
    f32 range;

    range = lbl_803E62AC;
    sub = (DbStealerwormControl *)tmp->control;
    if (*(s8 *)&((BaddieState *)p2)->moveJustStartedB != 0 || sub->unk34 != 0) {
        sub->flags15 &= ~4;
        sub->unk34 = 0;
        if (Stack_IsEmpty(sub->msgStack) == 0) {
            Stack_Pop(sub->msgStack, (int *)&sub->unk28);
        } else {
            if (((DbstealerwormPlacement *)data)->unk14 == 0xFFFFFFFF) {
                Obj_FreeObject(obj);
                return 0;
            }
            entry = (char *)&lbl_80329514[((DbstealerwormPlacement *)data)->unk24 * 8];
            n = *(s16 *)(entry + 4);
            off = n * 12;
            for (; n != 0; n--) {
                Stack_Push(sub->msgStack, (int *)(*(int *)entry + (off -= 12)));
            }
            sub->unk34 = 1;
            ((GameObject *)obj)->anim.localPosX = ((DbstealerwormPlacement *)data)->posX8;
            ((GameObject *)obj)->anim.localPosY = ((DbstealerwormPlacement *)data)->posY8;
            ((GameObject *)obj)->anim.localPosZ = ((DbstealerwormPlacement *)data)->posZ8;
        }
        switch (sub->unk2C) {
        case 0:
            if (sub->unk30 != 0) {
                *(int *)&((BaddieState *)p2)->targetObj = ObjGroup_FindNearestObjectForObject(sub->unk30, obj, &range);
            }
            break;
        case 1:
            *(int *)&((BaddieState *)p2)->targetObj = sub->unk30;
            break;
        }
        if (*(void **)&((BaddieState *)p2)->targetObj != NULL) {
            (**(void (**)(int, int, int))((char *)(*gPlayerInterface) + 0x14))(obj, p2, *(int *)&sub->unk28);
        }
        return 0;
    } else {
        switch (sub->unk2C) {
        case 0:
            if (*(void **)&((BaddieState *)p2)->targetObj == NULL) {
                sub->unk34 = 1;
            } else if (sub->unk30 != 0) {
                if (ObjGroup_ContainsObject(*(int *)&((BaddieState *)p2)->targetObj, sub->unk30) == 0) {
                    *(int *)&((BaddieState *)p2)->targetObj = ObjGroup_FindNearestObjectForObject(sub->unk30, obj, 0);
                    if (*(void **)&((BaddieState *)p2)->targetObj == NULL) {
                        sub->unk34 = 1;
                    }
                    ((BaddieState *)p2)->animSpeedA = lbl_803E62A8;
                }
            }
            break;
        case 1:
            if (*(void **)&((BaddieState *)p2)->targetObj == NULL) {
                sub->unk34 = 1;
            }
            break;
        }
        if (sub->unk1C == -1 && (ptr = *(char **)&sub->unk3C) != NULL) {
            if ((**(int (**)(char *))(*(int *)(*(int *)(ptr + 0x68))  + 0x20))(ptr) == 0) {
                sub->unk3C = 0;
                sub->unk34 = 1;
            }
        }
        return 0;
    }
}

int dbstealerworm_stateHandlerA0A(int obj, int p2)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int *args);
    extern void ObjMsg_SendToObject(int, int, int, int);
    extern int Obj_GetYawDeltaToObject(int, int, f32 *);
    extern f32 sqrtf(f32 x);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E6310;
    extern f32 lbl_803E6314;
    extern f32 lbl_803E6318;
    extern f32 lbl_803E631C;
    extern f32 lbl_803E6320;
    DbStealerwormControl *sub = (DbStealerwormControl *)(*(GroundBaddieState **)&((GameObject *)obj)->extra)->control;
    int c30 = sub->unk30;
    int c2c = sub->unk2C;
    int tmpB;
    int tmpA;
    int t;
    int q;
    f32 z;
    f32 dist;
    struct {
        f32 v[3];
        f32 out[3];
    } stk;
    int msgA[3];
    int msgB[3];
    int msgC[3];

    z = lbl_803E62A8;
    ((BaddieState *)p2)->animSpeedA = lbl_803E62A8;
    ((BaddieState *)p2)->animSpeedB = z;
    sub->flags14 |= 2;
    if (*(void **)&sub->linkedObj == NULL && sub->unk1C != -1) {
        tmpA = sub->unk30;
        tmpB = sub->unk2C;
        q = sub->msgStack;
        msgA[0] = sub->unk28;
        msgA[1] = tmpB;
        msgA[2] = tmpA;
        if (Stack_IsFull(q) == 0) {
            Stack_Push(q, msgA);
        }
        q = sub->msgStack;
        msgB[0] = 8;
        msgB[1] = c2c;
        msgB[2] = c30;
        if (Stack_IsFull(q) == 0) {
            Stack_Push(q, msgB);
        }
        sub->unk34 = 1;
        tmpA = sub->unk1C;
        q = sub->msgStack;
        msgC[0] = 9;
        msgC[1] = 0;
        msgC[2] = tmpA;
        if (Stack_IsFull(q) == 0) {
            Stack_Push(q, msgC);
        }
        sub->unk34 = 1;
        return 0;
    } else {
        sub->flags15 |= 4;
        if (sub->linkedObj != 0 && (((BaddieState *)p2)->eventFlags & 0x200) != 0) {
            t = *(int *)&((BaddieState *)p2)->targetObj;
            stk.v[0] = *(f32 *)(t + 0xc) - ((GameObject *)obj)->anim.localPosX;
            stk.v[1] = *(f32 *)(t + 0x10) - ((GameObject *)obj)->anim.localPosY;
            stk.v[2] = *(f32 *)(t + 0x14) - ((GameObject *)obj)->anim.localPosZ;
            dist = sqrtf(stk.v[0] * stk.v[0] + stk.v[2] * stk.v[2]);
            stk.v[1] = stk.v[1] * lbl_803E6310;
            dist = dist / lbl_803E6314;
            stk.out[1] = -(dist * (lbl_803E6318 * dist) - stk.v[1]) / dist;
            stk.out[1] = stk.out[1] * lbl_803E631C;
            stk.out[0] = lbl_803E62A8;
            stk.out[2] = lbl_803E6320;
            ObjMsg_SendToObject(sub->linkedObj, 0x11, obj, 0x11);
            (**(void (**)(int, f32 *))(*(int *)(*(int *)(sub->linkedObj + 0x68)) + 0x24))(sub->linkedObj, stk.out);
            sub->linkedObj = 0;
            sub->unk1C = -1;
        }
        ((GameObject *)obj)->anim.rotX += Obj_GetYawDeltaToObject(obj, *(int *)&((BaddieState *)p2)->targetObj, 0);
        ((BaddieState *)p2)->unk34D = 0x11;
        if (*(s8 *)&((BaddieState *)p2)->moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove((int)obj, 0x12, lbl_803E62A8, 0);
            ((BaddieState *)p2)->moveDone = 0;
        }
        if (*(s8 *)&((BaddieState *)p2)->moveDone != 0) {
            sub->unk34 = 1;
        }
        return 0;
    }
}

int dbstealerworm_stateHandlerA0B(int obj, int p2, f32 t)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int *args);
    extern int ObjGroup_ContainsObject(int, int);
    extern int *ObjGroup_GetObjects(int, int *);
    extern int ObjGroup_FindNearestObject(int, int, f32 *);
    extern int Obj_GetPlayerObject(void);
    extern int Obj_GetYawDeltaToObject(int, int, f32 *);
    extern int *seqFn_800394a0(void);
    extern s16 *objModelGetVecFn_800395d8(int, int);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E62B4;
    extern f32 lbl_803E62C4;
    extern f32 lbl_803E62CC;
    extern f32 lbl_803E62D0;
    extern int lbl_8032971C[];
    extern f32 lbl_8032972C[];
    GroundBaddieState *blob = ((GameObject *)obj)->extra;
    DbStealerwormControl *sub = (DbStealerwormControl *)blob->control;
    int c30 = sub->unk30;
    int tmpA;
    int tmpB;
    int i;
    int found;
    int q;
    int *objs;
    int player;
    int d;
    int flag;
    int zero;
    int *ptr;
    s16 *vec;
    f32 frac;
    int msg0[3];
    int msgA[3];
    int msgB[3];
    int msgC[3];
    int msgD[3];
    int msgE[3];
    int msgF[3];
    int msgG[3];
    int msgH[3];
    int msgI[3];
    int cnt1;
    int cnt2;
    f32 yawf;

    sub->flags14 |= 2;
    sub->flags15 &= ~4;
    if (ObjGroup_ContainsObject(*(int *)&((BaddieState *)p2)->targetObj, c30) == 0) {
        ObjGroup_GetObjects(c30, &cnt1);
        if (cnt1 == 0) {
            player = Obj_GetPlayerObject();
            q = sub->msgStack;
            msg0[0] = 0xf;
            msg0[1] = 1;
            msg0[2] = player;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msg0);
            }
            sub->unk34 = 1;
            return 0;
        }
    }
    q = *(int *)&((BaddieState *)p2)->targetObj;
    found = 0;
    objs = ObjGroup_GetObjects(3, &cnt2);
    for (i = 0; i < cnt2; i++) {
        if (*(s16 *)(*objs + 0x46) == 0x539) {
            if ((u32)(**(int (**)(int, int, int))(*(int *)(*(int *)(*objs + 0x68)) + 0x24))(*objs, 0x83, 0) == (u32)q) {
                found = 1;
            }
        }
        objs++;
    }
    if (found == 0) {
        if ((u32)obj == (u32)ObjGroup_FindNearestObject(3, *(int *)&((BaddieState *)p2)->targetObj, 0)) {
            sub->unk3C = *(int *)&((BaddieState *)p2)->targetObj;
            tmpA = sub->unk30;
            tmpB = sub->unk2C;
            q = sub->msgStack;
            msgA[0] = sub->unk28;
            msgA[1] = tmpB;
            msgA[2] = tmpA;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgA);
            }
            q = sub->msgStack;
            msgB[0] = 0xc;
            msgB[1] = 0;
            msgB[2] = 3;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgB);
            }
            sub->unk34 = 1;
            q = sub->msgStack;
            msgC[0] = 9;
            msgC[1] = 0;
            msgC[2] = c30;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgC);
            }
            sub->unk34 = 1;
            tmpA = sub->unk3C;
            q = sub->msgStack;
            msgD[0] = 7;
            msgD[1] = 1;
            msgD[2] = tmpA;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgD);
            }
            sub->unk34 = 1;
            return 0;
        }
    }
    sub = (DbStealerwormControl *)blob->control;
    ((BaddieState *)p2)->unk34D = 0x1f;
    if (*(s8 *)&((BaddieState *)p2)->moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove((int)obj, 0xf, lbl_803E62A8, 0);
        ((BaddieState *)p2)->moveDone = 0;
    }
    if (*(void **)&sub->unk3C != NULL) {
        if (ObjGroup_ContainsObject(*(int *)&((BaddieState *)p2)->targetObj, c30) != 0) {
            tmpA = sub->unk30;
            tmpB = sub->unk2C;
            q = sub->msgStack;
            msgE[0] = sub->unk28;
            msgE[1] = tmpB;
            msgE[2] = tmpA;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgE);
            }
            q = sub->msgStack;
            msgF[0] = 0xc;
            msgF[1] = 0;
            msgF[2] = 3;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgF);
            }
            sub->unk34 = 1;
            tmpA = sub->unk3C;
            q = sub->msgStack;
            msgG[0] = 0xd;
            msgG[1] = 1;
            msgG[2] = tmpA;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgG);
            }
            sub->unk34 = 1;
            return 0;
        }
    }
    frac = (f32)blob->aggression / lbl_803E62C4;
    fn_80202C78(obj, *(int *)&((BaddieState *)p2)->targetObj, lbl_803E62B4, frac, lbl_803E62CC, t);
    if (((u32)sub->flags44 >> 5 & 1) != 0) {
        fn_80202A2C(obj, lbl_8032971C, lbl_8032972C, 4, frac);
    }
    player = Obj_GetPlayerObject();
    d = (s16)Obj_GetYawDeltaToObject(obj, player, &yawf);
    flag = 0;
    if (d >= 0) {
    } else {
        d = -d;
    }
    if (d < 0x1c71 && yawf < lbl_803E62D0) {
        flag = 1;
    }
    if (flag != 0) {
        ptr = seqFn_800394a0();
        q = 1;
        ptr = ptr + 1;
        zero = 0;
        for (; q < 9; q++) {
            vec = objModelGetVecFn_800395d8(obj, *ptr);
            if (vec != 0) {
                vec[2] = zero;
                vec[0] = zero;
            }
            ptr++;
        }
        player = Obj_GetPlayerObject();
        *(int *)&((BaddieState *)p2)->targetObj = player;
        tmpA = sub->unk30;
        tmpB = sub->unk2C;
        q = sub->msgStack;
        msgH[0] = sub->unk28;
        msgH[1] = tmpB;
        msgH[2] = tmpA;
        if (Stack_IsFull(q) == 0) {
            Stack_Push(q, msgH);
        }
        q = sub->msgStack;
        msgI[0] = 2;
        msgI[1] = 0;
        msgI[2] = 0;
        if (Stack_IsFull(q) == 0) {
            Stack_Push(q, msgI);
        }
        sub->unk34 = 1;
    }
    return 0;
}

int dbstealerworm_stateHandlerA07(int obj, int p2, f32 t)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int *args);
    extern void Sfx_KeepAliveLoopedObjectSound(int, int);
    extern void ObjHits_EnableObject(int);
    extern void ObjHits_ClearHitVolumes(int);
    extern int RandomTimer_UpdateRangeTrigger(int, f32, f32);
    extern void Sfx_PlayFromObject(int, int);
    extern int Obj_GetPlayerObject(void);
    extern int Obj_GetYawDeltaToObject(int, int, f32 *);
    extern int *seqFn_800394a0(void);
    extern s16 *objModelGetVecFn_800395d8(int, int);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E62C4;
    extern f32 lbl_803E62C8;
    extern f32 lbl_803E62CC;
    extern f32 lbl_803E62D0;
    extern f32 lbl_803E62F4;
    extern f32 lbl_803E6300;
    extern f32 lbl_803E6324;
    extern f32 lbl_803E6328;
    extern f32 lbl_803E632C;
    extern f32 lbl_803E6330;
    extern int lbl_803296FC[];
    extern f32 lbl_8032970C[];
    GroundBaddieState *blob = ((GameObject *)obj)->extra;
    DbStealerwormControl *sub = (DbStealerwormControl *)blob->control;
    s16 h;
    register int q;
    register int *ptr;
    int tmpB;
    int tmpA;
    int tmp2B;
    int tmp2A;
    int player;
    int flag;
    int d;
    int zero;
    s16 *vec;
    s16 sa;
    s16 sb;
    f32 frac;
    int msgA[3];
    int msgB[3];
    int msgC[3];
    int msgD[3];
    f32 yawf;

    sub->flags14 |= 2;
    sub->flags15 &= ~4;
    Sfx_KeepAliveLoopedObjectSound(obj, 0x441);
    if (*(s8 *)&((BaddieState *)p2)->moveJustStartedA != 0) {
        ObjHits_EnableObject(obj);
    }
    ObjHits_ClearHitVolumes(obj);
    ((BaddieState *)p2)->moveSpeed = lbl_803E62F4;
    if (*(void **)&sub->linkedObj == NULL) {
        h = sub->unk1C;
        if (h != -1) {
            tmpA = sub->unk30;
            tmpB = sub->unk2C;
            q = sub->msgStack;
            msgA[0] = sub->unk28;
            msgA[1] = tmpB;
            msgA[2] = tmpA;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgA);
            }
            q = sub->msgStack;
            msgB[0] = 9;
            msgB[1] = 0;
            msgB[2] = h;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgB);
            }
            sub->unk34 = 1;
            sub->unk1C = -1;
        }
        if (*(s8 *)&((BaddieState *)p2)->moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove((int)obj, 0xf, lbl_803E62A8, 0);
            ((BaddieState *)p2)->moveDone = 0;
        }
        frac = (f32)blob->aggression / lbl_803E62C4;
        if (RandomTimer_UpdateRangeTrigger((int)&sub->randomTimer4C, lbl_803E62C8, lbl_803E632C) != 0) {
            Sfx_PlayFromObject(obj, 0x43f);
        }
    } else {
        if (RandomTimer_UpdateRangeTrigger((int)&sub->randomTimer48, lbl_803E62C8, lbl_803E632C) != 0) {
            Sfx_PlayFromObject(obj, 0x440);
        }
        if (*(s8 *)&((BaddieState *)p2)->moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove((int)obj, 0x11, lbl_803E62A8, 0);
            ((BaddieState *)p2)->moveDone = 0;
        }
        ((BaddieState *)p2)->moveSpeed = lbl_803E6300;
        frac = (f32)blob->aggression / lbl_803E6324;
    }
    ((BaddieState *)p2)->unk34D = 0x1f;
    if (fn_80202DA4((u8 *)obj, *(u8 **)&((BaddieState *)p2)->targetObj, lbl_803E6330, frac, lbl_803E62CC, t) != 0) {
        sub->unk34 = 1;
    }
    if (((u32)sub->flags44 >> 5 & 1) != 0) {
        fn_80202A2C(obj, lbl_803296FC, lbl_8032970C, 4, frac);
    } else if (*(void **)&sub->linkedObj == NULL) {
        player = Obj_GetPlayerObject();
        d = (s16)Obj_GetYawDeltaToObject(obj, player, &yawf);
        flag = 0;
        if (d >= 0) {
        } else {
            d = -d;
        }
        if (d < 0x1c71 && yawf < lbl_803E62D0) {
            flag = 1;
        }
        if (flag != 0) {
            ptr = seqFn_800394a0();
            q = 1;
            ptr = ptr + 1;
            zero = 0;
            for (; q < 9; q++) {
                vec = objModelGetVecFn_800395d8(obj, *ptr);
                if (vec != 0) {
                    vec[2] = zero;
                    vec[0] = zero;
                }
                ptr++;
            }
            player = Obj_GetPlayerObject();
            *(int *)&((BaddieState *)p2)->targetObj = player;
            tmp2A = sub->unk30;
            tmp2B = sub->unk2C;
            q = sub->msgStack;
            msgC[0] = sub->unk28;
            msgC[1] = tmp2B;
            msgC[2] = tmp2A;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgC);
            }
            q = sub->msgStack;
            msgD[0] = 2;
            msgD[1] = 0;
            msgD[2] = 0;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgD);
            }
            sub->unk34 = 1;
        }
    }
    if (((u32)sub->flags44 >> 6 & 1) != 0) {
        ptr = seqFn_800394a0();
        q = 1;
        ptr = ptr + 1;
        zero = 0;
        for (; q < 9; q++) {
            vec = objModelGetVecFn_800395d8(obj, *ptr);
            if (vec != 0) {
                vec[2] = zero;
                vec[0] = zero;
            }
            ptr++;
        }
    } else if (*(void **)&sub->linkedObj == NULL) {
        d = -(lbl_803E6328 * ((BaddieState *)p2)->animSpeedA);
        flag = -(lbl_803E6328 * ((BaddieState *)p2)->animSpeedB);
        d = (s16)d;
        if (d < -0x500) {
            d = -0x500;
        } else if (d > 0x500) {
            d = 0x500;
        }
        sa = d;
        flag = (s16)flag;
        if (flag < -0x500) {
            flag = -0x500;
        } else if (flag > 0x500) {
            flag = 0x500;
        }
        sb = flag;
        ptr = seqFn_800394a0();
        q = 1;
        ptr = ptr + 1;
        for (; q < 9; q++) {
            vec = objModelGetVecFn_800395d8(obj, *ptr);
            if (vec != 0) {
                vec[2] = sb;
                vec[0] = sa;
            }
            ptr++;
        }
    }
    ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)((int)obj, ((BaddieState *)p2)->animSpeedA,
                                 (float *)(p2 + 0x2a0));
    return 0;
}

#pragma opt_loop_invariants off
void dbstealerworm_update(u8 *objp)
{
    extern void Stack_Push(int sp, int *args);
    extern int allocModelStruct_800139e8(int, int);
    extern uint GameBit_Get(int);
    extern void ObjGroup_AddObject(int, int);
    extern int ObjMsg_Pop(int, u32 *, int *, int *);
    extern void ObjMsg_SendToObject(int, int, int, int);
    extern f32 sqrtf(f32);
    extern MapEventInterface **gMapEventInterface;
    extern void **gBaddieControlInterface;
    extern int *gPlayerInterface;
    extern f32 timeDelta;
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E62FC;
    extern f32 lbl_803E6388;
    extern f32 lbl_803E638C;
    extern u8 lbl_803AD0C0[];
    extern u8 lbl_803293B8[];
    char *st = (char *)lbl_803AD0C0;
    char *tbl = (char *)lbl_803293B8;
    int blob = *(int *)(objp + 0xb8);
    int data = *(int *)(objp + 0x4c);
    int sub = *(int *)&((GroundBaddieState *)blob)->control;
    int obj = (int)objp;
    int off;
    char *entry;
    int n;
    int sub2;
    int sub3;
    int t;
    struct {
        u32 msg;
        int argA;
        int argB;
        f32 v[3];
    } stk;

    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
    if ((u32)((DbStealerwormControl *)sub)->flags44 >> 4 & 1) {
        entry = (char *)((int)(tbl + *(s16 *)(data + 0x24) * 8) + 0x15c);
        ((DbStealerwormControl *)sub)->msgStack = allocModelStruct_800139e8(0x14, 0xc);
        n = *(s16 *)(entry + 4);
        off = n * 0xc;
        for (; n != 0; n--) {
            Stack_Push(((DbStealerwormControl *)sub)->msgStack, (int *)(*(int *)entry + (off -= 12)));
        }
        ((DbStealerwormControl *)sub)->unk34 = 1;
        ((AnimFlags44 *)&((DbStealerwormControl *)sub)->flags44)->flag10 = 0;
    }
    if (GameBit_Get(((GroundBaddieState *)blob)->gameBitC) != 0) {
        if (((GameObject *)obj)->unkF4 != 0) {
            if ((((GroundBaddieState *)blob)->configFlags & 4) == 0 &&
                (*gMapEventInterface)->isTimedEventActive(*(int *)(data + 0x14)) != 0) {
                ((void (*)(int, int, int, int, int, int, int, f32))((void **)*gBaddieControlInterface)[22])(obj, data, blob, 0x10, 7, 0x10a, 0x26, lbl_803E62FC);
                ObjGroup_AddObject(obj, 3);
                ((GroundBaddieState *)blob)->targetState = 0;
                ObjAnim_SetCurrentMove((int)obj, 8, lbl_803E62A8, 0x10);
                ((GroundBaddieState *)blob)->baddie.moveDone = 0;
                ((GameObject *)obj)->anim.alpha = 0xff;
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
            }
        } else if (((GameObject *)obj)->unkF8 == 0) {
            ((GameObject *)obj)->anim.localPosX = *(f32 *)(data + 8);
            ((GameObject *)obj)->anim.localPosY = *(f32 *)(data + 0xc);
            ((GameObject *)obj)->anim.localPosZ = *(f32 *)(data + 0x10);
            (*gObjectTriggerInterface)->runSequence(*(s8 *)(data + 0x2e), (void *)obj, -1);
            ((GameObject *)obj)->unkF8 = 1;
        } else {
            if (((int (*)(int, int, int))((void **)*gBaddieControlInterface)[12])(obj, blob, 0) == 0) {
                ((GroundBaddieState *)blob)->targetState = 0;
            } else {
                t = *(int *)&((GroundBaddieState *)blob)->baddie.targetObj;
                if (*(void **)&((GroundBaddieState *)blob)->baddie.targetObj != NULL) {
                    stk.v[0] = *(f32 *)(t + 0x18) - ((GameObject *)obj)->anim.worldPosX;
                    stk.v[1] = *(f32 *)(t + 0x1c) - ((GameObject *)obj)->anim.worldPosY;
                    stk.v[2] = *(f32 *)(t + 0x20) - ((GameObject *)obj)->anim.worldPosZ;
                    ((GroundBaddieState *)blob)->baddie.targetDistance = sqrtf(stk.v[2] * stk.v[2] + (stk.v[0] * stk.v[0] + stk.v[1] * stk.v[1]));
                }
                stk.msg = 0;
                stk.argA = 0;
                sub2 = *(int *)(*(int *)&((GameObject *)obj)->extra + 0x40c);
                while (ObjMsg_Pop(obj, &stk.msg, &stk.argB, &stk.argA) != 0) {
                    if (stk.msg == 0x11 && ((DbStealerwormControl *)sub2)->unk1C != -1) {
                        ObjMsg_SendToObject(((DbStealerwormControl *)sub2)->linkedObj, 0x11, obj, 0x14);
                        ((DbStealerwormControl *)sub2)->linkedObj = 0;
                        ((DbStealerwormControl *)sub2)->unk1C = -1;
                        ObjAnim_SetCurrentMove((int)obj, 0xf, lbl_803E62A8, 0);
                    }
                }
                if (((int (*)(int, int, int, int, char *, char *, int, char *))((void **)*gBaddieControlInterface)[20])(obj, blob, blob + 0x35c, ((GroundBaddieState *)blob)->gameBitB, tbl + 0x2ac, tbl + 0x324, 1, st) != 0) {
                    *(f32 *)(st + 0xc) = ((GameObject *)obj)->anim.localPosX;
                    *(f32 *)(st + 0x10) = ((GameObject *)obj)->anim.localPosY;
                    ((GroundBaddieState *)st)->baddie.posX = ((GameObject *)obj)->anim.localPosZ;
                    objLightFn_8009a1dc((void *)obj, lbl_803E638C, st, 1, 0);
                }
                if (((GroundBaddieState *)blob)->targetState == 0) {
                    fn_80203144(obj, blob, blob);
                } else {
                    sub3 = *(int *)&((GroundBaddieState *)blob)->control;
                    fn_80203000(obj, blob);
                    ((void (*)(int, int, f32, int))((void **)*gBaddieControlInterface)[11])(obj, blob, lbl_803E6388, -1);
                    if ((((DbStealerwormControl *)sub3)->flags15 & 4) == 0) {
                        ((void (*)(int, int, f32, int))((void **)*(int *)gPlayerInterface)[12])(obj, blob, timeDelta, 4);
                    }
                    ((GroundBaddieState *)blob)->savedObjC0 = *(int *)&((GameObject *)obj)->unkC0;
                    *(int *)&((GameObject *)obj)->unkC0 = 0;
                    ((void (*)(int, int, f32, f32, int, int))((void **)*(int *)gPlayerInterface)[2])(obj, blob, timeDelta, timeDelta, (int)(st + 0x34), (int)(st + 0x18));
                    *(int *)&((GameObject *)obj)->unkC0 = ((GroundBaddieState *)blob)->savedObjC0;
                }
            }
        }
    }
}
#pragma opt_loop_invariants reset

int dbstealerworm_stateHandlerA08(int obj, int p2, f32 t)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int *args);
    extern void ObjHits_EnableObject(int);
    extern void ObjHits_ClearHitVolumes(int);
    extern int Obj_GetPlayerObject(void);
    extern int Obj_GetYawDeltaToObject(int, int, f32 *);
    extern int *seqFn_800394a0(void);
    extern s16 *objModelGetVecFn_800395d8(int, int);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E62CC;
    extern f32 lbl_803E62D0;
    extern f32 lbl_803E62B4;
    extern f32 lbl_803E62F4;
    extern f32 lbl_803E6300;
    extern f32 lbl_803E6324;
    extern f32 lbl_803E6328;
    extern int lbl_803296FC[];
    extern f32 lbl_8032970C[];
    GroundBaddieState *blob = ((GameObject *)obj)->extra;
    DbStealerwormControl *sub = (DbStealerwormControl *)blob->control;
    s16 h;
    int q;
    int *ptr;
    int tmpB;
    int tmpA;
    int tmp2B;
    int tmp2A;
    int player;
    int flag;
    int d;
    int zero;
    s16 *vec;
    s16 sa;
    s16 sb;
    f32 frac;
    int msgA[3];
    int msgB[3];
    int msgC[3];
    int msgD[3];
    f32 yawf;

    sub->flags14 |= 2;
    sub->flags15 &= ~4;
    if (*(s8 *)&((BaddieState *)p2)->moveJustStartedA != 0) {
        ObjHits_EnableObject(obj);
        ObjHits_ClearHitVolumes(obj);
    }
    ((BaddieState *)p2)->moveSpeed = lbl_803E62F4;
    if (*(void **)&sub->linkedObj == NULL) {
        h = sub->unk1C;
        if (h != -1) {
            tmpA = sub->unk30;
            tmpB = sub->unk2C;
            q = sub->msgStack;
            msgA[0] = sub->unk28;
            msgA[1] = tmpB;
            msgA[2] = tmpA;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgA);
            }
            q = sub->msgStack;
            msgB[0] = 9;
            msgB[1] = 0;
            msgB[2] = h;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgB);
            }
            sub->unk34 = 1;
            sub->unk1C = -1;
        }
    } else {
        if (*(s8 *)&((BaddieState *)p2)->moveJustStartedA != 0) {
            ObjAnim_SetCurrentMove((int)obj, 0x11, lbl_803E62A8, 0);
            ((BaddieState *)p2)->moveDone = 0;
        }
        ((BaddieState *)p2)->moveSpeed = lbl_803E6300;
        frac = (f32)blob->aggression / lbl_803E6324;
    }
    ((BaddieState *)p2)->unk34D = 0x1f;
    if (fn_80202C78(obj, *(int *)&((BaddieState *)p2)->targetObj, lbl_803E62B4, frac, lbl_803E62CC, t) != 0) {
        sub->unk34 = 1;
    }
    if (((u32)sub->flags44 >> 5 & 1) != 0) {
        fn_80202A2C(obj, lbl_803296FC, lbl_8032970C, 4, frac);
    } else if (*(void **)&sub->linkedObj == NULL) {
        player = Obj_GetPlayerObject();
        d = (s16)Obj_GetYawDeltaToObject(obj, player, &yawf);
        flag = 0;
        if (d >= 0) {
        } else {
            d = -d;
        }
        if (d < 0x1c71 && yawf < lbl_803E62D0) {
            flag = 1;
        }
        if (flag != 0) {
            ptr = seqFn_800394a0();
            q = 1;
            ptr = ptr + 1;
            zero = 0;
            for (; q < 9; q++) {
                vec = objModelGetVecFn_800395d8(obj, *ptr);
                if (vec != 0) {
                    vec[2] = zero;
                    vec[0] = zero;
                }
                ptr++;
            }
            player = Obj_GetPlayerObject();
            *(int *)&((BaddieState *)p2)->targetObj = player;
            tmp2A = sub->unk30;
            tmp2B = sub->unk2C;
            q = sub->msgStack;
            msgC[0] = sub->unk28;
            msgC[1] = tmp2B;
            msgC[2] = tmp2A;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgC);
            }
            q = sub->msgStack;
            msgD[0] = 2;
            msgD[1] = 0;
            msgD[2] = 0;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgD);
            }
            sub->unk34 = 1;
        }
    }
    if (((u32)sub->flags44 >> 6 & 1) != 0) {
        ptr = seqFn_800394a0();
        q = 1;
        ptr = ptr + 1;
        zero = 0;
        for (; q < 9; q++) {
            vec = objModelGetVecFn_800395d8(obj, *ptr);
            if (vec != 0) {
                vec[2] = zero;
                vec[0] = zero;
            }
            ptr++;
        }
    } else if (*(void **)&sub->linkedObj == NULL) {
        d = -(lbl_803E6328 * ((BaddieState *)p2)->animSpeedA);
        flag = -(lbl_803E6328 * ((BaddieState *)p2)->animSpeedB);
        d = (s16)d;
        if (d < -0x500) {
            d = -0x500;
        } else if (d > 0x500) {
            d = 0x500;
        }
        sa = d;
        flag = (s16)flag;
        if (flag < -0x500) {
            flag = -0x500;
        } else if (flag > 0x500) {
            flag = 0x500;
        }
        sb = flag;
        ptr = seqFn_800394a0();
        q = 1;
        ptr = ptr + 1;
        for (; q < 9; q++) {
            vec = objModelGetVecFn_800395d8(obj, *ptr);
            if (vec != 0) {
                vec[2] = sb;
                vec[0] = sa;
            }
            ptr++;
        }
    }
    ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)((int)obj, ((BaddieState *)p2)->animSpeedA,
                                 (float *)(p2 + 0x2a0));
    return 0;
}

void fn_80204BF8(int obj)
{
    extern int Obj_GetPlayerObject(void);
    extern uint GameBit_Get(int);
    extern f32 Vec_xzDistance(int, int);
    extern int Sfx_IsPlayingFromObjectChannel(int, int);
    extern void Sfx_PlayFromObject(int, int);
    extern void Sfx_StopObjectChannel(int, int);
    extern f32 timeDelta;
    extern f32 lbl_803E639C;
    extern f32 lbl_803E63A0;
    extern f32 lbl_803E63A4;
    extern f32 lbl_803E63A8;
    int data = *(int *)&((GameObject *)obj)->anim.placementData;
    Dll22CState *blob = ((GameObject *)obj)->extra;
    int player;
    int h;
    f32 d;
    f32 k;

    player = Obj_GetPlayerObject();
    if ((u32)player == 0) {
        return;
    }
    switch (blob->mode) {
    case 0:
        if (GameBit_Get(blob->gameBit) != 0 && blob->unk0C != 1) {
            if (Vec_xzDistance(obj + 0x18, player + 0x18) < lbl_803E639C) {
                if (((GameObject *)obj)->anim.localPosY < lbl_803E63A0 + *(f32 *)(data + 0xc)) {
                    if (Sfx_IsPlayingFromObjectChannel(obj, 8) == 0) {
                        Sfx_PlayFromObject(obj, 0x116);
                        blob->sfxLatch = 1;
                    }
                    ((GameObject *)obj)->anim.localPosY += timeDelta;
                    if (((GameObject *)obj)->anim.localPosY >= lbl_803E63A0 + *(f32 *)(data + 0xc)) {
                        ((GameObject *)obj)->anim.localPosY = lbl_803E63A0 + *(f32 *)(data + 0xc);
                        blob->mode = 1;
                        Sfx_StopObjectChannel(obj, 8);
                    }
                }
            }
        } else {
            if (blob->unk0C == 1) {
                if (Vec_xzDistance(obj + 0x18, player + 0x18) < lbl_803E639C) {
                    if (((GameObject *)obj)->anim.localPosY < (k = lbl_803E63A0) + *(f32 *)(data + 0xc)) {
                        ((GameObject *)obj)->anim.localPosY += timeDelta;
                        if (((GameObject *)obj)->anim.localPosY >= k + *(f32 *)(data + 0xc)) {
                            ((GameObject *)obj)->anim.localPosY = k + *(f32 *)(data + 0xc);
                            blob->mode = 1;
                        }
                    }
                }
            }
        }
        break;
    case 1:
        blob->mode = 2;
        blob->pauseTimer = 0x64;
        break;
    case 2:
        h = blob->pauseTimer;
        if (h != 0) {
            blob->pauseTimer = h - (int)timeDelta;
            if (blob->pauseTimer <= 0) {
                blob->pauseTimer = 0;
            }
        } else {
            d = Vec_xzDistance(obj + 0x18, player + 0x18);
            if (d < lbl_803E63A4) {
                if (((GameObject *)obj)->anim.localPosY == lbl_803E63A0 + *(f32 *)(data + 0xc)) {
                    blob->mode = 3;
                    if (Sfx_IsPlayingFromObjectChannel(obj, 8) == 0) {
                        Sfx_PlayFromObject(obj, 0x1cb);
                        blob->sfxLatch = 1;
                    }
                } else if (((GameObject *)obj)->anim.localPosY == d - lbl_803E63A8) {
                    blob->mode = 4;
                    if (Sfx_IsPlayingFromObjectChannel(obj, 8) == 0) {
                        Sfx_PlayFromObject(obj, 0x1cb);
                        blob->sfxLatch = 1;
                    }
                }
            } else {
                if (*(f32 *)(player + 0x10) < *(f32 *)(data + 0xc)) {
                    blob->mode = 3;
                    if (blob->sfxLatch == 1) {
                        blob->sfxLatch = 0;
                    }
                } else if (*(f32 *)(player + 0x10) > *(f32 *)(data + 0xc)) {
                    blob->mode = 4;
                    if (blob->sfxLatch == 1) {
                        blob->sfxLatch = 0;
                    }
                }
            }
        }
        break;
    case 3:
        if (((GameObject *)obj)->anim.localPosY > *(f32 *)(data + 0xc) - (k = lbl_803E63A8)) {
            ((GameObject *)obj)->anim.localPosY -= timeDelta;
            if (((GameObject *)obj)->anim.localPosY <= *(f32 *)(data + 0xc) - k) {
                ((GameObject *)obj)->anim.localPosY = *(f32 *)(data + 0xc) - k;
                blob->mode = 2;
                Sfx_StopObjectChannel(obj, 8);
                blob->pauseTimer = 0x64;
            }
            Vec_xzDistance(obj + 0x18, player + 0x18);
        } else {
            Sfx_StopObjectChannel(obj, 8);
            Vec_xzDistance(obj + 0x18, player + 0x18);
            blob->mode = 2;
            blob->pauseTimer = 0x64;
        }
        break;
    case 4:
        if (((GameObject *)obj)->anim.localPosY < (k = lbl_803E63A0) + *(f32 *)(data + 0xc)) {
            ((GameObject *)obj)->anim.localPosY += timeDelta;
            if (((GameObject *)obj)->anim.localPosY >= k + *(f32 *)(data + 0xc)) {
                ((GameObject *)obj)->anim.localPosY = k + *(f32 *)(data + 0xc);
                blob->mode = 2;
                blob->pauseTimer = 0x64;
                Sfx_StopObjectChannel(obj, 8);
            }
            Vec_xzDistance(obj + 0x18, player + 0x18);
        } else {
            blob->mode = 2;
            blob->pauseTimer = 0x64;
            Sfx_StopObjectChannel(obj, 8);
            Vec_xzDistance(obj + 0x18, player + 0x18);
        }
        break;
    }
}

int dbstealerworm_stateHandlerA0C(int obj, int p2, f32 t)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int *args);
    extern void fn_80137948(char *, ...);
    extern int Obj_GetPlayerObject(void);
    extern int *ObjGroup_GetObjects(int, int *);
    extern f32 Vec_xzDistance(int, int);
    extern f32 vec3f_distanceSquared(int, int);
    extern f32 sqrtf(f32);
    extern int randomGetRange(int, int);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E62B0;
    extern f32 lbl_803E62B8;
    extern f32 lbl_803E6300;
    extern f32 lbl_803E6304;
    extern f32 lbl_803E6308;
    extern f32 lbl_803E630C;
    extern f32 lbl_803E62CC;
    extern u8 lbl_803293B8[];
    char *tbl = (char *)lbl_803293B8;
    GroundBaddieState *blob = ((GameObject *)obj)->extra;
    DbStealerwormControl *sub = (DbStealerwormControl *)blob->control;
    int c30 = sub->unk30;
    s16 h;
    int n;
    int q;
    int *objs;
    int player;
    int o;
    int best;
    int i;
    int tmpB;
    int tmpA;
    f32 frac;
    f32 ratio;
    f32 ds;
    f32 bestD;
    int msg0[3];
    int msgA[3];
    int msgB[3];
    int msgC[3];
    int cnt;

    sub->flags15 &= ~4;
    sub->flags14 |= 2;
    fn_80137948(tbl + 0x430, sub->unk3C, sub->linkedObj);
    if (*(void **)&sub->unk3C == NULL) {
        player = Obj_GetPlayerObject();
        q = sub->msgStack;
        msg0[0] = 0xf;
        msg0[1] = 1;
        msg0[2] = player;
        if (Stack_IsFull(q) == 0) {
            Stack_Push(q, msg0);
        }
        sub->unk34 = 1;
        return 0;
    }
    if (*(s8 *)&((BaddieState *)p2)->moveJustStartedA != 0) {
        ObjAnim_SetCurrentMove((int)obj, 0x11, lbl_803E62A8, 0);
        ((BaddieState *)p2)->moveDone = 0;
    }
    ((BaddieState *)p2)->moveSpeed = lbl_803E6300;
    frac = (f32)blob->aggression / lbl_803E62B8;
    if (*(void **)&sub->linkedObj == NULL) {
        h = sub->unk1C;
        if (h != -1) {
            tmpA = sub->unk30;
            tmpB = sub->unk2C;
            q = sub->msgStack;
            msgA[0] = sub->unk28;
            msgA[1] = tmpB;
            msgA[2] = tmpA;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgA);
            }
            q = sub->msgStack;
            msgB[0] = 9;
            msgB[1] = 0;
            msgB[2] = h;
            if (Stack_IsFull(q) == 0) {
                Stack_Push(q, msgB);
            }
            sub->unk34 = 1;
            sub->unk1C = -1;
        }
    }
    if (((u32)sub->flags44 >> 5 & 1) != 0) {
        fn_80202A2C(obj, (int *)(tbl + 0x344), (f32 *)(tbl + 0x354), 4, frac);
    }
    player = Obj_GetPlayerObject();
    ratio = (Vec_xzDistance(obj + 0x18, player + 0x18) - lbl_803E6304) / (lbl_803E6308 * (f32)blob->aggression);
    n = (int)(ratio < lbl_803E62A8 ? lbl_803E62A8 : (ratio > lbl_803E62B0 ? lbl_803E62B0 : ratio));
    fn_80137948(tbl + 0x444, n);
    player = Obj_GetPlayerObject();
    best = 0;
    bestD = lbl_803E62A8;
    objs = ObjGroup_GetObjects(c30, &cnt);
    for (i = 0; i < cnt; i++) {
        o = *objs;
        if ((u32)o != (u32)player) {
            ds = vec3f_distanceSquared(player + 0x18, o + 0x18);
            if (ds > bestD) {
                bestD = ds;
                best = *objs;
            }
        }
        objs++;
    }
    if ((u32)best != 0) {
        sqrtf(bestD);
    }
    if ((u32)best != 0) {
        if ((u32)best != (u32)obj) {
            if (*(s16 *)(best + 0x46) == 0x539) {
                *(int *)&((BaddieState *)p2)->targetObj = best;
                if (randomGetRange(0, n) == 0) {
                    if ((**(int (**)(int, int, int))(*(int *)(*(int *)(best + 0x68)) + 0x24))(best, 0x82, sub->linkedObj) != 0) {
                        sub->unk3C = 0;
                        q = sub->msgStack;
                        msgC[0] = 0xa;
                        msgC[1] = 1;
                        msgC[2] = best;
                        if (Stack_IsFull(q) == 0) {
                            Stack_Push(q, msgC);
                        }
                        sub->unk34 = 1;
                    }
                } else {
                    fn_80202C78(obj, best, lbl_803E630C, frac, lbl_803E62CC, t);
                }
            }
        }
    }
    return 0;
}

void chuka_update(int obj)
{
    extern int *ObjList_GetObjects(int *, int *);
    extern uint GameBit_Get(int);
    extern void Obj_SetActiveModelIndex(int, int);
    extern u8 gChukaModeTable[];
    extern f32 lbl_803E63F8;
    extern f32 lbl_803E63FC;
    int data = *(int *)&((GameObject *)obj)->anim.placementData;
    int blob = *(int *)&((GameObject *)obj)->extra;
    int ch;
    int *base;
    int i;
    int o;
    int h;
    int idx;
    int cnt;
    ObjAnimComponent *objAnim = (ObjAnimComponent *)obj;

    ch = ((ChukaState *)blob)->linkedObject;
    if ((u32)ch != 0) {
        if (*(s16 *)(ch + 6) & 0x40) {
            ((ChukaState *)blob)->linkedObject = 0;
            return;
        }
    }
    if (*(void **)&((ChukaState *)blob)->linkedObject == NULL) {
        base = ObjList_GetObjects(&idx, &cnt);
        for (i = idx; i < cnt; i++) {
            o = base[i];
            if (*(s16 *)(o + 0x46) == 0x431) {
                ((ChukaState *)blob)->linkedObject = o;
                i = cnt;
            }
        }
        if (*(void **)&((ChukaState *)blob)->linkedObject == NULL) {
            return;
        }
    }
    ch = ((ChukaState *)blob)->linkedObject;
    (**(void (**)(int, u8 *))(*(int *)(*(int *)(ch + 0x68)) + 0x20))(ch, gChukaModeTable);
    if (GameBit_Get(0x5e4) == 0) {
        ((ChukaState *)blob)->mode = 0;
    } else {
        ((ChukaState *)blob)->mode = gChukaModeTable[((ChukaState *)blob)->modeIndex];
    }
    switch (((ChukaState *)blob)->mode) {
    case 0:
        if (objAnim->bankIndex != 0) {
            Obj_SetActiveModelIndex(obj, 0);
        }
        h = ((ChukaPlacement *)data)->unk1C;
        if (h != 0) {
            ((GameObject *)obj)->anim.rootMotionScale = lbl_803E63F8 / ((f32)h / lbl_803E63FC);
        }
        break;
    case 1:
        if (objAnim->bankIndex != 1) {
            Obj_SetActiveModelIndex(obj, 1);
        }
        h = ((ChukaPlacement *)data)->unk1C;
        if (h != 0) {
            ((GameObject *)obj)->anim.rootMotionScale = lbl_803E63F8 / ((f32)h / lbl_803E63FC);
        }
        if (((GameObject *)obj)->anim.rotZ != 0) {
            ((GameObject *)obj)->anim.rotZ = 0;
        }
        break;
    case 2:
        if (objAnim->bankIndex != 2) {
            Obj_SetActiveModelIndex(obj, 2);
        }
        h = ((ChukaPlacement *)data)->unk1C;
        if (h != 0) {
            ((GameObject *)obj)->anim.rootMotionScale = lbl_803E63F8 / ((f32)h / lbl_803E63FC);
        }
        if (((GameObject *)obj)->anim.rotZ != 0) {
            ((GameObject *)obj)->anim.rotZ = 0;
        }
        break;
    case 3:
        if (objAnim->bankIndex != 2) {
            Obj_SetActiveModelIndex(obj, 2);
        }
        h = ((ChukaPlacement *)data)->unk1C;
        if (h != 0) {
            ((GameObject *)obj)->anim.rootMotionScale = lbl_803E63F8 / ((f32)h / lbl_803E63FC);
        }
        if (((GameObject *)obj)->anim.rotZ != 0x3fff) {
            ((GameObject *)obj)->anim.rotZ = 0x7fff;
        }
        break;
    case 4:
        if (objAnim->bankIndex != 1) {
            Obj_SetActiveModelIndex(obj, 1);
        }
        h = ((ChukaPlacement *)data)->unk1C;
        if (h != 0) {
            ((GameObject *)obj)->anim.rootMotionScale = lbl_803E63F8 / ((f32)h / lbl_803E63FC);
        }
        if (((GameObject *)obj)->anim.rotZ != 0x3fff) {
            ((GameObject *)obj)->anim.rotZ = 0x7fff;
        }
        break;
    default:
        if (objAnim->bankIndex != 0) {
            Obj_SetActiveModelIndex(obj, 0);
        }
        h = ((ChukaPlacement *)data)->unk1C;
        if (h != 0) {
            ((GameObject *)obj)->anim.rootMotionScale = lbl_803E63F8 / ((f32)h / lbl_803E63FC);
        }
        if (((GameObject *)obj)->anim.rotZ != 0) {
            ((GameObject *)obj)->anim.rotZ = 0;
        }
        break;
    }
}

void DFP_Torch_update(int obj)
{
    extern void Sfx_PlayFromObject(int, int);
    extern void Sfx_StopObjectChannel(int, int);
    extern void objUpdateOpacity(int);
    extern int ObjHits_GetPriorityHit(int, int, int, int);
    extern uint GameBit_Get(int);
    extern void GameBit_Set(int, int);
    extern u8 lbl_803DDCE8;
    extern f32 timeDelta;
    extern f32 lbl_803E63E0;
    extern int lbl_802C2510[];
    typedef struct {
        int m0;
        int m1;
        int m2;
        int m3;
    } TorchPrm;
    DfpTorchState *blob = ((GameObject *)obj)->extra;
    void *res;
    int h;
    int i;
    f32 buf[5];
    TorchPrm prm;

    prm = *(TorchPrm *)lbl_802C2510;
    Sfx_PlayFromObject(obj, 0x72);
    objUpdateOpacity(obj);
    switch (blob->mode) {
    case 0:
        break;
    case 1:
        buf[4] = lbl_803E63E0;
        blob->prevLit = blob->lit;
        if (ObjHits_GetPriorityHit(obj, 0, 0, 0) != 0) {
            blob->lit = 1 - blob->lit;
            if (blob->lit != 0) {
                blob->litTimer = 0x7d0;
            }
        }
        if (blob->lit != 0) {
            h = blob->litTimer;
            if (h != 0) {
                blob->litTimer = h - (int)timeDelta;
                if (blob->litTimer <= 0) {
                    blob->litTimer = 0;
                    blob->lit = 0;
                }
            }
        }
        if (blob->lit != 0 && blob->flickerTimer <= 0 && blob->sfxPending != 0) {
            blob->sfxPending = 0;
            Sfx_PlayFromObject(obj, 0x80);
        }
        if (blob->lit != blob->prevLit) {
            if (blob->lit != 0) {
                res = Resource_Acquire(0x69, 1);
                prm.m1 = blob->colorIdx * 2 + 0x19d;
                prm.m2 = blob->colorIdx * 2 + 0x19e;
                (*(void (*)(int, int, f32 *, int, int, void *))(*(int *)(*(int *)res + 4)))(obj, 1, buf, 0x10004, -1, &prm);
                Resource_Release(res);
                for (i = 0; i < 0x64; i++) {
                    (*gPartfxInterface)->spawnObject((void *)obj, 0x1a3, NULL, 0, -1,
                                                     NULL);
                }
                if (blob->gameBit != -1) {
                    if (GameBit_Get(blob->gameBit) == 0) {
                        GameBit_Set(blob->gameBit, 1);
                    }
                }
                if ((s8)lbl_803DDCE8 == 0 && blob->colorIdx == 0 && GameBit_Get(blob->gameBit) != 0) {
                    lbl_803DDCE8 = 1;
                }
                if ((s8)lbl_803DDCE8 == 1 && blob->colorIdx == 1 && GameBit_Get(blob->gameBit) != 0) {
                    GameBit_Set(0x5e2, 1);
                    lbl_803DDCE8 = 2;
                }
                blob->sfxPending = 1;
                blob->flickerTimer = 1;
            } else {
                Sfx_StopObjectChannel(obj, 0x40);
                (*gModgfxInterface)->detachSource((void *)obj);
                (*gExpgfxInterface)->freeSource((u32)obj);
                if (blob->gameBit != -1) {
                    if (GameBit_Get(blob->gameBit) != 0) {
                        GameBit_Set(blob->gameBit, 0);
                    }
                }
                if ((s8)lbl_803DDCE8 == 1 && blob->colorIdx == 0) {
                    lbl_803DDCE8 = 0;
                }
                if ((s8)lbl_803DDCE8 == 2 && blob->colorIdx == 1 && GameBit_Get(0x5e2) == 0) {
                    GameBit_Set(0x5e2, 0);
                    lbl_803DDCE8 = 0;
                }
            }
        }
        break;
    }
}

void drakorenergy_update(int obj)
{
    extern int Obj_GetPlayerObject(void);
    extern uint GameBit_Get(int);
    extern void objMove(int, f32, f32, f32);
    extern f32 Vec_distance(int, int);
    extern f32 Vec_xzDistance(int, int);
    extern void playerAddHealth(int, int);
    extern void Sfx_PlayFromObject(int, int);
    extern f32 mathSinf(f32);
    extern void fn_80221C18(int, int, f32 *, f32);
    extern void PSVECSubtract(f32 *, f32 *, f32 *);
    extern void PSVECNormalize(f32 *, f32 *);
    extern void PSVECScale(f32 *, f32 *, f32);
    extern void objfx_spawnFlaggedTrailBurst(int, f32, int, int, int, int);
    extern f32 timeDelta;
    extern u8 framesThisStep;
    extern f32 lbl_803E627C;
    extern f32 lbl_803E6280;
    extern f32 lbl_803E6284;
    extern f32 lbl_803E6288;
    extern f32 lbl_803E628C;
    extern f32 lbl_803E6290;
    extern f32 lbl_803E6294;
    extern f32 lbl_803DC160;
    extern f32 lbl_803DC164;
    extern f32 lbl_803DC168;
    extern f32 lbl_803DC16C;
    extern int lbl_803DC170;
    extern f32 lbl_803DC174;
    extern s16 lbl_803DC178;
    int blob = *(int *)&((GameObject *)obj)->extra;
    int data;
    int player;
    f32 v;
    f32 dist;
    f32 spd;
    f32 v1[3];
    f32 v2[3];
    s16 trio[12];

    player = Obj_GetPlayerObject();
    data = *(int *)&((GameObject *)obj)->anim.placementData;
    switch (((DrakorEnergyState *)blob)->mode) {
    case 0:
        if (GameBit_Get(((DrakorenergyPlacement *)data)->unk20) == 1) {
            ((DrakorEnergyState *)blob)->mode = 2;
        }
        break;
    case 1:
        if (((DrakorEnergyState *)blob)->startY - ((GameObject *)obj)->anim.localPosY > (v = lbl_803E627C)) {
            ((GameObject *)obj)->anim.velocityY = lbl_803E6280 * -((GameObject *)obj)->anim.velocityY;
            dist = ((GameObject *)obj)->anim.velocityY;
            dist = dist >= v ? -dist : dist;
            if (dist < lbl_803E6284) {
                ((DrakorEnergyState *)blob)->mode = 2;
                ((GameObject *)obj)->anim.velocityX = lbl_803E627C;
                ((GameObject *)obj)->anim.velocityZ = lbl_803E627C;
                break;
            }
        }
        ((GameObject *)obj)->anim.velocityY += lbl_803E6288;
        objMove(obj, ((GameObject *)obj)->anim.velocityX, ((GameObject *)obj)->anim.velocityY, ((GameObject *)obj)->anim.velocityZ);
        trio[2] = 0xff;
        trio[1] = 0xff - ((DrakorEnergyState *)blob)->phase % 0x500;
        trio[0] = 0xff;
        (*gPartfxInterface)->spawnObject((void *)obj, 0x357, trio, 0, -1, NULL);
        break;
    case 2:
        ((GameObject *)obj)->anim.velocityY = lbl_803DC160 * mathSinf(lbl_803E628C * (f32)((DrakorEnergyState *)blob)->phase / lbl_803E6290);
        objMove(obj, ((GameObject *)obj)->anim.velocityX, ((GameObject *)obj)->anim.velocityY, ((GameObject *)obj)->anim.velocityZ);
        if (Vec_distance(obj + 0x18, player + 0x18) < lbl_803DC164) {
            ((DrakorEnergyState *)blob)->mode = 3;
        }
        objfx_spawnFlaggedTrailBurst(obj, lbl_803DC174, 1, 0xc22, 0x14, obj + 0x24);
        break;
    case 3:
        dist = Vec_xzDistance(obj + 0x18, player + 0x18);
        if (dist < lbl_803DC168) {
            playerAddHealth(player, lbl_803DC170);
            Sfx_PlayFromObject(obj, 0x49);
            ((DrakorEnergyState *)blob)->mode = 4;
        } else {
            spd = lbl_803DC16C;
            fn_80221C18(player, obj + 0xc, v1, spd / lbl_803E6294);
            PSVECSubtract(v1, (f32 *)(obj + 0xc), v2);
            PSVECNormalize(v2, v2);
            if (dist < spd) {
                spd = dist;
            }
            PSVECScale(v2, (f32 *)(obj + 0x24), spd);
            objMove(obj, ((GameObject *)obj)->anim.velocityX * timeDelta, ((GameObject *)obj)->anim.velocityY * timeDelta, ((GameObject *)obj)->anim.velocityZ * timeDelta);
            trio[2] = 0xff;
            trio[1] = 0;
            trio[0] = 0xff;
            objfx_spawnFlaggedTrailBurst(obj, lbl_803DC174, 1, 0xc22, 0x14, obj + 0x24);
        }
        break;
    case 5:
        ((DrakorEnergyState *)blob)->mode = 0;
        break;
    }
    *(s16 *)obj += lbl_803DC178;
    ((DrakorEnergyState *)blob)->phase += framesThisStep * 0x500;
}

int dfpseqpoint_SeqFn(int obj, int p2, ObjAnimUpdateState *animUpdate)
{
    extern void unlockLevel(int a, int b, int c);
    extern int mapGetDirIdx(int);
    extern void lockLevel(int, int);
    extern void warpToMap(int, int);
    extern MapEventInterface **gMapEventInterface;
    int blob = *(int *)&((GameObject *)obj)->extra;
    int data = *(int *)&((GameObject *)obj)->anim.placementData;
    int i;

    animUpdate->activeHitVolumePair = -1;
    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < animUpdate->eventCount; i++) {
        switch (((DfpSeqPointState *)blob)->triggerId) {
        case 1:
            if (animUpdate->eventIds[i] == 1) {
                if ((*gMapEventInterface)->getMode(((GameObject *)obj)->anim.mapEventSlot) == 1) {
                    (*gMapEventInterface)->setAnimEvent(((GameObject *)obj)->anim.mapEventSlot, 5, 0);
                    (*gMapEventInterface)->setAnimEvent(((GameObject *)obj)->anim.mapEventSlot, 6, 0);
                    (*gMapEventInterface)->setAnimEvent(((GameObject *)obj)->anim.mapEventSlot, 7, 0);
                } else if ((*gMapEventInterface)->getMode(((GameObject *)obj)->anim.mapEventSlot) == 2) {
                    (*gMapEventInterface)->setAnimEvent(((GameObject *)obj)->anim.mapEventSlot, 5, 0);
                    (*gMapEventInterface)->setAnimEvent(((GameObject *)obj)->anim.mapEventSlot, 6, 0);
                    (*gMapEventInterface)->setAnimEvent(((GameObject *)obj)->anim.mapEventSlot, 7, 0);
                }
            }
            break;
        case 0xa:
            if (animUpdate->eventIds[i] == 0x14) {
                if (*(u32 *)&((DfpseqpointPlacement *)data)->unk14 == 0x49de8) {
                    ((DfpFlags7 *)&((DfpSeqPointState *)blob)->flags0F)->b80 = 1;
                } else {
                    if ((*gMapEventInterface)->getMode(((GameObject *)obj)->anim.mapEventSlot) == 1 ||
                        (*gMapEventInterface)->getMode(((GameObject *)obj)->anim.mapEventSlot) == 2) {
                        unlockLevel(0, 0, 1);
                        lockLevel(mapGetDirIdx(0x32), 0);
                        (*gMapEventInterface)->setMode(0x32, 2);
                        warpToMap(0x73, 0);
                    }
                }
            }
            break;
        }
        animUpdate->eventIds[i] = 0;
    }
    return 0;
}

void dfpseqpoint_update(int obj)
{
    extern int Obj_GetPlayerObject(void);
    extern uint GameBit_Get(int);
    extern void GameBit_Set(int, int);
    extern f32 Vec_distance(int, int);
    int player;
    int blob;
    int h;

    player = Obj_GetPlayerObject();
    blob = *(int *)&((GameObject *)obj)->extra;
    if (((u32)((DfpSeqPointState *)blob)->flags0F >> 7 & 1) != 0) {
        GameBit_Set(0xef7, 1);
        ((DfpFlags7 *)&((DfpSeqPointState *)blob)->flags0F)->b80 = 0;
    }
    h = ((DfpSeqPointState *)blob)->gameBitDone;
    if (h != -1) {
        if (((DfpSeqPointState *)blob)->doneLatch != 0) {
            if (GameBit_Get(h) != 0) {
                return;
            }
            GameBit_Set(((DfpSeqPointState *)blob)->gameBitDone, 1);
            ((DfpSeqPointState *)blob)->doneLatch = 1;
            return;
        }
        if (GameBit_Get(h) != 0) {
            ((DfpSeqPointState *)blob)->doneLatch = 1;
            return;
        }
    }
    if (((DfpSeqPointState *)blob)->doneLatch != 0) {
        return;
    }
    switch (((DfpSeqPointState *)blob)->triggerMode) {
    case 0:
        if (Vec_distance(obj + 0x18, player + 0x18) < ((DfpSeqPointState *)blob)->triggerRadius) {
            (*gObjectTriggerInterface)->runSequence(((DfpSeqPointState *)blob)->triggerId,
                                                    (void *)obj, -1);
            ((DfpSeqPointState *)blob)->doneLatch = 1;
        }
        break;
    case 1:
        h = ((DfpSeqPointState *)blob)->gameBitGate;
        if (h != -1 && GameBit_Get(h) != 0) {
            (*gObjectTriggerInterface)->runSequence(((DfpSeqPointState *)blob)->triggerId,
                                                    (void *)obj, -1);
            ((DfpSeqPointState *)blob)->doneLatch = 1;
        }
        break;
    case 2:
        if (Vec_distance(obj + 0x18, player + 0x18) < ((DfpSeqPointState *)blob)->triggerRadius) {
            h = ((DfpSeqPointState *)blob)->gameBitGate;
            if (h != -1 && GameBit_Get(h) != 0) {
                (*gObjectTriggerInterface)->runSequence(((DfpSeqPointState *)blob)->triggerId,
                                                        (void *)obj, -1);
                ((DfpSeqPointState *)blob)->doneLatch = 1;
            }
        }
        break;
    case 3:
        if (Vec_distance(obj + 0x18, player + 0x18) < ((DfpSeqPointState *)blob)->triggerRadius) {
            h = ((DfpSeqPointState *)blob)->gameBitGate;
            if (h != -1 && GameBit_Get(h) == 0) {
                (*gObjectTriggerInterface)->runSequence(((DfpSeqPointState *)blob)->triggerId,
                                                        (void *)obj, -1);
                GameBit_Set(((DfpSeqPointState *)blob)->gameBitGate, 1);
                ((DfpSeqPointState *)blob)->doneLatch = 1;
            }
        }
        break;
    case 4:
        h = ((DfpSeqPointState *)blob)->gameBitGate;
        if (h != -1 && GameBit_Get(h) == 0) {
            (*gObjectTriggerInterface)->runSequence(((DfpSeqPointState *)blob)->triggerId,
                                                    (void *)obj, -1);
            GameBit_Set(((DfpSeqPointState *)blob)->gameBitGate, 1);
            ((DfpSeqPointState *)blob)->doneLatch = 1;
        }
        break;
    case 5:
        h = ((DfpSeqPointState *)blob)->gameBitGate;
        if (h != -1 && GameBit_Get(h) != 0) {
            (*gObjectTriggerInterface)->runSequence(((DfpSeqPointState *)blob)->triggerId,
                                                    (void *)obj, -1);
        }
        break;
    }
}

int dbstealerworm_stateHandlerA0F(int obj, int p2, f32 t)
{
    extern int Stack_IsFull(int sp);
    extern void Stack_Push(int sp, int *args);
    extern f32 Vec_xzDistance(int, int);
    extern int randomGetRange(int, int);
    extern f32 lbl_803E62A8;
    extern f32 lbl_803E62C0;
    extern f32 lbl_803E62C4;
    extern f32 lbl_803E62C8;
    extern f32 lbl_803E62CC;
    extern f32 lbl_803E62D0;
    extern f32 lbl_803E62D4;
    extern f32 lbl_803E62D8;
    extern int lbl_8032973C[];
    extern f32 lbl_8032974C[];
    GroundBaddieState *blob = ((GameObject *)obj)->extra;
    DbStealerwormControl *sub = (DbStealerwormControl *)blob->control;
    int n = 0x1f40 / blob->aggression;
    int tmpA;
    int tmpB;
    int q;
    int target;
    f32 frac;
    f32 d;
    int msgA[3];
    int msgB[3];
    int msgC[3];
    int msgD[3];

    sub->flags14 |= 2;
    sub->flags15 &= ~4;
    if (*(u16 *)(*(int *)&((BaddieState *)p2)->targetObj + 0xb0) & 0x1000) {
        ((BaddieState *)p2)->animSpeedA = lbl_803E62A8;
        ((BaddieState *)p2)->animSpeedB = lbl_803E62A8;
        ((BaddieState *)p2)->moveSpeed = lbl_803E62C0;
        return 0;
    }
    frac = (f32)blob->aggression / lbl_803E62C4;
    fn_80202C78(obj, *(int *)&((BaddieState *)p2)->targetObj, lbl_803E62C8, frac, lbl_803E62CC, t);
    if (((u32)sub->flags44 >> 5 & 1) != 0) {
        fn_80202A2C(obj, lbl_8032973C, lbl_8032974C, 4, frac);
    }
    d = Vec_xzDistance(obj + 0x18, *(int *)&((BaddieState *)p2)->targetObj + 0x18);
    ((BaddieState *)p2)->unk34D = 1;
    if (d < lbl_803E62D0) {
        ((BaddieState *)p2)->animSpeedA *= lbl_803E62D4;
        ((BaddieState *)p2)->animSpeedB *= lbl_803E62D4;
        target = *(int *)&((BaddieState *)p2)->targetObj;
        tmpA = sub->unk30;
        tmpB = sub->unk2C;
        q = sub->msgStack;
        msgA[0] = sub->unk28;
        msgA[1] = tmpB;
        msgA[2] = tmpA;
        if (Stack_IsFull(q) == 0) {
            Stack_Push(q, msgA);
        }
        q = sub->msgStack;
        msgB[0] = 2;
        msgB[1] = 1;
        msgB[2] = target;
        if (Stack_IsFull(q) == 0) {
            Stack_Push(q, msgB);
        }
        sub->unk34 = 1;
        return 0;
    }
    if (d < lbl_803E62D8 && randomGetRange(0, n) == 0) {
        ((BaddieState *)p2)->animSpeedA = lbl_803E62A8;
        ((BaddieState *)p2)->animSpeedB = lbl_803E62A8;
        target = *(int *)&((BaddieState *)p2)->targetObj;
        tmpA = sub->unk30;
        tmpB = sub->unk2C;
        q = sub->msgStack;
        msgC[0] = sub->unk28;
        msgC[1] = tmpB;
        msgC[2] = tmpA;
        if (Stack_IsFull(q) == 0) {
            Stack_Push(q, msgC);
        }
        q = sub->msgStack;
        msgD[0] = 4;
        msgD[1] = 1;
        msgD[2] = target;
        if (Stack_IsFull(q) == 0) {
            Stack_Push(q, msgD);
        }
        sub->unk34 = 1;
        return 0;
    }
    ((ObjAnimSampleRootCurveObjectFirstFn)ObjAnim_SampleRootCurvePhase)((int)obj, ((BaddieState *)p2)->animSpeedA,
                                 (float *)(p2 + 0x2a0));
    return 0;
}

void dbegg_update(int obj)
{
    extern int Obj_GetPlayerObject(void);
    extern int objPosToMapBlockIdx(f32, f32, f32);
    extern void dbegg_processMessages(int);
    extern int fn_801FE560(int, f32 *, f32, f32, int);
    extern void fn_801FE774(int, f32 *);
    extern void objMove(int, f32, f32, f32);
    extern void Sfx_PlayFromObject(int, int);
    extern void Sfx_KeepAliveLoopedObjectSound(int, int);
    extern uint GameBit_Get(int);
    extern void GameBit_Set(int, int);
    extern int randomGetRange(int, int);
    extern f32 Vec_xzDistance(int, int);
    extern void ObjGroup_RemoveObject(int, int);
    extern void ObjGroup_AddObject(int, int);
    extern void ObjMsg_SendToObject(int, int, int, int);
    extern uint getButtonsJustPressed(int);
    extern int Curve_AdvanceAlongPath(int, f32);
    extern f32 sqrtf(f32);
    extern void Vec3_Normalize(int);
    extern f32 PSVECMag(int);
    extern void fn_80137948(char *, ...);
    extern void ObjHits_EnableObject(int);
    extern void ObjHits_DisableObject(int);
    extern WaterfxInterface **gWaterfxInterface;
    extern f32 timeDelta;
    extern f32 oneOverTimeDelta;
    extern char sAnimGreaterMessage[];
    extern int lbl_803E61C0;
    extern int lbl_803E61C4;
    extern f32 lbl_803E61C8;
    extern f32 lbl_803E61CC;
    extern f32 lbl_803E61E4;
    extern f32 lbl_803E61EC;
    extern f32 lbl_803E6200;
    extern f32 lbl_803E6220;
    extern f32 lbl_803E6224;
    extern f32 lbl_803E6228;
    extern f32 lbl_803E622C;
    extern f32 lbl_803E6230;
    extern f32 lbl_803E6234;
    extern f32 lbl_803E6238;
    extern f32 lbl_803E623C;
    extern f32 lbl_803E6240;
    extern f32 lbl_803E6244;
    extern f32 lbl_803E6248;
    extern f32 lbl_803E624C;
    extern f32 lbl_803E6250;
    extern f32 lbl_803E6254;
    extern f32 lbl_803E6258;
    extern f32 lbl_803E625C;
    extern f32 lbl_803E6260;
    extern f32 lbl_803E6264;
    extern f32 lbl_803E6268;
    int data = *(int *)&((GameObject *)obj)->anim.placementData;
    int player;
    int blob;
    int p2;
    int b2;
    int d2;
    int n;
    int i;
    f32 v;
    f32 fx;
    f32 fz;
    f32 b3[3];
    f32 d[3];
    int buf2[2];
    f32 h;

    player = Obj_GetPlayerObject();
    blob = *(int *)&((GameObject *)obj)->extra;
    n = lbl_803E61C0;
    i = lbl_803E61C4;
    buf2[1] = i;
    buf2[0] = n;
    if (objPosToMapBlockIdx(((GameObject *)obj)->anim.localPosX, ((GameObject *)obj)->anim.localPosY, ((GameObject *)obj)->anim.localPosZ) != -1) {
        dbegg_processMessages(obj);
        (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->flags &= ~0x400;
        switch (((DbEggState *)blob)->mode) {
        case 5:
            if (((GameObject *)obj)->unkF8 == 0) {
                (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->flags |= 1;
            }
            if (fn_801FE560(obj, &h, lbl_803E61C8, *(f32 *)&lbl_803E61C8, 1) == 0) {
                ((DbEggState *)blob)->mode = 2;
                break;
            }
            v = h;
            v = v >= lbl_803E61C8 ? v : -v;
            if (v < lbl_803E6220) {
                if (((DbEggState *)blob)->flags119 & 0x10) {
                    ((DbEggState *)blob)->mode = 0xd;
                } else {
                    ((DbEggState *)blob)->mode = 1;
                }
                fz = lbl_803E61C8;
                ((GameObject *)obj)->anim.velocityX = lbl_803E61C8;
                ((GameObject *)obj)->anim.velocityZ = fz;
                ((GameObject *)obj)->anim.velocityY = fz;
                ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.localPosY + h;
            } else {
                ((GameObject *)obj)->anim.velocityY += lbl_803E6224;
                if (h > lbl_803E61C8) {
                    ((GameObject *)obj)->anim.velocityY = lbl_803E6228 * -((GameObject *)obj)->anim.velocityY;
                    ((GameObject *)obj)->anim.velocityX = ((GameObject *)obj)->anim.velocityX * lbl_803E622C;
                    ((GameObject *)obj)->anim.velocityZ = ((GameObject *)obj)->anim.velocityZ * lbl_803E622C;
                    v = ((GameObject *)obj)->anim.velocityY;
                    v = v >= lbl_803E61C8 ? v : -v;
                    if (v > lbl_803E6230) {
                        Sfx_PlayFromObject(obj, 0x2df);
                    }
                }
                objMove(obj, ((GameObject *)obj)->anim.velocityX * timeDelta, ((GameObject *)obj)->anim.velocityY * timeDelta, ((GameObject *)obj)->anim.velocityZ * timeDelta);
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
            }
            break;
        case 1:
            if (((GameObject *)obj)->unkF8 == 0) {
                (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->flags |= 1;
            }
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~8;
            break;
        case 2:
            if (((DbEggState *)blob)->flags119 & 4) {
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
                ((GameObject *)obj)->anim.velocityX = ((GameObject *)obj)->anim.velocityX + (((DbeggPlacement *)data)->posX8 - ((GameObject *)obj)->anim.localPosX) / (fz = lbl_803E61E4);
                ((GameObject *)obj)->anim.velocityY = ((GameObject *)obj)->anim.velocityY + (((DbeggPlacement *)data)->posY8 - ((GameObject *)obj)->anim.localPosY) / fz;
                ((GameObject *)obj)->anim.velocityZ = ((GameObject *)obj)->anim.velocityZ + (((DbeggPlacement *)data)->posZ8 - ((GameObject *)obj)->anim.localPosZ) / fz;
                if (GameBit_Get(0x44d) != 0) {
                    ((DbEggState *)blob)->mode = 0xa;
                }
            }
            (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->flags |= 0x400;
            fz = lbl_803E61C8;
            b3[0] = lbl_803E61C8;
            b3[1] = fz;
            b3[2] = fz;
            fn_801FE774(obj, b3);
            ((GameObject *)obj)->anim.velocityX = ((GameObject *)obj)->anim.velocityX + b3[0];
            ((GameObject *)obj)->anim.velocityY = ((GameObject *)obj)->anim.velocityY + b3[1];
            ((GameObject *)obj)->anim.velocityZ = ((GameObject *)obj)->anim.velocityZ + b3[2];
            if (fn_801FE560(obj, &h, ((GameObject *)obj)->anim.velocityX * timeDelta, ((GameObject *)obj)->anim.velocityZ * timeDelta, 1) != 0) {
                ((GameObject *)obj)->anim.velocityX = lbl_803E6234 * ((GameObject *)obj)->anim.velocityX;
                ((GameObject *)obj)->anim.velocityZ = lbl_803E6234 * ((GameObject *)obj)->anim.velocityZ;
                fn_801FE560(obj, &h, ((GameObject *)obj)->anim.velocityX * timeDelta, ((GameObject *)obj)->anim.velocityZ * timeDelta, 1);
            }
            h = h + ((DbEggState *)blob)->waterOffset;
            if (oneOverTimeDelta != lbl_803E61C8) {
                ((GameObject *)obj)->anim.velocityY = h * (lbl_803E6238 * oneOverTimeDelta);
            } else {
                ((GameObject *)obj)->anim.velocityY = lbl_803E61C8;
            }
            randomGetRange(0x64, 0x1388);
            randomGetRange(0x64, 0x1388);
            objMove(obj, ((GameObject *)obj)->anim.velocityX * timeDelta, ((GameObject *)obj)->anim.velocityY * timeDelta, ((GameObject *)obj)->anim.velocityZ * timeDelta);
            if (randomGetRange(0, 10) == 0) {
                int nb = h < lbl_803E6200;
                nb = (nb < 0) ? -nb : nb;
                if (nb != 0) {
                ((void (*)(f32, f32, f32, s16, f32, int))(*gWaterfxInterface)->spawnRipple)(
                    ((GameObject *)obj)->anim.localPosX,
                    ((GameObject *)obj)->anim.localPosY - ((DbEggState *)blob)->waterOffset,
                    ((GameObject *)obj)->anim.localPosZ, *(s16 *)obj, (f32)randomGetRange(1, 10), 1);
                }
            }
            if (GameBit_Get(0x426) != 0) {
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~8;
                ((DbEggState *)blob)->waterOffset = ((DbEggState *)blob)->waterOffset - lbl_803E623C * timeDelta;
                if (((DbEggState *)blob)->waterOffset < lbl_803E61EC) {
                    GameBit_Set(0x428, GameBit_Get(0x428) + 1);
                    ((DbEggState *)blob)->mode = 7;
                    fz = lbl_803E61C8;
                    ((GameObject *)obj)->anim.velocityY = lbl_803E61C8;
                    ((GameObject *)obj)->anim.velocityX = fz;
                    ((GameObject *)obj)->anim.velocityZ = fz;
                    *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
                }
            } else if (((DbEggState *)blob)->flags119 & 2) {
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
            }
            break;
        case 4:
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
            break;
        case 6:
            if (Vec_xzDistance(obj + 0x18, data + 8) > lbl_803E6240 && (((DbEggState *)blob)->flags119 & 2) == 0) {
                p2 = Obj_GetPlayerObject();
                b2 = *(int *)&((GameObject *)obj)->extra;
                d2 = *(int *)&((GameObject *)obj)->anim.placementData;
                ObjGroup_RemoveObject(obj, 0x24);
                ((DbEggState *)b2)->mode = 3;
                GameBit_Set(0x3c4, 1);
                GameBit_Set(0x86d, 1);
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
                GameBit_Set(((DbeggPlacement *)d2)->unk1C, 1);
                ((DbEggState *)b2)->msg11C = -1;
                ((DbEggState *)b2)->msg11E = 0;
                ((DbEggState *)b2)->msg120 = lbl_803E61CC;
                ObjMsg_SendToObject(p2, 0x7000a, obj, b2 + 0x11c);
                ((GameObject *)obj)->unkF8 = 0;
            } else if (getButtonsJustPressed(0) & 0x100) {
                ((DbEggState *)blob)->mode = 5;
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~8;
            } else {
                (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->flags &= ~1;
                ObjMsg_SendToObject(player, 0x100008, obj, 0x38000);
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
            }
            break;
        case 0xb:
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
            return;
        case 7:
            fn_801FE560(obj, &h, lbl_803E61C8, *(f32 *)&lbl_803E61C8, 0);
            v = h;
            v = v >= lbl_803E61C8 ? v : -v;
            if (v < lbl_803E6220) {
                ((DbEggState *)blob)->mode = 8;
                fz = lbl_803E61C8;
                ((GameObject *)obj)->anim.velocityX = lbl_803E61C8;
                ((GameObject *)obj)->anim.velocityZ = fz;
            } else {
                ((GameObject *)obj)->anim.velocityY += lbl_803E6244;
                if (h > lbl_803E61C8) {
                    ((GameObject *)obj)->anim.velocityY = lbl_803E6248 * -((GameObject *)obj)->anim.velocityY;
                }
                objMove(obj, ((GameObject *)obj)->anim.velocityX * timeDelta, ((GameObject *)obj)->anim.velocityY * timeDelta, ((GameObject *)obj)->anim.velocityZ * timeDelta);
            }
            break;
        case 8:
            if (GameBit_Get(0x42a) != 0) {
                dbegg_setupFromDef(obj, (int *)blob);
            } else if (randomGetRange(0, 10) == 0) {
                (*gPartfxInterface)->spawnObject((void *)obj, 0x3be, NULL, 0, -1, NULL);
            }
            break;
        case 0xa:
            if ((*gRomCurveInterface)->initCurve((void *)(blob + 4), (void *)obj, lbl_803E624C,
                                                 buf2, 2) != 0) {
                ((DbEggState *)blob)->mode = 5;
            } else {
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~8;
                ((DbEggState *)blob)->mode = 9;
                n = ((DbEggState *)blob)->flags119;
                if (n & 4) {
                    ((DbEggState *)blob)->flags119 = n & ~4;
                }
            }
            break;
        case 9:
            if (Curve_AdvanceAlongPath(blob + 4, lbl_803E6250) != 0 || ((DbEggState *)blob)->unk14 != 0) {
                if ((*gRomCurveInterface)->goNextPoint((void *)(blob + 4)) != 0) {
                    ((DbEggState *)blob)->mode = 5;
                }
            } else {
                ((GameObject *)obj)->anim.velocityX = ((DbEggState *)blob)->curvePosX - ((GameObject *)obj)->anim.localPosX;
                ((GameObject *)obj)->anim.velocityY = ((DbEggState *)blob)->curvePosY - ((GameObject *)obj)->anim.localPosY;
                ((GameObject *)obj)->anim.velocityZ = ((DbEggState *)blob)->curvePosZ - ((GameObject *)obj)->anim.localPosZ;
                fx = sqrtf(((GameObject *)obj)->anim.velocityZ * ((GameObject *)obj)->anim.velocityZ + (((GameObject *)obj)->anim.velocityX * ((GameObject *)obj)->anim.velocityX + ((GameObject *)obj)->anim.velocityY * ((GameObject *)obj)->anim.velocityY));
                if (fx > lbl_803E6254 * timeDelta) {
                    Vec3_Normalize(obj + 0x24);
                    ((GameObject *)obj)->anim.velocityX = ((GameObject *)obj)->anim.velocityX * (lbl_803E6254 * timeDelta);
                    ((GameObject *)obj)->anim.velocityY = ((GameObject *)obj)->anim.velocityY * (lbl_803E6254 * timeDelta);
                    ((GameObject *)obj)->anim.velocityZ = ((GameObject *)obj)->anim.velocityZ * (lbl_803E6254 * timeDelta);
                    fn_80137948(sAnimGreaterMessage);
                }
                ((GameObject *)obj)->anim.localPosX = ((GameObject *)obj)->anim.localPosX + ((GameObject *)obj)->anim.velocityX;
                ((GameObject *)obj)->anim.localPosY = ((GameObject *)obj)->anim.localPosY + ((GameObject *)obj)->anim.velocityY;
                ((GameObject *)obj)->anim.localPosZ = ((GameObject *)obj)->anim.localPosZ + ((GameObject *)obj)->anim.velocityZ;
            }
            break;
        case 0xc:
            if (GameBit_Get(((DbeggPlacement *)data)->unk24) != 0) {
                ObjGroup_AddObject(obj, 0x24);
                ((DbEggState *)blob)->mode = 5;
            }
            break;
        case 0xd:
            ObjHits_DisableObject(obj);
            ((GameObject *)obj)->anim.velocityX = ((GameObject *)obj)->anim.velocityX + (((DbeggPlacement *)data)->posX8 - ((GameObject *)obj)->anim.localPosX) / (fz = lbl_803E6258);
            ((GameObject *)obj)->anim.velocityY = ((GameObject *)obj)->anim.velocityY + (((DbeggPlacement *)data)->posY8 - ((GameObject *)obj)->anim.localPosY) / fz;
            ((GameObject *)obj)->anim.velocityZ = ((GameObject *)obj)->anim.velocityZ + (((DbeggPlacement *)data)->posZ8 - ((GameObject *)obj)->anim.localPosZ) / fz;
            d[0] = ((GameObject *)obj)->anim.localPosX - ((DbeggPlacement *)data)->posX8;
            d[1] = ((GameObject *)obj)->anim.localPosY - ((DbeggPlacement *)data)->posY8;
            d[2] = ((GameObject *)obj)->anim.localPosZ - ((DbeggPlacement *)data)->posZ8;
            Sfx_KeepAliveLoopedObjectSound(obj, 0x442);
            fz = *(f32 *)((int)d + 8);
            fz = fz >= lbl_803E61C8 ? fz : -fz;
            fx = *(f32 *)((int)d + 0);
            fx = fx >= lbl_803E61C8 ? fx : -fx;
            if (fx + fz < lbl_803E625C) {
                ObjHits_EnableObject(obj);
                ((DbEggState *)blob)->mode = 1;
                ((GameObject *)obj)->anim.localPosX = ((DbeggPlacement *)data)->posX8;
                ((GameObject *)obj)->anim.localPosY = ((DbeggPlacement *)data)->posY8;
                ((GameObject *)obj)->anim.localPosZ = ((DbeggPlacement *)data)->posZ8;
            } else {
                n = (int)(PSVECMag(obj + 0x24) / lbl_803E6260);
                for (i = 0; i < n; i++) {
                    (*gPartfxInterface)->spawnObject((void *)obj, 0x345, NULL, 1, -1, NULL);
                }
                objMove(obj, ((GameObject *)obj)->anim.velocityX * timeDelta, ((GameObject *)obj)->anim.velocityY * timeDelta, ((GameObject *)obj)->anim.velocityZ * timeDelta);
            }
            break;
        }
        if (((DbEggState *)blob)->flags119 & 8) {
            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
            ObjHits_DisableObject(obj);
            if (GameBit_Get(((DbeggPlacement *)data)->unk1C) != 0) {
                ((DbEggState *)blob)->flags119 &= ~9;
                *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode &= ~8;
                ObjHits_EnableObject(obj);
            }
        } else if (*(u8 *)&((GameObject *)obj)->anim.resetHitboxMode & 1) {
            if (GameBit_Get(0x3c4) == 0) {
                if (Vec_xzDistance(obj + 0x18, player + 0x18) < lbl_803E6264) {
                    if ((((DbEggState *)blob)->flags119 & 1) == 0) {
                        p2 = Obj_GetPlayerObject();
                        b2 = *(int *)&((GameObject *)obj)->extra;
                        d2 = *(int *)&((GameObject *)obj)->anim.placementData;
                        ObjGroup_RemoveObject(obj, 0x24);
                        ((DbEggState *)b2)->mode = 3;
                        GameBit_Set(0x3c4, 1);
                        GameBit_Set(0x86d, 1);
                        *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
                        GameBit_Set(((DbeggPlacement *)d2)->unk1C, 1);
                        ((DbEggState *)b2)->msg11C = -1;
                        ((DbEggState *)b2)->msg11E = 0;
                        ((DbEggState *)b2)->msg120 = lbl_803E61CC;
                        ObjMsg_SendToObject(p2, 0x7000a, obj, b2 + 0x11c);
                    } else {
                        v = ((GameObject *)obj)->anim.localPosY - *(f32 *)(player + 0x10);
                        v = v >= lbl_803E61C8 ? v : -v;
                        if (v < lbl_803E6268) {
                            *(u8 *)&((GameObject *)obj)->anim.resetHitboxMode |= 8;
                            ((DbEggState *)blob)->mode = 6;
                            (*(ObjHitsPriorityState **)&((GameObject *)obj)->anim.hitReactState)->flags &= ~1;
                        }
                    }
                }
            }
        }
    }
}
