/* === moved from main/dll/genprops.c [80171D14-801723DC) (TU re-split, docs/boundary_audit.md) === */
#pragma scheduling off
#pragma peephole off
#include "ghidra_import.h"
#include "main/obj_placement.h"
#include "main/game_object.h"
#include "main/audio/sfx_ids.h"
#include "main/dll/genprops.h"
#include "main/dll/path_control_interface.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/camera_interface.h"
#include "main/mapEvent.h"
#include "main/objanim_internal.h"
#include "main/objhits_types.h"
#include "main/objseq.h"
#include "main/resource.h"

typedef struct SideloadPlacement
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
    u8 unk18;
    u8 pad19[0x1A - 0x19];
    u8 unk1A;
    u8 pad1B[0x3C - 0x1B];
    s16 unk3C;
    u8 pad3E[0x48 - 0x3E];
    void* unk48;
    u8 pad4C[0x50 - 0x4C];
    f32 unk50;
    u8 pad54[0x70 - 0x54];
    u8 unk70;
    u8 pad71[0x98 - 0x71];
    f32 unk98;
    u8 pad9C[0xAA - 0x9C];
    u8 unkAA;
    u8 padAB[0xB0 - 0xAB];
    s16 unkB0;
    u8 padB2[0xB8 - 0xB2];
    f32 unkB8;
    f32 unkBC;
    f32 unkC0;
    u8 padC4[0x2B1 - 0xC4];
    s8 unk2B1;
    u8 pad2B2[0x2B8 - 0x2B2];
} SideloadPlacement;


typedef struct StaticCameraState
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    f32 unk8;
    f32 unkC;
    f32 unk10;
    u8 pad14[0x18 - 0x14];
    u8 unk18;
    u8 pad19[0x1A - 0x19];
    u8 unk1A;
    u8 pad1B[0x3C - 0x1B];
    s16 unk3C;
    u8 pad3E[0x48 - 0x3E];
    void* unk48;
    u8 pad4C[0x50 - 0x4C];
    f32 unk50;
    u8 pad54[0x70 - 0x54];
    u8 unk70;
    u8 pad71[0x98 - 0x71];
    f32 unk98;
    u8 pad9C[0xAA - 0x9C];
    u8 unkAA;
    u8 padAB[0xB0 - 0xAB];
    s16 unkB0;
    u8 padB2[0xB8 - 0xB2];
    f32 unkB8;
    f32 unkBC;
    f32 unkC0;
    u8 padC4[0x2B1 - 0xC4];
    s8 unk2B1;
    u8 pad2B2[0x2B8 - 0x2B2];
} StaticCameraState;


typedef struct FireballPlacement
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x2C - 0x22];
    s16 unk2C;
    u8 pad2E[0x30 - 0x2E];
} FireballPlacement;


typedef struct AnimatedobjPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 unk8;
    f32 unkC;
    f32 unk10;
    s32 unk14;
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x2C - 0x22];
    s16 unk2C;
    u8 pad2E[0x30 - 0x2E];
} AnimatedobjPlacement;


typedef struct Dim2roofrubPlacement
{
    u8 pad0[0x8 - 0x0];
    f32 posX;
    f32 posY;
    f32 posZ;
    s32 unk14;
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x2C - 0x22];
    s16 unk2C;
    u8 pad2E[0x30 - 0x2E];
} Dim2roofrubPlacement;


typedef struct DllF7Placement
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x2C - 0x22];
    s16 unk2C;
    u8 pad2E[0x30 - 0x2E];
} DllF7Placement;


typedef struct BaddieinterestpPlacement
{
    u8 pad0[0x14 - 0x0];
    s32 unk14;
    s16 unk18;
    s16 unk1A;
    s16 unk1C;
    s16 unk1E;
    s16 unk20;
    u8 pad22[0x2C - 0x22];
    s16 unk2C;
    u8 pad2E[0x30 - 0x2E];
} BaddieinterestpPlacement;


typedef struct MikabombState
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    u8 unk8;
    s8 unk9;
    u8 unkA;
    u8 unkB;
    u8 unkC;
    u8 padD[0x18 - 0xD];
    u8 unk18;
    u8 pad19[0x24 - 0x19];
    f32 unk24;
    f32 unk28;
    f32 unk2C;
    u8 pad30[0x50 - 0x30];
    f32 unk50;
    u8 pad54[0x70 - 0x54];
    u8 unk70;
    u8 pad71[0xAA - 0x71];
    u8 unkAA;
    u8 padAB[0xB0 - 0xAB];
    s16 unkB0;
    u8 padB2[0xB8 - 0xB2];
} MikabombState;


typedef struct StaffDoGrowShrinkAnimState
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    u8 unk8;
    s8 unk9;
    u8 unkA;
    u8 unkB;
    u8 unkC;
    u8 padD[0x18 - 0xD];
    u8 unk18;
    u8 pad19[0x24 - 0x19];
    f32 unk24;
    f32 unk28;
    f32 unk2C;
    u8 pad30[0x50 - 0x30];
    f32 unk50;
    u8 pad54[0x70 - 0x54];
    u8 unk70;
    u8 pad71[0xAA - 0x71];
    u8 unkAA;
    u8 padAB[0xB0 - 0xAB];
    s16 unkB0;
    u8 padB2[0xB8 - 0xB2];
} StaffDoGrowShrinkAnimState;


typedef struct Dim2roofrubState
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    u8 unk8;
    s8 unk9;
    u8 unkA;
    u8 unkB;
    u8 unkC;
    u8 padD[0x18 - 0xD];
    u8 unk18;
    u8 pad19[0x24 - 0x19];
    f32 unk24;
    s32 unk28;
    f32 unk2C;
    u8 pad30[0x50 - 0x30];
    f32 unk50;
    u8 pad54[0x6A - 0x54];
    s16 unk6A;
    u8 pad6C[0x6E - 0x6C];
    s16 unk6E;
    u8 unk70;
    u8 pad71[0x94 - 0x71];
    s32 unk94;
    s32 unk98;
    u8 pad9C[0xAA - 0x9C];
    u8 unkAA;
    u8 padAB[0xB0 - 0xAB];
    s16 unkB0;
    u8 padB2[0x114 - 0xB2];
    s16 unk114;
    s16 unk116;
    u8 pad118[0x140 - 0x118];
} Dim2roofrubState;


typedef struct AnimatedobjState
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    u8 unk8;
    s8 unk9;
    u8 unkA;
    u8 unkB;
    u8 unkC;
    u8 padD[0x18 - 0xD];
    u8 unk18;
    u8 pad19[0x24 - 0x19];
    f32 unk24;
    s32 unk28;
    f32 unk2C;
    u8 pad30[0x50 - 0x30];
    f32 unk50;
    u8 pad54[0x6A - 0x54];
    s16 unk6A;
    u8 pad6C[0x6E - 0x6C];
    s16 unk6E;
    u8 unk70;
    u8 pad71[0x94 - 0x71];
    s32 unk94;
    s32 unk98;
    u8 pad9C[0xAA - 0x9C];
    u8 unkAA;
    u8 padAB[0xB0 - 0xAB];
    s16 unkB0;
    u8 padB2[0xE8 - 0xB2];
    s32 unkE8;
    u8 padEC[0x114 - 0xEC];
    s16 unk114;
    s16 unk116;
    u8 pad118[0x140 - 0x118];
} AnimatedobjState;


typedef struct FlamethrowerspeState
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    f32 unk8;
    f32 unkC;
    s32 unk10;
    u8 pad14[0x18 - 0x14];
    u8 unk18;
    u8 pad19[0x24 - 0x19];
    f32 unk24;
    s32 unk28;
    f32 unk2C;
    u8 pad30[0x50 - 0x30];
    f32 unk50;
    u8 pad54[0x6A - 0x54];
    s16 unk6A;
    u8 pad6C[0x6E - 0x6C];
    s16 unk6E;
    u8 unk70;
    u8 pad71[0x94 - 0x71];
    s32 unk94;
    s32 unk98;
    u8 pad9C[0xAA - 0x9C];
    u8 unkAA;
    u8 padAB[0xB0 - 0xAB];
    s16 unkB0;
    u8 padB2[0xE8 - 0xB2];
    s32 unkE8;
    u8 padEC[0x114 - 0xEC];
    s16 unk114;
    s16 unk116;
} FlamethrowerspeState;


typedef struct ShieldState
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    f32 unk8;
    f32 unkC;
    s32 unk10;
    u8 pad14[0x18 - 0x14];
    u8 unk18;
    u8 pad19[0x24 - 0x19];
    f32 unk24;
    s32 unk28;
    f32 unk2C;
    u8 pad30[0x50 - 0x30];
    f32 unk50;
    u8 pad54[0x5C - 0x54];
    u8 unk5C;
    u8 unk5D;
    u8 unk5E;
    u8 unk5F;
    u8 pad60[0x6A - 0x60];
    s16 unk6A;
    u8 pad6C[0x6E - 0x6C];
    s16 unk6E;
    u8 unk70;
    u8 pad71[0x94 - 0x71];
    s32 unk94;
    s32 unk98;
    u8 pad9C[0xAA - 0x9C];
    u8 unkAA;
    u8 padAB[0xB0 - 0xAB];
    s16 unkB0;
    u8 padB2[0xE8 - 0xB2];
    s32 unkE8;
    u8 padEC[0x114 - 0xEC];
    s16 unk114;
    s16 unk116;
} ShieldState;


typedef struct FireballState
{
    u8 pad0[0x4 - 0x0];
    f32 unk4;
    f32 unk8;
    f32 unkC;
    s32 unk10;
    u8 pad14[0x18 - 0x14];
    u8 unk18;
    u8 pad19[0x24 - 0x19];
    f32 posX;
    s32 posY;
    f32 posZ;
    f32 flightDuration;
    f32 elapsedTime;
    f32 fadeoutTimer;
    f32 startupDelay;
    s16 unk40;
    s16 unk42;
    u8 pad44[0x46 - 0x44];
    u16 spiralPhase;
    u8 pad48[0x50 - 0x48];
    f32 unk50;
    u8 pad54[0x5C - 0x54];
    u8 unk5C;
    u8 unk5D;
    u8 unk5E;
    u8 unk5F;
    u8 pad60[0x6A - 0x60];
    s16 unk6A;
    u8 pad6C[0x6E - 0x6C];
    s16 unk6E;
    u8 stateFlags;
    u8 colorIndex;
    u8 pad72[0x94 - 0x72];
    s32 unk94;
    s32 unk98;
    u8 pad9C[0xAA - 0x9C];
    u8 unkAA;
    u8 padAB[0xB0 - 0xAB];
    s16 unkB0;
    u8 padB2[0xE8 - 0xB2];
    s32 unkE8;
    u8 padEC[0x114 - 0xEC];
    s16 unk114;
    s16 unk116;
} FireballState;


extern undefined4 FUN_80006810();
extern undefined4 FUN_8001753c();
extern undefined4 FUN_80017588();
extern undefined4 FUN_8001759c();
extern undefined4 FUN_800175b0();
extern undefined4 FUN_800175bc();
extern undefined4 FUN_800175cc();
extern undefined4 FUN_800175d0();
extern undefined4 FUN_800175d8();
extern undefined4 FUN_800175ec();
extern void* FUN_80017624();
extern undefined4 FUN_80017688();
extern uint FUN_80017690();
extern undefined8 FUN_80017698();
extern int FUN_80017a54();
extern int FUN_80017a90();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern int* Obj_SetupObject(void* setup, int mode, int mapLayer, int objIndex, void* parent);
extern undefined8 FUN_8002fc3c();
extern undefined4 ObjHits_SetTargetMask();
extern undefined4 ObjHitbox_SetSphereRadius();
extern undefined4 ObjHits_ClearHitVolumes();
extern undefined4 ObjHits_SetHitVolumeSlot();
extern undefined4 ObjHits_EnableObject();
extern int ObjHits_GetPriorityHitWithPosition();
extern undefined4 ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 ObjLink_AttachChild();
extern u32 ObjHitRegion_FindContainingId(f32 x, f32 y, f32 z);
extern undefined4 FUN_8003b818();
extern void gxSetPeControl_ZCompLoc_();
extern void gxSetZMode_();
extern undefined4 FUN_800810f8();
extern undefined4 FUN_80081118();
extern undefined8 FUN_800e842c();
extern undefined4 PSVECDotProduct();
extern int FUN_80286838();
extern undefined4 FUN_80286884();
extern undefined4 fcos16Precise();
extern undefined4 FUN_80294c48();
extern undefined4 FUN_80294c60();
extern int FUN_80294cf8();
extern int FUN_80294d10();
extern undefined4 FUN_80294d60();
extern undefined4 FUN_80294d6c();

extern undefined4 DAT_80321678;
extern int DAT_80321688;
extern undefined4 DAT_80321698;
extern int DAT_803216a8;
extern undefined4 DAT_803ad324;
extern undefined4 DAT_803ad328;
extern undefined4 DAT_803ad32c;
extern undefined4 DAT_803ad330;
extern undefined4 DAT_803ad334;
extern undefined4 DAT_803ad338;
extern ObjectTriggerInterface** gObjectTriggerInterface;
extern ModgfxInterface** gModgfxInterface;
extern EffectInterface** gPartfxInterface;
extern void** gTitleMenuControlInterfaceCopy;
extern f64 DOUBLE_803e3e28;
extern f64 DOUBLE_803e3e50;
extern f64 DOUBLE_803e3e88;
extern f64 DOUBLE_803e3eb0;
extern f64 DOUBLE_803e3ed0;
extern f64 DOUBLE_803e3f18;
extern f64 DOUBLE_803e3fb0;
extern f64 DOUBLE_803e4030;
extern f64 DOUBLE_803e4068;
extern f64 DOUBLE_803e4078;
extern f64 DOUBLE_803e40d0;
extern f32 lbl_803DC074;
extern f32 lbl_803DC9C8;
extern f32 lbl_803DC9D0;
extern f32 lbl_803DC9D4;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803E3E30;
extern f32 lbl_803E3E34;
extern f32 lbl_803E3E3C;
extern f32 lbl_803E3E40;
extern f32 lbl_803E3E44;
extern f32 lbl_803E3E48;
extern f32 lbl_803E3E5C;
extern f32 lbl_803E3E60;
extern f32 lbl_803E3E64;
extern f32 lbl_803E3E68;
extern f32 lbl_803E3E6C;
extern f32 lbl_803E3E70;
extern f32 lbl_803E3E74;
extern f32 lbl_803E3E78;
extern f32 lbl_803E3E7C;
extern f32 lbl_803E3E94;
extern f32 lbl_803E3E98;
extern f32 lbl_803E3E9C;
extern f32 lbl_803E3EA0;
extern f32 lbl_803E3EA4;
extern f32 lbl_803E3EA8;
extern f32 lbl_803E3EBC;
extern f32 lbl_803E3EC0;
extern f32 lbl_803E3EC4;
extern f32 lbl_803E3EC8;
extern f32 lbl_803E3ED8;
extern f32 lbl_803E3EDC;
extern f32 lbl_803E3EE0;
extern f32 lbl_803E3EE4;
extern f32 lbl_803E3EE8;
extern f32 lbl_803E3EEC;
extern f32 lbl_803E3EF0;
extern f32 lbl_803E3EF4;
extern f32 lbl_803E3EF8;
extern f32 lbl_803E3EFC;
extern f32 lbl_803E3F00;
extern f32 lbl_803E3F04;
extern f32 lbl_803E3F08;
extern f32 lbl_803E3F0C;
extern f32 lbl_803E3F10;
extern f32 lbl_803E3F14;
extern f32 lbl_803E3F20;
extern f32 lbl_803E3F24;
extern f32 lbl_803E3F28;
extern f32 lbl_803E3F2C;
extern f32 lbl_803E3F30;
extern f32 lbl_803E3F34;
extern f32 lbl_803E3F38;
extern f32 lbl_803E3F3C;
extern f32 lbl_803E3F40;
extern f32 lbl_803E3F44;
extern f32 lbl_803E3F48;
extern f32 lbl_803E3F4C;
extern f32 lbl_803E3F50;
extern f32 lbl_803E3F54;
extern f32 lbl_803E3F58;
extern f32 lbl_803E3F5C;
extern f32 lbl_803E3F60;
extern f32 lbl_803E3F64;
extern f32 lbl_803E3F68;
extern f32 lbl_803E3F6C;
extern f32 lbl_803E3F70;
extern f32 lbl_803E3F74;
extern f32 lbl_803E3F78;
extern f32 lbl_803E3F7C;
extern f32 lbl_803E3F80;
extern f32 lbl_803E3F84;
extern f32 lbl_803E3F88;
extern f32 lbl_803E3F8C;
extern f32 lbl_803E3F90;
extern f32 lbl_803E3F94;
extern f32 lbl_803E3F98;
extern f32 lbl_803E3FA4;
extern f32 lbl_803E3FA8;
extern f32 lbl_803E3FB8;
extern f32 lbl_803E3FBC;
extern f32 lbl_803E3FC0;
extern f32 lbl_803E3FC4;
extern f32 lbl_803E3FC8;
extern f32 lbl_803E3FCC;
extern f32 lbl_803E3FD8;
extern f32 lbl_803E3FE8;
extern f32 lbl_803E3FF0;
extern f32 lbl_803E3FF4;
extern f32 lbl_803E3FF8;
extern f32 lbl_803E3FFC;
extern f32 lbl_803E4000;
extern f32 lbl_803E4004;
extern f32 lbl_803E4010;
extern f32 lbl_803E4014;
extern f32 lbl_803E4018;
extern f32 lbl_803E4024;
extern f32 lbl_803E4028;
extern f32 lbl_803E402C;
extern f32 lbl_803E4038;
extern f32 lbl_803E4040;
extern f32 lbl_803E4044;
extern f32 lbl_803E4048;
extern f32 lbl_803E404C;
extern f32 lbl_803E4050;
extern f32 lbl_803E4054;
extern f32 lbl_803E4058;
extern f32 lbl_803E405C;
extern f32 lbl_803E4060;
extern f32 lbl_803E4064;
extern f32 lbl_803E4070;
extern f32 lbl_803E4074;
extern f32 lbl_803E4080;
extern f32 lbl_803E4084;
extern f32 lbl_803E4098;
extern f32 lbl_803E409C;
extern f32 lbl_803E40A0;
extern f32 lbl_803E40A4;
extern f32 lbl_803E40A8;
extern f32 lbl_803E40AC;
extern f32 lbl_803E40B0;
extern f32 lbl_803E40B8;
extern f32 lbl_803E40BC;
extern f32 lbl_803E40C0;
extern f32 lbl_803E40C4;
extern f32 lbl_803E40C8;
extern f32 lbl_803E40E8;
extern f32 lbl_803E40EC;
extern void* PTR_DAT_803211ec;


/*
 * --INFO--
 *
 * Function: staticCamera_free
 * EN v1.0 Address: 0x8016BAC4
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x8016BD54
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: staticCamera_render
 * EN v1.0 Address: 0x8016BAE8
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x8016BD78
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: staticCamera_init
 * EN v1.0 Address: 0x8016BB10
 * EN v1.0 Size: 168b
 * EN v1.1 Address: 0x8016BDB0
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_8016d188
 * EN v1.0 Address: 0x8016D188
 * EN v1.0 Size: 2060b
 * EN v1.1 Address: 0x8016D394
 * EN v1.1 Size: 2820b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/*
 * --INFO--
 *
 * Function: FUN_8016d994
 * EN v1.0 Address: 0x8016D994
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x8016DE98
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: FUN_8016e8cc
 * EN v1.0 Address: 0x8016E8CC
 * EN v1.0 Size: 1068b
 * EN v1.1 Address: 0x8016F0A8
 * EN v1.1 Size: 756b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8016e8cc(undefined8 param_1, undefined8 param_2, double param_3, undefined8 param_4, undefined8 param_5, undefined8 param_6, undefined8 param_7, undefined8 param_8, int param_9);


/*
 * --INFO--
 *
 * Function: FUN_80170048
 * EN v1.0 Address: 0x80170048
 * EN v1.0 Size: 2352b
 * EN v1.1 Address: 0x8017082C
 * EN v1.1 Size: 1804b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


/*
 * --INFO--
 *
 * Function: checkpoint4_render
 * EN v1.0 Address: 0x80170F68
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x80171EA4
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
extern f32 lbl_803E3420;


/*
 * --INFO--
 *
 * Function: checkpoint4_init
 * EN v1.0 Address: 0x80170F88
 * EN v1.0 Size: 308b
 * EN v1.1 Address: 0x80171ED0
 * EN v1.1 Size: 392b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

extern u8 Obj_IsLoadingLocked(void);
extern void* getTrickyObject(void);
extern u32 GameBit_Get(int eventId);
extern void* Obj_AllocObjectSetup(int size, int type);
extern int* Obj_SetupObject(void* setup, int a, int b, int c, void* d);

/*
 * --INFO--
 *
 * Function: sideload_update
 * EN v1.0 Address: 0x801710BC
 * EN v1.0 Size: 352b
 * EN v1.1 Address: 0x80172058
 * EN v1.1 Size: 212b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */


extern f32 lbl_803E31D8;
extern f32 lbl_803E31DC;
extern f32 lbl_803E31E0;
extern f32 lbl_803E31E4;

void mikabombshadow_update(int* obj);

extern f32 lbl_803E33F4;
extern f32 lbl_803E33F8;


void siderepel_init(int obj, int param_2);


/*
 * --INFO--
 *
 * Function: FUN_801713ac
 * EN v1.0 Address: 0x801713AC
 * EN v1.0 Size: 956b
 * EN v1.1 Address: 0x80172308
 * EN v1.1 Size: 744b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */

/* Trivial 4b 0-arg blr leaves. */



















void staff_func0F(void);


void staff_func0B(void);

void staff_setScale(void);

void staff_render(void);

void staff_hitDetect(void);

void fireball_release(void);

void fireball_initialise(void);

void flamethrowerspe_modelMtxFn(void);

void flamethrowerspe_free(void);

void flamethrowerspe_hitDetect(void);

void flamethrowerspe_release(void);

void flamethrowerspe_initialise(void);

void shield_hitDetect(void);

void shield_release(void);

void shield_initialise(void);

extern void ModelLightStruct_free(void* p);
extern int Sfx_StopFromObject(int obj, int sfxId);

void shield_free(int obj);












void setuppoint_init(void);

/* 8b "li r3, N; blr" returners. */
int animatedobj_getExtraSize(void);
int dim2roofrub_getExtraSize(void);
int depthoffieldpoint_getExtraSize(void);
int staff_getExtraSize(void);
int staff_getObjectTypeId(void);
int fireball_getExtraSize(void);
int fireball_getObjectTypeId(void);
int flamethrowerspe_getExtraSize(void);
int flamethrowerspe_getObjectTypeId(void);
int shield_getExtraSize(void);
int shield_getObjectTypeId(void);

extern void* lbl_803DDAB0;
extern void* lbl_803DDAB4;

void dll_F7_free(int obj);

extern void Sfx_StopObjectChannel(int* obj, int channel);

void dim2roofrub_free(int* obj);

int siderepel_getExtraSize(void);

extern void gcbaddieshield_update(int* obj);
extern void animatedobj_free();
extern void animatedobj_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
extern void animatedobj_update(int* obj);
extern void animatedobj_init();
extern void dim2roofrub_render(int* obj, int p2, int p3, int p4, int p5);
extern void dim2roofrub_update(int* obj);
extern void dim2roofrub_init();
extern void depthoffieldpoint_update();
extern void depthoffieldpoint_init();
extern void staff_free(int* obj);
extern void staff_update();
extern void staff_init();
extern void staff_release();
extern void staff_initialise();
extern void staff_modelMtxFn(int* obj, int p4, int p5);
extern void staff_hitDetectGeometry();
void staff_func10(int* obj, s32 v);
void staff_setHitReactValue(int* obj, s32 v);
void staff_addHitReactValue(int* obj, s32 delta);
extern s16 staff_getHitReactValue(int* obj);
void staff_getHitGeometryPoints(int* obj, f32* outA, f32* outB);
void staff_func15(int* obj, s16 idx, f32 f1, f32 f2);
extern s32 staff_func16(int* obj);
extern void fireball_free();
extern void fireball_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
extern void fireball_hitDetect();
extern void fireball_update();
extern void fireball_init();
void flamethrowerspe_setScale(int* obj, s16 a, s16 b, f32 f1, f32 f2, f32 f3);
extern void flamethrowerspe_func0B(int* obj);
extern void flamethrowerspe_render(void);
extern void flamethrowerspe_update();
extern void flamethrowerspe_init();
extern void shield_free();
extern void shield_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
extern void shield_update();

void restartmarker_init(int* obj, int* state);

extern void dll_F7_free();
extern void dll_F7_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);
extern void dll_F7_update();
extern void dll_F7_init();
void staffFn_80170380(int* obj, int cmd);
extern int* Obj_GetActiveModel(int obj);
extern void postRenderSetAlphaBlendState(void);
extern void ObjModel_SetPostRenderCallback(int* model, void* callback);

void shield_init(int* obj, void* initData);

ObjectDescriptor gMikaBombObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)mikabomb_initialise,
    (ObjectDescriptorCallback)mikabomb_release,
    0,
    (ObjectDescriptorCallback)mikabomb_init,
    (ObjectDescriptorCallback)mikabomb_update,
    (ObjectDescriptorCallback)mikabomb_hitDetect,
    (ObjectDescriptorCallback)mikabomb_render,
    (ObjectDescriptorCallback)mikabomb_free,
    (ObjectDescriptorCallback)mikabomb_getObjectTypeId,
    mikabomb_getExtraSize,
};

ObjectDescriptor gMikaBombShadowObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)mikabombshadow_initialise,
    (ObjectDescriptorCallback)mikabombshadow_release,
    0,
    (ObjectDescriptorCallback)mikabombshadow_init,
    (ObjectDescriptorCallback)mikabombshadow_update,
    (ObjectDescriptorCallback)mikabombshadow_hitDetect,
    (ObjectDescriptorCallback)mikabombshadow_render,
    (ObjectDescriptorCallback)mikabombshadow_free,
    (ObjectDescriptorCallback)mikabombshadow_getObjectTypeId,
    mikabombshadow_getExtraSize,
};

ObjectDescriptor gStaticCameraObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)StaticCamera_initialise,
    (ObjectDescriptorCallback)StaticCamera_release,
    0,
    (ObjectDescriptorCallback)StaticCamera_init,
    (ObjectDescriptorCallback)StaticCamera_update,
    (ObjectDescriptorCallback)StaticCamera_hitDetect,
    (ObjectDescriptorCallback)StaticCamera_render,
    (ObjectDescriptorCallback)StaticCamera_free,
    (ObjectDescriptorCallback)StaticCamera_getObjectTypeId,
    StaticCamera_getExtraSize,
};

ObjectDescriptor gGCbaddieShieldObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)gcbaddieshield_initialise,
    (ObjectDescriptorCallback)gcbaddieshield_release,
    0,
    (ObjectDescriptorCallback)gcbaddieshield_init,
    (ObjectDescriptorCallback)gcbaddieshield_update,
    (ObjectDescriptorCallback)gcbaddieshield_hitDetect,
    (ObjectDescriptorCallback)gcbaddieshield_render,
    (ObjectDescriptorCallback)gcbaddieshield_free,
    (ObjectDescriptorCallback)gcbaddieshield_getObjectTypeId,
    gcbaddieshield_getExtraSize,
};

ObjectDescriptor gBaddieInterestPObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)baddieinterestp_initialise,
    (ObjectDescriptorCallback)baddieinterestp_release,
    0,
    (ObjectDescriptorCallback)baddieinterestp_init,
    (ObjectDescriptorCallback)baddieinterestp_update,
    (ObjectDescriptorCallback)baddieinterestp_hitDetect,
    (ObjectDescriptorCallback)baddieinterestp_render,
    (ObjectDescriptorCallback)baddieinterestp_free,
    (ObjectDescriptorCallback)baddieinterestp_getObjectTypeId,
    baddieinterestp_getExtraSize,
};

u32 lbl_80320700[] = {
    0xFFFFFFFF,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
    0,
};

ObjectDescriptor gAnimatedObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)animatedobj_init,
    (ObjectDescriptorCallback)animatedobj_update,
    0,
    (ObjectDescriptorCallback)animatedobj_render,
    (ObjectDescriptorCallback)animatedobj_free,
    0,
    animatedobj_getExtraSize,
};

u32 lbl_80320768[] = {
    0x00000000,
    0x3FD5A1CB,
    0xC0253F7D,
    0x3C23D70A,
    0x06100000,
    0x402F3B64,
    0x3F4B020C,
    0xBFFA1CAC,
    0x3C23D70A,
    0x09200000,
    0x402EB852,
    0x3F476C8B,
    0xBF73B646,
    0x3C23D70A,
    0x07200000,
    0x4032E148,
    0xBF795810,
    0xBFF8F5C3,
    0x3C23D70A,
    0x09200000,
    0x4033F7CF,
    0xBF810625,
    0xBF747AE1,
    0x3C23D70A,
    0x07200000,
    0xC02F3B64,
    0x3F4B020C,
    0xBFFC28F6,
    0x3C23D70A,
    0x09200000,
    0xC02EB852,
    0x3F476C8B,
    0xBF73B646,
    0x3C23D70A,
    0x07200000,
    0xC032E148,
    0xBF795810,
    0xBFFC49BA,
    0x3C23D70A,
    0x09200000,
    0xC033F7CF,
    0xBF810625,
    0xBF747AE1,
    0x3C23D70A,
    0x07200000,
    0x00000000,
    0x3ECF5C29,
    0x403CED91,
    0x3C23D70A,
    0x08400000,
};

ObjectDescriptor gDIM2RoofRubObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)dim2roofrub_init,
    (ObjectDescriptorCallback)dim2roofrub_update,
    0,
    (ObjectDescriptorCallback)dim2roofrub_render,
    (ObjectDescriptorCallback)dim2roofrub_free,
    0,
    dim2roofrub_getExtraSize,
};

ObjectDescriptor gDepthOfFieldPointObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)depthoffieldpoint_init,
    (ObjectDescriptorCallback)depthoffieldpoint_update,
    0,
    0,
    0,
    0,
    depthoffieldpoint_getExtraSize,
};

u16 lbl_803208A0[] = {
    0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3,
    0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3,
    0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3,
    0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3, 0x00C3,
    0x00C2, 0x006F, 0x00C3, 0x00C3, 0x00C3, 0x00C3,
    0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
};

u32 lbl_803208E8[] = {
    0,
    0,
    0,
    0,
    0,
    0,
    0x01020000,
    0,
    0,
};

ObjectDescriptor23 gStaffObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_23_SLOTS,
    (ObjectDescriptorCallback)staff_initialise,
    (ObjectDescriptorCallback)staff_release,
    0,
    (ObjectDescriptorCallback)staff_init,
    (ObjectDescriptorCallback)staff_update,
    (ObjectDescriptorCallback)staff_hitDetect,
    (ObjectDescriptorCallback)staff_render,
    (ObjectDescriptorCallback)staff_free,
    (ObjectDescriptorCallback)staff_getObjectTypeId,
    staff_getExtraSize,
    (ObjectDescriptorCallback)staff_setScale,
    (ObjectDescriptorCallback)staff_func0B,
    (ObjectDescriptorCallback)staff_modelMtxFn,
    (ObjectDescriptorCallback)staff_hitDetectGeometry,
    (ObjectDescriptorCallback)staff_func0E,
    (ObjectDescriptorCallback)staff_func0F,
    (ObjectDescriptorCallback)staff_func10,
    (ObjectDescriptorCallback)staff_setHitReactValue,
    (ObjectDescriptorCallback)staff_addHitReactValue,
    (ObjectDescriptorCallback)staff_getHitReactValue,
    (ObjectDescriptorCallback)staff_getHitGeometryPoints,
    (ObjectDescriptorCallback)staff_func15,
    (ObjectDescriptorCallback)staff_func16,
};

u32 lbl_80320978[] = {
    0xFF202020,
    0xFF202020,
    0xFF000000,
};

ObjectDescriptor10WithPadding gFireballObjDescriptor = {
    {
        0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
        (ObjectDescriptorCallback)fireball_initialise,
        (ObjectDescriptorCallback)fireball_release,
        0,
        (ObjectDescriptorCallback)fireball_init,
        (ObjectDescriptorCallback)fireball_update,
        (ObjectDescriptorCallback)fireball_hitDetect,
        (ObjectDescriptorCallback)fireball_render,
        (ObjectDescriptorCallback)fireball_free,
        (ObjectDescriptorCallback)fireball_getObjectTypeId,
        fireball_getExtraSize,
    },
    0,
};

u32 lbl_803209C0[] = {
    0x0000004F,
    0xFFC40000,
    0x0000001F,
    0x0000004F,
    0x00C4FF00,
    0x00000005,
    0x0000004F,
    0x00C4FF00,
    0x0000001E,
};

ObjectDescriptor13 gFlameThrowerSpeObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_13_SLOTS,
    (ObjectDescriptorCallback)flamethrowerspe_initialise,
    (ObjectDescriptorCallback)flamethrowerspe_release,
    0,
    (ObjectDescriptorCallback)flamethrowerspe_init,
    (ObjectDescriptorCallback)flamethrowerspe_update,
    (ObjectDescriptorCallback)flamethrowerspe_hitDetect,
    (ObjectDescriptorCallback)flamethrowerspe_render,
    (ObjectDescriptorCallback)flamethrowerspe_free,
    (ObjectDescriptorCallback)flamethrowerspe_getObjectTypeId,
    flamethrowerspe_getExtraSize,
    (ObjectDescriptorCallback)flamethrowerspe_setScale,
    (ObjectDescriptorCallback)flamethrowerspe_func0B,
    (ObjectDescriptorCallback)flamethrowerspe_modelMtxFn,
};

f32 lbl_80320A28[] = {
    0.5f,
    0.55f,
    0.65f,
    0.7f,
    0.5f,
    0.5f,
    0.5f,
    0.5f,
    0.5f,
    0.5f,
    0.5f,
    0.5f,
    0.3f,
    0.3f,
    0.3f,
    0.3f,
};

ObjectDescriptor gShieldObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)shield_initialise,
    (ObjectDescriptorCallback)shield_release,
    0,
    (ObjectDescriptorCallback)shield_init,
    (ObjectDescriptorCallback)shield_update,
    (ObjectDescriptorCallback)shield_hitDetect,
    (ObjectDescriptorCallback)shield_render,
    (ObjectDescriptorCallback)shield_free,
    (ObjectDescriptorCallback)shield_getObjectTypeId,
    shield_getExtraSize,
};

u32 jumptable_80320AA0[] = {
    (u32)((char*)staffFn_80170380 + 0x10C),
    (u32)((char*)staffFn_80170380 + 0x184),
    (u32)((char*)staffFn_80170380 + 0x35C),
    (u32)((char*)staffFn_80170380 + 0x3D0),
    (u32)((char*)staffFn_80170380 + 0x584),
    (u32)((char*)staffFn_80170380 + 0x550),
    (u32)((char*)staffFn_80170380 + 0x65C),
    (u32)((char*)staffFn_80170380 + 0x84),
};

ObjectDescriptor12 gCurveObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_12_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)curve_init,
    0,
    0,
    (ObjectDescriptorCallback)curve_render,
    (ObjectDescriptorCallback)curve_free,
    (ObjectDescriptorCallback)curve_getObjectTypeId,
    curve_getExtraSize,
    (ObjectDescriptorCallback)curve_setScale,
    (ObjectDescriptorCallback)curve_func11,
};

ObjectDescriptor gReStartMarkerObjDescriptor = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    0,
    0,
    0,
    (ObjectDescriptorCallback)restartmarker_init,
    0,
    0,
    0,
    0,
    0,
    0,
};

ObjectDescriptor dll_F7 = {
    0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_10_SLOTS,
    (ObjectDescriptorCallback)dll_F7_initialise,
    (ObjectDescriptorCallback)dll_F7_release,
    0,
    (ObjectDescriptorCallback)dll_F7_init,
    (ObjectDescriptorCallback)dll_F7_update,
    (ObjectDescriptorCallback)dll_F7_hitDetect,
    (ObjectDescriptorCallback)dll_F7_render,
    (ObjectDescriptorCallback)dll_F7_free,
    (ObjectDescriptorCallback)dll_F7_getObjectTypeId,
    dll_F7_getExtraSize,
};

ObjectDescriptor11WithPadding gCheckpoint4ObjDescriptor = {
    {
        0, 0, 0, OBJECT_DESCRIPTOR_FLAGS_11_SLOTS,
        (ObjectDescriptorCallback)checkpoint4_initialise,
        (ObjectDescriptorCallback)checkpoint4_release,
        0,
        (ObjectDescriptorCallback)checkpoint4_init,
        (ObjectDescriptorCallback)checkpoint4_update,
        (ObjectDescriptorCallback)checkpoint4_hitDetect,
        (ObjectDescriptorCallback)checkpoint4_render,
        (ObjectDescriptorCallback)checkpoint4_free,
        (ObjectDescriptorCallback)checkpoint4_getObjectTypeId,
        checkpoint4_getExtraSize,
        (ObjectDescriptorCallback)checkpoint4_setScale,
    },
    0,
};

typedef struct StaffState
{
    u8 pad00[0x54];
    f32 geometryPointAX;
    u8 pad58[4];
    f32 geometryPointAY;
    u8 pad60[4];
    f32 geometryPointAZ;
    u8 pad68[4];
    f32 geometryPointBX;
    u8 pad70[4];
    f32 geometryPointBY;
    u8 pad78[4];
    f32 geometryPointBZ;
    u8 pad80[8];
    s16 hitReactValue;
    u8 pad8A[0x28];
    s16 fieldB2;
    u8 padB4[5];
    s8 fieldB9;
} StaffState;

/* Pattern wrappers. */
s16 staff_getHitReactValue(int* obj);
u8 fn_8016F16C(int* obj);
u8 collectible_func0F(int* obj) { return *(u8*)((char*)((int**)obj)[0xb8 / 4] + 0x1e); }

/* 16b chained patterns. */
s32 staff_func16(int* obj);

/* render-with-objRenderFn_8003b8f4 pattern. */
extern f32 lbl_803E31E8;
extern f32 lbl_803E3220;
extern f32 lbl_803E33F0;
extern f32 lbl_803E31F8;





/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E3388;
void flamethrowerspe_render(void);
void fn_801719F8(void);

/* ObjGroup_RemoveObject(x, N) wrappers. */
void siderepel_free(int x);

/* misc 8b leaves */
int collectible_setScale(int* obj) { return ((GameObject*)obj)->unkF4; }

/* misc 16b 4-insn patterns. */
void objSetAnimField48to0(int* obj);

void flamethrowerspe_func0B(int* obj);

extern void quakeSpellFn_8016cee8(int* obj, int* x);
void playerRenderQuakeSpell(int* obj);

/* state-byte setters / leaf writers. */
#pragma dont_inline on
void staffSetGlow(int* obj, u8 a, u8 b);
#pragma dont_inline reset



void collectible_func0E(int* obj, u32 v)
{
    *(u8*)((char*)((int**)obj)[0xb8 / 4] + 0x1e) = (u8)v;
}

void collectible_render2(int* obj, f32 f1, f32 f2, f32 f3)
{
    s32 v = 0x8;
    *(u8*)((char*)((int**)obj)[0xb8 / 4] + 0x1d) = (u8)v;
    ((GameObject*)obj)->anim.velocityX = f1;
    ((GameObject*)obj)->anim.velocityY = f2;
    ((GameObject*)obj)->anim.velocityZ = f3;
}

extern void saveGame_saveObjectPos(int obj);

void collectible_func10(int* obj, f32 f1, f32 f2, f32 f3)
{
    char* inner = (char*)((int**)obj)[0xb8 / 4];
    ((GameObject*)obj)->anim.localPosX = f1;
    *(f32*)(inner + 0x24) = f1;
    ((GameObject*)obj)->anim.localPosY = f2;
    *(f32*)(inner + 0x28) = f2;
    ((GameObject*)obj)->anim.localPosZ = f3;
    *(f32*)(inner + 0x2c) = f3;
    if (GameBit_Get(*(s16*)(inner + 0x10)) == 0)
    {
        saveGame_saveObjectPos((int)obj);
    }
}

void collectible_func0B(int* obj, int flag)
{
    extern undefined8 ObjHits_DisableObject(); /* #57 */
    char* inner = (char*)((int**)obj)[0xb8 / 4];
    *(u8*)(inner + 0xf) = (u8)flag;
    if (flag != 0)
    {
        ObjHits_DisableObject(obj);
    }
    else
    {
        if (GameBit_Get(*(s16*)(inner + 0x10)) == 0)
        {
            ObjHits_EnableObject(obj);
        }
    }
}

int collectible_modelMtxFn(int* obj)
{
    int* inner = (int*)*(int*)&((GameObject*)obj)->extra;
    if (*(int*)((char*)inner + 0x18) == -2)
    {
        f32 f1 = ((GameObject*)obj)->anim.worldPosX;
        f32 f2 = ((GameObject*)obj)->anim.worldPosY;
        f32 f3 = ((GameObject*)obj)->anim.worldPosZ;
        *(u32*)((char*)inner + 0x18) = (u16)ObjHitRegion_FindContainingId(f1, f2, f3);
    }
    return *(int*)((char*)inner + 0x18);
}

extern void staff_setupSwipe(int p1, int p2, int p3, int p4);
extern int getHudHiddenFrameCount(void);

void staff_modelMtxFn(int* obj, int p4, int p5);





extern void objShadowFn_80062498(int* obj, int p2, int p3, u8 frames);
extern u8 framesThisStep;




int* fn_801702D4(int* obj, f32 fv);

extern void mm_free(int* p);
extern f32 lbl_803E31FC;
extern f32 lbl_803E3200;
extern f32 lbl_803E3204;
extern f32 lbl_803E3208;
extern f32 lbl_803E320C;
extern f32 lbl_803E3210;
extern f32 timeDelta;

void gcbaddieshield_update(int* obj);

void staff_free(int* obj);

void fireball_free(int* obj);

typedef struct DofState
{
    u8 enabled : 1;
    u8  : 7;
    u8 field1;
    u8 field2;
} DofState;

extern void Rcp_DisableBlurFilter(void);
extern void turnOnBlurFilter(f32 a, f32 b, f32 c, int field1, int field2);
extern int textureFree(int tex);
extern void* lbl_803DDAA0;
extern void* lbl_803DDAA8[2];

void depthoffieldpoint_init(int* obj);

void depthoffieldpoint_update(int* obj);

void staff_release(void);

extern void fn_80065684(int obj, f32 a, f32 b, f32 c, f32* out, int flag);

void mikabombshadow_init(int* obj);

void StaticCamera_init(int* obj, int* params, int flag);

extern void storeZeroToFloatParam(f32 * p);
extern f32 lbl_803E33A0;
extern f32 lbl_803DBD60;
extern f32 lbl_803E338C;

void flamethrowerspe_init(int* obj, int* params);

extern void Sfx_RemoveLoopedObjectSoundForObject(int* obj);
extern void clearCurSeqNo(void);

void animatedobj_free(int* obj, int seqFlag);

extern int mmAlloc(int size, int a, int b);
extern f32 lbl_803E3328;
extern u8 lbl_803AC6B8[];

void staff_init(int* obj);

extern void fn_8003B5E0(int a, int b, int c, int d);
extern f32 lbl_803E3400;
extern f32 lbl_803E3404;

void dll_F7_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);

extern f32 lbl_803E32B4;
extern f32 lbl_803E3320;
extern f32 lbl_803E3288;
extern f32 lbl_803E3324;

void staffDoGrowShrinkAnim(int* obj, u8 grow, u8 flag2);


void dll_F7_init(int* obj, int* params);


extern void modelLightStruct_setEnabled(int handle, int flag, f32 v);
extern f32 lbl_803E3330;


extern int cmbsrc_getColorIndex(int* p);
extern void modelLightStruct_setDiffuseColor(int* light, int r, int g, int b, int a);
extern void projectileParticleFxFn_80099660(int* obj, f32 v, int kind);
extern f32 lbl_803E3354;
extern f32 lbl_803E3358;

void fireball_hitDetect(int* obj);

extern void objSetSlot(int* obj, int slot);
extern f32 lbl_803E3270;

void dim2roofrub_init(int* obj, int* params);

extern void Obj_SetModelRenderOpAlpha(int* obj, int alpha);
extern f32 lbl_803E3228;

void animatedobj_init(int* obj, int* params);

extern void objMove(int* obj, f32 x, f32 y, f32 z);
extern void s16toFloat(f32* out, s16 v);
extern void vecRotateZXY(int* obj, f32* p);
extern void firepipe_releaseEffectObject(int* obj);
extern int timerCountDown(f32 * p);
extern f32 lbl_803E3390;
extern f32 lbl_803E3394;
extern f32 lbl_803DBD68;
extern f32 lbl_803DBD6C;
extern int lbl_803DBD64;

void flamethrowerspe_update(int* obj);

extern u32 lbl_803E31A0;
extern f32 lbl_803E31A4;
extern f32 lbl_803E31A8;
extern f32 lbl_803E31AC;
extern f32 lbl_803E31B0;
extern f32 lbl_803E31C4;
extern f32 lbl_803E31C8;
extern f32 lbl_803E31CC;
extern f32 lbl_803E31D0;
extern f32 lbl_803E31D4;
extern void CameraShake_Start(f32 a, f32 b, f32 c);
extern int loadObjectAtObject(int* obj, void* params);


void mikabomb_init(int* obj);

extern f32 vec3f_distanceSquared(f32 * a, f32 * b);
extern void GameBit_Set(int eventId, int value);
extern int* gSHthorntailAnimationInterface;
extern void fn_801504BC(int* obj, int kind);
extern f32 lbl_803E3224;

#pragma opt_loop_invariants off
void baddieinterestp_update(int* obj);
#pragma opt_loop_invariants reset

extern int* ObjList_GetObjects(int* startIndex, int* objectCount);
extern f32 lbl_803E322C;

#pragma opt_loop_invariants off
void animatedobj_update(int* obj);
#pragma opt_loop_invariants reset

extern void Obj_BuildWorldTransformMatrix(int* obj, f32* m, int p3);
extern void PSMTXTrans(f32* m, f32 x, f32 y, f32 z);
extern void PSMTXConcat(f32 * a, f32 * b, f32 * out);
extern void PSMTXRotRad(f32* m, int axis, f32 rad);
extern void objRenderModel(int* obj);
extern void objSetMtxFn_800412d4(f32 * m);
extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
extern f32 lbl_803E3230;

void animatedobj_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);

typedef struct Dim2FxRow
{
    f32 x;
    f32 y;
    f32 z;
    f32 w;
    u8 b1;
    u8 b2;
    u8 pad[2];
} Dim2FxRow;

typedef struct Dim2FxVec
{
    u8 pad[8];
    f32 fade;
    f32 x;
    f32 y;
    f32 z;
} Dim2FxVec;

extern void objfx_spawnMaskedHitEffect(int* obj, f32 scale, int a, int b, int c, void* params);
extern void objfx_spawnLightPulse(int* obj, f32 scale, int a, int b, int c, f32 v, void* params);
extern f32 lbl_803E3240;
extern f32 lbl_803E3244;
extern f32 lbl_803E3248;
extern f32 lbl_803E324C;
extern f32 lbl_803E3250;
extern f32 lbl_803E3254;
extern f32 lbl_803E3258;
extern f32 lbl_803E325C;
extern f32 lbl_803E3260;
extern f32 lbl_803E3264;
extern f32 lbl_803E3268;
extern f32 lbl_803E326C;
extern f32 lbl_803E3274;
extern f32 lbl_803E3278;
extern f32 lbl_803E327C;

void dim2roofrub_spawnEffects(int* obj);

void dim2roofrub_render(int* obj, int p2, int p3, int p4, int p5);

typedef struct Dim2PartVec
{
    u8 pad[0xc];
    f32 x;
    f32 y;
    f32 z;
} Dim2PartVec;

void dim2roofrub_update(int* obj);

extern int objCreateLight(int* obj, int arg);
extern void lightSetField4D(int light, int v);
extern void lightSetFieldBC_8001db14(int light, int v);
extern void modelLightStruct_setPosition(int light, f32 a, f32 b, f32 c);
extern void modelLightStruct_setDistanceAttenuation(int light, f32 a, f32 b);
extern void modelLightStruct_setupGlow(int light, int a, int r, int g, int b, int e, f32 f);
extern void modelLightStruct_setGlowProjectionRadius(int light, f32 a);
extern void modelLightStruct_setLightKind(int light, int v);
extern f32 lbl_803E3378;
extern f32 lbl_803E337C;
extern f32 lbl_803E3380;

void fireball_init(int* obj);

extern f32 Vec3_Length(f32 * v);
extern int hitDetectFn_800658a4(int* obj, f32 x, f32 y, f32 z, f32* out, int flag);
extern WaterfxInterface** gWaterfxInterface;
extern f32 mathSinf(f32 v);
extern f32 mathCosf(f32 x);
extern void fn_8016F260(int* obj, int* state, int* other);
extern f32 lbl_803E3334;
extern f32 lbl_803E3338;
extern f32 lbl_803E333C;
extern f32 lbl_803E335C;
extern f32 lbl_803E3360;
extern f32 lbl_803E3364;
extern f32 lbl_803E3368;
extern f32 lbl_803E336C;

void fireball_update(int* obj);

extern u8 lbl_803DBD58[8];
extern void queueGlowRender(int light);
extern f32 lbl_803E3350;

void fireball_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);

extern int getAngle(f32 a, f32 b);
extern f32 sqrtf(f32 x);
extern f32 lbl_803E3340;

void fn_8016F260(int* obj, int* state, int* other);

extern f32 fcos16(u16 angle);
extern void Sfx_SetObjectSfxVolume(f32 ratio, s16* obj, int sfx, int vol);
extern f32 lbl_803E33A8;
extern f32 lbl_803E33AC;
extern f32 lbl_803E33C4;
extern f32 lbl_803E33E8;
extern f32 lbl_803E33EC;

void shield_update(int* obj);

typedef struct DllF7Vec
{
    u8 b[16];
} DllF7Vec;

extern DllF7Vec lbl_802C2260;

/* dll_F7 (bouncing prop) object extra-state */
typedef struct DllF7State
{
    f32 bounceOffset;
    f32 bounceVelocity;
    u8 byte8;
    s8 byte9;
    s8 hitsRemaining;
    s8 byteB;
} DllF7State;

extern void Sfx_PlayAtPositionFromObject(int* obj, f32 x, f32 y, f32 z, int sfx);
extern void Obj_SetActiveModelIndex(int* obj, int idx);
extern f32 lbl_803E3408;
extern f32 lbl_803E340C;
extern f32 lbl_803E3410;
extern f32 lbl_803E3414;
extern f32 lbl_803E3418;

void dll_F7_update(int* obj);

extern s16 lbl_803DBD50[4];
extern s16* lbl_803DDAA4;
extern void* textureLoad(int id, int flag);

void staff_initialise(void);

typedef struct ShieldFxVec
{
    u8 pad[8];
    f32 a;
    f32 v[3];
} ShieldFxVec;

extern s16 lbl_803DBD70[4];
extern s16 lbl_803DBD78[4];
extern s16 lbl_803DBD80[4];
extern s16 lbl_803DBD88[4];
extern f32 lbl_803E33D8;
extern f32 lbl_803E33DC;

void shield_render(int* obj, int p2, int p3, int p4, int p5, s8 visible);

extern void quakeSpellTextureFn_8007366c(int param);
extern f32* Camera_GetViewMatrix(void);
extern void PSMTXScale(f32* m, f32 x, f32 y, f32 z);
extern void GXLoadPosMtxImm(f32* m, int id);
extern void GXLoadTexMtxImm(f32* m, int id, int type);
extern void GXDrawTorus(f32 rc, u8 numc, u8 numt);
extern void* memcpy(void* dst, const void* src, unsigned int n);
extern f32 lbl_803E3300;

void quakeSpellTextureFn_8016dbf4(void);

extern f32 lbl_803E32A8;
extern f32 lbl_803E3290;
extern f32 lbl_803E32F4;
extern f32 lbl_803E32F8;
extern f32 lbl_803E32FC;
extern f32 lbl_803E32D0;

typedef struct QuakePartVec
{
    u16 h0, h1, h2;
    f32 scale;
    f32 x, y, z;
} QuakePartVec;

void superQuakeFn_8016d9fc(f32* pos);

typedef struct SwipeColorTable
{
    u32 w[16];
} SwipeColorTable;

/* per-swipe trail record (stride 0x18, 3 records) */
typedef struct SwipeRecord
{
    u8* vertexData;
    u8 pad04[0xc - 0x4];
    u16 startIndex;
    u16 endIndex;
    u8 pad10[2];
    s16 vertexCount;
    u8 flags;
    u8 pad15[0x18 - 0x15];
} SwipeRecord;

extern SwipeColorTable lbl_802C2220;
void staffDrawSwipe(int* obj, int* swipe);

void staff_hitDetectGeometry(int* obj);

typedef union
{
    u8 u8;
    u16 u16;
    u32 u32;
    s16 s16;
    s32 s32;
    f32 f32;
} GenPropsWGPipe;

volatile GenPropsWGPipe GXWGFifo : (0xCC008000);

static inline void swipePos3f32(const f32 x, const f32 y, const f32 z);

static inline void swipeColor4u8(const u8 r, const u8 g, const u8 b, const u8 a);

static inline void swipeTexCoord2f32(const f32 s, const f32 t);

extern void selectTexture(void* tex, int x);
extern void textureSetupFn_800799c0(void);
extern void geomDrawFn_800796f0(void);
extern void textRenderSetupFn_80079804(void);
extern void GXSetBlendMode(int a, int b, int c, int d);
extern void GXSetAlphaCompare(int a, int b, int c, int d, int e);
extern void GXSetCullMode(int a);
extern void GXClearVtxDesc(void);
extern void GXSetVtxDesc(int a, int b);
extern void GXSetCurrentMtx(int a);
extern void GXBegin(int type, int fmt, int n);
extern f32 lbl_803E3294;

#pragma opt_common_subs off

extern int objGetAnimState80A(int obj);
extern f32 lbl_803E330C;
extern f32 lbl_803E3310;
extern f32 lbl_803E332C;
extern f32 lbl_803E32E0;
extern f32 lbl_803E32E4;
extern f32 lbl_803E32E8;
extern f32 lbl_803E32EC;
extern f32 lbl_803E32F0;

void staff_update(int* obj);

extern void playerAddHealth(void* player, int amount);
extern void gameBitIncrement(int eventId);
extern void saveGame_unsaveObjectPos(int* obj);
extern f32 lbl_803E3450;
extern f32 lbl_803E3454;

void fn_80171E5C(int* obj)
{
    extern undefined8 ObjHits_DisableObject(); /* #57 */
    extern void itemPickupDoParticleFx(int* obj, f32 f, int a, int b); /* #57 */
    extern void Sfx_PlayFromObject(int* obj, int sfx); /* #57 */
    extern void* Obj_GetPlayerObject(void); /* #57 */
    u8* state = ((GameObject*)obj)->extra;
    u8* params = *(u8**)&((GameObject*)obj)->anim.placementData;
    u8* setup2 = *(u8**)(*(int*)&((GameObject*)obj)->anim.modelInstance + 0x18);
    Obj_GetPlayerObject();
    getTrickyObject();
    Obj_GetPlayerObject();
    getTrickyObject();
    ObjHits_DisableObject(obj);
    if (((GameObject*)obj)->anim.flags & 0x2000)
    {
        *(f32*)(state + 8) = lbl_803E3450;
        if (((GameObject*)obj)->anim.modelState != NULL)
        {
            ((GameObject*)obj)->anim.modelState->flags = OBJ_MODEL_STATE_SHADOW_FADE_OUT;
        }
    }
    if (*(s16*)(state + 0x10) != -1)
    {
        GameBit_Set(*(s16*)(state + 0x10), 1);
        saveGame_unsaveObjectPos(obj);
    }
    if (*(s16*)(params + 0x1e) != -1)
    {
        GameBit_Set(*(s16*)(params + 0x1e), 1);
    }
    if (*(s16*)(params + 0x2c) > 0)
    {
        gameBitIncrement(*(s16*)(params + 0x2c));
    }
    switch (*(s16*)(setup2 + 2))
    {
    case 1:
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 90:
            Sfx_PlayFromObject(obj, 73);
            itemPickupDoParticleFx(obj, lbl_803E3454, 2, 40);
            break;
        case 793:
            Sfx_PlayFromObject(obj, 362);
            GameBit_Set(1001, 1);
            *(s16*)(state + 0x3c) = 1200;
            itemPickupDoParticleFx(obj, lbl_803E3454, 255, 40);
            break;
        case 1702:
            {
                s8 c = GameBit_Get(2154);
                if (c < 7)
                {
                    c = c + 1;
                }
                GameBit_Set(2154, c);
                itemPickupDoParticleFx(obj, lbl_803E3454, 6, 40);
                Sfx_PlayFromObject(obj, 73);
                break;
            }
        case 34:
            Sfx_PlayFromObject(obj, 73);
            itemPickupDoParticleFx(obj, lbl_803E3454, 255, 40);
            break;
        default:
            Sfx_PlayFromObject(obj, 88);
            itemPickupDoParticleFx(obj, lbl_803E3454, 255, 40);
            break;
        }
        break;
    case 4:
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 11:
            Sfx_PlayFromObject(Obj_GetPlayerObject(), 73);
            playerAddHealth(Obj_GetPlayerObject(), 4);
            itemPickupDoParticleFx(obj, lbl_803E3454, 3, 40);
            break;
        case 973:
            playerAddHealth(Obj_GetPlayerObject(), 2);
            Sfx_PlayFromObject(Obj_GetPlayerObject(), 73);
            itemPickupDoParticleFx(obj, lbl_803E3454, 1, 40);
            break;
        default:
            Sfx_PlayFromObject(Obj_GetPlayerObject(), 88);
            itemPickupDoParticleFx(obj, lbl_803E3454, 255, 40);
            break;
        }
        break;
    default:
        Sfx_PlayFromObject(obj, 88);
        itemPickupDoParticleFx(obj, lbl_803E3454, 255, 40);
        break;
    }
    ((GameObject*)obj)->anim.rootMotionScale = *(f32*)(*(int*)&((GameObject*)obj)->anim.modelInstance + 4);
    ((GameObject*)obj)->unkF4 = 1;
}

extern f32 lbl_803E345C;
extern f32 lbl_803E3460;
extern f32 lbl_803E3464;
extern f32 lbl_803E3468;
extern f32 lbl_803E346C;

void fn_80172144(int* obj)
{
    u8* state = ((GameObject*)obj)->extra;
    if (((GameObject*)obj)->anim.seqId == 1702)
    {
        objMove(obj, lbl_803E345C, ((GameObject*)obj)->anim.velocityY * (f32)(u32)framesThisStep, lbl_803E345C);
    }
    else
    {
        u8 n = framesThisStep;
        objMove(obj, ((GameObject*)obj)->anim.velocityX * (f32)(u32)n,
                ((GameObject*)obj)->anim.velocityY * (f32)(u32)n,
                ((GameObject*)obj)->anim.velocityZ * (f32)(u32)n);
    }
    (*gPathControlInterface)->update(obj, state + 0x50, timeDelta);
    (*gPathControlInterface)->apply(obj, state + 0x50);
    (*gPathControlInterface)->advance(obj, state + 0x50, timeDelta);
    if (*(s8*)(state + 0x2b1) != 0)
    {
        f32 nx = -((GameObject*)obj)->anim.velocityX;
        f32 ny = -((GameObject*)obj)->anim.velocityY;
        f32 nz = -((GameObject*)obj)->anim.velocityZ;
        f32 len = sqrtf(nx * nx + ny * ny + nz * nz);
        if (lbl_803E345C != len)
        {
            f32 inv = lbl_803E3454 / len;
            nx = nx * inv;
            ny = ny * inv;
            nz = nz * inv;
        }
        {
            f32 px = *(f32*)(state + 0xb8);
            f32 py = *(f32*)(state + 0xbc);
            f32 pz = *(f32*)(state + 0xc0);
            f32 d = lbl_803E3460 * (nx * px + ny * py + nz * pz);
            ((GameObject*)obj)->anim.velocityX = px * d;
            ((GameObject*)obj)->anim.velocityY = py * d;
            ((GameObject*)obj)->anim.velocityZ = pz * d;
        }
        ((GameObject*)obj)->anim.velocityX -= nx;
        ((GameObject*)obj)->anim.velocityY -= ny;
        ((GameObject*)obj)->anim.velocityZ -= nz;
        ((GameObject*)obj)->anim.velocityY *= len;
        ((GameObject*)obj)->anim.velocityY *= lbl_803E3464;
        ((GameObject*)obj)->anim.velocityX *= len;
        ((GameObject*)obj)->anim.velocityZ *= len;
        state[0x1d] -= 1;
        if (state[0x1d] == 0)
        {
            f32 z;
            state[0x1d] = 0;
            z = lbl_803E345C;
            ((GameObject*)obj)->anim.velocityX = z;
            ((GameObject*)obj)->anim.velocityY = z;
            ((GameObject*)obj)->anim.velocityZ = z;
        }
    }
    else
    {
        ((GameObject*)obj)->anim.velocityY = ((GameObject*)obj)->anim.velocityY * lbl_803E3468;
        ((GameObject*)obj)->anim.velocityY = -(lbl_803E346C * timeDelta - ((GameObject*)obj)->anim.velocityY);
    }
}

extern f32 fastFloorf(f32 v);
extern f32 Curve_EvalBSpline(f32* a, f32 t, f32* out);
extern f32 lbl_803E3304;
extern f32 lbl_803E3308;
extern f32 lbl_803E32A4;
extern f32 lbl_803E32AC;

void staff_setupSwipe(int p1, int p2, int p3, int p4);

extern int* fn_802966CC(int* player);
extern void modelLightStruct_setSpecularColor(int light, int r, int g, int b, int a);
extern void modelLightStruct_startColorFade(int light, int a, int b);
extern void modelLightStruct_setAffectsAabbLightSelection(int light, int v);
extern f32 lbl_803E33B0;
extern f32 lbl_803E33B4;
extern f32 lbl_803E33B8;
extern f32 lbl_803E33BC;
extern f32 lbl_803E33C0;
extern f32 lbl_803E33C8;
extern f32 lbl_803E33CC;


extern int objFn_80296700(int* obj);
extern void objfx_spawnArcedBurst(int* obj, f32 a, int type, int ba, int one, int n, f32 b, f32 c, f32 d, int x, int y);
extern void fn_802961A4(int* obj, int* type, f32* power);
extern void fn_802960F4(int objc4, u8** out);
extern f32 lbl_803E328C;
extern f32 lbl_803E3298;
extern f32 lbl_803E329C;
extern f32 lbl_803E32A0;
extern f32 lbl_803E32B0;
extern f32 lbl_803E32B8;
extern f32 lbl_803E32BC;
extern f32 lbl_803E32C0;
extern f32 lbl_803E32C4;
extern f32 lbl_803E32C8;
extern f32 lbl_803E32CC;
extern f32 lbl_803E32D4;
extern f32 lbl_803E32D8;
extern f32 lbl_803E32DC;

typedef struct QuakeFxParams
{
    u16 id;
    u16 a;
    u16 b;
    s16 count;
    f32 f0;
    f32 f1;
    f32 f2;
    f32 f3;
} QuakeFxParams;

void quakeSpellFn_8016cee8(int* obj, int* obj2);
#pragma scheduling reset
#pragma peephole reset
/* segment pragma-stack balance (re-split): */
#pragma opt_common_subs reset

#include "main/audio/sfx_ids.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
#include "main/game_object.h"
#include "main/dll/path_control_interface.h"
#include "main/dll/gfxemit_state.h"
#include "main/dll/gfxEmit.h"
#include "main/objanim_internal.h"
#include "main/objhits_types.h"

extern undefined4 FUN_80017710();
extern u32 randomGetRange(int min, int max);
extern undefined4 FUN_80017a88();
extern undefined4 ObjMsg_SendToObject();
extern int ObjTrigger_IsSet();
extern undefined4 FUN_8003b56c();
extern undefined4 FUN_800810f4();
extern int FUN_80286840();
extern undefined4 FUN_8028688c();
extern double FUN_80293900();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern uint FUN_80294c78();
extern int FUN_80294dbc();
extern uint countLeadingZeros();

extern undefined4 DAT_803dc070;
extern f64 DOUBLE_803e40e0;
extern f64 DOUBLE_803e4108;
extern f32 lbl_803E40F0;
extern f32 lbl_803E40F4;
extern f32 lbl_803E40F8;
extern f32 lbl_803E40FC;
extern f32 lbl_803E4100;
extern f32 lbl_803E4104;
extern f32 lbl_803E4110;
extern f32 lbl_803E4114;
extern f32 lbl_803E4118;
extern f32 lbl_803E411C;
extern f32 lbl_803E4124;
extern f32 lbl_803E4128;

/*
 * --INFO--
 *
 * Function: FUN_801723dc
 * EN v1.0 Address: 0x801723DC
 * EN v1.0 Size: 720b
 * EN v1.1 Address: 0x801725F0
 * EN v1.1 Size: 664b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801723dc(int param_1)
{
    float fVar1;
    float fVar2;
    uint uVar3;
    int iVar4;
    double dVar5;
    double dVar6;
    double dVar7;
    double dVar8;
    double dVar9;

    GfxEmitState* state = ((GameObject*)param_1)->extra;
    iVar4 = (int)state;
    if (((GameObject*)param_1)->anim.seqId == 0x6a6)
    {
        FUN_80017a88((double)lbl_803E40F4,
                     (double)(((GameObject*)param_1)->anim.velocityY *
                         (float)((double)CONCAT44(0x43300000, (uint)DAT_803dc070) - DOUBLE_803e4108))
                     , (double)lbl_803E40F4, param_1);
    }
    else
    {
        uVar3 = (uint)DAT_803dc070;
        FUN_80017a88((double)(((GameObject*)param_1)->anim.velocityX *
                         (float)((double)CONCAT44(0x43300000, uVar3) - DOUBLE_803e4108)),
                     (double)(((GameObject*)param_1)->anim.velocityY *
                         (float)((double)CONCAT44(0x43300000, uVar3) - DOUBLE_803e4108)),
                     (double)(((GameObject*)param_1)->anim.velocityZ *
                         (float)((double)CONCAT44(0x43300000, uVar3) - DOUBLE_803e4108)), param_1);
    }
    (*gPathControlInterface)->update((void*)param_1, state->pathState, lbl_803DC074);
    (*gPathControlInterface)->apply((void*)param_1, state->pathState);
    (*gPathControlInterface)->advance((void*)param_1, state->pathState, lbl_803DC074);
    if (*(char*)&((GfxEmitState*)iVar4)->unk2B1 == '\0')
    {
        ((GameObject*)param_1)->anim.velocityY = ((GameObject*)param_1)->anim.velocityY * lbl_803E4100;
        ((GameObject*)param_1)->anim.velocityY = -(lbl_803E4104 * lbl_803DC074 - ((GameObject*)param_1)->anim.
            velocityY);
    }
    else
    {
        dVar8 = -(double)((GameObject*)param_1)->anim.velocityX;
        dVar7 = -(double)((GameObject*)param_1)->anim.velocityY;
        dVar9 = -(double)((GameObject*)param_1)->anim.velocityZ;
        dVar6 = FUN_80293900((double)(float)(dVar9 * dVar9 +
            (double)(float)(dVar8 * dVar8 +
                (double)(float)(dVar7 * dVar7))));
        if ((double)lbl_803E40F4 != dVar6)
        {
            dVar5 = (double)(float)((double)lbl_803E40EC / dVar6);
            dVar8 = (double)(float)(dVar8 * dVar5);
            dVar7 = (double)(float)(dVar7 * dVar5);
            dVar9 = (double)(float)(dVar9 * dVar5);
        }
        fVar1 = *(float*)(iVar4 + 0xbc);
        fVar2 = *(float*)(iVar4 + 0xc0);
        dVar5 = (double)(lbl_803E40F8 *
            (float)(dVar9 * (double)fVar2 +
                (double)(float)(dVar8 * (double)*(float*)(iVar4 + 0xb8) +
                    (double)(float)(dVar7 * (double)fVar1))));
        ((GameObject*)param_1)->anim.velocityX = (float)((double)*(float*)(iVar4 + 0xb8) * dVar5);
        ((GameObject*)param_1)->anim.velocityY = (float)((double)fVar1 * dVar5);
        ((GameObject*)param_1)->anim.velocityZ = (float)((double)fVar2 * dVar5);
        ((GameObject*)param_1)->anim.velocityX = (float)((double)((GameObject*)param_1)->anim.velocityX - dVar8);
        ((GameObject*)param_1)->anim.velocityY = (float)((double)((GameObject*)param_1)->anim.velocityY - dVar7);
        ((GameObject*)param_1)->anim.velocityZ = (float)((double)((GameObject*)param_1)->anim.velocityZ - dVar9);
        ((GameObject*)param_1)->anim.velocityY = (float)((double)((GameObject*)param_1)->anim.velocityY * dVar6);
        ((GameObject*)param_1)->anim.velocityY = ((GameObject*)param_1)->anim.velocityY * lbl_803E40FC;
        ((GameObject*)param_1)->anim.velocityX = (float)((double)((GameObject*)param_1)->anim.velocityX * dVar6);
        ((GameObject*)param_1)->anim.velocityZ = (float)((double)((GameObject*)param_1)->anim.velocityZ * dVar6);
        *(char*)&((GfxEmitState*)iVar4)->unk1D = *(char*)&((GfxEmitState*)iVar4)->unk1D + -1;
        if (*(char*)&((GfxEmitState*)iVar4)->unk1D == '\0')
        {
            ((GfxEmitState*)iVar4)->unk1D = 0;
            fVar1 = lbl_803E40F4;
            ((GameObject*)param_1)->anim.velocityX = lbl_803E40F4;
            ((GameObject*)param_1)->anim.velocityY = fVar1;
            ((GameObject*)param_1)->anim.velocityZ = fVar1;
        }
    }
    return;
}


/*
 * --INFO--
 *
 * Function: collectible_free
 * EN v1.0 Address: 0x80173040
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x80172F80
 * EN v1.1 Size: 72b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
#pragma scheduling off
void collectible_free(int obj)
{
    (*gExpgfxInterface)->freeSource2((u32)obj);
    ObjGroup_RemoveObject(obj, 4);
    return;
}
#pragma scheduling reset


/*
 * --INFO--
 *
 * Function: collectible_getExtraSize
 * EN v1.0 Address: 0x80172E34
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80172D70
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int collectible_getExtraSize(void)
{
    return 0x2b8;
}

/*
 * --INFO--
 *
 * Function: collectible_getObjectTypeId
 * EN v1.0 Address: 0x80172E3C
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80172D78
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int collectible_getObjectTypeId(void)
{
    return 0x13;
}

/*
 * --INFO--
 *
 * Function: collectible_hitDetect
 * EN v1.0 Address: 0x80172F90
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80172ECC
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void collectible_hitDetect(void)
{
}

extern uint GameBit_Get(int);
extern f32 mathSinf(f32 x);
extern f32 lbl_803E3458;
extern f32 lbl_803E3484;
extern f32 lbl_803E3488;
extern f32 lbl_803E348C;

#pragma scheduling off
#pragma peephole off
int collectible_SeqFn(int obj, int unused, ObjAnimUpdateState* animUpdate)
{
    extern void objfx_spawnDirectionalBurst(int obj, int a, f32 fa, int b, int c, int d, f32 fb, int e, int f); /* #57 */
    int* state = ((GameObject*)obj)->extra;
    f32 buf[6];
    int j;
    int i;
    f32 s_val;
    f32 c_val;
    f32 vy;

    if (((GfxEmitState*)state)->enableGameBit != -1)
    {
        ((GfxEmitState*)state)->enableGameBitClear = (u8)(GameBit_Get((s32)((GfxEmitState*)state)->enableGameBit) == 0);
    }
    if (((GfxEmitState*)state)->enableGameBitClear == 0)
    {
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 0x6a6:
            objfx_spawnDirectionalBurst(obj, 5, lbl_803E3454, 6, 1, 0x14, lbl_803E3458, 0, 0);
            break;
        }
    }

    animUpdate->sequenceEventActive = 0;
    for (i = 0; i < (s32)animUpdate->eventCount; i++)
    {
        u8 cmd = animUpdate->eventIds[i];
        if (cmd == 1)
        {
            s_val = lbl_803E3484 * mathCosf(lbl_803E3488);
            c_val = lbl_803E3484 * mathSinf(lbl_803E3488);
            *(u8*)((char*)((GameObject*)obj)->extra + 0x1d) = 8;
            ((GameObject*)obj)->anim.velocityX = c_val;
            ((GameObject*)obj)->anim.velocityY = (vy = lbl_803E3460);
            ((GameObject*)obj)->anim.velocityZ = s_val;
            *(u8*)((char*)((GameObject*)obj)->extra + 0x1d) = 8;
            ((GameObject*)obj)->anim.velocityX = lbl_803E348C;
            ((GameObject*)obj)->anim.velocityY = vy;
            ((GameObject*)obj)->anim.velocityZ = lbl_803E345C;
        }
        else if (cmd == 2)
        {
            *(u8*)((char*)state + 0x3e) = 1;
        }
        else if (cmd == 3)
        {
            f32 z;
            j = 0;
            z = lbl_803E345C;
            for (; j < 10; j++)
            {
                buf[3] = z;
                buf[4] = z;
                buf[5] = z;
                (*gPartfxInterface)->spawnObject((void*)obj, 0x7ef, buf, 1,
                                                 -1, NULL);
            }
        }
    }
    return 0;
}

extern void fn_8003B608(s16 a, s16 b, s16 c);
extern u8* fn_802972A8(void);
extern f32 Vec_xzDistance(f32 * a, f32 * b);
extern int fn_8029622C(u8 * player);
extern void GameBit_Set(int bit, int value);
extern f32 lbl_803E3490;

void fn_80172824(int obj, u8* state)
{
    extern void fn_80171E5C(int obj); /* #57 */
    extern u8* Obj_GetPlayerObject(void); /* #57 */
    u8* player;
    s16* attach;
    u8* focus;
    f32 dist;
    f32 dy;

    attach = ((GameObject*)obj)->anim.placementData;
    player = Obj_GetPlayerObject();
    if (player == NULL)
    {
        return;
    }
    if ((state[0x37] & 1) != 0)
    {
        return;
    }
    focus = fn_802972A8();
    if (focus == NULL)
    {
        focus = player;
    }
    dist = Vec_xzDistance(&((GameObject*)obj)->anim.worldPosX, (f32*)(focus + 0x18));
    dy = *(f32*)(focus + 0x1c) - ((GameObject*)obj)->anim.worldPosY;
    if (dy < lbl_803E345C)
    {
        dy = -dy;
    }
    if (dy < lbl_803E3490 && dist < *(f32*)(state + 4) && fn_8029622C(player) != 0)
    {
        ((GfxEmitState*)state)->unk48 = -1;
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 0xb:
            if (GameBit_Get(0x90e) == 0)
            {
                ObjMsg_SendToObject(player, 0x7000a, obj, state + 0x48);
                GameBit_Set(0x90e, 1);
            }
            else
            {
                fn_80171E5C(obj);
            }
            state[0x37] |= 1;
            break;
        case 0x319:
            fn_80171E5C(obj);
            state[0x37] |= 1;
            break;
        case 0x49:
        case 0x2da:
        case 0x3cd:
            if (GameBit_Get(0x90f) == 0)
            {
                ObjMsg_SendToObject(player, 0x7000a, obj, state + 0x48);
                GameBit_Set(0x90f, 1);
            }
            else
            {
                fn_80171E5C(obj);
            }
            state[0x37] |= 1;
            break;
        case 0x6a6:
            if (GameBit_Get(0x9a8) == 0)
            {
                ObjMsg_SendToObject(player, 0x7000a, obj, state + 0x48);
                GameBit_Set(0x9a8, 1);
            }
            else
            {
                fn_80171E5C(obj);
            }
            state[0x37] |= 1;
            break;
        default:
            if (ObjTrigger_IsSet(obj) != 0)
            {
                GameBit_Set(0xa7b, 1);
                ((GfxEmitState*)state)->unk48 = attach[0xf];
                ObjMsg_SendToObject(player, 0x7000a, obj, state + 0x48);
                state[0x37] |= 1;
                if (((GameObject*)obj)->anim.modelState != NULL)
                {
                    ((GameObject*)obj)->anim.modelState->flags = OBJ_MODEL_STATE_SHADOW_FADE_OUT;
                }
            }
            break;
        }
    }
    *(f32*)state = dist;
}

extern f32 lbl_803E3478;
extern f32 lbl_803E347C;
extern f32 lbl_803E3480;

extern void fn_801723DC(int obj);


extern int ObjMsg_Pop(int obj, int* outMessage, int* outParam, int* outSender);

void collectible_update(int obj)
{
    extern void fn_80172144(int obj); /* #57 */
    extern void Obj_FreeObject(int obj); /* #57 */
    extern void ObjHits_DisableObject(int obj); /* #57 */
    extern void itemPickupDoParticleFx(int obj, f32 scale, int a, int b); /* #57 */
    extern void fn_80171E5C(int obj); /* #57 */
    extern u8* Obj_GetPlayerObject(void); /* #57 */
    extern void objfx_spawnDirectionalBurst(int obj, int a, f32 fa, int b, int c, int d, f32 fb, int e, int f); /* #57 */
    u8* state = ((GameObject*)obj)->extra;
    int msgParam;
    int msg;
    int t;
    f32 timer;
    f32 zero;

    *(u8*)&((GameObject*)obj)->anim.resetHitboxMode |= 8;
    timer = ((GfxEmitState*)state)->delayTimer;
    zero = lbl_803E345C;
    if (timer != zero)
    {
        ((GfxEmitState*)state)->delayTimer = timer - timeDelta;
        if (((GfxEmitState*)state)->delayTimer <= zero)
        {
            ((GfxEmitState*)state)->delayTimer = zero;
            ObjHits_DisableObject(obj);
            if ((((GameObject*)obj)->anim.flags & 0x2000) != 0)
            {
                Obj_FreeObject(obj);
            }
        }
        return;
    }
    if (((GfxEmitState*)state)->enableGameBit != -1)
    {
        state[0x1e] = (u8)(GameBit_Get((s32)((GfxEmitState*)state)->enableGameBit) == 0);
    }
    if (state[0x1e] != 0 || state[0xf] != 0)
    {
        return;
    }
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x6a6:
        objfx_spawnDirectionalBurst(obj, 5, lbl_803E3454, 6, 1, 0x14, lbl_803E3458, 0, 0);
        break;
    }
    timer = ((GfxEmitState*)state)->intervalTimer;
    zero = lbl_803E345C;
    if (timer != zero)
    {
        ((GfxEmitState*)state)->intervalTimer = timer - timeDelta;
        if (((GfxEmitState*)state)->intervalTimer <= zero)
        {
            if ((((GameObject*)obj)->anim.flags & 0x2000) != 0)
            {
                ((GfxEmitState*)state)->delayTimer = lbl_803E3450;
                if (((GameObject*)obj)->anim.modelState != NULL)
                {
                    ((GameObject*)obj)->anim.modelState->flags = OBJ_MODEL_STATE_SHADOW_FADE_OUT;
                }
                itemPickupDoParticleFx(obj, lbl_803E3454, 255, 40);
            }
            ((GfxEmitState*)state)->intervalTimer = lbl_803E345C;
            return;
        }
    }
    while (ObjMsg_Pop(obj, &msg, &msgParam, NULL) != 0)
    {
        switch (msg)
        {
        case 0x7000b:
            fn_80171E5C(obj);
            break;
        }
    }
    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0x319:
        t = ((GfxEmitState*)state)->hideFrames;
        if (t != 0)
        {
            ((GfxEmitState*)state)->hideFrames -= framesThisStep;
            if (((GfxEmitState*)state)->hideFrames <= 0)
            {
                ((GfxEmitState*)state)->hideFrames = 0;
                state[0x37] &= ~1;
                ((GameObject*)obj)->anim.alpha = 255;
                ((GameObject*)obj)->unkF4 = 0;
            }
        }
        break;
    }
    if (((GameObject*)obj)->unkF4 != 0)
    {
        if (((GameObject*)obj)->anim.hitReactState != NULL)
        {
            (*(ObjHitsPriorityState**)&((GameObject*)obj)->anim.hitReactState)->flags |= 0x100;
        }
        ObjHits_DisableObject(obj);
        if (((GfxEmitState*)state)->hideGameBit != -1 && GameBit_Get((s32)((GfxEmitState*)state)->hideGameBit) == 0)
        {
            ((GameObject*)obj)->unkF4 = 0;
        }
    }
    else
    {
        *(u8*)&((GameObject*)obj)->anim.resetHitboxMode &= ~8;
        fn_801723DC(obj);
        if (state[0x1d] != 0)
        {
            fn_80172144(obj);
        }
        if (state[0x3e] != 0)
        {
            state[0x3e]--;
            if (state[0x3e] == 0)
            {
                ((GfxEmitState*)state)->unk48 = -1;
                ObjMsg_SendToObject(Obj_GetPlayerObject(), 0x7000a, obj, state + 0x48);
            }
        }
        else
        {
            fn_80172824(obj, state);
        }
    }
}

void collectible_render(int obj, int a, int b, int c, int d, s8 visible)
{
    extern void objRenderFn_8003b8f4(int obj, int a, int b, int c, int d, f32 e); /* #57 */
    extern void objfx_spawnDirectionalBurst(int obj, int a, f32 fa, int b, int c, int d, f32 fb, int e, int f); /* #57 */
    int state = *(int*)&((GameObject*)obj)->extra;
    if (visible != 0 && ((GfxEmitState*)state)->delayTimer == lbl_803E345C && ((GameObject*)obj)->unkF4 == 0
        && (((GameObject*)obj)->anim.seqId == 0x156 || ((GfxEmitState*)state)->enableGameBitClear == 0))
    {
        if ((((ObjAnimComponent*)obj)->modelInstance->flags & 0x10000) != 0 && ((GfxEmitState*)state)->useColor != 0)
        {
            fn_8003B608(((GfxEmitState*)state)->colorR, ((GfxEmitState*)state)->colorG, ((GfxEmitState*)state)->colorB);
        }
        objRenderFn_8003b8f4(obj, a, b, c, d, lbl_803E3454);
        if (((GameObject*)obj)->anim.seqId == 0xa8)
        {
            objfx_spawnDirectionalBurst(obj, 7, lbl_803E3454, 5, 1, 10, lbl_803E348C, 0, 0x20000000);
        }
    }
}

void fn_801723DC(int obj)
{
    extern void itemPickupDoParticleFx(int obj, f32 scale, int a, int b); /* #57 */
    extern void Sfx_PlayFromObject(int obj, int sfx); /* #57 */
    u8* state = ((GameObject*)obj)->extra;

    switch (((GameObject*)obj)->anim.seqId)
    {
    case 0xb:
        if ((((GfxEmitState*)state)->spinTimer -= framesThisStep) <= 0)
        {
            ((GfxEmitState*)state)->spinSpeed = (f32)(int)
            randomGetRange(600, 800);
            ((GfxEmitState*)state)->spinTimer = (s16)randomGetRange(180, 240);
            Sfx_PlayFromObject(obj, SFXwp_whiz3_c);
        }
        ((GameObject*)obj)->anim.rotY = ((GfxEmitState*)state)->spinSpeed;
        ((GfxEmitState*)state)->spinSpeed *= lbl_803E3478;
        if (((GameObject*)obj)->anim.rotY < 10 && ((GameObject*)obj)->anim.rotY > -10)
        {
            ((GameObject*)obj)->anim.rotY = 0;
        }
        break;
    case 0x12d:
    case 0x135:
    case 0x137:
    case 0x156:
    case 0x246:
        *(s16*)obj = lbl_803E347C * timeDelta + (f32) * (s16*)obj;
        break;
    case 0x22:
        *(s16*)obj = lbl_803E347C * timeDelta + (f32) * (s16*)obj;
        itemPickupDoParticleFx(obj, lbl_803E3454, 10, 1);
        break;
    case 0x27f:
        if (*(f32*)state < lbl_803E347C)
        {
            if ((int)randomGetRange(0, 10) == 0)
            {
                (*gPartfxInterface)->spawnObject((void*)obj, 0x423, NULL, 2,
                                                 -1, NULL);
            }
            *(s16*)obj += (s16)(lbl_803E3480 * timeDelta);
        }
        break;
    case 0x5e8:
        *(s16*)obj = lbl_803E347C * timeDelta + (f32) * (s16*)obj;
        itemPickupDoParticleFx(obj, lbl_803E3454, 9, 1);
        break;
    }
}

/* segment pragma-stack balance (re-split): */
#pragma scheduling reset
#pragma peephole reset

/* === moved from main/dll/texframeanimator.c [80172F14-80173224) (TU re-split, docs/boundary_audit.md) === */
#pragma scheduling off
#pragma peephole off
#include "main/dll/texframeanimator.h"
#include "main/obj_placement.h"
#include "main/effect_interfaces.h"
#include "main/expgfx.h"
/* IDENTITY NOTE: this TU contains the COLLECTIBLE/MAGICDUST family; the
 * real texframeanimator_* symbols live in MMP_asteroid.c (symbols.txt-
 * verified). File rename parked as a repo-owner proposal. */
#include "main/game_object.h"
#include "main/dll/collectible_state.h"
#include "main/dll/gfxEmit.h"
#include "main/dll/path_control_interface.h"
#include "main/objanim_internal.h"

extern uint GameBit_Get(int eventId);
extern int ObjMsg_Pop();
extern undefined4 ObjMsg_AllocQueue();

extern undefined4 DAT_803218a8;
extern undefined4 DAT_803e40d8;
extern undefined4 DAT_803e40dc;
extern f32 lbl_803E412C;
extern f32 lbl_803E4130;
extern f32 lbl_803E4134;
extern f32 lbl_803E4138;
extern u8 lbl_80320C58[];
extern u32 lbl_803E3440;
extern u8 lbl_803E3444;
extern f32 lbl_803E3494;
extern f32 lbl_803E3498;
extern f32 lbl_803E349C;
extern f32 lbl_803E34A0;

/*
 * --INFO--
 *
 * Function: collectible_init
 * EN v1.0 Address: 0x80172F14
 * EN v1.0 Size: 1104b
 * EN v1.1 Address: 0x801730D0
 * EN v1.1 Size: 752b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void collectible_init(int obj, int setup)
{
    ObjAnimComponent* objAnim;
    u8* state;
    int setupObj;
    int setupModelIndex;
    u8* data;
    u32 pathWord;
    u8 pathByte;

    objAnim = (ObjAnimComponent*)obj;
    state = ((GameObject*)obj)->extra;
    pathWord = lbl_803E3440;
    pathByte = lbl_803E3444;
    ObjGroup_AddObject(obj, 4);
    ObjMsg_AllocQueue(obj, 2);
    ((GameObject*)obj)->anim.rotX = (s16)((u8) * (u8*)(setup + 0x1b) << 8);
    ((GameObject*)obj)->anim.rotY = (s16)((u8) * (u8*)(setup + 0x22) << 8);
    ((GameObject*)obj)->anim.rotZ = (s16)((u8) * (u8*)(setup + 0x23) << 8);
    setupObj = (int)objAnim->modelInstance;
    ((GameObject*)obj)->anim.rootMotionScale = *(f32*)(setupObj + 4);
    ((GameObject*)obj)->animEventCallback = (void*)collectible_SeqFn;
    setupModelIndex = *(s8*)(setup + 0x26);
    objAnim->bankIndex = (s8)setupModelIndex;
    if (objAnim->bankIndex >= objAnim->modelInstance->modelCount)
    {
        objAnim->bankIndex = 0;
    }
    ((GameObject*)obj)->objectFlags = ((GameObject*)obj)->objectFlags | 0x2000;
    ((CollectibleState*)state)->unkC = *(u8*)(setup + 0x19);
    ((CollectibleState*)state)->unkD = *(u8*)(setup + 0x1a);
    ((CollectibleState*)state)->unkF = 0;
    ((CollectibleState*)state)->unk18 = -2;
    ((CollectibleState*)state)->unk1D = 0;
    ((CollectibleState*)state)->visibilityGameBit = *(s16*)(setup + 0x24);
    ((CollectibleState*)state)->mapId = ((ObjPlacement*)setup)->mapId;
    ((CollectibleState*)state)->basePosX = ((GameObject*)obj)->anim.localPosX;
    ((CollectibleState*)state)->basePosY = ((GameObject*)obj)->anim.localPosY;
    ((CollectibleState*)state)->basePosZ = ((GameObject*)obj)->anim.localPosZ;
    ((CollectibleState*)state)->unk36 = *(u8*)(setup + 0x27);
    ((CollectibleState*)state)->unk3E = 0;
    if (((CollectibleState*)state)->visibilityGameBit != -1)
    {
        ((CollectibleState*)state)->gameBitValue = (u8)(
            (u32)__cntlzw(GameBit_Get(((CollectibleState*)state)->visibilityGameBit)) >> 5);
    }
    ((CollectibleState*)state)->hideGameBit = *(s16*)(setup + 0x1c);
    if (((CollectibleState*)state)->hideGameBit != -1)
    {
        *(u32*)&((GameObject*)obj)->unkF4 = GameBit_Get(((CollectibleState*)state)->hideGameBit);
    }
    else
    {
        *(u32*)&((GameObject*)obj)->unkF4 = 0;
    }
    if (((GameObject*)obj)->unkF4 == 0)
    {
        data = *(u8**)(*(int*)&((GameObject*)obj)->anim.modelInstance + 0x18);
        if (data != 0)
        {
            ((CollectibleState*)state)->scale = (f32) * (s8*)(data + 8);
        }
        else
        {
            ((CollectibleState*)state)->scale = lbl_803E3494;
        }
        data = *(u8**)(*(int*)&((GameObject*)obj)->anim.modelInstance + 0x40);
        if (data != 0)
        {
            ((CollectibleState*)state)->scale = (f32)(s32)(*(u8*)(data + 0xc) << 2);
        }
        if (((((ObjAnimComponent*)obj)->modelInstance->flags & 0x10000) != 0) &&
            (((CollectibleState*)state)->unk36 != 0))
        {
            ((CollectibleState*)state)->unk38 = *(u8*)(setup + 0x28);
            ((CollectibleState*)state)->unk39 = *(u8*)(setup + 0x29);
            ((CollectibleState*)state)->unk3A = *(u8*)(setup + 0x2a);
        }
        switch (((GameObject*)obj)->anim.seqId)
        {
        case 0xb:
            ((CollectibleState*)state)->unk40 = lbl_803E345C;
            ((CollectibleState*)state)->unk44 = lbl_803E3498;
            break;
        case 0x3cd:
            ((CollectibleState*)state)->unk40 = lbl_803E349C;
            ((CollectibleState*)state)->unk44 = lbl_803E3498;
            break;
        default:
            ((CollectibleState*)state)->unk40 = lbl_803E34A0;
            break;
        }
        (*gPathControlInterface)->init(state + 0x50, 0, 0x40006, 1);
        (*gPathControlInterface)->setup(state + 0x50, 1, lbl_80320C58, &pathWord, &pathByte);
        (*gPathControlInterface)->attachObject((void*)obj, state + 0x50);
    }
}




/*
 * --INFO--
 *
 * Function: collectible_release
 * EN v1.0 Address: 0x8017321C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80173378
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void collectible_release(void)
{
}

/*
 * --INFO--
 *
 * Function: collectible_initialise
 * EN v1.0 Address: 0x80173220
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8017337C
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void collectible_initialise(void)
{
}

/* 8b "li r3, N; blr" returners. */

/* render-with-fn(lbl) (no visibility check). */
extern f32 lbl_803E34B0;
#pragma scheduling reset
#pragma peephole reset
