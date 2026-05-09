#include "ghidra_import.h"
#include "main/dll/baddie/Tumbleweed.h"
#include "main/dll/FRONT/dll_39.h"

extern undefined4 FUN_80003494();
extern undefined4 FUN_80006728();
extern undefined4 FUN_800067bc();
extern undefined4 FUN_800067c0();
extern bool FUN_800067f0();
extern undefined4 FUN_80006810();
extern undefined8 FUN_80006824();
extern void* FUN_800069a8();
extern int FUN_800069c0();
extern undefined4 FUN_800069d4();
extern byte FUN_80006b20();
extern undefined4 FUN_80006b30();
extern int FUN_80006b7c();
extern undefined4 FUN_80006b84();
extern uint FUN_80006c00();
extern uint FUN_80006c10();
extern undefined4 FUN_80006c84();
extern undefined8 FUN_80006c88();
extern void* FUN_80006c9c();
extern void* FUN_80017470();
extern undefined4 FUN_80017478();
extern undefined4 FUN_8001747c();
extern undefined8 FUN_80017484();
extern int FUN_8001748c();
extern undefined8 FUN_80017494();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern double FUN_80017708();
extern double FUN_80017714();
extern int FUN_80017730();
extern uint FUN_80017760();
extern int FUN_800178dc();
extern undefined4 FUN_800178e4();
extern undefined4 FUN_800178e8();
extern undefined4 FUN_80017964();
extern undefined4 FUN_80017a2c();
extern int FUN_80017a54();
extern int FUN_80017a98();
extern void* FUN_80017aa4();
extern undefined8 FUN_80017ac8();
extern undefined4 FUN_80017ae4();
extern int FUN_8002fc3c();
extern undefined4 FUN_800305f8();
extern uint ObjGroup_ContainsObject();
extern int ObjGroup_FindNearestObject();
extern void* ObjGroup_GetObjects();
extern undefined8 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern undefined4 FUN_80039468();
extern undefined4 FUN_8003b1a4();
extern undefined4 FUN_8003b280();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_8003b878();
extern undefined4 FUN_8004812c();
extern undefined8 FUN_80053754();
extern undefined4 FUN_8005398c();
extern uint FUN_8005b024();
extern undefined4 FUN_8005d370();
extern uint FUN_8006f764();
extern undefined4 FUN_8006fd90();
extern undefined4 FUN_80070414();
extern undefined4 FUN_8007089c();
extern undefined4 FUN_800709d8();
extern undefined4 FUN_800709e0();
extern undefined4 FUN_800709e8();
extern undefined4 FUN_800713a4();
extern undefined4 FUN_80080f70();
extern undefined4 FUN_80080f7c();
extern undefined4 FUN_80080f80();
extern int FUN_801113c0();
extern undefined4 FUN_80117318();
extern undefined4 FUN_801184b8();
extern undefined4 FUN_80129fb0();
extern undefined4 FUN_80129ff8();
extern undefined4 FUN_8012c9e8();
extern undefined4 FUN_801302a4();
extern ushort FUN_8013041c();
extern undefined4 FUN_80131cc4();
extern double FUN_8014cbcc();
extern undefined4 FUN_80242114();
extern undefined4 FUN_802430ec();
extern undefined4 FUN_80243e74();
extern undefined4 FUN_80243e9c();
extern undefined4 FUN_80246a0c();
extern undefined4 FUN_80246dcc();
extern undefined8 FUN_802475b8();
extern undefined4 FUN_80247a48();
extern undefined4 FUN_8024c8cc();
extern undefined4 FUN_8024c910();
extern undefined8 FUN_8024d054();
extern undefined4 FUN_8024dcb8();
extern undefined4 FUN_8024ddd4();
extern undefined4 FUN_80256bc4();
extern undefined4 FUN_802570dc();
extern undefined4 FUN_80257b5c();
extern undefined8 FUN_80258a94();
extern undefined4 FUN_80259000();
extern undefined4 FUN_80259288();
extern undefined4 FUN_8025c428();
extern undefined4 FUN_8025d6ac();
extern undefined4 FUN_8025d80c();
extern undefined4 FUN_8025d888();
extern undefined4 FUN_8025da88();
extern int FUN_80286718();
extern undefined2 FUN_802867ac();
extern undefined4 FUN_802867f8();
extern ulonglong FUN_8028682c();
extern undefined8 FUN_80286830();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern short FUN_80286840();
extern undefined4 FUN_80286878();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_8028fde8();
extern undefined4 FUN_8028fec8();
extern undefined4 FUN_8029312c();
extern undefined4 FUN_80293f90();
extern undefined4 FUN_80294964();
extern uint FUN_80294be4();
extern uint countLeadingZeros();

extern undefined4 DAT_8030eac0;
extern undefined4 DAT_8030eac4;
extern undefined4 DAT_8031d15c;
extern undefined4 DAT_8031d15e;
extern undefined4 DAT_8031d15f;
extern undefined4 DAT_8031d270;
extern undefined4 DAT_8031d300;
extern undefined4 DAT_8031d302;
extern undefined4 DAT_8031d304;
extern undefined4 DAT_8031d888;
extern undefined4 DAT_8031d88a;
extern undefined4 DAT_8031d8a0;
extern short DAT_8031da38;
extern undefined4 DAT_8031dae0;
extern undefined4 DAT_8031dae2;
extern undefined4 DAT_803974e0;
extern undefined4 DAT_803aaa30;
extern undefined4 DAT_803aab98;
extern int DAT_803aabf8;
extern undefined4 DAT_803aabfc;
extern undefined4 DAT_803aac00;
extern undefined4 DAT_803aac04;
extern undefined4 DAT_803aac08;
extern undefined4 DAT_803aac0c;
extern undefined4 DAT_803aac10;
extern undefined4 DAT_803aac14;
extern undefined4 DAT_803aac18;
extern undefined4 DAT_803aac38;
extern undefined4 DAT_803aac3c;
extern undefined4 DAT_803aac40;
extern undefined4 DAT_803aac44;
extern undefined4 DAT_803aac50;
extern undefined4 DAT_803aac60;
extern undefined DAT_803aac78;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc071;
extern undefined4 DAT_803dc6d6;
extern undefined4 DAT_803dc818;
extern undefined4 DAT_803dc819;
extern undefined4 DAT_803dc828;
extern undefined4 DAT_803dc82c;
extern undefined4 DAT_803dc830;
extern undefined4 DAT_803dc838;
extern undefined4 DAT_803dc83a;
extern undefined4 DAT_803dc850;
extern undefined4 DAT_803dc858;
extern undefined4 DAT_803dc860;
extern undefined4 DAT_803dc864;
extern undefined4 DAT_803dc868;
extern undefined4 DAT_803dc86c;
extern undefined4 DAT_803dc870;
extern undefined4 DAT_803dc871;
extern undefined4 DAT_803dc872;
extern undefined4 DAT_803dc878;
extern undefined* DAT_803dc87c;
extern undefined4 DAT_803dc880;
extern undefined4 DAT_803dc884;
extern undefined4 DAT_803dc888;
extern undefined4 DAT_803dc890;
extern undefined4 DAT_803dc898;
extern undefined4 DAT_803dd5e8;
extern undefined4* DAT_803dd6d0;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd6e8;
extern undefined4* DAT_803dd708;
extern undefined4* DAT_803dd720;
extern undefined4* DAT_803dd72c;
extern undefined4* DAT_803dd738;
extern undefined4 DAT_803dd968;
extern undefined4 DAT_803dd96c;
extern undefined4 DAT_803de3db;
extern undefined4 DAT_803de400;
extern undefined4 DAT_803de422;
extern undefined4 DAT_803de43a;
extern undefined4 DAT_803de5a8;
extern undefined4 DAT_803de5a9;
extern undefined4 DAT_803de5aa;
extern undefined4 DAT_803de5ac;
extern undefined4 DAT_803de5b0;
extern undefined4 DAT_803de5b2;
extern undefined4 DAT_803de5b4;
extern undefined4 DAT_803de5b8;
extern undefined4 DAT_803de5bc;
extern undefined4 DAT_803de5c0;
extern undefined4 DAT_803de5c4;
extern undefined4 DAT_803de5c5;
extern undefined4 DAT_803de5c6;
extern undefined4 DAT_803de5c7;
extern undefined4 DAT_803de5c8;
extern undefined4 DAT_803de5ca;
extern undefined4 DAT_803de5dc;
extern undefined4 DAT_803de5e0;
extern undefined4 DAT_803de5ec;
extern undefined4 DAT_803de5f0;
extern undefined4 DAT_803de5f4;
extern undefined4 DAT_803de5f8;
extern undefined4 DAT_803de600;
extern undefined4 DAT_803de604;
extern undefined4 DAT_803de608;
extern undefined4 DAT_803de610;
extern undefined4 DAT_803de611;
extern undefined4 DAT_803de612;
extern undefined4 DAT_803de613;
extern undefined4 DAT_803de614;
extern undefined4 DAT_803de616;
extern undefined4 DAT_803de618;
extern undefined4 DAT_803de620;
extern undefined4 DAT_803de624;
extern undefined4 DAT_803de628;
extern undefined4 DAT_803de62a;
extern undefined4 DAT_803de62b;
extern undefined4 DAT_803de62c;
extern undefined4 DAT_803de638;
extern undefined4 DAT_803de63c;
extern undefined4 DAT_803de640;
extern undefined4 DAT_803de654;
extern undefined4 DAT_803de660;
extern undefined4 DAT_803de661;
extern undefined4 DAT_803de664;
extern undefined4 DAT_803de670;
extern undefined4 DAT_803de671;
extern undefined4 DAT_803de672;
extern undefined4 DAT_803de673;
extern undefined4 DAT_803de674;
extern undefined4 DAT_803de676;
extern undefined4 DAT_803de678;
extern undefined4 DAT_803de67c;
extern undefined4 DAT_803de680;
extern undefined4 DAT_803de684;
extern undefined4 DAT_803de688;
extern undefined4 DAT_803de68c;
extern undefined4 DAT_803de690;
extern undefined4 DAT_803de694;
extern undefined4 DAT_803de696;
extern undefined4 DAT_803de698;
extern undefined4 DAT_803de69a;
extern undefined4 DAT_803de69c;
extern undefined4 DAT_803de6a0;
extern undefined4 DAT_803de6a4;
extern undefined4 DAT_803de6a8;
extern undefined4 DAT_803de6ac;
extern undefined4 DAT_803de6b0;
extern undefined4 DAT_803de6b4;
extern undefined4 DAT_803de6b8;
extern undefined4 DAT_803de6bc;
extern undefined4 DAT_803de6c0;
extern undefined4 DAT_803e2e90;
extern undefined4 DAT_803e2e94;
extern undefined4 DAT_cc008000;
extern f64 DOUBLE_803e2ee0;
extern f64 DOUBLE_803e2ee8;
extern f64 DOUBLE_803e2f50;
extern f64 DOUBLE_803e2f58;
extern f64 DOUBLE_803e2f60;
extern f64 DOUBLE_803e2f78;
extern f64 DOUBLE_803e2f98;
extern f64 DOUBLE_803e2fa0;
extern f64 DOUBLE_803e3038;
extern f64 DOUBLE_803e3040;
extern f64 DOUBLE_803e3090;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dc81c;
extern f32 FLOAT_803dc820;
extern f32 FLOAT_803dc824;
extern f32 FLOAT_803dc83c;
extern f32 FLOAT_803dc840;
extern f32 FLOAT_803dc844;
extern f32 FLOAT_803dc848;
extern f32 FLOAT_803dc84c;
extern f32 FLOAT_803dc854;
extern f32 FLOAT_803dc874;
extern f32 FLOAT_803de5cc;
extern f32 FLOAT_803de5d0;
extern f32 FLOAT_803de5d4;
extern f32 FLOAT_803de5d8;
extern f32 FLOAT_803de5e8;
extern f32 FLOAT_803de5fc;
extern f32 FLOAT_803de61c;
extern f32 FLOAT_803de630;
extern f32 FLOAT_803de634;
extern f32 FLOAT_803de644;
extern f32 FLOAT_803de648;
extern f32 FLOAT_803de64c;
extern f32 FLOAT_803de650;
extern f32 FLOAT_803de658;
extern f32 FLOAT_803de65c;
extern f32 FLOAT_803de668;
extern f32 FLOAT_803de66c;
extern f32 FLOAT_803e2e98;
extern f32 FLOAT_803e2e9c;
extern f32 FLOAT_803e2ea0;
extern f32 FLOAT_803e2ea4;
extern f32 FLOAT_803e2ea8;
extern f32 FLOAT_803e2eac;
extern f32 FLOAT_803e2eb4;
extern f32 FLOAT_803e2eb8;
extern f32 FLOAT_803e2ebc;
extern f32 FLOAT_803e2ec0;
extern f32 FLOAT_803e2ec4;
extern f32 FLOAT_803e2ec8;
extern f32 FLOAT_803e2ecc;
extern f32 FLOAT_803e2ed0;
extern f32 FLOAT_803e2ed4;
extern f32 FLOAT_803e2ed8;
extern f32 FLOAT_803e2edc;
extern f32 FLOAT_803e2ef0;
extern f32 FLOAT_803e2ef4;
extern f32 FLOAT_803e2ef8;
extern f32 FLOAT_803e2efc;
extern f32 FLOAT_803e2f08;
extern f32 FLOAT_803e2f0c;
extern f32 FLOAT_803e2f10;
extern f32 FLOAT_803e2f14;
extern f32 FLOAT_803e2f18;
extern f32 FLOAT_803e2f1c;
extern f32 FLOAT_803e2f20;
extern f32 FLOAT_803e2f24;
extern f32 FLOAT_803e2f28;
extern f32 FLOAT_803e2f2c;
extern f32 FLOAT_803e2f30;
extern f32 FLOAT_803e2f38;
extern f32 FLOAT_803e2f3c;
extern f32 FLOAT_803e2f40;
extern f32 FLOAT_803e2f44;
extern f32 FLOAT_803e2f48;
extern f32 FLOAT_803e2f70;
extern f32 FLOAT_803e2f80;
extern f32 FLOAT_803e2f84;
extern f32 FLOAT_803e2f88;
extern f32 FLOAT_803e2f8c;
extern f32 FLOAT_803e2f90;
extern f32 FLOAT_803e2f94;
extern f32 FLOAT_803e2fa8;
extern f32 FLOAT_803e2fac;
extern f32 FLOAT_803e2fb0;
extern f32 FLOAT_803e2fb4;
extern f32 FLOAT_803e2fb8;
extern f32 FLOAT_803e2fbc;
extern f32 FLOAT_803e2fc8;
extern f32 FLOAT_803e2fcc;
extern f32 FLOAT_803e2fd0;
extern f32 FLOAT_803e2fd4;
extern f32 FLOAT_803e2fd8;
extern f32 FLOAT_803e2fdc;
extern f32 FLOAT_803e2fe0;
extern f32 FLOAT_803e2fe4;
extern f32 FLOAT_803e2fe8;
extern f32 FLOAT_803e2fec;
extern f32 FLOAT_803e2ff0;
extern f32 FLOAT_803e2ff4;
extern f32 FLOAT_803e2ff8;
extern f32 FLOAT_803e2ffc;
extern f32 FLOAT_803e3000;
extern f32 FLOAT_803e3004;
extern f32 FLOAT_803e3008;
extern f32 FLOAT_803e300c;
extern f32 FLOAT_803e3010;
extern f32 FLOAT_803e3014;
extern f32 FLOAT_803e3018;
extern f32 FLOAT_803e3020;
extern f32 FLOAT_803e3024;
extern f32 FLOAT_803e3028;
extern f32 FLOAT_803e302c;
extern f32 FLOAT_803e3030;
extern f32 FLOAT_803e3034;
extern f32 FLOAT_803e3048;
extern f32 FLOAT_803e306c;
extern f32 FLOAT_803e3070;
extern f32 FLOAT_803e3074;
extern f32 FLOAT_803e3078;
extern f32 FLOAT_803e307c;
extern f32 FLOAT_803e3080;
extern f32 FLOAT_803e3084;
extern f32 FLOAT_803e3088;
extern f32 FLOAT_803e3098;
extern f32 FLOAT_803e309c;
extern f32 FLOAT_803e30a8;
extern void* PTR_DAT_8030eac8;
extern void* PTR_DAT_8030eacc;
extern void* PTR_DAT_8031d158;
extern int iRam803dc834;
extern char s_Alignment_8031de30[];
extern char s_Exception__8031de04[];
extern char s_General_Purpose_Registers_8031dec0[];
extern char s_Machine_check_8031de20[];
extern char s_Memory_Protection_Error_8031de6c[];
extern char s_Performance_monitor_8031de3c[];
extern char s_Stack__x__depth__d_8031dea0[];
extern char s_Stack_trace_8031de94[];
extern char s_System_management_interrupt_8031de50[];
extern char s_System_reset_8031de10[];
extern char s_Unknown_error_8031de84[];
extern char s__08x__08x_8031deb4[];
extern char s__08x__08x__08x__08x_8031dedc[];
extern char s__d____d_803dc89c[];
extern char s_errorThreadFunc__x_8031ddf0[];

/*
 * --INFO--
 *
 * Function: FUN_80132024
 * EN v1.0 Address: 0x80132024
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801323AC
 * EN v1.1 Size: 5296b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80132024(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,short *param_11,int param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80132028
 * EN v1.0 Address: 0x80132028
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8013385C
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80132028(void)
{
  return DAT_803de5b8 & 0xffff;
}

/*
 * --INFO--
 *
 * Function: FUN_80132034
 * EN v1.0 Address: 0x80132034
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80133868
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80132034(void)
{
  bool bVar1;
  
  bVar1 = false;
  if ((DAT_803de5c4 == '\x02') && (DAT_803dc818 != '\0')) {
    bVar1 = true;
  }
  if (!bVar1) {
    return;
  }
  DAT_803de5a8 = 5;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80132068
 * EN v1.0 Address: 0x80132068
 * EN v1.0 Size: 544b
 * EN v1.1 Address: 0x801338A4
 * EN v1.1 Size: 508b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80132068(void)
{
  double dVar1;
  double dVar2;
  double in_f27;
  double dVar3;
  double in_f28;
  double dVar4;
  double in_f29;
  double dVar5;
  double in_f30;
  double dVar6;
  double in_f31;
  double dVar7;
  double in_ps27_1;
  double in_ps28_1;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  uint uStack_6c;
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
  float local_48;
  float fStack_44;
  float local_38;
  float fStack_34;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  local_38 = (float)in_f28;
  fStack_34 = (float)in_ps28_1;
  local_48 = (float)in_f27;
  fStack_44 = (float)in_ps27_1;
  local_74 = CONCAT31((int3)((uint)DAT_803e2e90 >> 8),(char)DAT_803de5b0);
  FLOAT_803de5cc = -(FLOAT_803e2ef0 * FLOAT_803dc074 - FLOAT_803de5cc);
  if (FLOAT_803e2eb4 < FLOAT_803de5cc) {
    FLOAT_803de5cc = FLOAT_803de5cc - FLOAT_803e2ef4;
  }
  dVar1 = (double)FUN_80293f90();
  dVar7 = (double)(float)((double)FLOAT_803e2ef8 * dVar1);
  dVar1 = (double)FUN_80294964();
  dVar6 = (double)(float)((double)FLOAT_803e2ef8 * dVar1);
  dVar1 = (double)FUN_80293f90();
  dVar5 = (double)(float)((double)FLOAT_803e2efc * dVar1);
  dVar1 = (double)FUN_80294964();
  dVar4 = (double)(float)((double)FLOAT_803e2efc * dVar1);
  dVar1 = (double)FUN_80293f90();
  dVar3 = (double)(float)((double)FLOAT_803e2efc * dVar1);
  dVar1 = (double)FUN_80294964();
  local_78 = local_74;
  dVar2 = (double)FLOAT_803e2f08;
  uStack_6c = DAT_803de5b8 + 0x32U ^ 0x80000000;
  local_70 = 0x43300000;
  local_68 = 0x43300000;
  local_60 = 0x43300000;
  uStack_64 = uStack_6c;
  uStack_5c = uStack_6c;
  FUN_80070414((double)(float)(dVar2 - dVar7),
               (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_6c) -
                                              DOUBLE_803e2ee0) - dVar6),
               (double)(float)(dVar2 - dVar5),
               (double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_6c) -
                                              DOUBLE_803e2ee0) - dVar4),
               (double)(float)(dVar2 - dVar3),
               (double)((float)((double)CONCAT44(0x43300000,uStack_6c) - DOUBLE_803e2ee0) -
                       (float)((double)FLOAT_803e2efc * dVar1)),&local_78);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80132288
 * EN v1.0 Address: 0x80132288
 * EN v1.0 Size: 240b
 * EN v1.1 Address: 0x80133AA0
 * EN v1.1 Size: 256b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80132288(void)
{
  int iVar1;
  int iVar2;
  byte bVar3;
  byte bVar4;
  
  FUN_80286840();
  bVar4 = 2;
  FUN_80129ff8((double)FLOAT_803e2f0c,(double)FLOAT_803e2f08,(double)FLOAT_803e2f10);
  bVar3 = DAT_803de5aa >> 3 & 1;
  if ((bVar3 != 0) && (*(char *)(iRam803dc834 + 0xad) == '\0')) {
    FUN_80006824(0,0x3f1);
  }
  *(byte *)(iRam803dc834 + 0xad) = bVar3;
  if (DAT_803de5b4 == 0) {
    bVar4 = 1;
  }
  for (bVar3 = 0; bVar3 < bVar4; bVar3 = bVar3 + 1) {
    iVar1 = (uint)bVar3 * 4;
    FUN_8003b878(0,0,0,0,*(int *)(&DAT_803dc830 + iVar1),1);
    iVar2 = FUN_80017a54(*(int *)(&DAT_803dc830 + iVar1));
    *(ushort *)(iVar2 + 0x18) = *(ushort *)(iVar2 + 0x18) & 0xfff7;
    *(undefined *)(*(int *)(&DAT_803dc830 + iVar1) + 0x37) = 0xff;
  }
  FUN_80129fb0();
  FUN_8028688c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80132378
 * EN v1.0 Address: 0x80132378
 * EN v1.0 Size: 472b
 * EN v1.1 Address: 0x80133BA0
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80132378(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  undefined2 *puVar2;
  undefined4 uVar3;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  byte bVar4;
  undefined8 extraout_f1;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  
  dVar5 = (double)FLOAT_803e2f14;
  dVar6 = (double)FLOAT_803e2f18;
  dVar7 = (double)FLOAT_803e2e98;
  dVar8 = (double)FLOAT_803e2f1c;
  dVar9 = (double)FLOAT_803e2f20;
  for (bVar4 = 0; bVar4 < 2; bVar4 = bVar4 + 1) {
    puVar2 = FUN_80017aa4(0x20,bVar4 + 0x7da);
    uVar3 = FUN_80017ae4(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar2,4,
                         0xff,0xffffffff,(uint *)0x0,in_r8,in_r9,in_r10);
    iVar1 = (uint)bVar4 * 4;
    *(undefined4 *)(&DAT_803dc830 + iVar1) = uVar3;
    *(float *)(*(int *)(&DAT_803dc830 + iVar1) + 0xc) = (float)dVar5;
    *(float *)(*(int *)(&DAT_803dc830 + iVar1) + 0x10) = (float)dVar6;
    *(float *)(*(int *)(&DAT_803dc830 + iVar1) + 0xc) = (float)dVar7;
    *(float *)(*(int *)(&DAT_803dc830 + iVar1) + 0x10) = (float)dVar7;
    *(float *)(*(int *)(&DAT_803dc830 + iVar1) + 0x14) = (float)dVar8;
    **(undefined2 **)(&DAT_803dc830 + iVar1) = 2000;
    *(undefined2 *)(*(int *)(&DAT_803dc830 + iVar1) + 2) = 0;
    *(float *)(*(int *)(&DAT_803dc830 + iVar1) + 8) = (float)dVar9;
    param_1 = extraout_f1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80132550
 * EN v1.0 Address: 0x80132550
 * EN v1.0 Size: 56b
 * EN v1.1 Address: 0x80133CBC
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80132550(void)
{
  if (DAT_803de5bc != 0) {
    FUN_80053754();
    DAT_803de5bc = 0;
    DAT_803de5ac = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80132588
 * EN v1.0 Address: 0x80132588
 * EN v1.0 Size: 1720b
 * EN v1.1 Address: 0x80133CF4
 * EN v1.1 Size: 1336b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80132588(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  bool bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  char cVar5;
  short sVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  short *psVar11;
  ushort uVar12;
  undefined8 extraout_f1;
  undefined8 uVar13;
  double dVar14;
  float local_18 [3];
  
  local_18[0] = FLOAT_803e2f24;
  uVar12 = 0;
  iVar7 = FUN_80017a98();
  if (((((iVar7 == 0) || (iVar8 = (**(code **)(*DAT_803dd6d0 + 0x10))(), iVar8 == 0x44)) ||
       (iVar8 = FUN_800069c0(), (short)iVar8 != 0)) ||
      (((*(ushort *)(iVar7 + 0xb0) & 0x1000) != 0 || (uVar9 = FUN_80294be4(iVar7), uVar9 == 0)))) ||
     (DAT_803de400 != '\0')) {
    if (DAT_803de5c5 != '\0') {
      FUN_80006810(0,0x3f0);
      DAT_803de5c5 = '\0';
    }
  }
  else {
    if (DAT_803de5a8 != '\0') {
      DAT_803de5a8 = DAT_803de5a8 + -1;
    }
    iVar8 = (**(code **)(*DAT_803dd6e8 + 0x20))(0xc8d);
    uVar13 = extraout_f1;
    if (iVar8 != 0) {
      DAT_803dc818 = '\x01' - DAT_803dc818;
      if (DAT_803dc818 == '\x01') {
        uVar12 = 0x3eb;
      }
      else if (DAT_803dc818 == '\0') {
        uVar12 = 0x3ec;
      }
      uVar13 = FUN_80006824(0,uVar12);
    }
    uVar12 = 0;
    if ((DAT_803dc818 == '\0') && (DAT_803de43a == '\0')) {
      if (DAT_803de5c5 != '\0') {
        FUN_80006810(0,0x3f0);
        DAT_803de5c5 = '\0';
      }
    }
    else {
      if (DAT_803de5a9 == '\0') {
        DAT_803de5a9 = '\x01';
        FUN_80132378(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
      uVar9 = FUN_80006c10(0);
      uVar10 = FUN_80006c00(0);
      if ((uVar9 & 0xc) == 0) {
        if ((uVar10 & 1) == 0) {
          if ((uVar10 & 2) != 0) {
            DAT_803de5c4 = DAT_803de5c4 + '\x01';
            uVar12 = 0x3ed;
            if ('\x02' < DAT_803de5c4) {
              DAT_803de5c4 = '\0';
            }
          }
        }
        else {
          DAT_803de5c4 = DAT_803de5c4 + -1;
          uVar12 = 0x3ed;
          if (DAT_803de5c4 < '\0') {
            DAT_803de5c4 = '\x02';
          }
        }
      }
      if (DAT_803de43a == '\0') {
        if (DAT_803dc819 != -1) {
          DAT_803de5c4 = DAT_803dc819;
          DAT_803dc819 = -1;
        }
      }
      else {
        if (DAT_803dc819 == -1) {
          DAT_803dc819 = DAT_803de5c4;
        }
        DAT_803de5c4 = '\x02';
      }
      if (DAT_803de5c4 == '\x01') {
        if (DAT_803de5c5 != '\0') {
          FUN_80006810(0,0x3f0);
          DAT_803de5c5 = '\0';
        }
        DAT_803de5b4 = ObjGroup_FindNearestObject(0x4f,iVar7,local_18);
        if (DAT_803de5b4 != 0) {
          if (FLOAT_803e2ef0 <= local_18[0]) {
            DAT_803de5aa = '\0';
            cVar5 = DAT_803de5aa;
          }
          else {
            cVar5 = DAT_803de5aa + '\x01';
            if (local_18[0] < FLOAT_803e2f2c) {
              cVar5 = DAT_803de5aa + '\x02';
            }
          }
          DAT_803de5aa = cVar5;
          psVar11 = FUN_800069a8();
          iVar7 = FUN_80017730();
          sVar6 = (*psVar11 + (short)iVar7) - *(short *)(iRam803dc834 + 4);
          if (0x8000 < sVar6) {
            sVar6 = sVar6 + 1;
          }
          if (sVar6 < -0x8000) {
            sVar6 = sVar6 + -1;
          }
          iVar7 = (int)sVar6 / 5 + ((int)sVar6 >> 0x1f);
          *(short *)(iRam803dc834 + 4) =
               *(short *)(iRam803dc834 + 4) + ((short)iVar7 - (short)(iVar7 >> 0x1f));
        }
      }
      else if (DAT_803de5c4 < '\x01') {
        if (-1 < DAT_803de5c4) {
          if ((uVar9 & 4) == 0) {
            if ((uVar9 & 8) == 0) {
              FLOAT_803dc84c = FLOAT_803e2f28;
            }
            else {
              dVar14 = (double)FUN_8029312c((double)FLOAT_803dc840,(double)FLOAT_803dc074);
              FLOAT_803dc84c = (float)((double)FLOAT_803dc84c * dVar14);
            }
          }
          else {
            dVar14 = (double)FUN_8029312c((double)FLOAT_803dc83c,(double)FLOAT_803dc074);
            FLOAT_803dc84c = (float)((double)FLOAT_803dc84c * dVar14);
          }
          fVar2 = FLOAT_803dc844;
          if ((FLOAT_803dc844 <= FLOAT_803dc84c) &&
             (fVar2 = FLOAT_803dc84c, FLOAT_803dc848 < FLOAT_803dc84c)) {
            fVar2 = FLOAT_803dc848;
          }
          fVar3 = FLOAT_803dc81c * fVar2;
          fVar4 = FLOAT_803dc820;
          if ((FLOAT_803dc820 <= fVar3) && (fVar4 = fVar3, FLOAT_803dc824 < fVar3)) {
            fVar4 = FLOAT_803dc824;
          }
          FLOAT_803dc84c = fVar2;
          if (fVar4 == FLOAT_803dc81c) {
            FLOAT_803dc81c = fVar4;
            if (DAT_803de5c5 != '\0') {
              FUN_80006810(0,0x3f0);
              DAT_803de5c5 = '\0';
            }
          }
          else {
            FLOAT_803dc81c = fVar4;
            if (DAT_803de5c5 == '\0') {
              FUN_80006824(0,0x3f0);
              DAT_803de5c5 = '\x01';
            }
          }
        }
      }
      else if (DAT_803de5c4 < '\x03') {
        if (DAT_803de5c5 != '\0') {
          FUN_80006810(0,0x3f0);
          DAT_803de5c5 = '\0';
        }
        iVar7 = (int)DAT_803dc6d6;
        bVar1 = iVar7 != DAT_803dc850;
        DAT_803dc850 = iVar7;
        if (bVar1) {
          if (iVar7 == -1) {
            uVar12 = 0x3ef;
          }
          else {
            uVar12 = 0x3ee;
          }
        }
      }
      if (uVar12 != 0) {
        FUN_80006824(0,uVar12);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80132c40
 * EN v1.0 Address: 0x80132C40
 * EN v1.0 Size: 252b
 * EN v1.1 Address: 0x8013422C
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80132c40(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  byte bVar1;
  undefined8 uVar2;
  
  if (DAT_803de5bc != 0) {
    FUN_80053754();
  }
  uVar2 = FUN_80053754();
  for (bVar1 = 0; bVar1 < 2; bVar1 = bVar1 + 1) {
    if (*(int *)(&DAT_803dc830 + (uint)bVar1 * 4) != 0) {
      uVar2 = FUN_80017ac8(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                           *(int *)(&DAT_803dc830 + (uint)bVar1 * 4));
      *(undefined4 *)(&DAT_803dc830 + (uint)bVar1 * 4) = 0;
    }
  }
  DAT_803de5bc = 0;
  DAT_803de5c0 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80132d3c
 * EN v1.0 Address: 0x80132D3C
 * EN v1.0 Size: 148b
 * EN v1.1 Address: 0x801342C8
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80132d3c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  DAT_803de5c0 = FUN_8005398c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0xbe5,
                              param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  DAT_803de5b8 = 0x154;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80132dd0
 * EN v1.0 Address: 0x80132DD0
 * EN v1.0 Size: 440b
 * EN v1.1 Address: 0x801342F8
 * EN v1.1 Size: 220b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80132dd0(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  byte bVar3;
  undefined4 uVar1;
  int iVar2;
  int *in_r6;
  int in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 extraout_f1;
  undefined8 uVar4;
  int local_28;
  int local_24;
  int local_20;
  float local_1c;
  undefined auStack_18 [20];
  
  local_1c = FLOAT_803e2f30;
  local_20 = 0;
  local_24 = 0;
  local_28 = 0;
  bVar3 = FUN_80006b20();
  if (bVar3 != 0) {
    FUN_80006b30(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
  }
  uVar1 = FUN_80017a98();
  iVar2 = ObjGroup_FindNearestObject(9,uVar1,&local_1c);
  uVar4 = extraout_f1;
  if (iVar2 != 0) {
    in_r6 = &local_28;
    in_r7 = **(int **)(iVar2 + 0x68);
    uVar4 = (**(code **)(in_r7 + 0x54))(iVar2,&local_20,&local_24);
  }
  local_24 = local_28 - (local_24 - local_20);
  if (local_24 < 0) {
    local_24 = 0;
  }
  FUN_8028fde8(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)auStack_18,
               &DAT_803dc858,local_24,in_r6,in_r7,in_r8,in_r9,in_r10);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80132f88
 * EN v1.0 Address: 0x80132F88
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801343D4
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80132f88(void)
{
  FUN_80053754();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80132fa8
 * EN v1.0 Address: 0x80132FA8
 * EN v1.0 Size: 140b
 * EN v1.1 Address: 0x801343F8
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80132fa8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  DAT_803de5e0 = FUN_8005398c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x47a,
                              param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80133034
 * EN v1.0 Address: 0x80133034
 * EN v1.0 Size: 848b
 * EN v1.1 Address: 0x80134428
 * EN v1.1 Size: 708b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80133034(void)
{
  float fVar1;
  float fVar2;
  float fVar3;
  double dVar4;
  uint uVar5;
  char cVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  ushort *puVar10;
  undefined8 local_10;
  
  dVar4 = DOUBLE_803e2f50;
  if (DAT_803de5f0 < 10) {
    fVar1 = FLOAT_803de5e8 + FLOAT_803dc074;
    if ((float)((double)CONCAT44(0x43300000,
                                 (uint)*(ushort *)(&DAT_8031d302 + (uint)DAT_803de5f0 * 0x98)) -
               DOUBLE_803e2f50) <= fVar1) {
      DAT_803de5f0 = DAT_803de5f0 + 1;
    }
    FLOAT_803de5e8 = fVar1;
    if (DAT_803de5f0 < 10) {
      iVar9 = 0;
      iVar8 = (uint)DAT_803de5f0 * 0x98;
      for (iVar7 = 0; iVar7 < (int)(uint)(byte)(&DAT_8031d304)[iVar8]; iVar7 = iVar7 + 1) {
        puVar10 = (ushort *)(&DAT_8031d270 + iVar9 + iVar8);
        uVar5 = (uint)*puVar10;
        if ((float)((double)CONCAT44(0x43300000,uVar5) - dVar4) <= fVar1) {
          if ((float)((double)CONCAT44(0x43300000,(uint)puVar10[1]) - dVar4) <= fVar1) {
            uVar5 = (uint)puVar10[2];
            local_10 = (double)CONCAT44(0x43300000,uVar5);
            if ((float)(local_10 - dVar4) <= fVar1) {
              local_10 = (double)CONCAT44(0x43300000,(uint)puVar10[3]);
              if ((float)(local_10 - dVar4) <= fVar1) {
                cVar6 = '\0';
              }
              else {
                local_10 = (double)CONCAT44(0x43300000,uVar5);
                fVar2 = (fVar1 - (float)(local_10 - dVar4)) /
                        (float)((double)CONCAT44(0x43300000,puVar10[3] - uVar5 ^ 0x80000000) -
                               DOUBLE_803e2f58);
                fVar3 = FLOAT_803e2f38;
                if ((FLOAT_803e2f38 <= fVar2) && (fVar3 = fVar2, FLOAT_803e2f3c < fVar2)) {
                  fVar3 = FLOAT_803e2f3c;
                }
                cVar6 = -1 - (char)(int)(FLOAT_803e2f40 * fVar3);
              }
            }
            else {
              cVar6 = -1;
            }
          }
          else {
            local_10 = (double)CONCAT44(0x43300000,puVar10[1] - uVar5 ^ 0x80000000);
            fVar2 = (fVar1 - (float)((double)CONCAT44(0x43300000,uVar5) - dVar4)) /
                    (float)(local_10 - DOUBLE_803e2f58);
            fVar3 = FLOAT_803e2f38;
            if ((FLOAT_803e2f38 <= fVar2) && (fVar3 = fVar2, FLOAT_803e2f3c < fVar2)) {
              fVar3 = FLOAT_803e2f3c;
            }
            cVar6 = (char)(int)(FLOAT_803e2f40 * fVar3);
          }
        }
        else {
          cVar6 = '\0';
        }
        *(char *)((int)puVar10 + 0xb) = cVar6;
        local_10 = (double)CONCAT44(0x43300000,(uint)*puVar10);
        if ((((float)(local_10 - dVar4) <= fVar1) &&
            (local_10 = (double)CONCAT44(0x43300000,(uint)puVar10[3]),
            fVar1 <= (float)(local_10 - dVar4))) &&
           (local_10 = (double)CONCAT44(0x43300000,
                                        (uint)*(ushort *)(&DAT_8031d300 + (uint)DAT_803de5f0 * 0x98)
                                       ), (float)(local_10 - dVar4) <= fVar1)) {
          *(float *)(puVar10 + 6) =
               FLOAT_803e2f44 * (FLOAT_803dc074 / FLOAT_803e2f48) + *(float *)(puVar10 + 6);
        }
        iVar9 = iVar9 + 0x10;
      }
    }
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80133384
 * EN v1.0 Address: 0x80133384
 * EN v1.0 Size: 32b
 * EN v1.1 Address: 0x801346EC
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80133384(void)
{
  FUN_80053754();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801333a4
 * EN v1.0 Address: 0x801333A4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80134710
 * EN v1.1 Size: 68b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801333a4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801333a8
 * EN v1.0 Address: 0x801333A8
 * EN v1.0 Size: 296b
 * EN v1.1 Address: 0x80134754
 * EN v1.1 Size: 304b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801333a8(undefined4 param_1,undefined4 param_2,short *param_3,int param_4,int *param_5)
{
  uint uVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  char cVar5;
  uint uVar6;
  uint uVar7;
  short *psVar8;
  uint uVar9;
  undefined8 uVar10;
  
  uVar10 = FUN_80286830();
  uVar9 = 0;
  iVar3 = 0;
  psVar8 = param_3;
  for (iVar4 = 0; iVar4 < param_4; iVar4 = iVar4 + 1) {
    uVar1 = FUN_80017690((int)*psVar8);
    if (uVar1 != 0) {
      iVar3 = iVar3 + 1;
    }
    psVar8 = psVar8 + 2;
  }
  iVar3 = ((param_4 - iVar3) * 0x2a) / 2 + 0x52;
  cVar5 = '\0';
  for (iVar4 = 0; uVar7 = (uint)((ulonglong)uVar10 >> 0x20), uVar1 = (uint)uVar10, iVar4 < param_4;
      iVar4 = iVar4 + 1) {
    uVar2 = FUN_80017690((int)*param_3);
    uVar6 = uVar1;
    if (uVar2 != 0) {
      FUN_80003494(uVar1,uVar7,0x3c);
      *(short *)(uVar1 + 6) = (short)iVar3;
      *(char *)(uVar1 + 0x1a) = cVar5 + -1;
      *(char *)(uVar1 + 0x1b) = cVar5 + '\x01';
      *param_5 = iVar4;
      param_5 = param_5 + 1;
      uVar6 = uVar1 + 0x3c;
      iVar3 = iVar3 + 0x2a;
      cVar5 = cVar5 + '\x01';
      uVar9 = uVar1;
    }
    param_3 = param_3 + 2;
    uVar10 = CONCAT44(uVar7 + 0x3c,uVar6);
  }
  if (uVar9 != 0) {
    *(undefined *)(uVar9 + 0x1b) = 0xff;
  }
  FUN_8028687c();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801334d0
 * EN v1.0 Address: 0x801334D0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80134884
 * EN v1.1 Size: 780b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801334d0(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801334d4
 * EN v1.0 Address: 0x801334D4
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x80134B90
 * EN v1.1 Size: 44b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801334d4(void)
{
  FUN_80053754();
  FUN_80053754();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801334f8
 * EN v1.0 Address: 0x801334F8
 * EN v1.0 Size: 328b
 * EN v1.1 Address: 0x80134BBC
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801334f8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  DAT_803de604 = FUN_8005398c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x4fa,
                              param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  DAT_803de600 = FUN_8005398c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x5e3,
                              param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  FLOAT_803de5fc = FLOAT_803e2f70;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80133640
 * EN v1.0 Address: 0x80133640
 * EN v1.0 Size: 336b
 * EN v1.1 Address: 0x80134BF8
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80133640(uint param_1,int param_2)
{
  char cVar1;
  short sVar2;
  int iVar3;
  
  for (iVar3 = 0; iVar3 < *(char *)(param_2 + 0x1b); iVar3 = iVar3 + 1) {
    sVar2 = *(short *)(param_1 + 0x46);
    if (sVar2 == 0x77f) {
      cVar1 = *(char *)(param_2 + iVar3 + 0x13);
      if (cVar1 == '\0') {
        FUN_80006824(param_1,0x36b);
      }
      else if (cVar1 == '\a') {
        FUN_80006824(param_1,0x421);
      }
    }
    else if (sVar2 < 0x77f) {
      if (sVar2 == 0x77d) {
        if (*(char *)(param_2 + iVar3 + 0x13) == '\0') {
          FUN_80006824(param_1,0x368);
        }
      }
      else if (0x77c < sVar2) {
        cVar1 = *(char *)(param_2 + iVar3 + 0x13);
        if (cVar1 == '\0') {
          FUN_80006824(param_1,0x370);
        }
        else if (cVar1 == '\a') {
          FUN_80006824(param_1,0x36c);
        }
      }
    }
    else if (sVar2 < 0x781) {
      cVar1 = *(char *)(param_2 + iVar3 + 0x13);
      if (cVar1 == '\0') {
        FUN_80006824(param_1,0x36a);
      }
      else if (cVar1 == '\a') {
        FUN_80006824(param_1,0x369);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80133790
 * EN v1.0 Address: 0x80133790
 * EN v1.0 Size: 616b
 * EN v1.1 Address: 0x80134D50
 * EN v1.1 Size: 500b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80133790(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  uint uVar2;
  uint uVar3;
  byte bVar4;
  undefined8 uVar5;
  
  uVar3 = (uint)DAT_803de618;
  if (uVar3 < DAT_803dc872) {
    if (DAT_803de628 < 1) {
      uVar2 = (uint)DAT_803de616;
      if (uVar2 < 0x14) {
        bVar4 = (byte)((uVar2 * 0xff) / 0x14);
      }
      else if ((int)uVar2 < (int)(*(ushort *)(&DAT_8031dae2 + uVar3 * 4) - 0x14)) {
        bVar4 = 0xff;
      }
      else {
        if ((uVar3 == DAT_803dc872 - 1) && (DAT_803de624 == 0)) {
          FUN_800067bc(3,2,4000);
          DAT_803de624 = 1;
        }
        iVar1 = ((uint)DAT_803de616 - (uint)*(ushort *)(&DAT_8031dae2 + (uint)DAT_803de618 * 4)) *
                0xff;
        iVar1 = iVar1 / 0x14 + (iVar1 >> 0x1f);
        bVar4 = -((char)iVar1 - (char)(iVar1 >> 0x1f)) - 1;
      }
      uVar5 = FUN_80017484(0xff,0xff,0xff,bVar4);
      FUN_80006c84(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   (uint)*(ushort *)(&DAT_8031dae0 + (uint)DAT_803de618 * 4),0,0);
      DAT_803de614 = DAT_803de614 + (ushort)DAT_803dc071;
      DAT_803de616 = DAT_803de616 + DAT_803dc071;
      if (*(ushort *)(&DAT_8031dae2 + (uint)DAT_803de618 * 4) <= DAT_803de616) {
        uVar3 = DAT_803de618 + 1;
        DAT_803de618 = (ushort)uVar3;
        DAT_803de628 = 0x3c;
        if ((uVar3 & 0xffff) < (uint)DAT_803dc872) {
          DAT_803de616 = 0;
        }
      }
    }
    else {
      DAT_803de628 = DAT_803de628 - (ushort)DAT_803dc071;
      if (DAT_803de628 < 0) {
        DAT_803de628 = 0;
      }
    }
  }
  else {
    iVar1 = (**(code **)(*DAT_803dd6d0 + 0x10))();
    if (iVar1 == 0x57) {
      DAT_803de613 = 0;
      FUN_80006b84(4);
      FUN_80117318(4);
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801339f8
 * EN v1.0 Address: 0x801339F8
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80134F44
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_801339f8(void)
{
  return DAT_803de613;
}

/*
 * --INFO--
 *
 * Function: FUN_80133a04
 * EN v1.0 Address: 0x80133A04
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x80134F4C
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80133a04(void)
{
  DAT_803de613 = 1;
  DAT_803de614 = 0;
  DAT_803de616 = 0;
  DAT_803de628 = 0;
  DAT_803de618 = 0;
  DAT_803de62a = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80133a28
 * EN v1.0 Address: 0x80133A28
 * EN v1.0 Size: 64b
 * EN v1.1 Address: 0x80134F70
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80133a28(void)
{
  int iVar1;
  undefined4 uVar2;
  
  iVar1 = FUN_80006b7c();
  if ((iVar1 - 2U < 5) || (iVar1 == 7)) {
    uVar2 = 1;
  }
  else {
    uVar2 = 0;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_80133a68
 * EN v1.0 Address: 0x80133A68
 * EN v1.0 Size: 468b
 * EN v1.1 Address: 0x80134FB0
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80133a68(double param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 char param_9)
{
  ushort *puVar1;
  undefined *puVar2;
  undefined8 uVar3;
  double dVar4;
  double dVar5;
  
  if (param_9 == '\0') {
    if (DAT_803de620 == '\0') {
      FLOAT_803de61c = FLOAT_803e2fa8;
      param_1 = (double)FLOAT_803de634;
      if ((double)FLOAT_803e2fac < param_1) {
        DAT_803de620 = '\x01';
      }
    }
    else {
      FLOAT_803de61c = FLOAT_803de634;
    }
  }
  else {
    FLOAT_803de61c = FLOAT_803e2fa8;
    DAT_803de620 = '\0';
  }
  puVar1 = FUN_80017470(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x3d9);
  if (*puVar1 != 0xffff) {
    puVar2 = FUN_80006c9c((uint)*(byte *)(puVar1 + 2));
    if (DAT_803de62c == 0) {
      DAT_803de62c = (uint)*(short *)(puVar2 + 0x16);
    }
    dVar5 = (double)FLOAT_803e2fb0;
    dVar4 = (double)(FLOAT_803e2fa8 - FLOAT_803de61c);
    *(short *)(puVar2 + 0x16) =
         (short)(int)(dVar5 * dVar4 +
                     (double)(float)((double)CONCAT44(0x43300000,DAT_803de62c ^ 0x80000000) -
                                    DOUBLE_803e2f78));
    uVar3 = FUN_80017484(0xff,0xff,0xff,(byte)(int)(FLOAT_803e2fb4 * FLOAT_803de630));
    FUN_80006c88(uVar3,dVar4,dVar5,param_4,param_5,param_6,param_7,param_8,0x3d9);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80133c3c
 * EN v1.0 Address: 0x80133C3C
 * EN v1.0 Size: 3048b
 * EN v1.1 Address: 0x801350C8
 * EN v1.1 Size: 2772b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80133c3c(undefined4 param_1,undefined4 param_2,uint param_3)
{
  int iVar1;
  float fVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  ushort uVar9;
  undefined *puVar7;
  int iVar8;
  uint uVar10;
  int iVar11;
  uint uVar12;
  double dVar13;
  undefined8 uVar14;
  double dVar15;
  double dVar16;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  ulonglong uVar17;
  undefined8 local_e8;
  undefined8 local_e0;
  undefined8 local_d8;
  undefined8 local_d0;
  undefined8 local_c8;
  undefined8 local_b8;
  undefined8 local_a8;
  undefined8 local_a0;
  undefined8 local_98;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_58;
  
  uVar17 = FUN_8028682c();
  uVar4 = (uint)(uVar17 >> 0x20);
  FLOAT_803de644 = FLOAT_803de644 + FLOAT_803dc074;
  if (FLOAT_803e2f80 < FLOAT_803de644) {
    FLOAT_803de644 = FLOAT_803de644 - FLOAT_803e2f80;
  }
  dVar13 = (double)FUN_80294964();
  iVar8 = DAT_803aac08;
  DAT_803de640 = (byte)(int)((double)FLOAT_803e2fbc * dVar13 + (double)FLOAT_803e2fb8);
  if (FLOAT_803e2f88 < FLOAT_803de648) {
    iVar1 = (int)DAT_803aac50;
    iVar11 = (int)DAT_803aac60;
    iVar5 = FUN_80286718((double)(FLOAT_803e2f90 * FLOAT_803de648));
    local_d8 = (double)CONCAT44(0x43300000,
                                iVar1 + -0x32 + (uint)*(ushort *)(DAT_803aac10 + 10) + 0x5a ^
                                0x80000000);
    local_d0 = (double)CONCAT44(0x43300000,iVar11 - 0x10U ^ 0x80000000);
    FUN_800709e0((double)(float)(local_d8 - DOUBLE_803e2f78),
                 (double)(float)(local_d0 - DOUBLE_803e2f78),iVar8,uVar4,0x100,
                 (uint)*(ushort *)(iVar8 + 10),iVar5 + 0x10,0);
    iVar8 = DAT_803aac10;
    iVar5 = FUN_80286718((double)(FLOAT_803e2f90 * FLOAT_803de648));
    local_c8 = (double)CONCAT44(0x43300000,iVar1 + 0x28U ^ 0x80000000);
    FUN_800709e0((double)(float)(local_c8 - DOUBLE_803e2f78),
                 (double)(float)((double)CONCAT44(0x43300000,iVar11 - 0x10U ^ 0x80000000) -
                                DOUBLE_803e2f78),iVar8,0xff,0x100,(uint)*(ushort *)(iVar8 + 10),
                 iVar5 + 0x10,0);
    iVar8 = DAT_803aac10;
    uVar9 = *(ushort *)(DAT_803aac10 + 10);
    iVar5 = FUN_80286718((double)(FLOAT_803e2f90 * FLOAT_803de648));
    local_b8 = (double)CONCAT44(0x43300000,
                                iVar1 + -0x32 + (uint)*(ushort *)(DAT_803aac08 + 10) + (uint)uVar9 +
                                0x57 ^ 0x80000000);
    FUN_800709e0((double)(float)(local_b8 - DOUBLE_803e2f78),
                 (double)(float)((double)CONCAT44(0x43300000,iVar11 - 0x10U ^ 0x80000000) -
                                DOUBLE_803e2f78),iVar8,0xff,0x100,(uint)uVar9,iVar5 + 0x10,1);
    iVar8 = DAT_803aabf8;
    iVar5 = FUN_80286718((double)(FLOAT_803e2f90 * FLOAT_803de648));
    local_a8 = (double)CONCAT44(0x43300000,iVar1 - 0xfU ^ 0x80000000);
    local_a0 = (double)CONCAT44(0x43300000,iVar11 - 0x10U ^ 0x80000000);
    FUN_800709e0((double)(float)(local_a8 - DOUBLE_803e2f78),
                 (double)(float)(local_a0 - DOUBLE_803e2f78),iVar8,0xff,0x100,
                 (uint)*(ushort *)(iVar8 + 10),iVar5 + 0x10,0);
  }
  iVar8 = (int)DAT_803aac50;
  iVar1 = (int)DAT_803aac60;
  if (FLOAT_803de648 <= FLOAT_803e2f88) {
    uVar12 = (uint)DAT_803de640;
  }
  else {
    uVar12 = 0xff;
  }
  local_b8 = (double)CONCAT44(0x43300000,
                              (iVar1 - (uint)*(ushort *)(DAT_803aabfc + 0xc)) + 3 ^ 0x80000000);
  FUN_800709e8((double)(float)((double)CONCAT44(0x43300000,iVar8 - 0x18U ^ 0x80000000) -
                              DOUBLE_803e2f78),(double)(float)(local_b8 - DOUBLE_803e2f78),
               DAT_803aabfc,0xff,0xff);
  local_c8 = (double)CONCAT44(0x43300000,iVar1 - 0x2eU ^ 0x80000000);
  FUN_800709e8((double)(float)((double)CONCAT44(0x43300000,iVar8 + 0xa1U ^ 0x80000000) -
                              DOUBLE_803e2f78),(double)(float)(local_c8 - DOUBLE_803e2f78),
               DAT_803aac14,uVar12,0xff);
  iVar8 = (int)DAT_803aac50;
  uVar12 = (uint)DAT_803aac60;
  if (FLOAT_803de648 <= FLOAT_803e2f88) {
    uVar10 = (uint)DAT_803de640;
  }
  else {
    uVar10 = 0xff;
  }
  local_e0 = (double)CONCAT44(0x43300000,iVar8 - 0x18U ^ 0x80000000);
  local_e8 = (double)CONCAT44(0x43300000,uVar12 ^ 0x80000000);
  FUN_800709e8((double)(float)(local_e0 - DOUBLE_803e2f78),
               (double)(FLOAT_803e2f8c +
                       FLOAT_803e2f90 * FLOAT_803de648 + (float)(local_e8 - DOUBLE_803e2f78)),
               DAT_803aac00,0xff,0xff);
  local_98 = (double)CONCAT44(0x43300000,iVar8 + 0xa1U ^ 0x80000000);
  dVar16 = (double)FLOAT_803e2f94;
  dVar15 = (double)FLOAT_803e2f90;
  dVar13 = DOUBLE_803e2f78;
  FUN_800709e8((double)(float)(local_98 - DOUBLE_803e2f78),
               (double)(float)(dVar16 + (double)(float)(dVar15 * (double)FLOAT_803de648 +
                                                       (double)(float)((double)CONCAT44(0x43300000,
                                                                                        uVar12 ^ 
                                                  0x80000000) - DOUBLE_803e2f78))),DAT_803aac14,
               uVar10,0xff);
  local_88 = (double)CONCAT44(0x43300000,(uint)DAT_803de640);
  local_88 = local_88 - DOUBLE_803e2fa0;
  uVar14 = FUN_80017484(0xff,0xff,0xff,
                        (byte)(int)(local_88 * (DOUBLE_803e2f98 - (double)FLOAT_803de648)));
  FUN_80006c88(uVar14,local_88,dVar15,dVar16,dVar13,in_f6,in_f7,in_f8,0x3da);
  local_70 = (double)CONCAT44(0x43300000,(int)DAT_803aac50 - 0x32U ^ 0x80000000);
  local_68 = (double)CONCAT44(0x43300000,0xfe - (*(ushort *)(DAT_803aac04 + 10) >> 1) ^ 0x80000000);
  FUN_800709e8((double)(float)(local_70 - DOUBLE_803e2f78),
               (double)(float)(local_68 - DOUBLE_803e2f78),DAT_803aac04,0xff,0xff);
  if ((FLOAT_803e2fc8 <= FLOAT_803de648) && ((uVar17 & 0xff) == 0)) {
    iVar8 = (int)DAT_803aac50;
    iVar1 = (int)DAT_803aac60;
    iVar11 = 0;
    dVar15 = (double)FLOAT_803e2f90;
    dVar13 = DOUBLE_803e2f78;
    do {
      iVar5 = DAT_803aac08;
      iVar6 = FUN_80286718((double)(float)(dVar15 * (double)FLOAT_803de648));
      iVar3 = iVar11 + 1;
      local_68 = (double)CONCAT44(0x43300000,
                                  iVar8 + (uint)*(ushort *)(DAT_803aac10 + 10) + 0x28 + iVar3 * -4 ^
                                  0x80000000);
      local_70 = (double)CONCAT44(0x43300000,iVar1 + -0x10 + iVar3 * -3 ^ 0x80000000);
      FUN_800709e0((double)(float)(local_68 - dVar13),(double)(float)(local_70 - dVar13),iVar5,
                   (int)(uint)DAT_803de640 >> (iVar11 + 3U & 0x3f) & 0xff,0x100,
                   (uint)*(ushort *)(iVar5 + 10) + iVar3 * 8,iVar6 + iVar3 * 6 + 0x10,4);
      iVar11 = iVar11 + 1;
    } while (iVar11 < 4);
  }
  if (FLOAT_803e2f88 < FLOAT_803de648) {
    uVar9 = FUN_8013041c();
    if (uVar9 != 0xffff) {
      puVar7 = FUN_80006c9c((uint)uVar9);
      if ((uVar17 & 0xff) == 0) {
        local_68 = (double)CONCAT44(0x43300000,(int)DAT_803aac50 + 0x2fU ^ 0x80000000);
        local_70 = (double)CONCAT44(0x43300000,
                                    ((int)*(short *)(puVar7 + 0x16) + (int)DAT_803aac60) - 1U ^
                                    0x80000000);
        FUN_800709e8((double)(float)(local_68 - DOUBLE_803e2f78),
                     (double)(float)(local_70 - DOUBLE_803e2f78),DAT_803aac0c,uVar4,0xff);
      }
    }
  }
  uVar4 = (uint)DAT_803de640;
  local_70 = (double)CONCAT44(0x43300000,(int)(FLOAT_803e2f80 * FLOAT_803de630) - 0x50U ^ 0x80000000
                             );
  local_80 = (double)CONCAT44(0x43300000,
                              (int)(FLOAT_803e2f84 * FLOAT_803de634) + 0x1e0U ^ 0x80000000);
  FUN_800709e0((double)(float)(local_70 - DOUBLE_803e2f78),
               (double)(float)(local_80 - DOUBLE_803e2f78),DAT_803aac40,0xff,0x100,
               (uint)*(ushort *)(DAT_803aac40 + 10),(uint)*(ushort *)(DAT_803aac40 + 0xc),1);
  iVar8 = *(int *)(&DAT_803aac18 + ((int)(uVar4 << 3) >> 8) * 4);
  local_a0 = (double)CONCAT44(0x43300000,
                              (int)(FLOAT_803e2f84 * FLOAT_803de634) + 0x1e0U ^ 0x80000000);
  FUN_800709e0((double)(float)((double)CONCAT44(0x43300000,
                                                ((int)(FLOAT_803e2f80 * FLOAT_803de630) +
                                                (uint)*(ushort *)(DAT_803aac40 + 10)) - 0x4a ^
                                                0x80000000) - DOUBLE_803e2f78),
               (double)(float)(local_a0 - DOUBLE_803e2f78),iVar8,0xff,0x100,
               (uint)*(ushort *)(iVar8 + 10),(uint)*(ushort *)(iVar8 + 0xc),0);
  FUN_800709e0((double)(float)((double)CONCAT44(0x43300000,
                                                (0x280 - ((int)(FLOAT_803e2f80 * FLOAT_803de630) +
                                                         -0x50)) -
                                                (uint)*(ushort *)(DAT_803aac40 + 10) ^ 0x80000000) -
                              DOUBLE_803e2f78),
               (double)(float)((double)CONCAT44(0x43300000,
                                                (int)(FLOAT_803e2f84 * FLOAT_803de634) + 0x1e0U ^
                                                0x80000000) - DOUBLE_803e2f78),DAT_803aac40,0xff,
               0x100,(uint)*(ushort *)(DAT_803aac40 + 10),(uint)*(ushort *)(DAT_803aac40 + 0xc),0);
  iVar8 = *(int *)(&DAT_803aac18 + ((int)(uVar4 << 3) >> 8) * 4);
  local_d0 = (double)CONCAT44(0x43300000,
                              ((0x27a - ((int)(FLOAT_803e2f80 * FLOAT_803de630) + -0x50)) -
                              (uint)*(ushort *)(DAT_803aac40 + 10)) - (uint)*(ushort *)(iVar8 + 10)
                              ^ 0x80000000);
  local_e0 = (double)CONCAT44(0x43300000,
                              (int)(FLOAT_803e2f84 * FLOAT_803de634) + 0x1e0U ^ 0x80000000);
  FUN_800709e0((double)(float)(local_d0 - DOUBLE_803e2f78),
               (double)(float)(local_e0 - DOUBLE_803e2f78),iVar8,0xff,0x100,
               (uint)*(ushort *)(iVar8 + 10),(uint)*(ushort *)(iVar8 + 0xc),1);
  fVar2 = FLOAT_803de634;
  if (FLOAT_803de630 < FLOAT_803de634) {
    fVar2 = FLOAT_803de630;
  }
  local_e8 = (double)CONCAT44(0x43300000,
                              (0x280 - ((int)((uint)*(ushort *)(DAT_803de654 + 10) * 0xbe) >> 8)) /
                              2 ^ 0x80000000);
  local_58 = (double)CONCAT44(0x43300000,(int)(FLOAT_803e2fd0 * fVar2 + FLOAT_803e2fcc) ^ 0x80000000
                             );
  FUN_800709e8((double)(float)(local_e8 - DOUBLE_803e2f78),
               (double)(float)(local_58 - DOUBLE_803e2f78),DAT_803de654,0xff,0xbe);
  if ((param_3 & 0xff) != 0) {
    iVar8 = (int)DAT_803aac50;
    iVar1 = (int)DAT_803aac60;
    local_68 = (double)CONCAT44(0x43300000,iVar8 + 0x2fU ^ 0x80000000);
    local_70 = (double)CONCAT44(0x43300000,iVar1 + 0x14U ^ 0x80000000);
    FUN_800709e8((double)(float)(local_68 - DOUBLE_803e2f78),
                 (double)(float)(local_70 - DOUBLE_803e2f78),DAT_803aac3c,0xff,0xff);
    local_78 = (double)CONCAT44(0x43300000,iVar8 + 0x2fU ^ 0x80000000);
    local_80 = (double)CONCAT44(0x43300000,iVar1 + 0x4bU ^ 0x80000000);
    FUN_800709e8((double)(float)(local_78 - DOUBLE_803e2f78),
                 (double)(float)(local_80 - DOUBLE_803e2f78),DAT_803aac38,0xff,0xff);
  }
  FUN_80286878();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80134824
 * EN v1.0 Address: 0x80134824
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80135B9C
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80134824(undefined4 param_1,undefined4 param_2)
{
  DAT_803de63c = param_1;
  DAT_803de638 = param_2;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80134830
 * EN v1.0 Address: 0x80134830
 * EN v1.0 Size: 140b
 * EN v1.1 Address: 0x80135BA8
 * EN v1.1 Size: 136b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80134830(double param_1,double param_2)
{
  FUN_80247a48(param_1,param_2,(double)FLOAT_803e2f88,(undefined4 *)&DAT_803aac44);
  FLOAT_803de648 = (float)((double)FLOAT_803e2fd4 - param_2) / FLOAT_803e2fd8;
  FLOAT_803de634 = (float)(param_1 - (double)FLOAT_803e2fdc) / FLOAT_803e2fe0;
  FLOAT_803de630 = FLOAT_803e2fa8 - FLOAT_803de648;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801348bc
 * EN v1.0 Address: 0x801348BC
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80135C30
 * EN v1.1 Size: 488b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801348bc(undefined8 param_1,double param_2,double param_3,double param_4,undefined4 param_5
                 ,undefined4 param_6,short param_7,undefined2 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801348c0
 * EN v1.0 Address: 0x801348C0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80135E18
 * EN v1.1 Size: 352b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801348c0(undefined8 param_1,double param_2,double param_3,double param_4,undefined4 param_5
                 ,undefined4 param_6,undefined2 param_7,undefined2 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801348c4
 * EN v1.0 Address: 0x801348C4
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x80135F78
 * EN v1.1 Size: 60b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801348c4(int param_1)
{
  if (*(short *)(param_1 + 0x46) == 0x77d) {
    FUN_800067c0((int *)0x3a,0);
    DAT_803de613 = 0;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80134900
 * EN v1.0 Address: 0x80134900
 * EN v1.0 Size: 148b
 * EN v1.1 Address: 0x80135FB4
 * EN v1.1 Size: 156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80134900(int param_1)
{
  char in_r8;
  
  if ((in_r8 != '\0') && (DAT_803de62b != '\0')) {
    FUN_8003b818(param_1);
    if ((DAT_803de613 != '\0') && (DAT_803de62a == '\0')) {
      FUN_80017698(0xdf6,1);
      DAT_803de62a = '\x01';
      (**(code **)(*DAT_803dd6d4 + 0x50))(0x57,0,0,0);
      n_attractmode_releaseMovieBuffers();
      DAT_803de624 = 0;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80134994
 * EN v1.0 Address: 0x80134994
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80136050
 * EN v1.1 Size: 2784b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80134994(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,short *param_9,
                 undefined4 param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80134998
 * EN v1.0 Address: 0x80134998
 * EN v1.0 Size: 508b
 * EN v1.1 Address: 0x80136B30
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80134998(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined2 *param_9,int param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  short sVar1;
  int iVar2;
  double dVar3;
  
  iVar2 = *(int *)(param_9 + 0x5c);
  *(undefined *)(iVar2 + 0x30) = 0;
  *param_9 = (short)((int)*(char *)(param_10 + 0x18) << 8);
  sVar1 = param_9[0x23];
  if ((sVar1 < 0x77d) || (0x780 < sVar1)) {
    dVar3 = (double)FLOAT_803e2f88;
    *(float *)(iVar2 + 0x34) = FLOAT_803e2f88;
    *(undefined *)(iVar2 + 0x31) = 0xfe;
    if (param_9[0x23] == 0x78a) {
      FUN_800305f8(dVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,1,0,
                   param_12,param_13,param_14,param_15,param_16);
    }
    else if (param_9[0x23] == 0x781) {
      FUN_800305f8((double)FLOAT_803e2fa8,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                   param_9,0,0,param_12,param_13,param_14,param_15,param_16);
      FUN_80017964(**(int **)(param_9 + 0x3e),FUN_801184b8);
    }
  }
  else {
    *(char *)(iVar2 + 0x31) = (char)sVar1 + -0x7d;
    *(undefined4 *)(iVar2 + 0x34) = *(undefined4 *)(&DAT_8030eac0 + (short)param_9[0x23] * 0x20);
    FUN_800305f8((double)FLOAT_803e2f88,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 param_9,0,0,param_12,param_13,param_14,param_15,param_16);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80134b94
 * EN v1.0 Address: 0x80134B94
 * EN v1.0 Size: 28b
 * EN v1.1 Address: 0x80136C2C
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80134b94(char param_1)
{
  if (param_1 == DAT_803de611) {
    return;
  }
  DAT_803dc871 = DAT_803de611;
  DAT_803de611 = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80134bb0
 * EN v1.0 Address: 0x80134BB0
 * EN v1.0 Size: 20b
 * EN v1.1 Address: 0x80136C4C
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80134bb0(undefined param_1)
{
  DAT_803dc870 = DAT_803de610;
  DAT_803de610 = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80134bc4
 * EN v1.0 Address: 0x80134BC4
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80136C5C
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80134bc4(void)
{
  DAT_803de62b = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80134bd0
 * EN v1.0 Address: 0x80134BD0
 * EN v1.0 Size: 116b
 * EN v1.1 Address: 0x80136C68
 * EN v1.1 Size: 124b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80134bd0(void)
{
  int iVar1;
  int *piVar2;
  
  FUN_80053754();
  DAT_803de654 = 0;
  iVar1 = 0;
  piVar2 = &DAT_803aabf8;
  do {
    if (*piVar2 != 0) {
      FUN_80053754();
      *piVar2 = 0;
    }
    piVar2 = piVar2 + 1;
    iVar1 = iVar1 + 1;
  } while (iVar1 < 0x13);
  DAT_803de612 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80134c44
 * EN v1.0 Address: 0x80134C44
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80136CE4
 * EN v1.1 Size: 228b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80134c44(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80134c48
 * EN v1.0 Address: 0x80134C48
 * EN v1.0 Size: 1012b
 * EN v1.1 Address: 0x80136DC8
 * EN v1.1 Size: 960b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80134c48(undefined4 param_1,int param_2)
{
  uint uVar1;
  uint uVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  
  if (param_2 < 0x40) {
    if (DAT_803de678 != 0) {
      if (DAT_803de68c != 0) {
        FUN_8004812c(DAT_803de6a4,0);
        FLOAT_803de66c =
             FLOAT_803e3020 /
             (FLOAT_803e3024 *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803de6a4 + 10)) -
                    DOUBLE_803e3038));
        FLOAT_803de668 =
             FLOAT_803e3020 /
             (FLOAT_803e3024 *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803de6a4 + 0xc)) -
                    DOUBLE_803e3038));
      }
      DAT_803de678 = 0;
    }
    param_2 = param_2 + -0x21;
  }
  else if (param_2 < 0x60) {
    if (DAT_803de678 != 1) {
      if (DAT_803de68c != 0) {
        FUN_8004812c(DAT_803de6a0,0);
        FLOAT_803de66c =
             FLOAT_803e3020 /
             (FLOAT_803e3024 *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803de6a0 + 10)) -
                    DOUBLE_803e3038));
        FLOAT_803de668 =
             FLOAT_803e3020 /
             (FLOAT_803e3024 *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803de6a0 + 0xc)) -
                    DOUBLE_803e3038));
      }
      DAT_803de678 = 1;
    }
    param_2 = param_2 + -0x40;
  }
  else if (param_2 < 0x80) {
    if (DAT_803de678 != 2) {
      if (DAT_803de68c != 0) {
        FUN_8004812c(DAT_803de69c,0);
        FLOAT_803de66c =
             FLOAT_803e3020 /
             (FLOAT_803e3024 *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803de69c + 10)) -
                    DOUBLE_803e3038));
        FLOAT_803de668 =
             FLOAT_803e3020 /
             (FLOAT_803e3024 *
             (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(DAT_803de69c + 0xc)) -
                    DOUBLE_803e3038));
      }
      DAT_803de678 = 2;
    }
    param_2 = param_2 + -0x60;
  }
  iVar3 = DAT_803de678 * 0x40 + -0x7fce2410;
  uVar5 = (uint)*(byte *)(iVar3 + param_2 * 2);
  uVar4 = (*(byte *)(iVar3 + param_2 * 2 + 1) - uVar5) + 1;
  if (DAT_803de68c != 0) {
    uVar1 = (uint)((float)((double)CONCAT44(0x43300000,(uint)DAT_803de69a) - DOUBLE_803e3038) *
                  (FLOAT_803de658 +
                  (float)((double)CONCAT44(0x43300000,(uint)DAT_803de660) - DOUBLE_803e3038)));
    uVar2 = (uint)((float)((double)CONCAT44(0x43300000,(uint)DAT_803de698) - DOUBLE_803e3038) *
                  (FLOAT_803de65c +
                  (float)((double)CONCAT44(0x43300000,(uint)DAT_803de661) - DOUBLE_803e3038)));
    FUN_800713a4();
    FUN_8007089c((double)((float)((double)CONCAT44(0x43300000,uVar5 << 5 ^ 0x80000000) -
                                 DOUBLE_803e3040) * FLOAT_803de66c),(double)FLOAT_803e3030,
                 (double)(FLOAT_803de66c *
                         (float)((double)CONCAT44(0x43300000,(uVar5 + uVar4) * 0x20 ^ 0x80000000) -
                                DOUBLE_803e3040)),(double)(FLOAT_803e3034 * FLOAT_803de668),
                 uVar1 << 2,uVar2 << 2,
                 (short)(int)(FLOAT_803e3028 *
                             ((float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) -
                                     DOUBLE_803e3040) *
                              (FLOAT_803de658 +
                              (float)((double)CONCAT44(0x43300000,(uint)DAT_803de660) -
                                     DOUBLE_803e3038)) +
                             (float)((double)CONCAT44(0x43300000,uVar1 ^ 0x80000000) -
                                    DOUBLE_803e3040))),
                 (short)(int)(FLOAT_803e3028 *
                             (FLOAT_803e302c *
                              (FLOAT_803de65c +
                              (float)((double)CONCAT44(0x43300000,(uint)DAT_803de661) -
                                     DOUBLE_803e3038)) +
                             (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) -
                                    DOUBLE_803e3040))));
  }
  return uVar4;
}

/*
 * --INFO--
 *
 * Function: FUN_8013503c
 * EN v1.0 Address: 0x8013503C
 * EN v1.0 Size: 1856b
 * EN v1.1 Address: 0x80137188
 * EN v1.1 Size: 1824b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013503c(void)
{
  byte bVar1;
  undefined4 uVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint uVar13;
  byte *pbVar14;
  byte *pbVar15;
  double in_f29;
  double dVar16;
  double in_f30;
  double dVar17;
  double in_f31;
  double dVar18;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar19;
  undefined4 local_a8;
  undefined4 local_a4;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined4 local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  uint uStack_84;
  undefined4 local_80;
  uint uStack_7c;
  undefined4 local_78;
  uint uStack_74;
  undefined4 local_70;
  uint uStack_6c;
  undefined4 local_68;
  uint uStack_64;
  undefined4 local_60;
  uint uStack_5c;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  uVar19 = FUN_8028682c();
  uVar4 = (undefined4)((ulonglong)uVar19 >> 0x20);
  pbVar14 = (byte *)uVar19;
  dVar17 = DOUBLE_803e3038;
  dVar18 = DOUBLE_803e3040;
  do {
    uVar13 = (uint)*pbVar14;
    pbVar15 = pbVar14 + 1;
    if (uVar13 == 0) {
      FUN_80286878();
      return;
    }
    uVar12 = 0;
    if (uVar13 == 0x82) {
      if (DAT_803de68c == 0) {
        iVar5 = DAT_803de698 + 10;
        uVar11 = (uint)DAT_803de694;
        uVar10 = (uint)DAT_803de696;
        uVar3 = countLeadingZeros(DAT_803de69a - uVar10);
        uVar9 = countLeadingZeros(iVar5 - uVar11);
        if (uVar3 >> 5 == 0 && uVar9 >> 5 == 0) {
          if (1 < uVar10) {
            uVar10 = uVar10 - 2;
          }
          uVar3 = DAT_803de69a + 2;
          local_88 = 0x43300000;
          uStack_7c = (uint)DAT_803de660;
          local_80 = 0x43300000;
          dVar16 = (double)(FLOAT_803de658 +
                           (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e3038));
          uStack_84 = uVar10;
          iVar6 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,uVar10) -
                                                              DOUBLE_803e3038) * dVar16));
          local_78 = 0x43300000;
          uStack_74 = uVar3;
          iVar7 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,uVar3) -
                                                              DOUBLE_803e3038) * dVar16));
          local_70 = 0x43300000;
          uStack_64 = (uint)DAT_803de661;
          local_68 = 0x43300000;
          dVar16 = (double)(FLOAT_803de65c +
                           (float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e3038));
          uStack_6c = uVar11;
          iVar8 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,uVar11) -
                                                              DOUBLE_803e3038) * dVar16));
          local_60 = 0x43300000;
          uStack_5c = iVar5;
          iVar5 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,iVar5) -
                                                              DOUBLE_803e3038) * dVar16));
          local_98 = CONCAT31(CONCAT21(CONCAT11(DAT_803de673,DAT_803de672),DAT_803de671),
                              DAT_803de670);
          local_94 = local_98;
          FUN_8006fd90(iVar6,iVar8,iVar7,iVar5,&local_94);
        }
      }
      DAT_803de696 = CONCAT11(pbVar14[2],*pbVar15);
      pbVar15 = pbVar14 + 5;
      DAT_803de694 = CONCAT11(pbVar14[4],pbVar14[3]);
      DAT_803de698 = DAT_803de694;
      DAT_803de69a = DAT_803de696;
    }
    else if (uVar13 < 0x82) {
      if (uVar13 == 0x20) {
        uVar12 = 6;
      }
      else if (uVar13 < 0x20) {
        if (uVar13 == 10) {
          if (DAT_803de68c == 0) {
            uVar11 = DAT_803de698 + 10;
            uVar10 = (uint)DAT_803de694;
            uStack_5c = (uint)DAT_803de696;
            uVar3 = countLeadingZeros(DAT_803de69a - uStack_5c);
            uVar9 = countLeadingZeros(uVar11 - uVar10);
            if (uVar3 >> 5 == 0 && uVar9 >> 5 == 0) {
              if (1 < uStack_5c) {
                uStack_5c = uStack_5c - 2;
              }
              iVar6 = DAT_803de69a + 2;
              local_60 = 0x43300000;
              uStack_64 = (uint)DAT_803de660;
              local_68 = 0x43300000;
              dVar16 = (double)(FLOAT_803de658 +
                               (float)((double)CONCAT44(0x43300000,uStack_64) - DOUBLE_803e3038));
              iVar5 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                    uStack_5c) -
                                                                  DOUBLE_803e3038) * dVar16));
              local_70 = 0x43300000;
              uStack_6c = iVar6;
              iVar6 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,iVar6
                                                                                   ) -
                                                                  DOUBLE_803e3038) * dVar16));
              local_78 = 0x43300000;
              uStack_7c = (uint)DAT_803de661;
              local_80 = 0x43300000;
              dVar16 = (double)(FLOAT_803de65c +
                               (float)((double)CONCAT44(0x43300000,uStack_7c) - DOUBLE_803e3038));
              uStack_74 = uVar10;
              iVar7 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                    uVar10) -
                                                                  DOUBLE_803e3038) * dVar16));
              local_88 = 0x43300000;
              uStack_84 = uVar11;
              iVar8 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                    uVar11) -
                                                                  DOUBLE_803e3038) * dVar16));
              local_a0 = CONCAT31(CONCAT21(CONCAT11(DAT_803de673,DAT_803de672),DAT_803de671),
                                  DAT_803de670);
              local_9c = local_a0;
              FUN_8006fd90(iVar5,iVar7,iVar6,iVar8,&local_9c);
            }
          }
          DAT_803de696 = (ushort)DAT_803de688;
          DAT_803de694 = DAT_803de698 + 0xb;
          DAT_803de698 = DAT_803de694;
          DAT_803de69a = DAT_803de696;
        }
        else {
          if ((9 < uVar13) || (uVar13 < 9)) goto LAB_80137674;
          uVar12 = (uint)DAT_803dc878;
          iVar5 = (uint)DAT_803de69a - (DAT_803de69a / uVar12) * uVar12;
          if (iVar5 != 0) {
            uVar12 = uVar12 - iVar5;
          }
        }
      }
      else if (uVar13 < 0x81) {
LAB_80137674:
        uVar12 = FUN_80134c48(uVar4,uVar13);
      }
      else {
        uVar2 = *(undefined4 *)pbVar15;
        pbVar15 = pbVar14 + 5;
        if (DAT_803de68c != 0) {
          local_90 = uVar2;
          local_8c = uVar2;
          FUN_8025c428(1,(byte *)&local_90);
        }
      }
    }
    else if (uVar13 == 0x86) {
      bVar1 = *pbVar15;
      pbVar15 = pbVar14 + 3;
      DAT_803dc878 = CONCAT11(pbVar14[2],bVar1);
    }
    else if (uVar13 < 0x86) {
      if (uVar13 == 0x84) {
        DAT_803de690 = 1;
      }
      else if (uVar13 < 0x84) {
        DAT_803de690 = 0;
      }
      else {
        bVar1 = *pbVar15;
        pbVar15 = pbVar14 + 5;
        if (DAT_803de68c == 0) {
          DAT_803de670 = pbVar14[4];
          DAT_803de671 = pbVar14[3];
          DAT_803de672 = pbVar14[2];
          DAT_803de673 = bVar1;
          FUN_8005d370(uVar4,bVar1,pbVar14[2],pbVar14[3],pbVar14[4]);
        }
      }
    }
    else {
      if (0x87 < uVar13) goto LAB_80137674;
      DAT_803de660 = *pbVar15;
      DAT_803de661 = pbVar14[2];
      pbVar15 = pbVar14 + 3;
    }
    if (((DAT_803de690 != 0) && (0x1f < uVar13)) && (uVar13 < 0x80)) {
      uVar12 = 7;
    }
    uVar13 = DAT_803de69a + uVar12 & 0xffff;
    DAT_803de69a = (ushort)(DAT_803de69a + uVar12);
    local_60 = 0x43300000;
    uStack_64 = (uint)DAT_803de660;
    local_68 = 0x43300000;
    dVar16 = (double)(FLOAT_803de658 + (float)((double)CONCAT44(0x43300000,uStack_64) - dVar17));
    uStack_6c = DAT_803de676 - 0x10 ^ 0x80000000;
    local_70 = 0x43300000;
    pbVar14 = pbVar15;
    uStack_5c = uVar13;
    if ((float)((double)CONCAT44(0x43300000,uStack_6c) - dVar18) <
        (float)((double)(float)((double)CONCAT44(0x43300000,uVar13) - dVar17) * dVar16)) {
      if (DAT_803de68c == 0) {
        uVar9 = DAT_803de698 + 10;
        uVar11 = (uint)DAT_803de694;
        uStack_5c = (uint)DAT_803de696;
        uVar12 = countLeadingZeros(uVar13 - uStack_5c);
        uVar3 = countLeadingZeros(uVar9 - uVar11);
        if (uVar12 >> 5 == 0 && uVar3 >> 5 == 0) {
          if (1 < uStack_5c) {
            uStack_5c = uStack_5c - 2;
          }
          local_60 = 0x43300000;
          iVar5 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,uStack_5c
                                                                               ) - DOUBLE_803e3038)
                                              * dVar16));
          local_68 = 0x43300000;
          uStack_64 = uVar13 + 2;
          iVar6 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,
                                                                                uVar13 + 2) -
                                                              DOUBLE_803e3038) * dVar16));
          local_70 = 0x43300000;
          uStack_74 = (uint)DAT_803de661;
          local_78 = 0x43300000;
          dVar16 = (double)(FLOAT_803de65c +
                           (float)((double)CONCAT44(0x43300000,uStack_74) - DOUBLE_803e3038));
          uStack_6c = uVar11;
          iVar7 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,uVar11) -
                                                              DOUBLE_803e3038) * dVar16));
          local_80 = 0x43300000;
          uStack_7c = uVar9;
          iVar8 = FUN_80286718((double)(float)((double)(float)((double)CONCAT44(0x43300000,uVar9) -
                                                              DOUBLE_803e3038) * dVar16));
          local_a8 = CONCAT31(CONCAT21(CONCAT11(DAT_803de673,DAT_803de672),DAT_803de671),
                              DAT_803de670);
          local_a4 = local_a8;
          FUN_8006fd90(iVar5,iVar7,iVar6,iVar8,&local_a4);
          uVar13 = uStack_5c;
        }
      }
      uStack_5c = uVar13;
      DAT_803de696 = (ushort)DAT_803de688;
      DAT_803de694 = DAT_803de698 + 0xb;
      DAT_803de698 = DAT_803de694;
      DAT_803de69a = DAT_803de696;
    }
  } while( true );
}

/*
 * --INFO--
 *
 * Function: FUN_8013577c
 * EN v1.0 Address: 0x8013577C
 * EN v1.0 Size: 108b
 * EN v1.1 Address: 0x801378A8
 * EN v1.1 Size: 128b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013577c(undefined param_1,undefined param_2,undefined param_3,undefined param_4)
{
  undefined *puVar1;
  
  DAT_803de664 = DAT_803de664 + 1;
  if (0xfa < DAT_803de664) {
    return;
  }
  puVar1 = DAT_803dc87c + 1;
  *DAT_803dc87c = 0x81;
  DAT_803dc87c = puVar1;
  puVar1 = DAT_803dc87c + 1;
  *DAT_803dc87c = param_1;
  DAT_803dc87c = puVar1;
  puVar1 = DAT_803dc87c + 1;
  *DAT_803dc87c = param_2;
  DAT_803dc87c = puVar1;
  puVar1 = DAT_803dc87c + 1;
  *DAT_803dc87c = param_3;
  DAT_803dc87c = puVar1;
  puVar1 = DAT_803dc87c + 1;
  *DAT_803dc87c = param_4;
  DAT_803dc87c = puVar1;
  puVar1 = DAT_803dc87c + 1;
  *DAT_803dc87c = 0;
  DAT_803dc87c = puVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801357e8
 * EN v1.0 Address: 0x801357E8
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x80137928
 * EN v1.1 Size: 40b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801357e8(void)
{
  DAT_803dc87c = &DAT_803aac78;
  DAT_803de69a = (short)DAT_803de688;
  DAT_803de698 = (short)DAT_803de680;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8013580c
 * EN v1.0 Address: 0x8013580C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80137950
 * EN v1.1 Size: 736b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013580c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80135810
 * EN v1.0 Address: 0x80135810
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80137C30
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135810(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 char *param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80135814
 * EN v1.0 Address: 0x80135814
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80137CD0
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135814(void)
{
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80135818
 * EN v1.0 Address: 0x80135818
 * EN v1.0 Size: 504b
 * EN v1.1 Address: 0x80137D20
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135818(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  FUN_8006f764();
  FLOAT_803de658 = FLOAT_803e3048;
  FLOAT_803de65c = FLOAT_803e3048;
  DAT_803de660 = 0;
  DAT_803de661 = 0;
  DAT_803de6a4 = FUN_8005398c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x25d,
                              param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  DAT_803de6a0 = FUN_8005398c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,1,
                              param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  DAT_803de69c = FUN_8005398c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,2,
                              param_10,param_11,param_12,param_13,param_14,param_15,param_16);
  DAT_803dc87c = &DAT_803aac78;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80135a10
 * EN v1.0 Address: 0x80135A10
 * EN v1.0 Size: 360b
 * EN v1.1 Address: 0x80137D88
 * EN v1.1 Size: 384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135a10(undefined4 param_1,undefined4 param_2,byte *param_3)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  int iVar9;
  int iVar10;
  int iVar11;
  int iVar12;
  undefined8 uVar13;
  
  uVar13 = FUN_80286838();
  iVar1 = (int)((ulonglong)uVar13 >> 0x20);
  if (DAT_803de6a8 != '\0') {
    iVar10 = 0;
    iVar8 = ((int)uVar13 + 1) * 0x280;
    iVar9 = (int)uVar13 * 0x280;
    do {
      iVar7 = 0;
      iVar6 = iVar1 + iVar9;
      iVar11 = iVar1 + iVar8;
      iVar5 = (iVar11 + 1) * 2;
      iVar4 = iVar11 * 2;
      iVar3 = (iVar6 + 1) * 2;
      iVar2 = iVar6 * 2;
      iVar12 = 4;
      do {
        if ((1 << iVar7 & (uint)*param_3) != 0) {
          *(undefined2 *)(DAT_803de6b0 + iVar2) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar3) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar4) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar5) = 0xc080;
        }
        if ((1 << iVar7 + 1 & (uint)*param_3) != 0) {
          *(undefined2 *)(DAT_803de6b0 + iVar2 + 2) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar3 + 2) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar4 + 2) = 0xc080;
          *(undefined2 *)(DAT_803de6b0 + iVar5 + 2) = 0xc080;
        }
        iVar2 = iVar2 + 4;
        iVar3 = iVar3 + 4;
        iVar4 = iVar4 + 4;
        iVar5 = iVar5 + 4;
        iVar7 = iVar7 + 2;
        iVar12 = iVar12 + -1;
      } while (iVar12 != 0);
      FUN_80242114(DAT_803de6b0 + iVar6 * 2,0x10);
      FUN_80242114(DAT_803de6b0 + iVar11 * 2,0x10);
      iVar9 = iVar9 + 0x500;
      iVar8 = iVar8 + 0x500;
      iVar10 = iVar10 + 1;
      param_3 = param_3 + 1;
    } while (iVar10 < 5);
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80135b78
 * EN v1.0 Address: 0x80135B78
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80137F08
 * EN v1.1 Size: 424b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135b78(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,char *param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80135b7c
 * EN v1.0 Address: 0x80135B7C
 * EN v1.0 Size: 196b
 * EN v1.1 Address: 0x801380B0
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135b7c(void)
{
  FUN_802430ec(0,FUN_80135c48);
  FUN_802430ec(1,FUN_80135c48);
  FUN_802430ec(2,FUN_80135c48);
  FUN_802430ec(0xb,FUN_80135c48);
  FUN_802430ec(0xd,FUN_80135c48);
  FUN_802430ec(0xf,FUN_80135c48);
  FUN_802430ec(3,FUN_80135c48);
  FUN_802430ec(5,FUN_80135c48);
  FUN_80246a0c(-0x7fc54288,FUN_80135c44,0,0x803ad088,0x1000,0,1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80135c40
 * EN v1.0 Address: 0x80135C40
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8013817C
 * EN v1.1 Size: 4b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135c40(void)
{
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80135c44
 * EN v1.0 Address: 0x80135C44
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80138180
 * EN v1.1 Size: 2776b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135c44(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80135c48
 * EN v1.0 Address: 0x80135C48
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x80138C58
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135c48(undefined2 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4)
{
  DAT_803de6b4 = param_4;
  DAT_803de6b8 = param_3;
  DAT_803de6bc = param_2;
  DAT_803de6c0 = param_1;
  FUN_80246dcc(-0x7fc54288);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80135c84
 * EN v1.0 Address: 0x80135C84
 * EN v1.0 Size: 24b
 * EN v1.1 Address: 0x80138C90
 * EN v1.1 Size: 24b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135c84(int param_1,uint param_2)
{
  *(byte *)(*(int *)(param_1 + 0xb8) + 0x58) =
       (byte)((param_2 & 0xff) << 6) & 0x40 | *(byte *)(*(int *)(param_1 + 0xb8) + 0x58) & 0xbf;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80135c9c
 * EN v1.0 Address: 0x80135C9C
 * EN v1.0 Size: 184b
 * EN v1.1 Address: 0x80138CA8
 * EN v1.1 Size: 192b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80135c9c(int param_1,ushort param_2,short param_3)
{
  undefined4 uVar1;
  bool bVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if ((*(byte *)(iVar3 + 0x58) >> 6 & 1) == 0) {
    if ((*(short *)(param_1 + 0xa0) < 0x30) && (0x28 < *(short *)(param_1 + 0xa0))) {
      uVar1 = 0;
    }
    else {
      bVar2 = FUN_800067f0(param_1,0x10);
      if (bVar2) {
        uVar1 = 0;
      }
      else {
        FUN_80039468(param_1,iVar3 + 0x3a8,param_2,param_3,0xffffffff,0);
        uVar1 = 1;
      }
    }
  }
  else {
    uVar1 = 0;
  }
  return uVar1;
}

/*
 * --INFO--
 *
 * Function: FUN_80135d54
 * EN v1.0 Address: 0x80135D54
 * EN v1.0 Size: 484b
 * EN v1.1 Address: 0x80138D68
 * EN v1.1 Size: 384b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135d54(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10,int *param_11)
{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  char local_18 [12];
  
  if (*param_11 != 0) {
    uVar4 = ObjLink_DetachChild(param_9,*param_11);
    FUN_80017ac8(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*param_11);
    *param_11 = 0;
    local_18[0] = -1;
    local_18[1] = 0xff;
    local_18[2] = 0xff;
    iVar1 = *(int *)(param_10 + 0x7a8);
    if (iVar1 != 0) {
      local_18[*(byte *)(param_10 + 0x7bc) >> 6] = '\x01';
    }
    iVar2 = *(int *)(param_10 + 0x7b0);
    if (iVar2 != 0) {
      local_18[*(byte *)(param_10 + 0x7bc) >> 4 & 3] = '\x01';
    }
    iVar3 = *(int *)(param_10 + 0x7b8);
    if (iVar3 != 0) {
      local_18[*(byte *)(param_10 + 0x7bc) >> 2 & 3] = '\x01';
    }
    if (local_18[0] == -1) {
      if (iVar1 == 0) {
        if (iVar2 == 0) {
          if (iVar3 != 0) {
            ObjLink_DetachChild(param_9,iVar3);
            ObjLink_AttachChild(param_9,*(int *)(param_10 + 0x7b8),0);
            *(byte *)(param_10 + 0x7bc) = *(byte *)(param_10 + 0x7bc) & 0xf3;
          }
        }
        else {
          ObjLink_DetachChild(param_9,iVar2);
          ObjLink_AttachChild(param_9,*(int *)(param_10 + 0x7b0),0);
          *(byte *)(param_10 + 0x7bc) = *(byte *)(param_10 + 0x7bc) & 0xcf;
        }
      }
      else {
        ObjLink_DetachChild(param_9,iVar1);
        ObjLink_AttachChild(param_9,*(int *)(param_10 + 0x7a8),0);
        *(byte *)(param_10 + 0x7bc) = *(byte *)(param_10 + 0x7bc) & 0x3f;
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80135f38
 * EN v1.0 Address: 0x80135F38
 * EN v1.0 Size: 984b
 * EN v1.1 Address: 0x80138EE8
 * EN v1.1 Size: 540b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80135f38(int param_1,undefined4 *param_2)
{
  float fVar1;
  float fVar2;
  int *piVar3;
  
  FUN_80017a54(param_1);
  if (*(char *)((int)param_2 + 0x82e) < '\0') {
    piVar3 = (int *)FUN_80017a54(param_1);
    FUN_800178e8((double)FLOAT_803e306c,piVar3,1,-1,0x1a,0x21);
    param_2[0x20c] = FLOAT_803e3070;
    FUN_800178e4((double)FLOAT_803e306c,piVar3,0);
    *(byte *)((int)param_2 + 0x82e) = *(byte *)((int)param_2 + 0x82e) & 0x7f;
    *(byte *)((int)param_2 + 0x82e) = *(byte *)((int)param_2 + 0x82e) & 0xbf | 0x40;
  }
  if ((*(byte *)((int)param_2 + 0x82e) >> 6 & 1) != 0) {
    fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(byte *)*param_2) - DOUBLE_803e3090) /
            (float)((double)CONCAT44(0x43300000,(uint)((byte *)*param_2)[1]) - DOUBLE_803e3090);
    if (fVar1 <= (float)param_2[0x20c]) {
      if (fVar1 < (float)param_2[0x20c]) {
        param_2[0x20d] = -(FLOAT_803e3074 * FLOAT_803dc074 - (float)param_2[0x20d]);
        param_2[0x20c] = (float)param_2[0x20d] * FLOAT_803dc074 + (float)param_2[0x20c];
        fVar2 = FLOAT_803e306c;
        if ((float)param_2[0x20c] < FLOAT_803e306c) {
          param_2[0x20d] = FLOAT_803e306c;
          param_2[0x20c] = fVar2;
        }
        if ((float)param_2[0x20c] < fVar1) {
          if ((float)param_2[0x20d] <= FLOAT_803e3084) {
            param_2[0x20d] = (float)param_2[0x20d] * FLOAT_803e3080;
          }
          else {
            param_2[0x20d] = FLOAT_803e306c;
            param_2[0x20c] = fVar1;
          }
        }
      }
    }
    else {
      param_2[0x20d] = FLOAT_803e3074 * FLOAT_803dc074 + (float)param_2[0x20d];
      param_2[0x20c] = (float)param_2[0x20d] * FLOAT_803dc074 + (float)param_2[0x20c];
      fVar2 = FLOAT_803e3078;
      if ((float)param_2[0x20c] <= FLOAT_803e3078) {
        if (fVar1 < (float)param_2[0x20c]) {
          if (FLOAT_803e307c <= (float)param_2[0x20d]) {
            param_2[0x20d] = (float)param_2[0x20d] * FLOAT_803e3080;
          }
          else {
            param_2[0x20d] = FLOAT_803e306c;
            param_2[0x20c] = fVar1;
          }
        }
      }
      else {
        param_2[0x20d] = FLOAT_803e306c;
        param_2[0x20c] = fVar2;
      }
    }
    piVar3 = (int *)FUN_80017a54(param_1);
    FUN_800178e4((double)(FLOAT_803e3088 * (float)param_2[0x20c] - FLOAT_803e3078),piVar3,1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80136310
 * EN v1.0 Address: 0x80136310
 * EN v1.0 Size: 524b
 * EN v1.1 Address: 0x80139104
 * EN v1.1 Size: 380b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80136310(int param_1,int *param_2)
{
  float fVar1;
  uint uVar2;
  uint uVar3;
  int iVar4;
  undefined uVar5;
  
  uVar2 = *(byte *)(*param_2 + 2) / 10;
  if (*(byte *)(param_2 + 0x20b) != uVar2) {
    uVar3 = FUN_80017690(0x3ed);
    if (uVar3 == 0) {
      FUN_80017698(0x3ed,1);
      (**(code **)(*DAT_803dd6d4 + 0x48))(5,param_1,0xffffffff);
      param_2[0x15] = param_2[0x15] | 0x4000;
      param_2[0x20a] = (int)((float)param_2[0x20a] + FLOAT_803e3098);
    }
    param_2[0x20a] = (int)((float)param_2[0x20a] - FLOAT_803dc074);
    fVar1 = (float)param_2[0x20a];
    if (fVar1 <= FLOAT_803e3098) {
      uVar5 = (undefined)uVar2;
      if (fVar1 <= FLOAT_803e306c) {
        *(undefined *)(param_2 + 0x20b) = uVar5;
        FUN_80017a2c(param_1,0,0,0,0,0);
      }
      else {
        if (fVar1 <= FLOAT_803e3070) {
          iVar4 = FUN_80017a54(param_1);
          *(undefined *)(*(int *)(iVar4 + 0x34) + 8) = uVar5;
          fVar1 = (float)param_2[0x20a] / FLOAT_803e3070;
        }
        else {
          fVar1 = FLOAT_803e3078 - (fVar1 - FLOAT_803e3070) / FLOAT_803e3070;
        }
        FUN_80017a2c(param_1,0xff,0xff,0xff,(int)(FLOAT_803e309c * fVar1),1);
      }
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8013651c
 * EN v1.0 Address: 0x8013651C
 * EN v1.0 Size: 28b
 * EN v1.1 Address: 0x80139280
 * EN v1.1 Size: 28b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8013651c(int param_1)
{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(uint *)(iVar1 + 0x54) = *(uint *)(iVar1 + 0x54) | 0x80000000;
  *(float *)(iVar1 + 0x808) = FLOAT_803e3098;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80136538
 * EN v1.0 Address: 0x80136538
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x8013929C
 * EN v1.1 Size: 100b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80136538(int param_1)
{
  uint uVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  uVar1 = FUN_80017690(0x4e4);
  if ((uVar1 == 0) ||
     (*(uint *)(iVar3 + 0x54) = *(uint *)(iVar3 + 0x54) | 0x10000,
     (*(uint *)(iVar3 + 0x54) & 0x10) == 0)) {
    uVar2 = 0;
  }
  else {
    uVar2 = 1;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_80136594
 * EN v1.0 Address: 0x80136594
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80139300
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
double FUN_80136594(int param_1)
{
  return (double)*(float *)(*(int *)(param_1 + 0xb8) + 0x14);
}

/*
 * --INFO--
 *
 * Function: FUN_801365a0
 * EN v1.0 Address: 0x801365A0
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x8013930C
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801365a0(int param_1)
{
  return *(undefined4 *)(*(int *)(param_1 + 0xb8) + 0x24);
}

/*
 * --INFO--
 *
 * Function: FUN_801365ac
 * EN v1.0 Address: 0x801365AC
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80139318
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_801365ac(int param_1)
{
  return (int)*(short *)(*(int *)(param_1 + 0xb8) + 0x414);
}

/*
 * --INFO--
 *
 * Function: FUN_801365b8
 * EN v1.0 Address: 0x801365B8
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80139324
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_801365b8(int param_1)
{
  return *(int *)(param_1 + 0xb8) + 0x408;
}

/*
 * --INFO--
 *
 * Function: FUN_801365c4
 * EN v1.0 Address: 0x801365C4
 * EN v1.0 Size: 496b
 * EN v1.1 Address: 0x80139330
 * EN v1.1 Size: 444b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801365c4(void)
{
  short sVar1;
  int *piVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  double extraout_f1;
  double dVar8;
  double in_f30;
  double dVar9;
  double in_f31;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar10;
  int local_48 [12];
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  uVar10 = FUN_80286834();
  dVar9 = extraout_f1;
  piVar2 = ObjGroup_GetObjects(3,local_48);
  dVar9 = (double)(float)(dVar9 * dVar9);
  for (iVar7 = 0; iVar7 < local_48[0]; iVar7 = iVar7 + 1) {
    iVar3 = FUN_801113c0(*piVar2);
    if (iVar3 == 0) {
      dVar8 = FUN_8014cbcc(*piVar2);
    }
    else {
      dVar8 = (double)(**(code **)(*DAT_803dd738 + 0x60))(*piVar2);
    }
    iVar3 = *(int *)(*piVar2 + 0x4c);
    if ((int)*(short *)(iVar3 + 0x18) == 0xffffffff) {
      uVar5 = 0;
    }
    else {
      uVar5 = FUN_80017690((int)*(short *)(iVar3 + 0x18));
    }
    if ((int)*(short *)(iVar3 + 0x1a) == 0xffffffff) {
      uVar6 = 1;
    }
    else {
      uVar6 = FUN_80017690((int)*(short *)(iVar3 + 0x1a));
    }
    uVar4 = ObjGroup_ContainsObject(*piVar2,0x31);
    if ((((((uVar4 == 0) && ((double)FLOAT_803e306c < dVar8)) && (uVar5 == 0)) &&
         ((uVar6 != 0 && (*(short *)(*piVar2 + 0x46) != 0x851)))) &&
        (iVar3 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(iVar3 + 0x14)), iVar3 != 0)) &&
       ((((int)uVar10 != 0 ||
         (((sVar1 = *(short *)(*piVar2 + 0x46), sVar1 != 0x3fe && (sVar1 != 0x4d7)) &&
          ((sVar1 != 0x27c && (sVar1 != 0x251)))))) &&
        (dVar8 = FUN_80017714((float *)((int)((ulonglong)uVar10 >> 0x20) + 0x18),
                              (float *)(*piVar2 + 0x18)), dVar8 < dVar9)))) {
      dVar9 = dVar8;
    }
    piVar2 = piVar2 + 1;
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801367b4
 * EN v1.0 Address: 0x801367B4
 * EN v1.0 Size: 188b
 * EN v1.1 Address: 0x801394EC
 * EN v1.1 Size: 252b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801367b4(undefined2 *param_1,int param_2)
{
  bool bVar1;
  char cVar2;
  undefined2 local_28;
  undefined2 local_26;
  undefined2 local_24;
  float local_20;
  float local_1c;
  float local_18;
  float local_14;
  
  cVar2 = '\x14';
  if ((*(uint *)(param_2 + 0x54) & 0x1800) != 0) {
    local_1c = *(float *)(param_2 + 0x408) - *(float *)(param_1 + 0xc);
    local_18 = *(float *)(param_2 + 0x40c) - *(float *)(param_1 + 0xe);
    local_14 = *(float *)(param_2 + 0x410) - *(float *)(param_1 + 0x10);
    local_20 = FLOAT_803e3078;
    local_28 = *param_1;
    local_26 = param_1[1];
    local_24 = param_1[2];
    if ((*(uint *)(param_2 + 0x54) & 0x800) == 0) {
      while (bVar1 = cVar2 != '\0', cVar2 = cVar2 + -1, bVar1) {
        (**(code **)(*DAT_803dd708 + 8))(param_1,0x533,&local_28,2,0xffffffff,0);
      }
      *(uint *)(param_2 + 0x54) = *(uint *)(param_2 + 0x54) & 0xffffefff;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80136870
 * EN v1.0 Address: 0x80136870
 * EN v1.0 Size: 304b
 * EN v1.1 Address: 0x801395E8
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80136870(void)
{
  int iVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_8028683c();
  iVar1 = (int)((ulonglong)uVar9 >> 0x20);
  dVar7 = (double)FLOAT_803e30a8;
  iVar4 = 0;
  iVar3 = 0;
  iVar2 = iVar1;
  dVar8 = dVar7;
  for (iVar5 = 0; iVar5 < (int)(uint)*(byte *)(iVar1 + 0x798); iVar5 = iVar5 + 1) {
    if ((int)*(char *)(iVar2 + 0x74d) == (int)uVar9) {
      dVar6 = FUN_80017708((float *)(*(int *)(iVar1 + 4) + 0x18),
                           (float *)(*(int *)(iVar2 + 0x748) + 0x18));
      if (*(char *)(iVar2 + 0x74c) == '\x01') {
        if (dVar6 < dVar8) {
          iVar4 = *(int *)(iVar2 + 0x748);
          dVar8 = dVar6;
        }
      }
      else if (dVar6 < dVar7) {
        iVar3 = *(int *)(iVar2 + 0x748);
        dVar7 = dVar6;
      }
    }
    iVar2 = iVar2 + 8;
  }
  if (iVar4 == 0) {
    if (iVar3 == 0) goto LAB_801396fc;
    *(int *)(iVar1 + 0x24) = iVar3;
  }
  else {
    *(int *)(iVar1 + 0x24) = iVar4;
  }
  iVar2 = *(int *)(iVar1 + 0x24) + 0x18;
  if (*(int *)(iVar1 + 0x28) != iVar2) {
    *(int *)(iVar1 + 0x28) = iVar2;
    *(uint *)(iVar1 + 0x54) = *(uint *)(iVar1 + 0x54) & 0xfffffbff;
    *(undefined2 *)(iVar1 + 0xd2) = 0;
  }
  *(undefined *)(iVar1 + 10) = 0;
LAB_801396fc:
  FUN_80286888();
  return;
}

/* ===== EN v1.0 retargeted leaves ========================================= */

extern u32 lbl_803DD938;
extern u8  lbl_803DD988;
extern u32 lbl_803DD9B8;
extern u32 lbl_803DD9BC;
extern u8  lbl_803DD9AB;

/* 4-byte and 8-byte trivial leaves. */
void fn_80134040(void) {}
void Credits_render(void) {}
void Credits_frameEnd(void) {}
void WarpstoneUI_frameEnd(void) {}
void fn_80137DF4(void) {}
int  fn_80134044(void) { return 0; }
u8   fn_80134BBC(u8* obj) { return *obj; }

/* EN v1.0 0x801334D4  size: 12b  u16-narrow getter for lbl_803DD938. */
u16 fn_801334D4(void) { return (u16)lbl_803DD938; }

/* EN v1.0 0x801344F0  size: 12b  u8 setter writing arg low byte to
 * lbl_803DD988. */
#pragma peephole off
void WarpstoneUI_setState(int val) { lbl_803DD988 = (u8)val; }
#pragma peephole reset

/* EN v1.0 0x80135814  size: 12b  Two-word setter for state pair. */
void fn_80135814(u32 a, u32 b) { lbl_803DD9BC = a; lbl_803DD9B8 = b; }

/* EN v1.0 0x801368D4  size: 12b  Clear lbl_803DD9AB to 0. */
void fn_801368D4(void) { lbl_803DD9AB = 0; }

/* EN v1.0 0x80138F78  size: 12b  obj->_b8->_14 (f32). */
f32 fn_80138F78(u8* obj) { return *(f32*)(*(u8**)(obj + 0xb8) + 0x14); }
/* EN v1.0 0x80138F84  size: 12b  obj->_b8->_24 (u32). */
u32 fn_80138F84(u8* obj) { return *(u32*)(*(u8**)(obj + 0xb8) + 0x24); }
/* EN v1.0 0x80138F90  size: 12b  obj->_b8->_414 (s16). */
s16 fn_80138F90(u8* obj) { return *(s16*)(*(u8**)(obj + 0xb8) + 0x414); }
/* EN v1.0 0x80138F9C  size: 12b  Returns obj->_b8 + 0x408. */
void* fn_80138F9C(u8* obj) { return (void*)(*(u8**)(obj + 0xb8) + 0x408); }

/* EN v1.0 0x80135BC4  size: 8b   titlescreen_getExtraSize -> 56. */
int titlescreen_getExtraSize(void) { return 56; }

/* EN v1.0 0x80135CC4  size: 4b   titlescreen_hitDetect (empty stub). */
void titlescreen_hitDetect(void) {}

/* EN v1.0 0x80135BCC  size: 36b  titlescreen_func08: returns 74 if
 * obj->_46 (s16) is in [1917, 1920], else returns 0. */
int titlescreen_func08(u8* obj)
{
    s16 v = *(s16*)(obj + 0x46);
    if (v >= 1917 && v < 1921) return 74;
    return 0;
}

extern void* lbl_803DD9D4;
extern void* lbl_803A9F98[0x13];
extern u8    lbl_803DD992;
extern f32   lbl_803DD968;
extern f32   lbl_803E22A8;
extern u8    lbl_803DD970;
extern void* lbl_803DD974;
extern void* lbl_803DD96C;
extern void* gameTextGet(s32);
extern void* textureLoadAsset(s32);
extern void  textureFree(void*);

/* EN v1.0 0x801368E0  size: 124b  titlescreen_release: free the main
 * buffer at lbl_803DD9D4 and walk the 19-slot table at lbl_803A9F98
 * releasing each non-null entry, then clear the busy byte at
 * lbl_803DD992. */
#pragma scheduling off
#pragma peephole off
void titlescreen_release(void)
{
    void** p;
    int i;
    textureFree(lbl_803DD9D4);
    lbl_803DD9D4 = NULL;
    i = 0;
    p = lbl_803A9F98;
    while (i < 19) {
        if (*p != NULL) {
            textureFree(*p);
            *p = NULL;
        }
        p++;
        i++;
    }
    lbl_803DD992 = 0;
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x80134388  size: 68b  Acquire two buffers and prime the
 * float at lbl_803DD968. */
#pragma scheduling off
#pragma peephole off
void Credits_initialise(void)
{
    lbl_803DD974 = textureLoadAsset(0xC5);
    lbl_803DD96C = gameTextGet(0x1FD);
    lbl_803DD970 = 0;
    lbl_803DD968 = lbl_803E22A8;
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x80138F14  size: 100b  GameBit-gated bit toggle on
 * obj->_b8->_54: requires GameBit_Get(0x4E4); sets bit 0x10000 then
 * checks bit 0x10. Returns 1 only when the post-OR check passes. */
int fn_80138F14(u8* obj)
{
    u8* b = *(u8**)(obj + 0xb8);
    if (GameBit_Get(0x4E4) == 0) return 0;
    *(u32*)(b + 0x54) |= 0x10000;
    if ((*(u32*)(b + 0x54) & 0x10) != 0) return 1;
    return 0;
}

extern u8    lbl_803A9FE4[0x34];
extern f32   lbl_803E22F8;
extern f32   lbl_803E2344;
extern f32   lbl_803E2348;
extern f32   lbl_803E234C;
extern f32   lbl_803E2350;
extern f32   lbl_803E2318;
extern f32   lbl_803DD9C8;
extern f32   lbl_803DD9B4;
extern f32   lbl_803DD9B0;
extern void  PSMTXTrans(void*, f32, f32, f32);

extern void* lbl_803DBBC8[2];
extern void  Obj_FreeObject(void*);
extern void* minimapTexture;
extern void* lbl_803DD940;

extern f32   lbl_803E23B8;
extern f32   lbl_803DD9D8;
extern f32   lbl_803DD9DC;
extern u8    lbl_803DD9E0;
extern u8    lbl_803DD9E1;
extern void* lbl_803DDA1C;
extern void* lbl_803DDA20;
extern void* lbl_803DDA24;
extern void* debugLogEnd;
extern u8    debugLogBuffer[0x1100];
extern void  getScreenResolution(void);

/* EN v1.0 0x80137998  size: 104b  Title-screen system init. Calls
 * getScreenResolution, primes the two float counters, clears two state bytes,
 * acquires three sized buffers (605/1/2 bytes) and primes the
 * debugLogEnd cursor to the start of the 0x1100-byte arena. */
#pragma scheduling off
#pragma peephole off
void fn_80137998(void)
{
    getScreenResolution();
    lbl_803DD9D8 = lbl_803E23B8;
    lbl_803DD9DC = lbl_803E23B8;
    lbl_803DD9E0 = 0;
    lbl_803DD9E1 = 0;
    lbl_803DDA24 = textureLoadAsset(0x25D);
    lbl_803DDA20 = textureLoadAsset(1);
    lbl_803DDA1C = textureLoadAsset(2);
    debugLogEnd = debugLogBuffer;
}
#pragma peephole reset
#pragma scheduling reset

extern int  Sfx_IsPlayingFromObjectChannel(u8*, int);
extern void fn_800393F8(u8*, u8*, int, int, int, int);

/* EN v1.0 0x80138920  size: 192b  Drop-anim trigger guard. Returns 1
 * (and dispatches the drop anim via fn_800393F8) only when:
 *   - bit 0x40 of obj->_b8->_58 is set,
 *   - the target halfword obj->_a0 is OUTSIDE the [41, 47] window,
 *   - Sfx_IsPlayingFromObjectChannel(obj, 16) returns 0. */
#pragma scheduling off
#pragma peephole off
int fn_80138920(u8* obj, int arg1, int arg2)
{
    u8* b = *(u8**)(obj + 0xb8);
    if ((u32)((b[0x58] >> 6) & 1) != 0u) return 0;
    {
        s16 v = *(s16*)(obj + 0xa0);
        if (v < 48 && v >= 41) return 0;
    }
    if (Sfx_IsPlayingFromObjectChannel(obj, 16) != 0) return 0;
    fn_800393F8(obj, b + 936, arg1, arg2, -1, 0);
    return 1;
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x80133EA4  size: 156b  Two-step shutdown helper. Releases
 * the buffers at minimapTexture and lbl_803DD940 (the first only if
 * non-null), then walks the 2-slot live-objects table at lbl_803DBBC8
 * tearing down each non-null entry via Obj_FreeObject. Both buffer
 * pointers are zeroed at the end. */
void Minimap_release(void)
{
    u8 i;
    void** slots;
    if (minimapTexture != NULL) textureFree(minimapTexture);
    textureFree(lbl_803DD940);
    slots = lbl_803DBBC8;
    i = 0;
    while ((u32)i < 2) {
        if (slots[i] != NULL) {
            Obj_FreeObject(slots[i]);
            slots[i] = NULL;
        }
        i++;
    }
    minimapTexture = NULL;
    lbl_803DD940 = NULL;
}

/* EN v1.0 0x80135820  size: 136b  Set up the title-screen translation
 * matrix at lbl_803A9FE4 and derive the three normalized cursor
 * positions from the supplied (a, b) coordinates. */
#pragma scheduling off
#pragma peephole off
void fn_80135820(f32 a, f32 b)
{
    PSMTXTrans(lbl_803A9FE4, a, b, lbl_803E22F8);
    lbl_803DD9C8 = (lbl_803E2344 - b) / lbl_803E2348;
    lbl_803DD9B4 = (a - lbl_803E234C) / lbl_803E2350;
    lbl_803DD9B0 = lbl_803E2318 - lbl_803DD9C8;
}
#pragma peephole reset
#pragma scheduling reset

extern void* lbl_803DD960;
extern void* lbl_803DD974;
extern void* lbl_803DD96C;
extern u8    lbl_803DD970;
/* lbl_803DD940 declared later as void* */
extern u8    lbl_803DD990;
extern u8    lbl_803DD991;
extern u8    lbl_803DBC08;
extern u8    lbl_803DBC09;
extern f32   lbl_803E2408;

/* EN v1.0 0x80133F40  size: 48b  Acquire a 0xBE5-byte buffer via
 * textureLoadAsset into lbl_803DD940; reset frame counter at lbl_803DD938. */
#pragma scheduling off
#pragma peephole off
void Minimap_initialise(void)
{
    lbl_803DD940 = textureLoadAsset(0xBE5);
    lbl_803DD938 = 340;
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x8013404C  size: 36b  Release the buffer at lbl_803DD960
 * via textureFree. */
void fn_8013404C(void)
{
    textureFree(lbl_803DD960);
}

/* EN v1.0 0x80134070  size: 40b  Acquire 0x47A-byte buffer into
 * lbl_803DD960. */
#pragma scheduling off
#pragma peephole off
void fn_80134070(void)
{
    lbl_803DD960 = textureLoadAsset(0x47A);
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x80134364  size: 36b  Release lbl_803DD974 buffer. */
void Credits_release(void)
{
    textureFree(lbl_803DD974);
}

/* EN v1.0 0x801368A4  size: 32b  Two-byte state push: if arg differs
 * from lbl_803DD991, save old to lbl_803DBC09 and set new. */
void fn_801368A4(s8 arg)
{
    u8 cur = lbl_803DD991;
    if (arg == (s8)cur) return;
    lbl_803DBC09 = cur;
    lbl_803DD991 = (u8)arg;
}

/* EN v1.0 0x801368C4  size: 16b  Two-byte state push (no equality
 * check): copy lbl_803DD990 to lbl_803DBC08 and write new value. */
void fn_801368C4(u8 arg)
{
    lbl_803DBC08 = lbl_803DD990;
    lbl_803DD990 = arg;
}

/* EN v1.0 0x80138EF8  size: 28b  Set bit 0x80000000 of obj->_b8->_54
 * and store lbl_803E2408 into obj->_b8->_808. */
void fn_80138EF8(u8* obj)
{
    u8* b = *(u8**)(obj + 0xb8);
    *(u32*)(b + 0x54) |= 0x80000000;
    *(f32*)(b + 0x808) = lbl_803E2408;
}

extern void* lbl_803DD984;
extern void* lbl_803DD980;
extern void* minimapTexture;
extern void* lbl_803DD92C;
extern f32   lbl_803DD97C;
extern f32   lbl_803E22E0;
extern u8    lbl_803DD993;
extern u8    lbl_803DD9AA;
extern s16   lbl_803DD994;
extern s16   lbl_803DD996;
extern s16   lbl_803DD998;
extern s16   lbl_803DD9A8;
extern int   fn_80014940(void);

/* EN v1.0 0x80134808  size: 44b  Release two buffer slots in sequence:
 * textureFree(lbl_803DD984) then textureFree(lbl_803DD980). */
void WarpstoneUI_release(void)
{
    textureFree(lbl_803DD984);
    textureFree(lbl_803DD980);
}

/* EN v1.0 0x80134834  size: 60b  Acquire two buffer slots and prime
 * the float at lbl_803DD97C with the constant from lbl_803E22E0. */
#pragma scheduling off
#pragma peephole off
void WarpstoneUI_initialise(void)
{
    lbl_803DD984 = textureLoadAsset(0x4FA);
    lbl_803DD980 = textureLoadAsset(0x5E3);
    lbl_803DD97C = lbl_803E22E0;
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x80134BC4  size: 32b  Reset the per-frame state group:
 * latch lbl_803DD993 = 1 and zero five halfword/byte counters. */
#pragma scheduling off
#pragma peephole off
void fn_80134BC4(void)
{
    lbl_803DD993 = 1;
    lbl_803DD994 = 0;
    lbl_803DD996 = 0;
    lbl_803DD9A8 = 0;
    lbl_803DD998 = 0;
    lbl_803DD9AA = 0;
}
#pragma peephole reset
#pragma scheduling reset

/* EN v1.0 0x80134BE8  size: 60b  Predicate. Returns 1 when the value
 * from fn_80014940 is in {2..6} or equals 7, else 0. */
int fn_80134BE8(void)
{
    int x = fn_80014940();
    if ((u32)(x - 2) <= 4 || x == 7) {
        return 1;
    }
    return 0;
}

/* EN v1.0 0x80133934  size: 52b  Release-and-clear pair: when
 * minimapTexture is non-null, release via textureFree and zero both
 * minimapTexture and lbl_803DD92C. */
void fn_80133934(void)
{
    if (minimapTexture != NULL) {
        textureFree(minimapTexture);
        minimapTexture = NULL;
        lbl_803DD92C = NULL;
    }
}
