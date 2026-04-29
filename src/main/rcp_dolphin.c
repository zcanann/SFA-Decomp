#include "ghidra_import.h"
#include "main/rcp_dolphin.h"

extern undefined4 FUN_800033a8();
extern undefined4 FUN_80003494();
extern undefined4 FUN_80006988();
extern undefined4 FUN_8001757c();
extern undefined4 FUN_80017588();
extern undefined4 FUN_8001758c();
extern undefined4 FUN_800175fc();
extern undefined4 FUN_80017600();
extern undefined4 FUN_80017604();
extern undefined4 FUN_80017608();
extern undefined4 FUN_80017610();
extern undefined4 FUN_80017614();
extern undefined4 FUN_8001763c();
extern undefined4 FUN_80017640();
extern undefined8 FUN_80017644();
extern undefined4 FUN_80017670();
extern undefined4 FUN_800176d8();
extern uint FUN_80017760();
extern undefined4 FUN_800177b4();
extern undefined4 FUN_800177c4();
extern int FUN_80017800();
extern undefined4 FUN_80017814();
extern undefined4 FUN_80017818();
extern uint FUN_80017824();
extern undefined8 FUN_8001782c();
extern uint FUN_80017830();
extern int FUN_80017a98();
extern undefined4 FUN_80017ae4();
extern undefined4 FUN_80040da0();
extern int FUN_80042838();
extern undefined4 FUN_80042f88();
extern undefined8 FUN_80044400();
extern undefined8 FUN_80044840();
extern undefined8 FUN_80044bc4();
extern undefined8 FUN_80044d44();
extern undefined4 FUN_80047d88();
extern undefined4 FUN_8004812c();
extern undefined4 FUN_8004adc4();
extern undefined4 FUN_8006b4f8();
extern undefined4 FUN_8006f8a4();
extern undefined4 FUN_8006f8fc();
extern undefined8 FUN_800723a0();
extern undefined4 FUN_80080f94();
extern int FUN_80080f98();
extern int FUN_80080fa0();
extern void* FUN_800e87a8();
extern undefined4 FUN_8011e7ac();
extern undefined4 FUN_8013028c();
extern undefined4 FUN_802420b0();
extern undefined4 FUN_80242114();
extern undefined4 FUN_80243e74();
extern undefined4 FUN_80243e9c();
extern undefined4 FUN_802475b8();
extern undefined4 FUN_80247a7c();
extern undefined4 FUN_80247dfc();
extern undefined4 FUN_802570dc();
extern undefined4 FUN_80257b5c();
extern undefined4 FUN_80258674();
extern undefined4 FUN_80258944();
extern undefined4 FUN_8025898c();
extern undefined8 FUN_80259000();
extern undefined4 FUN_80259288();
extern undefined4 FUN_80259340();
extern undefined4 FUN_80259400();
extern undefined4 FUN_802594c0();
extern undefined4 FUN_80259504();
extern undefined4 FUN_80259c0c();
extern undefined4 FUN_8025a2ec();
extern undefined4 FUN_8025a454();
extern int FUN_8025a850();
extern undefined4 FUN_8025aa74();
extern undefined4 FUN_8025ace8();
extern undefined4 FUN_8025ae7c();
extern uint FUN_8025ae84();
extern uint FUN_8025ae94();
extern int FUN_8025aea4();
extern undefined4 FUN_8025aeac();
extern undefined4 FUN_8025b054();
extern undefined4 FUN_8025b280();
extern undefined4 FUN_8025be54();
extern undefined4 FUN_8025be80();
extern undefined4 FUN_8025c1a4();
extern undefined4 FUN_8025c224();
extern undefined4 FUN_8025c2a8();
extern undefined4 FUN_8025c368();
extern undefined4 FUN_8025c428();
extern undefined4 FUN_8025c510();
extern undefined4 FUN_8025c584();
extern undefined4 FUN_8025c5f0();
extern undefined4 FUN_8025c65c();
extern undefined4 FUN_8025c6b4();
extern undefined4 FUN_8025c754();
extern undefined4 FUN_8025c828();
extern undefined4 FUN_8025ca04();
extern undefined4 FUN_8025cce8();
extern undefined4 FUN_8025d4a0();
extern undefined4 FUN_8025d568();
extern undefined4 FUN_8025d63c();
extern undefined4 FUN_8025d6ac();
extern undefined4 FUN_8025d80c();
extern undefined4 FUN_8025d848();
extern undefined4 FUN_8025d888();
extern undefined4 FUN_8025d8c4();
extern undefined4 FUN_8025da64();
extern undefined4 FUN_8025da88();
extern longlong FUN_80286810();
extern int FUN_80286830();
extern undefined8 FUN_80286834();
extern undefined8 FUN_80286838();
extern undefined8 FUN_8028683c();
extern undefined4 FUN_80286840();
extern undefined4 FUN_8028685c();
extern undefined4 FUN_8028687c();
extern undefined4 FUN_80286880();
extern undefined4 FUN_80286884();
extern undefined4 FUN_80286888();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_802924c4();
extern undefined4 FUN_80292f04();
extern double FUN_80293900();
extern uint countLeadingZeros();

extern undefined4 DAT_80000000;
extern undefined4 DAT_8030dac4;
extern undefined4 DAT_8030dac8;
extern undefined4 DAT_8030dacc;
extern undefined4 DAT_8030dbe8;
extern undefined4 DAT_80378600;
extern undefined4 DAT_80378620;
extern int DAT_8037ec60;
extern undefined4 DAT_8037ec6c;
extern undefined4 DAT_8037ec6d;
extern undefined4 DAT_8037ec6e;
extern undefined4 DAT_8037ec7b;
extern int DAT_8037ecec;
extern undefined4 DAT_8037ed08;
extern undefined4 DAT_8037ed0c;
extern undefined4 DAT_8037ed10;
extern int* DAT_8037ed14;
extern int* DAT_8037ed18;
extern int* DAT_8037ed1c;
extern undefined4 DAT_80382e28;
extern undefined4 DAT_80382e2c;
extern undefined4 DAT_80382e30;
extern undefined4 DAT_80382f14;
extern undefined4 DAT_80382f18;
extern undefined4 DAT_80382f1c;
extern undefined4 DAT_80382f20;
extern undefined4 DAT_80382f24;
extern undefined4 DAT_803870c8;
extern undefined4 DAT_803872a8;
extern undefined4 DAT_803872ac;
extern undefined4 DAT_803872b0;
extern undefined4* DAT_80388600;
extern undefined4 DAT_80388604;
extern undefined4 DAT_80388608;
extern undefined4 DAT_8038860c;
extern undefined4 DAT_8038860e;
extern undefined4 DAT_803dc070;
extern undefined4 DAT_803dc260;
extern undefined4 DAT_803dc264;
extern undefined4 DAT_803dc268;
extern undefined4 DAT_803dd6c0;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd6d8;
extern undefined4* DAT_803dd6dc;
extern undefined4* DAT_803dd6e0;
extern undefined4* DAT_803dd6e4;
extern undefined4* DAT_803dd72c;
extern undefined4 DAT_803dd9b0;
extern undefined4 DAT_803dd9c8;
extern undefined4 DAT_803dd9c9;
extern undefined4 DAT_803dd9ca;
extern undefined4 DAT_803dd9cb;
extern undefined4 DAT_803dd9cc;
extern undefined4 DAT_803dd9d0;
extern undefined4 DAT_803dd9d4;
extern undefined4 DAT_803dd9d8;
extern undefined4 DAT_803dd9dc;
extern undefined4 DAT_803dd9e0;
extern undefined4 DAT_803dd9e4;
extern undefined4 DAT_803dd9e8;
extern undefined4 DAT_803dd9e9;
extern undefined4 DAT_803dd9ea;
extern undefined4 DAT_803dd9eb;
extern undefined4 DAT_803dd9ec;
extern undefined4 DAT_803dd9f0;
extern undefined4 DAT_803dd9f4;
extern undefined4 DAT_803dd9f8;
extern undefined4 DAT_803dd9fc;
extern undefined4 DAT_803dda00;
extern undefined4 DAT_803dda04;
extern undefined4 DAT_803dda08;
extern undefined4 DAT_803dda0c;
extern undefined4 DAT_803dda10;
extern undefined4 DAT_803dda18;
extern undefined4 DAT_803dda1c;
extern undefined4 DAT_803dda20;
extern undefined4 DAT_803dda24;
extern undefined4 DAT_803dda25;
extern undefined4 DAT_803dda28;
extern undefined4 DAT_803dda2c;
extern undefined4 DAT_803dda30;
extern undefined4 DAT_803dda34;
extern undefined4* DAT_803dda38;
extern undefined4 DAT_803dda3c;
extern undefined4 DAT_803dda40;
extern int* DAT_803dda44;
extern undefined4 DAT_803dda60;
extern undefined4 DAT_803dda74;
extern undefined4 DAT_803dda75;
extern undefined4 DAT_803dda76;
extern undefined4 DAT_803dda77;
extern undefined4 DAT_803dda78;
extern undefined4 DAT_803dda79;
extern undefined4 DAT_803dda7a;
extern undefined4 DAT_803dda7b;
extern undefined4 DAT_803dda80;
extern undefined4 DAT_803ddab8;
extern undefined4 DAT_803ddac0;
extern undefined4* DAT_803ddaf8;
extern undefined4 DAT_803ddb38;
extern undefined4 DAT_803ddb3a;
extern undefined4 DAT_803ddb3c;
extern undefined4 DAT_803ddb3d;
extern undefined4 DAT_cc008000;
extern f64 DOUBLE_803df7e8;
extern f64 DOUBLE_803df820;
extern f64 DOUBLE_803df828;
extern f32 FLOAT_803dc28c;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;
extern f32 FLOAT_803ddabc;
extern f32 FLOAT_803ddac4;
extern f32 FLOAT_803ddac8;
extern f32 FLOAT_803ddacc;
extern f32 FLOAT_803ddad0;
extern f32 FLOAT_803df7c8;
extern f32 FLOAT_803df7cc;
extern f32 FLOAT_803df7d0;
extern f32 FLOAT_803df7d4;
extern f32 FLOAT_803df7d8;
extern f32 FLOAT_803df7dc;
extern f32 FLOAT_803df7e0;
extern f32 FLOAT_803df7e4;
extern f32 FLOAT_803df7f0;
extern f32 FLOAT_803df7f4;
extern f32 FLOAT_803df7f8;
extern f32 FLOAT_803df7fc;
extern f32 FLOAT_803df800;
extern f32 FLOAT_803df804;
extern f32 FLOAT_803df808;
extern f32 FLOAT_803df818;
extern f32 FLOAT_803df81c;
extern f32 FLOAT_803df838;
extern undefined uRam0000004b;
extern undefined uRam803ddac1;
extern undefined2 uRam803ddac2;

/*
 * --INFO--
 *
 * Function: FUN_80051868
 * EN v1.0 Address: 0x80051868
 * EN v1.0 Size: 668b
 * EN v1.1 Address: 0x800519E4
 * EN v1.1 Size: 664b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80051868(int param_1,float *param_2,int param_3)
{
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,4);
  FUN_8025c65c(DAT_803dda10,0,0);
  if (param_2 == (float *)0x0) {
    FUN_80258674(DAT_803dda08,1,DAT_803dd9f8,0x3c,0,0x7d);
  }
  else {
    FUN_8025d8c4(param_2,DAT_803dda00,0);
    FUN_80258674(DAT_803dda08,1,DAT_803dd9f8,0x3c,0,DAT_803dda00);
    DAT_803dda00 = DAT_803dda00 + 3;
  }
  if (param_3 == 0) {
    FUN_8025c1a4(DAT_803dda10,0xf,8,10,0xf);
  }
  else if (param_3 == 8) {
    FUN_8025c1a4(DAT_803dda10,0xf,8,10,6);
  }
  else if (param_3 == 4) {
    FUN_8025c1a4(DAT_803dda10,8,0xf,0xf,0);
  }
  else if (param_3 == 6) {
    FUN_8025c1a4(DAT_803dda10,0xf,8,0,0xf);
  }
  else if (param_3 == 9) {
    FUN_8025c1a4(DAT_803dda10,8,0,1,0xf);
  }
  else {
    FUN_8025c1a4(DAT_803dda10,8,0,1,0xf);
  }
  if (DAT_803dd9eb == '\0') {
    FUN_8025c224(DAT_803dda10,7,4,5,7);
    DAT_803dd9eb = '\x01';
  }
  else {
    FUN_8025c224(DAT_803dda10,7,4,0,7);
  }
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  if (param_1 != 0) {
    if (*(char *)(param_1 + 0x48) == '\0') {
      FUN_8025b054((uint *)(param_1 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(param_1 + 0x20),*(uint **)(param_1 + 0x40),DAT_803dda0c);
    }
  }
  DAT_803dd9f8 = DAT_803dd9f8 + 1;
  DAT_803dda08 = DAT_803dda08 + 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dda0c = DAT_803dda0c + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80051b04
 * EN v1.0 Address: 0x80051B04
 * EN v1.0 Size: 608b
 * EN v1.1 Address: 0x80051C7C
 * EN v1.1 Size: 604b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80051b04(int param_1,float *param_2,int param_3,char *param_4)
{
  undefined4 uStack_18;
  int local_14;
  
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,4);
  FUN_8025c65c(DAT_803dda10,0,0);
  if (param_2 == (float *)0x0) {
    FUN_80258674(DAT_803dda08,1,DAT_803dd9f8,0x3c,0,0x7d);
  }
  else {
    FUN_8025d8c4(param_2,DAT_803dda00,0);
    FUN_80258674(DAT_803dda08,1,DAT_803dd9f8,0x3c,0,DAT_803dda00);
    DAT_803dda00 = DAT_803dda00 + 3;
  }
  FUN_80047d88(param_4,'\x01','\0',&local_14,&uStack_18);
  FUN_8025c584(DAT_803dda10,local_14);
  if (param_3 == 0) {
    FUN_8025c1a4(DAT_803dda10,0xf,8,0xe,0xf);
  }
  else if (param_3 == 8) {
    FUN_8025c1a4(DAT_803dda10,0xf,8,0xe,6);
  }
  else {
    FUN_8025c1a4(DAT_803dda10,8,0,1,0xf);
  }
  if (DAT_803dd9eb == '\0') {
    FUN_8025c224(DAT_803dda10,7,4,5,7);
    DAT_803dd9eb = '\x01';
  }
  else {
    FUN_8025c224(DAT_803dda10,7,4,0,7);
  }
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  if (param_1 != 0) {
    if (*(char *)(param_1 + 0x48) == '\0') {
      FUN_8025b054((uint *)(param_1 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(param_1 + 0x20),*(uint **)(param_1 + 0x40),DAT_803dda0c);
    }
  }
  DAT_803dd9f8 = DAT_803dd9f8 + 1;
  DAT_803dda08 = DAT_803dda08 + 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dda0c = DAT_803dda0c + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80051d64
 * EN v1.0 Address: 0x80051D64
 * EN v1.0 Size: 608b
 * EN v1.1 Address: 0x80051ED8
 * EN v1.1 Size: 604b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80051d64(int param_1,float *param_2,int param_3,char *param_4)
{
  int local_18;
  undefined4 uStack_14;
  
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,4);
  FUN_8025c65c(DAT_803dda10,0,0);
  if (param_2 == (float *)0x0) {
    FUN_80258674(DAT_803dda08,1,DAT_803dd9f8,0x3c,0,0x7d);
  }
  else {
    FUN_8025d8c4(param_2,DAT_803dda00,0);
    FUN_80258674(DAT_803dda08,1,DAT_803dd9f8,0x3c,0,DAT_803dda00);
    DAT_803dda00 = DAT_803dda00 + 3;
  }
  FUN_80047d88(param_4,'\0','\x01',&uStack_14,&local_18);
  FUN_8025c5f0(DAT_803dda10,local_18);
  if (param_3 == 0) {
    FUN_8025c1a4(DAT_803dda10,0xf,8,10,0xf);
  }
  else if (param_3 == 8) {
    FUN_8025c1a4(DAT_803dda10,0xf,8,10,6);
  }
  else {
    FUN_8025c1a4(DAT_803dda10,8,0,1,0xf);
  }
  if (DAT_803dd9eb == '\0') {
    FUN_8025c224(DAT_803dda10,7,4,6,7);
    DAT_803dd9eb = '\x01';
  }
  else {
    FUN_8025c224(DAT_803dda10,7,4,0,7);
  }
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  if (param_1 != 0) {
    if (*(char *)(param_1 + 0x48) == '\0') {
      FUN_8025b054((uint *)(param_1 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(param_1 + 0x20),*(uint **)(param_1 + 0x40),DAT_803dda0c);
    }
  }
  DAT_803dd9f8 = DAT_803dd9f8 + 1;
  DAT_803dda08 = DAT_803dda08 + 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dda0c = DAT_803dda0c + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80051fc4
 * EN v1.0 Address: 0x80051FC4
 * EN v1.0 Size: 1056b
 * EN v1.1 Address: 0x80052134
 * EN v1.1 Size: 1048b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80051fc4(undefined4 param_1,undefined4 param_2,int param_3,char *param_4,uint param_5,
                 uint param_6)
{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  undefined4 local_28;
  int local_24;
  int local_20 [8];
  
  uVar3 = FUN_8028683c();
  iVar2 = (int)((ulonglong)uVar3 >> 0x20);
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
  FUN_8025c65c(DAT_803dda10,0,1);
  iVar1 = (param_5 & 0xff) * 0xc;
  FUN_8025c6b4(1,*(uint *)(&DAT_8030dac4 + iVar1),*(int *)(&DAT_8030dac8 + iVar1),
               *(uint *)(&DAT_8030dacc + iVar1),3);
  if ((float *)uVar3 == (float *)0x0) {
    FUN_80258674(DAT_803dda08,1,DAT_803dd9f8,0x3c,0,0x7d);
  }
  else {
    FUN_8025d8c4((float *)uVar3,DAT_803dda00,0);
    FUN_80258674(DAT_803dda08,1,DAT_803dd9f8,0x3c,0,DAT_803dda00);
    DAT_803dda00 = DAT_803dda00 + 3;
  }
  if ((param_6 & 0xff) == 0) {
    local_28 = *(undefined4 *)param_4;
    FUN_8025c510(DAT_803dd9f4,(byte *)&local_28);
    FUN_8025c584(DAT_803dda10,DAT_803dd9f0);
    if (*(int *)(iVar2 + 0x50) == 0) {
      FUN_8025c5f0(DAT_803dda10,DAT_803dd9ec);
    }
    else {
      FUN_8025c5f0(DAT_803dda10 + 1,DAT_803dd9ec);
    }
    DAT_803dd9f4 = DAT_803dd9f4 + 1;
    DAT_803dd9f0 = DAT_803dd9f0 + 1;
    DAT_803dd9ec = DAT_803dd9ec + 1;
  }
  else {
    FUN_80047d88(param_4,'\x01','\x01',local_20,&local_24);
    FUN_8025c584(DAT_803dda10,local_20[0]);
    if (*(int *)(iVar2 + 0x50) == 0) {
      FUN_8025c5f0(DAT_803dda10,local_24);
    }
    else {
      FUN_8025c5f0(DAT_803dda10 + 1,local_24);
    }
  }
  if (param_3 == 0) {
    FUN_8025c1a4(DAT_803dda10,0xf,8,0xe,0xf);
  }
  else if (param_3 == 8) {
    FUN_8025c1a4(DAT_803dda10,0xf,8,4,6);
  }
  else {
    FUN_8025c1a4(DAT_803dda10,8,0,1,0xf);
  }
  if (DAT_803dd9eb == '\0') {
    FUN_8025c224(DAT_803dda10,7,4,6,7);
  }
  else {
    FUN_8025c224(DAT_803dda10,7,4,0,7);
  }
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  if (iVar2 != 0) {
    if (*(char *)(iVar2 + 0x48) == '\0') {
      FUN_8025b054((uint *)(iVar2 + 0x20),DAT_803dda0c);
    }
    else {
      FUN_8025aeac((uint *)(iVar2 + 0x20),*(uint **)(iVar2 + 0x40),DAT_803dda0c);
    }
    if (*(int *)(iVar2 + 0x50) != 0) {
      FUN_800530b8(iVar2,(uint *)&DAT_80378600);
      FUN_8025b054((uint *)&DAT_80378600,1);
    }
  }
  if (*(int *)(iVar2 + 0x50) != 0) {
    DAT_803dd9ea = DAT_803dd9ea + '\x01';
    DAT_803dda10 = DAT_803dda10 + 1;
    DAT_803dda0c = DAT_803dda0c + 1;
    FUN_8025be80(DAT_803dda10);
    FUN_8025c828(DAT_803dda10,DAT_803dda08,DAT_803dda0c,0xff);
    FUN_8025c65c(DAT_803dda10,0,0);
    FUN_8025c1a4(DAT_803dda10,0xf,0xf,0xf,0);
    FUN_8025c224(DAT_803dda10,7,4,6,7);
    FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
    FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  }
  DAT_803dd9eb = 1;
  DAT_803dd9f8 = DAT_803dd9f8 + 1;
  DAT_803dda08 = DAT_803dda08 + 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dda0c = DAT_803dda0c + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  DAT_803dd9e9 = DAT_803dd9e9 + '\x01';
  FUN_80286888();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800523e4
 * EN v1.0 Address: 0x800523E4
 * EN v1.0 Size: 284b
 * EN v1.1 Address: 0x8005254C
 * EN v1.1 Size: 284b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800523e4(void)
{
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,0xff,0xff,4);
  FUN_8025c65c(DAT_803dda10,0,0);
  if ((DAT_803dd9ea == '\0') || (DAT_803dd9b0 == '\0')) {
    FUN_8025c1a4(DAT_803dda10,0xf,0xf,0xf,10);
    FUN_8025c224(DAT_803dda10,7,7,7,5);
  }
  else {
    FUN_8025c1a4(DAT_803dda10,0xf,0,10,0xf);
    FUN_8025c224(DAT_803dda10,7,0,5,7);
  }
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80052500
 * EN v1.0 Address: 0x80052500
 * EN v1.0 Size: 332b
 * EN v1.1 Address: 0x80052668
 * EN v1.1 Size: 332b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80052500(char *param_1)
{
  int local_18;
  undefined4 auStack_14 [4];
  
  FUN_8025be80(DAT_803dda10);
  FUN_8025c828(DAT_803dda10,0xff,0xff,4);
  FUN_8025c65c(DAT_803dda10,0,0);
  FUN_80047d88(param_1,'\0','\x01',auStack_14,&local_18);
  FUN_8025c5f0(DAT_803dda10,local_18);
  if ((DAT_803dd9ea == '\0') || (DAT_803dd9b0 == '\0')) {
    FUN_8025c1a4(DAT_803dda10,0xf,0xf,0xf,10);
    FUN_8025c224(DAT_803dda10,7,7,7,6);
  }
  else {
    FUN_8025c1a4(DAT_803dda10,0xf,0,10,0xf);
    FUN_8025c224(DAT_803dda10,7,0,6,7);
  }
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005264c
 * EN v1.0 Address: 0x8005264C
 * EN v1.0 Size: 300b
 * EN v1.1 Address: 0x800527B4
 * EN v1.1 Size: 300b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005264c(char *param_1)
{
  undefined4 local_18;
  undefined4 uStack_14;
  int local_10 [3];
  
  FUN_8025be80(DAT_803dda10);
  local_18 = *(undefined4 *)param_1;
  FUN_8025c428(1,(byte *)&local_18);
  FUN_80047d88(param_1,'\x01','\0',local_10,&uStack_14);
  FUN_8025c584(DAT_803dda10,local_10[0]);
  FUN_8025c828(DAT_803dda10,0xff,0xff,0xff);
  FUN_8025c65c(DAT_803dda10,0,0);
  if ((DAT_803dd9ea != '\0') && (DAT_803dd9b0 != '\0')) {
    FUN_8025c1a4(DAT_803dda10,0,0xe,3,0xf);
    FUN_8025c224(DAT_803dda10,7,7,7,0);
  }
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80052778
 * EN v1.0 Address: 0x80052778
 * EN v1.0 Size: 344b
 * EN v1.1 Address: 0x800528E0
 * EN v1.1 Size: 344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80052778(char *param_1)
{
  int local_18;
  int local_14 [4];
  
  FUN_8025be80(DAT_803dda10);
  FUN_80047d88(param_1,'\x01','\x01',local_14,&local_18);
  FUN_8025c5f0(DAT_803dda10,local_18);
  FUN_8025c584(DAT_803dda10,local_14[0]);
  FUN_8025c828(DAT_803dda10,0xff,0xff,4);
  FUN_8025c65c(DAT_803dda10,0,0);
  if ((DAT_803dd9ea == '\0') || (DAT_803dd9b0 == '\0')) {
    FUN_8025c1a4(DAT_803dda10,0xf,0xf,0xf,0xe);
    FUN_8025c224(DAT_803dda10,7,7,7,6);
  }
  else {
    FUN_8025c1a4(DAT_803dda10,0xf,0,0xe,0xf);
    FUN_8025c224(DAT_803dda10,7,0,6,7);
  }
  FUN_8025c2a8(DAT_803dda10,0,0,0,1,0);
  FUN_8025c368(DAT_803dda10,0,0,0,1,0);
  DAT_803dd9b0 = 1;
  DAT_803dda10 = DAT_803dda10 + 1;
  DAT_803dd9ea = DAT_803dd9ea + '\x01';
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800528d0
 * EN v1.0 Address: 0x800528D0
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x80052A38
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800528d0(void)
{
  FUN_80258944((uint)DAT_803dd9e9);
  FUN_8025ca04((uint)DAT_803dd9ea);
  FUN_8025be54((uint)DAT_803dd9e8);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80052904
 * EN v1.0 Address: 0x80052904
 * EN v1.0 Size: 132b
 * EN v1.1 Address: 0x80052A6C
 * EN v1.1 Size: 132b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80052904(void)
{
  DAT_803dd9d8 = 0x1e;
  DAT_803dda04 = 0x1e;
  DAT_803dd9d4 = 0x40;
  DAT_803dda00 = 0x40;
  DAT_803dd9e4 = 0;
  DAT_803dda10 = 0;
  DAT_803dd9dc = 0;
  DAT_803dda08 = 0;
  DAT_803dd9e0 = 0;
  DAT_803dda0c = 0;
  DAT_803dd9d0 = 0;
  DAT_803dd9fc = 0;
  DAT_803dd9cc = 4;
  DAT_803dd9f8 = 4;
  DAT_803dd9f4 = 0;
  DAT_803dd9f0 = 0xc;
  DAT_803dd9ec = 0x1c;
  DAT_803dd9eb = 0;
  DAT_803dd9cb = 0;
  DAT_803dd9ea = 0;
  DAT_803dd9ca = 0;
  DAT_803dd9e9 = 0;
  DAT_803dd9c9 = 0;
  DAT_803dd9e8 = 0;
  DAT_803dd9c8 = 0;
  DAT_803dd9b0 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80052988
 * EN v1.0 Address: 0x80052988
 * EN v1.0 Size: 600b
 * EN v1.1 Address: 0x80052AF0
 * EN v1.1 Size: 576b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80052988(void)
{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  undefined8 uVar14;
  
  if (DAT_803dda18 == '\0') {
    FUN_8025898c(1,0);
    FUN_802420b0(0x80378620,0x6640);
    FUN_8025d4a0(-0x7fc879e0,0x6640);
    uVar3 = 0;
    dVar9 = (double)FLOAT_803df7d8;
    dVar10 = (double)FLOAT_803df7dc;
    dVar11 = (double)FLOAT_803df7d4;
    dVar13 = (double)FLOAT_803df7e4;
    dVar12 = DOUBLE_803df7e8;
    do {
      uVar1 = 0x22;
      uVar14 = FUN_80259000(0x98,4,0x22);
      uVar2 = 0;
      dVar8 = (double)(float)((double)(float)((double)(float)(dVar11 * (double)(float)((double)
                                                  CONCAT44(0x43300000,uVar3) - dVar12)) / dVar9) -
                             dVar10);
      dVar5 = (double)(float)((double)(float)((double)(float)(dVar11 * (double)(float)((double)
                                                  CONCAT44(0x43300000,uVar3 + 1) - dVar12)) / dVar9)
                             - dVar10);
      do {
        dVar7 = (double)(float)((double)(float)((double)(float)(dVar11 * (double)(float)((double)
                                                  CONCAT44(0x43300000,uVar2) - dVar12)) / dVar9) -
                               dVar10);
        dVar6 = (double)(float)(dVar7 * dVar7);
        dVar4 = (double)(float)(dVar8 * dVar8 + dVar6);
        if (dVar10 <= dVar4) {
          dVar4 = (double)FLOAT_803df7e0;
        }
        else {
          dVar4 = FUN_80293900((double)(float)(dVar10 - dVar4));
        }
        DAT_cc008000 = (float)dVar8;
        DAT_cc008000 = (float)dVar7;
        DAT_cc008000 = (float)dVar13;
        DAT_cc008000 = (float)dVar8;
        DAT_cc008000 = (float)dVar7;
        DAT_cc008000 = (float)dVar4;
        dVar4 = (double)(float)(dVar5 * dVar5 + dVar6);
        if (dVar10 <= dVar4) {
          dVar4 = (double)FLOAT_803df7e0;
        }
        else {
          dVar4 = FUN_80293900((double)(float)(dVar10 - dVar4));
        }
        DAT_cc008000 = (float)dVar5;
        DAT_cc008000 = (float)dVar7;
        DAT_cc008000 = (float)dVar13;
        DAT_cc008000 = (float)dVar5;
        DAT_cc008000 = (float)dVar7;
        DAT_cc008000 = (float)dVar4;
        uVar2 = uVar2 + 1;
      } while (uVar2 < 0x11);
      uVar3 = uVar3 + 1;
    } while (uVar3 < 0x10);
    DAT_803dda1c = FUN_8025d568((int)((ulonglong)uVar14 >> 0x20),(int)uVar14,uVar1);
    DAT_803dda18 = '\x01';
    FUN_8025898c(1,8);
  }
  FUN_8025d63c(&DAT_80378620,DAT_803dda1c);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80052be0
 * EN v1.0 Address: 0x80052BE0
 * EN v1.0 Size: 516b
 * EN v1.1 Address: 0x80052D30
 * EN v1.1 Size: 524b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80052be0(int param_1,float *param_2)
{
  int iVar1;
  int iVar2;
  
  iVar1 = FUN_80080fa0();
  iVar2 = FUN_80080f98();
  if ((iVar1 != 0) && (iVar2 != 0)) {
    FUN_80017608(1);
    FUN_80017600(0,1,0);
    FUN_80017600(2,0,0);
    FUN_8001757c((double)*param_2,(double)FLOAT_803df7e0,iVar1);
    FUN_80017588(iVar1,0xff,0,0,0xff);
    FUN_800175fc(0,iVar1,param_1);
    FUN_8001757c((double)param_2[1],(double)FLOAT_803df7e0,iVar1);
    FUN_80017588(iVar1,0,0,0xff,0xff);
    FUN_800175fc(0,iVar1,param_1);
    FUN_8001758c((double)FLOAT_803df7f0,(double)FLOAT_803df7e0,(double)FLOAT_803df7e0,iVar1);
    FUN_800175fc(2,iVar1,param_1);
    FUN_80017600(1,1,0);
    FUN_80017600(3,0,0);
    FUN_8001757c((double)*param_2,(double)FLOAT_803df7e0,iVar2);
    FUN_80017588(iVar2,0xff,0,0,0xff);
    FUN_800175fc(1,iVar2,param_1);
    FUN_8001757c((double)param_2[1],(double)FLOAT_803df7e0,iVar2);
    FUN_80017588(iVar2,0,0,0xff,0xff);
    FUN_800175fc(1,iVar2,param_1);
    FUN_8001758c((double)FLOAT_803df7f4,(double)FLOAT_803df7e0,(double)FLOAT_803df7e0,iVar2);
    FUN_800175fc(3,iVar2,param_1);
    FUN_80017604();
    FUN_8001758c((double)FLOAT_803df7dc,(double)FLOAT_803df7e0,(double)FLOAT_803df7e0,iVar1);
    FUN_8001758c((double)FLOAT_803df7dc,(double)FLOAT_803df7e0,(double)FLOAT_803df7e0,iVar2);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_80052de4
 * EN v1.0 Address: 0x80052DE4
 * EN v1.0 Size: 312b
 * EN v1.1 Address: 0x80052F3C
 * EN v1.1 Size: 316b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80052de4(void)
{
  double dVar1;
  float afStack_78 [12];
  float afStack_48 [18];
  
  dVar1 = (double)FLOAT_803df7e0;
  FUN_8025da64(dVar1,dVar1,(double)FLOAT_803df7f8,(double)FLOAT_803df7f8,dVar1,
               (double)FLOAT_803df7dc);
  FUN_8025da88(0,0,0x20,0x20);
  FUN_80259340(0,0,0x20,0x20);
  FUN_802594c0(0x20);
  FUN_80259400(0,0,0x20,0x20);
  dVar1 = (double)FLOAT_803df7dc;
  FUN_80247dfc(dVar1,(double)FLOAT_803df7fc,dVar1,(double)FLOAT_803df7fc,dVar1,
               (double)FLOAT_803df7d8,afStack_48);
  FUN_8025d6ac(afStack_48,1);
  FUN_8025cce8(0,1,0,5);
  FUN_8006f8fc(0,2,0);
  FUN_80259288(0);
  FUN_8006f8a4(1);
  FUN_8025c754(7,0,0,7,0);
  FUN_80257b5c();
  FUN_802570dc(9,1);
  FUN_802570dc(10,1);
  FUN_802475b8(afStack_78);
  FUN_8025d80c(afStack_78,0);
  FUN_8025d848(afStack_78,0);
  FUN_8025d888(0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80052f1c
 * EN v1.0 Address: 0x80052F1C
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80053078
 * EN v1.1 Size: 1156b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80052f1c(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80052f20
 * EN v1.0 Address: 0x80052F20
 * EN v1.0 Size: 188b
 * EN v1.1 Address: 0x800534FC
 * EN v1.1 Size: 204b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80052f20(int *param_1)
{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  if (*param_1 != 0) {
    iVar2 = 0;
    piVar1 = &DAT_8037ec60;
    iVar3 = 6;
    do {
      if ((*(short *)(*piVar1 + 0xe) != 0) && (*piVar1 == *param_1)) {
        *(short *)((&DAT_8037ec60)[iVar2 * 7] + 0xe) =
             *(short *)((&DAT_8037ec60)[iVar2 * 7] + 0xe) + -1;
        break;
      }
      piVar1 = piVar1 + 7;
      iVar2 = iVar2 + 1;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  if (param_1[1] == 0) {
    return;
  }
  iVar2 = 0;
  piVar1 = &DAT_8037ec60;
  iVar3 = 6;
  while ((*(short *)(*piVar1 + 0xe) == 0 || (*piVar1 != param_1[1]))) {
    piVar1 = piVar1 + 7;
    iVar2 = iVar2 + 1;
    iVar3 = iVar3 + -1;
    if (iVar3 == 0) {
      return;
    }
  }
  *(short *)((&DAT_8037ec60)[iVar2 * 7] + 0xe) = *(short *)((&DAT_8037ec60)[iVar2 * 7] + 0xe) + -1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80052fdc
 * EN v1.0 Address: 0x80052FDC
 * EN v1.0 Size: 152b
 * EN v1.1 Address: 0x800535C8
 * EN v1.1 Size: 172b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80052fdc(int param_1,int *param_2,int param_3)
{
  int *piVar1;
  
  if (*(int *)(param_1 + 8) != 0) {
    if (param_3 == 0) {
      piVar1 = &DAT_8037ecec;
    }
    else {
      piVar1 = &DAT_8037ec60 + (6 - (*(byte *)(param_3 + 0xf2) + 1)) * 7;
    }
    *(short *)(*piVar1 + 0xe) = *(short *)(*piVar1 + 0xe) + 1;
    *param_2 = *piVar1;
  }
  if (*(int *)(param_1 + 0x14) == 0) {
    return;
  }
  if (*(byte *)(param_1 + 0x20) < 6) {
    piVar1 = &DAT_8037ec60 + ((int)(uint)*(byte *)(param_1 + 0x20) >> 1) * 7;
  }
  else {
    piVar1 = &DAT_8037ec60;
  }
  *(short *)(*piVar1 + 0xe) = *(short *)(*piVar1 + 0xe) + 1;
  param_2[1] = *piVar1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80053074
 * EN v1.0 Address: 0x80053074
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80053674
 * EN v1.1 Size: 456b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80053074(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80053078
 * EN v1.0 Address: 0x80053078
 * EN v1.0 Size: 60b
 * EN v1.1 Address: 0x8005383C
 * EN v1.1 Size: 64b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80053078(uint param_1)
{
  int iVar1;
  
  if ((param_1 & 0x80000000) != 0) {
    return param_1;
  }
  iVar1 = param_1 - 1;
  if ((-1 < iVar1) && (iVar1 < DAT_803dda3c)) {
    return *(uint *)(DAT_803dda44 + iVar1 * 0x10 + 4);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800530b4
 * EN v1.0 Address: 0x800530B4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x8005387C
 * EN v1.1 Size: 1344b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800530b4(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_800530b8
 * EN v1.0 Address: 0x800530B8
 * EN v1.0 Size: 296b
 * EN v1.1 Address: 0x80053DBC
 * EN v1.1 Size: 280b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800530b8(int param_1,uint *param_2)
{
  bool bVar1;
  double dVar2;
  
  bVar1 = 0 < (int)((uint)*(byte *)(param_1 + 0x1d) - (uint)*(byte *)(param_1 + 0x1c));
  FUN_8025aa74(param_2,param_1 + *(int *)(param_1 + 0x50) + 0x60,(uint)*(ushort *)(param_1 + 10),
               (uint)*(ushort *)(param_1 + 0xc),0,(uint)*(byte *)(param_1 + 0x17),
               (uint)*(byte *)(param_1 + 0x18),bVar1);
  if (bVar1) {
    FUN_8025ace8((double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x1c)) -
                                DOUBLE_803df820),
                 (double)(float)((double)CONCAT44(0x43300000,*(byte *)(param_1 + 0x1d) ^ 0x80000000)
                                - DOUBLE_803df828),(double)FLOAT_803df818,param_2,
                 (uint)*(byte *)(param_1 + 0x19),(uint)*(byte *)(param_1 + 0x1a),0,'\0',0);
  }
  else {
    dVar2 = (double)FLOAT_803df81c;
    FUN_8025ace8(dVar2,dVar2,dVar2,param_2,(uint)*(byte *)(param_1 + 0x19),
                 (uint)*(byte *)(param_1 + 0x1a),0,'\0',0);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800531e0
 * EN v1.0 Address: 0x800531E0
 * EN v1.0 Size: 380b
 * EN v1.1 Address: 0x80053ED4
 * EN v1.1 Size: 356b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800531e0(int param_1)
{
  bool bVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  uint *puVar5;
  double dVar6;
  
  *(undefined4 *)(param_1 + 0x40) = 0;
  *(undefined *)(param_1 + 0x48) = 0;
  puVar5 = (uint *)(param_1 + 0x20);
  bVar1 = 0 < (int)((uint)*(byte *)(param_1 + 0x1d) - (uint)*(byte *)(param_1 + 0x1c));
  FUN_8025aa74(puVar5,param_1 + 0x60,(uint)*(ushort *)(param_1 + 10),
               (uint)*(ushort *)(param_1 + 0xc),(uint)*(byte *)(param_1 + 0x16),
               (uint)*(byte *)(param_1 + 0x17),(uint)*(byte *)(param_1 + 0x18),bVar1);
  if (bVar1) {
    FUN_8025ace8((double)(float)((double)CONCAT44(0x43300000,(uint)*(byte *)(param_1 + 0x1c)) -
                                DOUBLE_803df820),
                 (double)(float)((double)CONCAT44(0x43300000,*(byte *)(param_1 + 0x1d) ^ 0x80000000)
                                - DOUBLE_803df828),(double)FLOAT_803df818,puVar5,
                 (uint)*(byte *)(param_1 + 0x19),(uint)*(byte *)(param_1 + 0x1a),0,'\0',0);
  }
  else {
    dVar6 = (double)FLOAT_803df81c;
    FUN_8025ace8(dVar6,dVar6,dVar6,puVar5,(uint)*(byte *)(param_1 + 0x19),
                 (uint)*(byte *)(param_1 + 0x1a),0,'\0',0);
  }
  FUN_8025ae7c((int)puVar5,param_1);
  iVar2 = FUN_8025aea4((int)puVar5);
  uVar3 = FUN_8025ae84((int)puVar5);
  uVar4 = FUN_8025ae94((int)puVar5);
  iVar2 = FUN_8025a850(uVar3,uVar4,iVar2,'\0',0);
  *(int *)(param_1 + 0x44) = iVar2;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005335c
 * EN v1.0 Address: 0x8005335C
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x80054038
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005335c(uint param_1)
{
  DAT_803dda28 = DAT_803dda28 & ~param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005336c
 * EN v1.0 Address: 0x8005336C
 * EN v1.0 Size: 16b
 * EN v1.1 Address: 0x8005404C
 * EN v1.1 Size: 16b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005336c(uint param_1)
{
  DAT_803dda28 = DAT_803dda28 | param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005337c
 * EN v1.0 Address: 0x8005337C
 * EN v1.0 Size: 80b
 * EN v1.1 Address: 0x8005405C
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int FUN_8005337c(int param_1)
{
  int *piVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = 0;
  piVar1 = DAT_803dda44;
  iVar3 = DAT_803dda3c;
  if (0 < DAT_803dda3c) {
    do {
      if (param_1 == *piVar1) {
        return DAT_803dda44[iVar2 * 4 + 1];
      }
      piVar1 = piVar1 + 4;
      iVar2 = iVar2 + 1;
      iVar3 = iVar3 + -1;
    } while (iVar3 != 0);
  }
  return 0;
}

/*
 * --INFO--
 *
 * Function: FUN_800533cc
 * EN v1.0 Address: 0x800533CC
 * EN v1.0 Size: 568b
 * EN v1.1 Address: 0x800540A8
 * EN v1.1 Size: 632b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800533cc(int param_1,uint *param_2,int *param_3)
{
  uint uVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  
  uVar1 = *param_2;
  uVar3 = uVar1 & 0x80000;
  if ((uVar1 & 0x20000) == 0) {
    if ((uVar1 & 0x40000) == 0) {
      if (uVar3 == 0) {
        *param_3 = *param_3 + (uint)*(ushort *)(param_1 + 0x14) * (uint)DAT_803dc070;
        while ((int)(uint)*(ushort *)(param_1 + 0x10) <= *param_3) {
          *param_3 = *param_3 - (uint)*(ushort *)(param_1 + 0x10);
        }
      }
      else {
        *param_3 = *param_3 - (uint)*(ushort *)(param_1 + 0x14) * (uint)DAT_803dc070;
        while (*param_3 < 0) {
          *param_3 = *param_3 + (uint)*(ushort *)(param_1 + 0x10);
        }
      }
    }
    else {
      if (uVar3 == 0) {
        *param_3 = *param_3 + (uint)*(ushort *)(param_1 + 0x14) * (uint)DAT_803dc070;
      }
      else {
        *param_3 = *param_3 - (uint)*(ushort *)(param_1 + 0x14) * (uint)DAT_803dc070;
      }
      do {
        iVar2 = *param_3;
        if (iVar2 < 0) {
          *param_3 = -iVar2;
          *param_2 = *param_2 & 0xfff7ffff;
        }
        iVar4 = *param_3;
        uVar3 = (uint)*(ushort *)(param_1 + 0x10);
        if ((int)uVar3 <= iVar4) {
          *param_3 = (uVar3 * 2 + -1) - iVar4;
          *param_2 = *param_2 | 0x80000;
        }
      } while ((int)uVar3 <= iVar4 || iVar2 < 0);
    }
  }
  else if ((uVar1 & 0x40000) == 0) {
    uVar3 = FUN_80017760(0,1000);
    if (0x3d9 < (int)uVar3) {
      *param_2 = *param_2 & 0xfff7ffff;
      *param_2 = *param_2 | 0x40000;
    }
  }
  else if (uVar3 == 0) {
    *param_3 = *param_3 + (uint)*(ushort *)(param_1 + 0x14) * (uint)DAT_803dc070;
    if ((int)(uint)*(ushort *)(param_1 + 0x10) <= *param_3) {
      *param_3 = ((uint)*(ushort *)(param_1 + 0x10) * 2 + -1) - *param_3;
      if (*param_3 < 0) {
        *param_3 = 0;
        *param_2 = *param_2 & 0xfff3ffff;
      }
      else {
        *param_2 = *param_2 | 0x80000;
      }
    }
  }
  else {
    *param_3 = *param_3 - (uint)*(ushort *)(param_1 + 0x14) * (uint)DAT_803dc070;
    if (*param_3 < 0) {
      *param_3 = 0;
      *param_2 = *param_2 & 0xfff3ffff;
    }
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80053604
 * EN v1.0 Address: 0x80053604
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x80054320
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80053604(int param_1,undefined2 param_2)
{
  *(undefined2 *)(param_1 + 0x14) = param_2;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005360c
 * EN v1.0 Address: 0x8005360C
 * EN v1.0 Size: 308b
 * EN v1.1 Address: 0x80054328
 * EN v1.1 Size: 328b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005360c(undefined4 param_1,undefined4 *param_2,undefined4 *param_3,uint param_4,
                 int param_5)
{
  undefined4 *puVar1;
  undefined4 *puVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  undefined4 *puVar6;
  
  if (param_2 != (undefined4 *)0x0) {
    iVar4 = param_5 >> 0x10;
    if (*(ushort *)(param_2 + 4) == 0) {
      uVar5 = 0;
    }
    else {
      uVar5 = (int)(uint)*(ushort *)(param_2 + 4) >> 8;
    }
    puVar1 = param_2;
    puVar6 = param_2;
    if ((1 < uVar5) && (iVar4 < (int)uVar5)) {
      iVar3 = 0;
      for (; (iVar3 < iVar4 && (puVar6 != (undefined4 *)0x0)); puVar6 = (undefined4 *)*puVar6) {
        iVar3 = iVar3 + 1;
      }
      if (puVar6 != (undefined4 *)0x0) {
        puVar1 = puVar6;
      }
      puVar6 = puVar1;
      if ((param_4 & 0x40) != 0) {
        if ((param_4 & 0x80000) == 0) {
          iVar3 = iVar4 + 1;
          if ((int)uVar5 <= iVar3) {
            if ((param_4 & 0x40000) == 0) {
              iVar3 = uVar5 - 1;
            }
            else {
              iVar3 = iVar4 + -1;
            }
          }
        }
        else {
          iVar3 = iVar4 + -1;
          if (iVar3 < 0) {
            if ((param_4 & 0x40000) == 0) {
              iVar3 = 0;
            }
            else {
              iVar3 = iVar4 + 1;
            }
          }
        }
        iVar4 = 0;
        for (puVar2 = param_2; (iVar4 < iVar3 && (puVar2 != (undefined4 *)0x0));
            puVar2 = (undefined4 *)*puVar2) {
          iVar4 = iVar4 + 1;
        }
        puVar6 = param_2;
        if (puVar2 != (undefined4 *)0x0) {
          puVar6 = puVar2;
        }
      }
    }
    if (param_3 != (undefined4 *)0x0) {
      puVar6 = param_3;
    }
    FUN_8004812c((int)puVar1,0);
    FUN_8004812c((int)puVar6,1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80053740
 * EN v1.0 Address: 0x80053740
 * EN v1.0 Size: 20b
 * EN v1.1 Address: 0x80054470
 * EN v1.1 Size: 20b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80053740(void)
{
  DAT_803dda28 = 0;
  DAT_803dda34 = 0;
  DAT_803dda30 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80053754
 * EN v1.0 Address: 0x80053754
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80054484
 * EN v1.1 Size: 412b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80053754(void)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80053758
 * EN v1.0 Address: 0x80053758
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80054620
 * EN v1.1 Size: 1932b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80053758(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_8005375c
 * EN v1.0 Address: 0x8005375C
 * EN v1.0 Size: 68b
 * EN v1.1 Address: 0x80054DAC
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8005375c(int param_1,int param_2)
{
  uint uVar1;
  uint uVar2;
  
  if ((int)(uint)*(ushort *)(param_1 + 0x10) <= param_2) {
    param_2 = *(ushort *)(param_1 + 0x10) - 1;
  }
  uVar1 = param_2 >> 8;
  if ((int)uVar1 < 1) {
    return;
  }
  uVar2 = uVar1 >> 3;
  if (uVar2 != 0) {
    do {
      uVar2 = uVar2 - 1;
    } while (uVar2 != 0);
    uVar1 = uVar1 & 7;
    if (uVar1 == 0) {
      return;
    }
  }
  do {
    uVar1 = uVar1 - 1;
  } while (uVar1 != 0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_800537a0
 * EN v1.0 Address: 0x800537A0
 * EN v1.0 Size: 492b
 * EN v1.1 Address: 0x80054E14
 * EN v1.1 Size: 188b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_800537a0(undefined4 param_1,undefined4 param_2,int param_3,char param_4,uint param_5,
                 undefined param_6,undefined param_7,undefined param_8,undefined param_9)
{
  int iVar1;
  undefined8 uVar2;
  
  uVar2 = FUN_80286834();
  iVar1 = FUN_8025a850((uint)((ulonglong)uVar2 >> 0x20),(uint)uVar2,param_3,param_4,param_5);
  iVar1 = FUN_80017830(iVar1 + 0x60,6);
  if (iVar1 != 0) {
    FUN_800033a8(iVar1,0,100);
    *(char *)(iVar1 + 0x16) = (char)param_3;
    *(short *)(iVar1 + 10) = (short)((ulonglong)uVar2 >> 0x20);
    *(short *)(iVar1 + 0xc) = (short)uVar2;
    *(undefined2 *)(iVar1 + 0x10) = 1;
    *(undefined2 *)(iVar1 + 0xe) = 0;
    *(undefined *)(iVar1 + 0x17) = param_6;
    *(undefined *)(iVar1 + 0x18) = param_7;
    *(undefined *)(iVar1 + 0x19) = param_8;
    *(undefined *)(iVar1 + 0x1a) = param_9;
    *(undefined4 *)(iVar1 + 0x50) = 0;
    FUN_800531e0(iVar1);
  }
  FUN_80286880();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_8005398c
 * EN v1.0 Address: 0x8005398C
 * EN v1.0 Size: 276b
 * EN v1.1 Address: 0x80054ED0
 * EN v1.1 Size: 92b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4
FUN_8005398c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5,
            undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
            undefined4 param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
            undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  uint uVar1;
  undefined4 local_18 [5];
  
  local_18[0] = 0;
  uVar1 = FUN_80042838();
  if ((uVar1 & 0x100000) == 0) {
    FUN_8001763c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_18,param_9,
                 param_11,param_12,param_13,param_14,param_15,param_16);
  }
  else {
    local_18[0] = 0;
  }
  return local_18[0];
}

/*
 * --INFO--
 *
 * Function: FUN_80053aa0
 * EN v1.0 Address: 0x80053AA0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80054F2C
 * EN v1.1 Size: 436b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80053aa0(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80053aa4
 * EN v1.0 Address: 0x80053AA4
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800550E0
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_80053aa4(void)
{
  return DAT_803ddab8;
}

/*
 * --INFO--
 *
 * Function: FUN_80053aac
 * EN v1.0 Address: 0x80053AAC
 * EN v1.0 Size: 8b
 * EN v1.1 Address: 0x800550E8
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80053aac(undefined4 param_1)
{
  DAT_803ddab8 = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80053ab4
 * EN v1.0 Address: 0x80053AB4
 * EN v1.0 Size: 48b
 * EN v1.1 Address: 0x800550F0
 * EN v1.1 Size: 48b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80053ab4(int param_1,float *param_2)
{
  if (*(int *)(param_1 + 0x30) != 0) {
    return;
  }
  *param_2 = *param_2 + FLOAT_803dda58;
  param_2[2] = param_2[2] + FLOAT_803dda5c;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80053ae4
 * EN v1.0 Address: 0x80053AE4
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80055120
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80053ae4(void)
{
  DAT_803dda76 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80053af0
 * EN v1.0 Address: 0x80053AF0
 * EN v1.0 Size: 76b
 * EN v1.1 Address: 0x8005512C
 * EN v1.1 Size: 80b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80053af0(double param_1,double param_2,undefined4 *param_3,undefined *param_4)
{
  DAT_80382e28 = *param_3;
  DAT_80382e2c = param_3[1];
  DAT_80382e30 = param_3[2];
  FLOAT_803ddac4 = (float)param_1;
  DAT_803ddac0 = *param_4;
  uRam803ddac1 = param_4[1];
  uRam803ddac2 = param_4[2];
  FLOAT_803ddabc = (float)param_2;
  DAT_803dda76 = 1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80053b3c
 * EN v1.0 Address: 0x80053B3C
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x8005517C
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80053b3c(void)
{
  undefined4 *puVar1;
  
  puVar1 = FUN_800e87a8();
  DAT_803dda80 = 0xffffffff;
  *(byte *)(puVar1 + 0x10) = *(byte *)(puVar1 + 0x10) & 0xdf;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80053b70
 * EN v1.0 Address: 0x80053B70
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x800551B4
 * EN v1.1 Size: 56b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80053b70(void)
{
  undefined4 *puVar1;
  
  puVar1 = FUN_800e87a8();
  DAT_803dda80 = 1;
  *(byte *)(puVar1 + 0x10) = *(byte *)(puVar1 + 0x10) | 0x20;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80053ba4
 * EN v1.0 Address: 0x80053BA4
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x800551EC
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80053ba4(void)
{
  DAT_803dda74 = 0;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80053bb0
 * EN v1.0 Address: 0x80053BB0
 * EN v1.0 Size: 52b
 * EN v1.1 Address: 0x800551F8
 * EN v1.1 Size: 32b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80053bb0(double param_1,double param_2,double param_3,undefined param_4,undefined param_5)
{
  DAT_803dda74 = 1;
  FLOAT_803ddad0 = (float)param_1;
  FLOAT_803ddacc = (float)param_2;
  FLOAT_803ddac8 = (float)param_3;
  DAT_803dda75 = param_4;
  DAT_803dda7b = param_5;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80053be4
 * EN v1.0 Address: 0x80053BE4
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80055218
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_80053be4(void)
{
  return DAT_803dda7a;
}

/*
 * --INFO--
 *
 * Function: FUN_80053bf0
 * EN v1.0 Address: 0x80053BF0
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80055220
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80053bf0(undefined param_1)
{
  DAT_803dda7a = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80053bfc
 * EN v1.0 Address: 0x80053BFC
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80055228
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80053bfc(undefined param_1)
{
  DAT_803dda79 = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80053c08
 * EN v1.0 Address: 0x80053C08
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80055230
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80053c08(undefined param_1)
{
  DAT_803dda78 = param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80053c14
 * EN v1.0 Address: 0x80053C14
 * EN v1.0 Size: 12b
 * EN v1.1 Address: 0x80055238
 * EN v1.1 Size: 8b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined FUN_80053c14(void)
{
  return DAT_803dda77;
}

/*
 * --INFO--
 *
 * Function: FUN_80053c20
 * EN v1.0 Address: 0x80053C20
 * EN v1.0 Size: 20b
 * EN v1.1 Address: 0x80055240
 * EN v1.1 Size: 12b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80053c20(double param_1,undefined param_2)
{
  DAT_803dda77 = param_2;
  FLOAT_803dc28c = (float)param_1;
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80053c34
 * EN v1.0 Address: 0x80053C34
 * EN v1.0 Size: 96b
 * EN v1.1 Address: 0x8005524C
 * EN v1.1 Size: 96b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80053c34(undefined4 param_1,undefined4 param_2,int param_3,int param_4,int param_5,
                 int param_6)
{
  if (param_3 < 0) {
    param_3 = 0;
  }
  if (param_4 < 0) {
    param_4 = 0;
  }
  if (param_5 < 0) {
    param_5 = 0;
  }
  if (param_6 < 0) {
    param_6 = 0;
  }
  FUN_8025da88(param_3,param_4,param_5 - param_3,param_6 - param_4);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80053c94
 * EN v1.0 Address: 0x80053C94
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x800552AC
 * EN v1.1 Size: 440b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80053c94(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80053c98
 * EN v1.0 Address: 0x80053C98
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x80055464
 * EN v1.1 Size: 200b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80053c98(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,char param_10,undefined4 param_11,undefined4 param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_80053c9c
 * EN v1.0 Address: 0x80053C9C
 * EN v1.0 Size: 708b
 * EN v1.1 Address: 0x8005552C
 * EN v1.1 Size: 556b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80053c9c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,uint *param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  byte bVar1;
  int iVar2;
  int *piVar3;
  uint uVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  bool bVar8;
  uint uVar9;
  int iVar10;
  uint uVar11;
  uint uVar12;
  undefined8 extraout_f1;
  undefined8 uVar13;
  
  uVar13 = FUN_80286838();
  iVar5 = (int)uVar13;
  iVar6 = iVar5 * 0x8c + -0x7fc7d0d8;
  iVar2 = *(int *)(iVar6 + param_11 * 4);
  if (iVar2 != -1) {
    uVar12 = 0;
    uVar9 = *(uint *)((int)((ulonglong)uVar13 >> 0x20) + 0x20);
    uVar11 = uVar9 + iVar2;
    for (uVar4 = uVar9; uVar4 < uVar11; uVar4 = uVar4 + (uint)*(byte *)(uVar4 + 2) * 4) {
      uVar12 = uVar12 + 1;
    }
    iVar7 = param_11 + 1;
    piVar3 = (int *)(iVar6 + iVar7 * 4);
    iVar2 = 0x21 - iVar7;
    if (iVar7 < 0x21) {
      do {
        if (*piVar3 != -1) break;
        piVar3 = piVar3 + 1;
        iVar7 = iVar7 + 1;
        iVar2 = iVar2 + -1;
      } while (iVar2 != 0);
    }
    iVar2 = *(int *)(iVar6 + iVar7 * 4);
    for (; uVar11 < uVar9 + iVar2; uVar11 = uVar11 + (uint)*(byte *)(uVar11 + 2) * 4) {
      iVar6 = (int)uVar12 >> 3;
      if ((int)uVar12 < 0) {
        bVar8 = false;
      }
      else if (iVar6 < 0xc4) {
        bVar8 = true;
        if ((1 << (uVar12 & 7) & (int)*(char *)(*(int *)((&DAT_803870c8)[iVar5] + 0x10) + iVar6)) ==
            0) {
          bVar8 = false;
        }
      }
      else {
        bVar8 = false;
      }
      if (!bVar8) {
        uVar4 = (**(code **)(*DAT_803dd72c + 0x40))(iVar5);
        uVar4 = uVar4 & 0xff;
        if (uVar4 == 0xffffffff) {
          bVar8 = false;
          goto LAB_800556c4;
        }
        if (uVar4 == 0) {
LAB_800556c0:
          bVar8 = true;
        }
        else if (uVar4 < 9) {
          if (((int)(uint)*(byte *)(uVar11 + 3) >> (uVar4 - 1 & 0x3f) & 1U) == 0) goto LAB_800556c0;
          bVar8 = false;
        }
        else {
          if (((int)(uint)*(byte *)(uVar11 + 5) >> (0x10 - uVar4 & 0x3f) & 1U) == 0)
          goto LAB_800556c0;
          bVar8 = false;
        }
LAB_800556c4:
        if (bVar8) {
          if (-1 < (int)uVar12) {
            iVar10 = (&DAT_803870c8)[iVar5];
            iVar7 = *(int *)(iVar10 + 0x10);
            bVar1 = (byte)(1 << (uVar12 & 7));
            *(byte *)(iVar7 + iVar6) = *(byte *)(iVar7 + iVar6) & ~bVar1;
            iVar7 = *(int *)(iVar10 + 0x10);
            *(byte *)(iVar7 + iVar6) = *(byte *)(iVar7 + iVar6) | bVar1;
          }
          FUN_80017ae4(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,uVar11,1,
                       (char)uVar13,uVar12,param_12,param_14,param_15,param_16);
        }
      }
      uVar12 = uVar12 + 1;
    }
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80053f60
 * EN v1.0 Address: 0x80053F60
 * EN v1.0 Size: 908b
 * EN v1.1 Address: 0x80055758
 * EN v1.1 Size: 932b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
uint FUN_80053f60(int param_1)
{
  int iVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  float fVar5;
  float fVar6;
  float fVar7;
  float fVar8;
  bool bVar9;
  uint uVar10;
  int iVar11;
  int iVar12;
  double dVar13;
  
  iVar12 = *(int *)(param_1 + 0x4c);
  if (iVar12 == 0) {
    return 0;
  }
  if ((*(byte *)(iVar12 + 4) & 2) != 0) {
    return 0;
  }
  uVar10 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0xac));
  uVar10 = uVar10 & 0xff;
  if (uVar10 == 0xffffffff) {
    bVar9 = false;
    goto LAB_80055824;
  }
  if (uVar10 != 0) {
    if (uVar10 < 9) {
      if (((int)(uint)*(byte *)(iVar12 + 3) >> (uVar10 - 1 & 0x3f) & 1U) != 0) {
        bVar9 = false;
        goto LAB_80055824;
      }
    }
    else if (((int)(uint)*(byte *)(iVar12 + 5) >> (0x10 - uVar10 & 0x3f) & 1U) != 0) {
      bVar9 = false;
      goto LAB_80055824;
    }
  }
  bVar9 = true;
LAB_80055824:
  if (bVar9) {
    if ((*(byte *)(iVar12 + 4) & 1) == 0) {
      if ((*(byte *)(iVar12 + 4) & 0x10) == 0) {
        if ((*(int *)(param_1 + 0xc0) == 0) || (-1 < *(short *)(param_1 + 0xb4))) {
          if (*(int *)(param_1 + 0xc4) == 0) {
            if (*(int *)(param_1 + 0x30) == 0) {
              dVar13 = (double)FUN_802924c4();
              iVar11 = (int)dVar13;
              dVar13 = (double)FUN_802924c4();
              iVar1 = (int)dVar13;
              if ((((iVar11 < 0) || (iVar1 < 0)) || (0xf < iVar11)) || (0xf < iVar1)) {
                return 1;
              }
              iVar11 = iVar11 + iVar1 * 0x10;
              if (*(char *)(iVar11 + DAT_80382f24) < '\0' &&
                  (*(char *)(iVar11 + DAT_80382f20) < '\0' &&
                  (*(char *)(iVar11 + DAT_80382f1c) < '\0' &&
                  (*(char *)(iVar11 + DAT_80382f18) < '\0' &&
                  *(char *)(iVar11 + DAT_80382f14) < '\0')))) {
                return 1;
              }
            }
            if ((*(byte *)(iVar12 + 4) & 0x20) == 0) {
              if ((((*(byte *)(iVar12 + 4) & 4) == 0) || (iVar12 = FUN_80017a98(), iVar12 == 0)) ||
                 (*(int *)(param_1 + 0x30) != 0)) {
                if (*(int *)(param_1 + 0x30) == 0) {
                  iVar12 = 0;
                }
                else {
                  iVar12 = *(char *)(*(int *)(param_1 + 0x30) + 0x35) + 1;
                }
                fVar2 = (float)(&DAT_803872a8)[iVar12 * 4];
                fVar3 = (float)(&DAT_803872ac)[iVar12 * 4];
                fVar4 = (float)(&DAT_803872b0)[iVar12 * 4];
              }
              else {
                fVar2 = *(float *)(iVar12 + 0x18);
                fVar3 = *(float *)(iVar12 + 0x1c);
                fVar4 = *(float *)(iVar12 + 0x20);
              }
              if (*(int *)(param_1 + 0x30) == 0) {
                fVar5 = *(float *)(param_1 + 0x18);
                fVar6 = *(float *)(param_1 + 0x1c);
                fVar7 = *(float *)(param_1 + 0x20);
              }
              else {
                fVar5 = *(float *)(param_1 + 0xc);
                fVar6 = *(float *)(param_1 + 0x10);
                fVar7 = *(float *)(param_1 + 0x14);
              }
              fVar8 = FLOAT_803df838 + *(float *)(param_1 + 0x3c);
              if (fVar8 * fVar8 <=
                  (fVar4 - fVar7) * (fVar4 - fVar7) +
                  (fVar2 - fVar5) * (fVar2 - fVar5) + (fVar3 - fVar6) * (fVar3 - fVar6)) {
                uVar10 = 1;
              }
              else {
                uVar10 = 0;
              }
            }
            else {
              uVar10 = 0;
            }
          }
          else {
            uVar10 = 0;
          }
        }
        else {
          uVar10 = 0;
        }
      }
      else {
        uVar10 = (**(code **)(*DAT_803dd72c + 0x4c))
                           ((int)*(char *)(param_1 + 0xac),*(undefined *)(iVar12 + 6));
        uVar10 = countLeadingZeros(uVar10 & 0xff);
        uVar10 = uVar10 >> 5;
      }
    }
    else {
      uVar10 = 0;
    }
  }
  else {
    uVar10 = 1;
  }
  return uVar10;
}

/* sda21 accessors. */
extern u32 lbl_803DCE38;
extern u8 lbl_803DCDFA;
extern u8 lbl_803DCDF9;
extern u8 lbl_803DCDF8;
extern u8 lbl_803DCDF7;
u32 fn_80054F64(void) { return lbl_803DCE38; }
void fn_80054F6C(u32 x) { lbl_803DCE38 = x; }
u8 fn_8005509C(void) { return lbl_803DCDFA; }
void fn_800550A4(u8 x) { lbl_803DCDFA = x; }
void fn_800550AC(u8 x) { lbl_803DCDF9 = x; }
void fn_800550B4(u8 x) { lbl_803DCDF8 = x; }
u8 fn_800550BC(void) { return lbl_803DCDF7; }

/* Pattern wrappers. */
extern u8 lbl_803DCDF6;
extern u8 lbl_803DCDF4;
void fn_80054FA4(void) { lbl_803DCDF6 = 0x0; }
void fn_80055070(void) { lbl_803DCDF4 = 0x0; }

/* misc 8b leaves */
void fn_800541A4(s16 *p, s16 v) { *(s16*)((char*)p + 0x14) = v; }
