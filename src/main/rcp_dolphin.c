#include "ghidra_import.h"
#include "main/mapEvent.h"
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
extern u32 randomGetRange(int min, int max);
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
extern void gxSetPeControl_ZCompLoc_();
extern void gxSetZMode_();
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
extern undefined4 __GXSendFlushPrim();
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
extern undefined4 GXSetBlendMode();
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
extern undefined4 TRKNubMainLoop();
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
extern f32 lbl_803DC28C;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;
extern f32 lbl_803DDABC;
extern f32 lbl_803DDAC4;
extern f32 lbl_803DDAC8;
extern f32 lbl_803DDACC;
extern f32 lbl_803DDAD0;
extern f32 lbl_803DF7C8;
extern f32 lbl_803DF7CC;
extern f32 lbl_803DF7D0;
extern f32 lbl_803DF7D4;
extern f32 lbl_803DF7D8;
extern f32 lbl_803DF7DC;
extern f32 lbl_803DF7E0;
extern f32 lbl_803DF7E4;
extern f32 lbl_803DF7F0;
extern f32 lbl_803DF7F4;
extern f32 lbl_803DF7F8;
extern f32 lbl_803DF7FC;
extern f32 lbl_803DF800;
extern f32 lbl_803DF804;
extern f32 lbl_803DF808;
extern f32 lbl_803DF818;
extern f32 lbl_803DF81C;
extern f32 lbl_803DF838;
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
  GXSetBlendMode(DAT_803dda10,local_14);
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
    GXSetBlendMode(DAT_803dda10,DAT_803dd9f0);
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
    GXSetBlendMode(DAT_803dda10,local_20[0]);
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
  GXSetBlendMode(DAT_803dda10,local_10[0]);
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
  GXSetBlendMode(DAT_803dda10,local_14[0]);
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
    __GXSendFlushPrim(1,0);
    FUN_802420b0(0x80378620,0x6640);
    FUN_8025d4a0(-0x7fc879e0,0x6640);
    uVar3 = 0;
    dVar9 = (double)lbl_803DF7D8;
    dVar10 = (double)lbl_803DF7DC;
    dVar11 = (double)lbl_803DF7D4;
    dVar13 = (double)lbl_803DF7E4;
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
          dVar4 = (double)lbl_803DF7E0;
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
          dVar4 = (double)lbl_803DF7E0;
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
    __GXSendFlushPrim(1,8);
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
    FUN_8001757c((double)*param_2,(double)lbl_803DF7E0,iVar1);
    FUN_80017588(iVar1,0xff,0,0,0xff);
    FUN_800175fc(0,iVar1,param_1);
    FUN_8001757c((double)param_2[1],(double)lbl_803DF7E0,iVar1);
    FUN_80017588(iVar1,0,0,0xff,0xff);
    FUN_800175fc(0,iVar1,param_1);
    FUN_8001758c((double)lbl_803DF7F0,(double)lbl_803DF7E0,(double)lbl_803DF7E0,iVar1);
    FUN_800175fc(2,iVar1,param_1);
    FUN_80017600(1,1,0);
    FUN_80017600(3,0,0);
    FUN_8001757c((double)*param_2,(double)lbl_803DF7E0,iVar2);
    FUN_80017588(iVar2,0xff,0,0,0xff);
    FUN_800175fc(1,iVar2,param_1);
    FUN_8001757c((double)param_2[1],(double)lbl_803DF7E0,iVar2);
    FUN_80017588(iVar2,0,0,0xff,0xff);
    FUN_800175fc(1,iVar2,param_1);
    FUN_8001758c((double)lbl_803DF7F4,(double)lbl_803DF7E0,(double)lbl_803DF7E0,iVar2);
    FUN_800175fc(3,iVar2,param_1);
    FUN_80017604();
    FUN_8001758c((double)lbl_803DF7DC,(double)lbl_803DF7E0,(double)lbl_803DF7E0,iVar1);
    FUN_8001758c((double)lbl_803DF7DC,(double)lbl_803DF7E0,(double)lbl_803DF7E0,iVar2);
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
  
  dVar1 = (double)lbl_803DF7E0;
  FUN_8025da64(dVar1,dVar1,(double)lbl_803DF7F8,(double)lbl_803DF7F8,dVar1,
               (double)lbl_803DF7DC);
  FUN_8025da88(0,0,0x20,0x20);
  FUN_80259340(0,0,0x20,0x20);
  FUN_802594c0(0x20);
  FUN_80259400(0,0,0x20,0x20);
  dVar1 = (double)lbl_803DF7DC;
  FUN_80247dfc(dVar1,(double)lbl_803DF7FC,dVar1,(double)lbl_803DF7FC,dVar1,
               (double)lbl_803DF7D8,afStack_48);
  FUN_8025d6ac(afStack_48,1);
  FUN_8025cce8(0,1,0,5);
  gxSetZMode_(0,2,0);
  FUN_80259288(0);
  gxSetPeControl_ZCompLoc_(1);
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
                                - DOUBLE_803df828),(double)lbl_803DF818,param_2,
                 (uint)*(byte *)(param_1 + 0x19),(uint)*(byte *)(param_1 + 0x1a),0,'\0',0);
  }
  else {
    dVar2 = (double)lbl_803DF81C;
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
                                - DOUBLE_803df828),(double)lbl_803DF818,puVar5,
                 (uint)*(byte *)(param_1 + 0x19),(uint)*(byte *)(param_1 + 0x1a),0,'\0',0);
  }
  else {
    dVar6 = (double)lbl_803DF81C;
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
    uVar3 = randomGetRange(0,1000);
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
  *param_2 = *param_2 + lbl_803DDA58;
  param_2[2] = param_2[2] + lbl_803DDA5C;
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
  lbl_803DDAC4 = (float)param_1;
  DAT_803ddac0 = *param_4;
  uRam803ddac1 = param_4[1];
  uRam803ddac2 = param_4[2];
  lbl_803DDABC = (float)param_2;
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
  lbl_803DDAD0 = (float)param_1;
  lbl_803DDACC = (float)param_2;
  lbl_803DDAC8 = (float)param_3;
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
  lbl_803DC28C = (float)param_1;
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
              fVar8 = lbl_803DF838 + *(float *)(param_1 + 0x3c);
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
extern u32 bEnableColorFilter;
extern u8 bEnableViewFinderHud;
extern u8 bEnableSpiritVision;
extern u8 bEnableMonochromeFilter;
extern u8 bEnableMotionBlur;
u32 Rcp_GetColorFilterEnabled(void) { return bEnableColorFilter; }
void Rcp_SetColorFilterEnabled(u32 x) { bEnableColorFilter = x; }
u8 Rcp_GetViewFinderHudEnabled(void) { return bEnableViewFinderHud; }
void Rcp_SetViewFinderHudEnabled(u8 x) { bEnableViewFinderHud = x; }
void Rcp_SetSpiritVisionEnabled(u8 x) { bEnableSpiritVision = x; }
void Rcp_SetMonochromeFilterEnabled(u8 x) { bEnableMonochromeFilter = x; }
u8 Rcp_GetMotionBlurEnabled(void) { return bEnableMotionBlur; }

extern f32 lbl_803DB62C;
void setMotionBlur(u8 enabled, f32 amount) { bEnableMotionBlur = enabled; lbl_803DB62C = amount; }

/* Pattern wrappers. */
extern u8 bEnableDistortionFilter;
extern u8 bEnableBlurFilter;
void Rcp_DisableDistortionFilter(void) { bEnableDistortionFilter = 0x0; }
void Rcp_DisableBlurFilter(void) { bEnableBlurFilter = 0x0; }

/* misc 8b leaves */
void fn_800541A4(s16 *p, s16 v) { *(s16*)((char*)p + 0x14) = v; }

extern u32 lbl_803DCDA8;
extern u32 lbl_803DCDB0;
extern u32 lbl_803DCDB4;

void fn_80053ED0(u32 bits) { lbl_803DCDA8 = lbl_803DCDA8 | bits; }
#pragma scheduling off
#pragma peephole off
void fn_80053EBC(u32 bits) {
    u32 v = lbl_803DCDA8;
    u32 nb = bits ^ 0xffffffff;
    lbl_803DCDA8 = v & nb;
}
#pragma peephole reset
#pragma scheduling reset
void fn_800542F4(void) { lbl_803DCDA8 = 0; lbl_803DCDB4 = 0; lbl_803DCDB0 = 0; }

extern f32 lbl_803DCE50;
extern f32 lbl_803DCE4C;
extern f32 blurFilterArea;
extern u8 bBlurFilterUseArea;
extern u8 bBiggerBlurFilter;
#pragma scheduling off
void turnOnBlurFilter(u8 useArea, u8 bigger, f32 a, f32 b, f32 area) {
    bEnableBlurFilter = 1;
    lbl_803DCE50 = a;
    lbl_803DCE4C = b;
    blurFilterArea = area;
    bBlurFilterUseArea = useArea;
    bBiggerBlurFilter = bigger;
}

extern u8 lbl_803DCD68;
extern u8 lbl_803DCD69;
extern u8 lbl_803DCD6A;
extern void GXSetNumTexGens(u8 n);
extern void GXSetNumTevStages(u8 n);
extern void GXSetNumIndStages(u8 n);
#pragma dont_inline on
void textureFn_800528bc(void) {
    GXSetNumTexGens(lbl_803DCD69);
    GXSetNumTevStages(lbl_803DCD6A);
    GXSetNumIndStages(lbl_803DCD68);
}
#pragma dont_inline reset

extern u8 *saveGameGetEnvState(void);
extern s32 lbl_803DCE00;
#pragma peephole off
void timeOfDayFn_80055000(void) {
    u8 *p = saveGameGetEnvState();
    lbl_803DCE00 = -1;
    p[0x40] = (u8)(p[0x40] & ~0x20);
}
void timeOfDayFn_80055038(void) {
    u8 *p = saveGameGetEnvState();
    lbl_803DCE00 = 1;
    p[0x40] = (u8)(p[0x40] | 0x20);
}
#pragma peephole reset

extern f32 playerMapOffsetX;
extern f32 playerMapOffsetZ;
void fn_80054F74(int *p, f32 *vec) {
    if (*(void**)((char*)p + 0x30) != NULL) return;
    vec[0] = vec[0] + playerMapOffsetX;
    vec[2] = vec[2] + playerMapOffsetZ;
}
#pragma scheduling reset

extern u8 lbl_803879A0[];
extern u8 *lbl_803DCE78;
extern s16 lbl_803DCEBA;
extern u8 lbl_803DCEBC;
extern u8 lbl_803DCEBD;
extern void *gScreenTransitionInterface;
extern int getTabEntry(void *p, int sz, int off, int unk);
extern void Pause_SetDisabled(int);

#pragma scheduling off
#pragma peephole off
void warpToMap(int idx, s8 transType) {
    u8 *p = lbl_803DCE78;
    getTabEntry(p, 28, idx << 4, 16);
    *(f32 *)(lbl_803879A0 + 0) = *(f32 *)(p + 0);
    *(f32 *)(lbl_803879A0 + 4) = *(f32 *)(p + 4);
    *(f32 *)(lbl_803879A0 + 8) = *(f32 *)(p + 8);
    *(s16 *)(lbl_803879A0 + 12) = *(s16 *)(p + 12);
    *(s16 *)(lbl_803879A0 + 14) = *(s16 *)(p + 14);
    lbl_803DCEBA = (s16)idx;
    lbl_803DCEBD = 1;
    *(s8 *)&lbl_803DCEBC = transType;
    if (transType != 0) {
        (*(void (***)(int, int))gScreenTransitionInterface)[2](2, 1);
    }
    Pause_SetDisabled(1);
}
#pragma peephole reset
#pragma scheduling reset

extern u8 lbl_8037E000[];

#pragma scheduling off
#pragma peephole off
void ShaderDef_free(int *def) {
    void *p1 = (void *)def[0];
    void *p2;
    int i;
    void *s;

    if (p1 != NULL) {
        for (i = 0; i < 6; i++) {
            s = *(void **)(lbl_8037E000 + i * 0x1C);
            if (*(u16 *)((char *)s + 0xE) != 0 && s == p1) {
                (*(u16 *)((char *)*(void **)(lbl_8037E000 + i * 0x1C) + 0xE))--;
                break;
            }
        }
    }
    p2 = (void *)def[1];
    if (p2 == NULL) return;
    for (i = 0; i < 6; i++) {
        s = *(void **)(lbl_8037E000 + i * 0x1C);
        if (*(u16 *)((char *)s + 0xE) != 0 && s == p2) {
            (*(u16 *)((char *)*(void **)(lbl_8037E000 + i * 0x1C) + 0xE))--;
            return;
        }
    }
}
#pragma peephole reset
#pragma scheduling reset

extern int lbl_803DCDBC;
extern void *lbl_803DCDC4;
#pragma peephole off
#pragma scheduling off
void* textureIdxToPtr(int idx) {
    int i;
    if ((u32)idx & 0x80000000) return (void*)idx;
    i = idx - 1;
    if (i < 0 || i >= lbl_803DCDBC) return NULL;
    return *(void**)((u8*)lbl_803DCDC4 + i * 16 + 4);
}

void* getLoadedTexture(int key) {
    u8 *iter = (u8 *)lbl_803DCDC4;
    int count = lbl_803DCDBC;
    int i;
    for (i = 0; i < count; i++) {
        if (*(int *)iter == key) {
            return *(void **)((u8 *)lbl_803DCDC4 + i * 16 + 4);
        }
        iter += 16;
    }
    return NULL;
}

extern int getLoadedFileFlags(int);
extern void loadTextureFile(void **out, int asset);
#pragma dont_inline on
void* textureLoadAsset(int asset) {
    void *out = NULL;
    if (getLoadedFileFlags(0) & 0x100000) return NULL;
    loadTextureFile(&out, asset);
    return out;
}
#pragma dont_inline reset

extern f32 distortionFilterVector[3];
extern f32 distortionFilterAngle1;
extern f32 distortionFilterAngle2;
extern u8 distortionFilterColor[3];
extern u8 bEnableDistortionFilter;
void turnOnDistortionFilter(f32 *vec, u8 *color, f32 angle2, f32 angle1) {
    distortionFilterVector[0] = vec[0];
    distortionFilterVector[1] = vec[1];
    distortionFilterVector[2] = vec[2];
    distortionFilterAngle2 = angle2;
    distortionFilterColor[0] = color[0];
    distortionFilterColor[1] = color[1];
    distortionFilterColor[2] = color[2];
    distortionFilterAngle1 = angle1;
    bEnableDistortionFilter = 1;
}

extern int lbl_803DCD58, lbl_803DCD84;
extern int lbl_803DCD54, lbl_803DCD80;
extern int lbl_803DCD64, lbl_803DCD90;
extern int lbl_803DCD5C, lbl_803DCD88;
extern int lbl_803DCD60, lbl_803DCD8C;
extern int lbl_803DCD50, lbl_803DCD7C;
extern int lbl_803DCD4C, lbl_803DCD78;
extern int lbl_803DCD74;
extern int lbl_803DCD70;
extern int lbl_803DCD6C;
extern u8 lbl_803DCD6B, lbl_803DCD4B;
extern u8 lbl_803DCD4A;
extern u8 lbl_803DCD49;
extern u8 lbl_803DCD48;
extern u8 lbl_803DCD30;
#pragma dont_inline on
void resetLotsOfRenderVars(void) {
    lbl_803DCD58 = 30;
    lbl_803DCD84 = 30;
    lbl_803DCD54 = 64;
    lbl_803DCD80 = 64;
    lbl_803DCD64 = 0;
    lbl_803DCD90 = 0;
    lbl_803DCD5C = 0;
    lbl_803DCD88 = 0;
    lbl_803DCD60 = 0;
    lbl_803DCD8C = 0;
    lbl_803DCD50 = 0;
    lbl_803DCD7C = 0;
    lbl_803DCD4C = 4;
    lbl_803DCD78 = 4;
    lbl_803DCD74 = 0;
    lbl_803DCD70 = 12;
    lbl_803DCD6C = 28;
    lbl_803DCD6B = 0;
    lbl_803DCD4B = 0;
    lbl_803DCD6A = 0;
    lbl_803DCD4A = 0;
    lbl_803DCD69 = 0;
    lbl_803DCD49 = 0;
    lbl_803DCD68 = 0;
    lbl_803DCD48 = 0;
    lbl_803DCD30 = 0;
}
#pragma dont_inline reset

extern void GXSetScissor(u32 left, u32 top, u32 wd, u32 ht);
void gxSetScissorRect(int p1, int p2, int x, int y, int x2, int y2) {
    if (x < 0) x = 0;
    if (y < 0) y = 0;
    if (x2 < 0) x2 = 0;
    if (y2 < 0) y2 = 0;
    GXSetScissor(x, y, x2 - x, y2 - y);
}

extern void GXSetTevDirect(int tev);
extern void GXSetTevOrder(int tev, int tc, int tm, int color);
extern void GXSetTevSwapMode(int tev, int ras, int tex);
extern void GXSetTevColorIn(int tev, int a, int b, int c, int d);
extern void GXSetTevAlphaIn(int tev, int a, int b, int c, int d);
extern void GXSetTevColorOp(int tev, int op, int bias, int scale, int clamp, int outreg);
extern void GXSetTevAlphaOp(int tev, int op, int bias, int scale, int clamp, int outreg);
extern int lbl_803DCD90;
void gxColorFn_800523d0(void) {
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 4);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    if (lbl_803DCD6A == 0 || lbl_803DCD30 == 0) {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0xf, 0xf, 0xa);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 5);
    } else {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0, 0xa, 0xf);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 0, 5, 7);
    }
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A++;
}

extern void GXSetTevColor(int id, int *color);
extern void GXSetTevKColorSel(int tev, int sel);
extern void gxTextureFn_8004bf88(int *p, int a, int b, int *out_sel, int *out_other);

extern f32 LastCommandWasRead_803DEB60;
extern f32 sDvdfsCurrentDirEntry;
typedef struct F32Pair {
    f32 lo;
    f32 hi;
} F32Pair;
extern F32Pair LastReadIssued_803DEB58;
extern f32 lbl_803DEB7C;
#pragma dont_inline on
void gxFn_80052dc0(void) {
    f32 omtx[4][4];
    f32 pmtx[3][4];
    GXSetViewport(LastCommandWasRead_803DEB60, LastCommandWasRead_803DEB60,
                  sDvdfsCurrentDirEntry, sDvdfsCurrentDirEntry,
                  LastCommandWasRead_803DEB60, LastReadIssued_803DEB58.hi);
    GXSetScissor(0, 0, 32, 32);
    GXSetDispCopySrc(0, 0, 32, 32);
    GXSetDispCopyDst(32, 32);
    GXSetTexCopySrc(0, 0, 32, 32);
    C_MTXOrtho(omtx, LastReadIssued_803DEB58.hi, lbl_803DEB7C,
               LastReadIssued_803DEB58.hi, lbl_803DEB7C,
               LastReadIssued_803DEB58.hi, LastReadIssued_803DEB58.lo);
    GXSetProjection(omtx, 1);
    GXSetBlendMode(0, 1, 0, 5);
    gxSetZMode_(0, 2, 0);
    GXSetCullMode(0);
    gxSetPeControl_ZCompLoc_(1);
    GXSetAlphaCompare(7, 0, 0, 7, 0);
    GXClearVtxDesc();
    GXSetVtxDesc(9, 1);
    GXSetVtxDesc(10, 1);
    PSMTXIdentity(pmtx);
    GXLoadPosMtxImm(pmtx, 0);
    GXLoadNrmMtxImm(pmtx, 0);
    GXSetCurrentMtx(0);
}
#pragma dont_inline reset
void gxTextureFn_80052638(int *param) {
    int sel;
    int v1;
    int color;
    GXSetTevDirect(lbl_803DCD90);
    color = param[0];
    GXSetTevColor(1, &color);
    gxTextureFn_8004bf88(param, 1, 0, &sel, &v1);
    GXSetTevKColorSel(lbl_803DCD90, sel);
    GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 0xff);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    if (lbl_803DCD6A != 0 && lbl_803DCD30 != 0) {
        GXSetTevColorIn(lbl_803DCD90, 0, 0xe, 3, 0xf);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 0);
    }
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A++;
}

extern void GXSetTevKAlphaSel(int tev, int sel);
#pragma dont_inline on
void textureFn_800524ec(int *param) {
    int sel_color;
    int sel_alpha;
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 4);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    gxTextureFn_8004bf88(param, 0, 1, &sel_color, &sel_alpha);
    GXSetTevKAlphaSel(lbl_803DCD90, sel_alpha);
    if (lbl_803DCD6A == 0 || lbl_803DCD30 == 0) {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0xf, 0xf, 0xa);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 6);
    } else {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0, 0xa, 0xf);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 0, 6, 7);
    }
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A++;
}
#pragma dont_inline reset

void gxColorFn_80052764(int *param) {
    int sel_color;
    int sel_alpha;
    GXSetTevDirect(lbl_803DCD90);
    gxTextureFn_8004bf88(param, 1, 1, &sel_color, &sel_alpha);
    GXSetTevKAlphaSel(lbl_803DCD90, sel_alpha);
    GXSetTevKColorSel(lbl_803DCD90, sel_color);
    GXSetTevOrder(lbl_803DCD90, 0xff, 0xff, 4);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    if (lbl_803DCD6A == 0 || lbl_803DCD30 == 0) {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0xf, 0xf, 0xe);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 7, 7, 6);
    } else {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0, 0xe, 0xf);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 0, 6, 7);
    }
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD6A++;
}

extern u32 GXGetTexBufferSize(u16 w, u16 h, u32 format, u8 mipmap, u8 max_lod);
extern void *mmAlloc(u32 size, int type, int p3);
extern void *memset(void *, int, u32);
extern void textureFn_80053d58(void *obj);
#pragma dont_inline on
void *textureAlloc(u16 w, u16 h, int fmt, u8 mip, u8 maxLod, u8 b8, u8 b9, u8 b10, u8 b11) {
    u8 *obj;
    u32 size = GXGetTexBufferSize(w, h, fmt, mip, maxLod) + 96;
    obj = (u8 *)mmAlloc(size, 6, 0);
    if (obj == NULL) return NULL;
    memset(obj, 0, 100);
    *(u8 *)(obj + 22) = fmt;
    *(u16 *)(obj + 10) = w;
    *(u16 *)(obj + 12) = h;
    *(u16 *)(obj + 16) = 1;
    *(u16 *)(obj + 14) = 0;
    *(u8 *)(obj + 23) = b8;
    *(u8 *)(obj + 24) = b9;
    *(u8 *)(obj + 25) = b10;
    *(u8 *)(obj + 26) = b11;
    *(int *)(obj + 80) = 0;
    textureFn_80053d58(obj);
    return obj;
}

extern void GXInitTexObj(void *obj, void *img, u16 w, u16 h, int fmt, u8 ws, u8 wt, u8 mipmap);
extern void GXInitTexObjLOD(void *obj, int mn, int mg, f32 minLod, f32 maxLod, f32 lodBias, u8 bclamp, u8 edgeLod, u8 aniso);
extern void GXInitTexObjUserData(void *obj, void *udata);
extern int GXGetTexObjFmt(void *obj);
extern u16 GXGetTexObjWidth(void *obj);
extern u16 GXGetTexObjHeight(void *obj);
extern f32 lbl_803DEB98;
extern f32 lbl_803DEB9C;
#pragma dont_inline reset
#pragma dont_inline on
void textureFn_80053d58(void *vobj) {
    u8 *obj = (u8 *)vobj;
    u8 mipmap = 0;
    *(int *)(obj + 64) = 0;
    obj[72] = 0;
    if ((int)obj[29] - (int)obj[28] > 0) mipmap = 1;
    GXInitTexObj((void *)(obj + 32), obj + 96,
                 *(u16 *)(obj + 10), *(u16 *)(obj + 12),
                 obj[22], obj[23], obj[24], mipmap);
    if (mipmap != 0) {
        GXInitTexObjLOD((void *)(obj + 32), obj[25], obj[26],
                        (f32)(u32)obj[28], (f32)(s32)obj[29],
                        lbl_803DEB98, 0, 0, 0);
    } else {
        GXInitTexObjLOD((void *)(obj + 32), obj[25], obj[26],
                        lbl_803DEB9C, lbl_803DEB9C, lbl_803DEB9C, 0, 0, 0);
    }
    GXInitTexObjUserData((void *)(obj + 32), obj);
    {
        int fmt = GXGetTexObjFmt((void *)(obj + 32));
        u16 w = GXGetTexObjWidth((void *)(obj + 32));
        u16 h = GXGetTexObjHeight((void *)(obj + 32));
        *(u32 *)(obj + 68) = GXGetTexBufferSize(w, h, fmt, 0, 0);
    }
}
#pragma dont_inline reset

extern void findSomething(int);
extern void mm_free(void *);
void textureFree(u8 *tex) {
    int i;
    u8 *iter;
    u8 *next;
    int count;
    if (tex == (u8 *)*(void **)((u8 *)lbl_803DCDC4 + 4)) return;
    if (tex == NULL) {
        tex[75] = 10;
        return;
    }
    if (*(u16 *)(tex + 14) == 0) {
        tex[75] = 10;
        return;
    }
    if (tex[73] != 0 && *(u16 *)(tex + 14) <= 1) {
        tex[75] = 10;
    }
    (*(u16 *)(tex + 14))--;
    if (*(u16 *)(tex + 14) != 0) return;
    i = 0;
    count = lbl_803DCDBC;
    if (count <= 0) return;
    {
        u8 *entry = (u8 *)lbl_803DCDC4;
        do {
            if (*(u8 **)(entry + 4) == tex) {
                iter = *(u8 **)tex;
                while (iter != NULL) {
                    if ((u32)iter < 0x80000000 || (u32)iter > 0x81800000) iter = NULL;
                    if ((u32)iter < 0x80000000 || (u32)iter >= 0xa0000000) iter = NULL;
                    if (iter == NULL) break;
                    next = *(u8 **)iter;
                    if (iter[72] != 0) findSomething(*(int *)(iter + 64));
                    if (iter[73] == 0) mm_free(iter);
                    iter = next;
                }
                if (tex[72] != 0) findSomething(*(int *)(tex + 64));
                if (tex[73] == 0) mm_free(tex);
                *(int *)((u8 *)lbl_803DCDC4 + i * 16) = -1;
                *(u8 **)((u8 *)lbl_803DCDC4 + i * 16 + 4) = NULL;
                return;
            }
            entry += 16;
            i++;
            count--;
        } while (count != 0);
    }
}

#pragma peephole reset
#pragma scheduling reset
int textureCrazyPointerFollowFn_80054c30(int *p, int n) {
    int limit = *(u16 *)((char *)p + 16);
    int q;
    if (n >= limit) n = limit - 1;
    n >>= 8;
    if (n <= 0) return (int)p;
    q = (u32)n >> 3;
    if (q != 0) {
        do {
            p = *(int **)p;
            p = *(int **)p;
            p = *(int **)p;
            p = *(int **)p;
            p = *(int **)p;
            p = *(int **)p;
            p = *(int **)p;
            p = *(int **)p;
        } while (--q != 0);
    }
    n = n & 7;
    if (n == 0) return (int)p;
    do {
        p = *(int **)p;
    } while (--n != 0);
    return (int)p;
}
#pragma peephole off
#pragma scheduling off
#pragma scheduling reset
#pragma peephole reset

#pragma scheduling off
#pragma peephole off
void shaderInit(u8 *def, void **out, u8 *obj)
{
    void **slot;
    void *s;

    if (*(void **)(def + 0x8) != NULL) {
        if (obj != NULL)
            slot = (void **)(lbl_8037E000 + (6 - (obj[0xf2] + 1)) * 0x1C);
        else
            slot = (void **)(lbl_8037E000 + 0x8C);
        s = *slot;
        (*(u16 *)((char *)s + 0xE))++;
        out[0] = *slot;
    }
    if (*(void **)(def + 0x14) == NULL)
        return;
    if (def[0x20] >= 6)
        slot = (void **)lbl_8037E000;
    else
        slot = (void **)(lbl_8037E000 + (def[0x20] >> 1) * 0x1C);
    s = *slot;
    (*(u16 *)((char *)s + 0xE))++;
    out[1] = *slot;
}
#pragma scheduling reset
#pragma peephole reset

extern void selectTexture(int handle, int slot);

#pragma scheduling off
#pragma peephole off
void textureFn_800541ac(int p1, int *tex, void *forceTex, int flags, int packed)
{
    int i;
    int idx, count;
    int *node;
    int *cur;
    int *result;
    int *walk;
    u16 f10;

    if (tex == NULL)
        return;
    idx = packed >> 16;
    f10 = *(u16 *)((char *)tex + 0x10);
    if (f10 != 0)
        count = f10 >> 8;
    else
        count = 0;
    cur = tex;
    result = tex;
    if (count > 1 && idx < count) {
        node = tex;
        for (i = 0; i < idx && node != NULL; i++)
            node = *(int **)node;
        if (node != NULL)
            cur = node;
        if (flags & 0x40) {
            if (flags & 0x80000) {
                idx--;
                if (idx < 0) {
                    if (flags & 0x40000)
                        idx += 2;
                    else
                        idx = 0;
                }
            } else {
                idx++;
                if (idx >= count) {
                    if (flags & 0x40000)
                        idx -= 2;
                    else
                        idx = count - 1;
                }
            }
            walk = tex;
            for (i = 0; i < idx && walk != NULL; i++)
                walk = *(int **)walk;
            if (walk != NULL)
                result = walk;
        } else {
            result = cur;
        }
    }
    if (forceTex != NULL)
        result = forceTex;
    selectTexture((int)cur, 0);
    selectTexture((int)result, 1);
}
#pragma scheduling reset
#pragma peephole reset

extern u8 framesThisStep;

#pragma scheduling off
#pragma peephole off
void textureAnimFn_80053f2c(u8 *def, u32 *node, int *cnt)
{
    u32 a, b, c;
    u32 v;
    int r;
    int flag2;

    v = node[0];
    a = v & 0x80000;
    b = v & 0x40000;
    c = v & 0x20000;
    if (c != 0) {
        if (b == 0) {
            r = randomGetRange(0, 0x3e8);
            if (r > 0x3d9) {
                node[0] &= ~0x80000;
                node[0] |= 0x40000;
            }
        } else if (a == 0) {
            *cnt += *(u16 *)(def + 0x14) * framesThisStep;
            if (*cnt >= *(u16 *)(def + 0x10)) {
                *cnt = *(u16 *)(def + 0x10) * 2 - 1 - *cnt;
                if (*cnt < 0) {
                    *cnt = 0;
                    node[0] &= ~0xc0000;
                } else {
                    node[0] |= 0x80000;
                }
            }
        } else {
            *cnt -= *(u16 *)(def + 0x14) * framesThisStep;
            if (*cnt < 0) {
                *cnt = 0;
                node[0] &= ~0xc0000;
            }
        }
    } else if (b != 0) {
        if (a == 0)
            *cnt += *(u16 *)(def + 0x14) * framesThisStep;
        else
            *cnt -= *(u16 *)(def + 0x14) * framesThisStep;
        do {
            flag2 = 0;
            if (*cnt < 0) {
                *cnt = -*cnt;
                node[0] &= ~0x80000;
                flag2 = 1;
            }
            if (*cnt >= *(u16 *)(def + 0x10)) {
                *cnt = *(u16 *)(def + 0x10) * 2 - 1 - *cnt;
                node[0] |= 0x80000;
                flag2 = 1;
            }
        } while (flag2 != 0);
    } else if (a == 0) {
        *cnt += *(u16 *)(def + 0x14) * framesThisStep;
        while (*cnt >= *(u16 *)(def + 0x10))
            *cnt -= *(u16 *)(def + 0x10);
    } else {
        *cnt -= *(u16 *)(def + 0x14) * framesThisStep;
        while (*cnt < 0)
            *cnt += *(u16 *)(def + 0x10);
    }
}
#pragma scheduling reset
#pragma peephole reset

extern char lbl_803822C8[];
extern void *gLoadedRomListPages[];
extern MapEventInterface **gMapEventInterface;
extern int *Obj_SetupObject(int *obj, int p1, int p2, int p3, int p4);

#pragma scheduling off
#pragma peephole off
void mapInstantiateObjects(int *p1, int mapId, int index, int p4)
{
    int *seg = (int *)(lbl_803822C8 + mapId * 0x8c);
    char *romBase;
    char *p, *obj, *end;
    int objIndex, i;
    int visible, v, flag;
    int byteIdx, bit;
    s8 *vis;

    if (seg[index] == -1)
        return;
    objIndex = 0;
    romBase = *(char **)((char *)p1 + 0x20);
    p = romBase;
    obj = romBase + seg[index];
    while (p < obj) {
        objIndex++;
        p += *(u8 *)(p + 2) * 4;
    }
    for (i = index + 1; i <= 0x20; i++) {
        if (seg[i] != -1)
            break;
    }
    end = romBase + seg[i];

    while (obj < end) {
        if (objIndex < 0) {
            visible = 0;
        } else {
            void *bm = gLoadedRomListPages[mapId];
            byteIdx = objIndex >> 3;
            if (byteIdx >= 0xc4) {
                visible = 0;
            } else {
                bit = 1 << (objIndex & 7);
                vis = *(s8 **)((char *)bm + 0x10);
                if ((bit & vis[byteIdx]) != 0)
                    visible = 1;
                else
                    visible = 0;
            }
        }
        if (visible == 0) {
            v = (*gMapEventInterface)->getMode(mapId);
            if (v == -1) {
                flag = 0;
            } else if (v == 0) {
                flag = 1;
            } else if (v < 9) {
                if ((*(u8 *)(obj + 3) >> (v - 1)) & 1)
                    flag = 0;
                else
                    flag = 1;
            } else {
                if ((*(u8 *)(obj + 5) >> (0x10 - v)) & 1)
                    flag = 0;
                else
                    flag = 1;
            }
            if (flag != 0) {
                if (objIndex >= 0) {
                    byteIdx = objIndex >> 3;
                    bit = 1 << (objIndex & 7);
                    vis = *(s8 **)((char *)gLoadedRomListPages[mapId] + 0x10);
                    vis[byteIdx] = vis[byteIdx] & ~bit;
                    vis[byteIdx] = vis[byteIdx] | bit;
                }
                Obj_SetupObject((int *)obj, 1, mapId, objIndex, p4);
            }
        }
        objIndex++;
        obj += *(u8 *)(obj + 2) * 4;
    }
}
#pragma scheduling reset
#pragma peephole reset

#pragma peephole off
#pragma scheduling off
extern void GXLoadTexMtxImm(f32 *mtx, int id, int type);
extern void GXSetTexCoordGen2(int dst, int fn, int src, int mtx, int normalize, int pt);
extern void GXLoadTexObjPreLoaded(u8 *obj, u32 *region, int map);
extern void GXLoadTexObj(u8 *obj, int map);

void fn_80051868(u8 *tex, f32 *mtx, int mode)
{
    int map;
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 4);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    if (mtx != NULL) {
        GXLoadTexMtxImm(mtx, lbl_803DCD80, 0);
        GXSetTexCoordGen2(lbl_803DCD88, 1, lbl_803DCD78, 0x3c, 0, lbl_803DCD80);
        lbl_803DCD80 = lbl_803DCD80 + 3;
    } else {
        GXSetTexCoordGen2(lbl_803DCD88, 1, lbl_803DCD78, 0x3c, 0, 0x7d);
    }
    if (mode == 0) {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 0xa, 0xf);
    } else if (mode == 8) {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 0xa, 6);
    } else if (mode == 4) {
        GXSetTevColorIn(lbl_803DCD90, 8, 0xf, 0xf, 0);
    } else if (mode == 6) {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 0, 0xf);
    } else if (mode == 9) {
        GXSetTevColorIn(lbl_803DCD90, 8, 0, 1, 0xf);
    } else {
        GXSetTevColorIn(lbl_803DCD90, 8, 0, 1, 0xf);
    }
    if (lbl_803DCD6B != 0) {
        GXSetTevAlphaIn(lbl_803DCD90, 7, 4, 0, 7);
    } else {
        GXSetTevAlphaIn(lbl_803DCD90, 7, 4, 5, 7);
        lbl_803DCD6B = 1;
    }
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    map = lbl_803DCD8C;
    if (tex != NULL) {
        u8 *to = tex + 0x20;
        if (tex[0x48] != 0) {
            GXLoadTexObjPreLoaded(to, *(u32 **)(tex + 0x40), map);
        } else {
            GXLoadTexObj(to, map);
        }
    }
    lbl_803DCD78 = lbl_803DCD78 + 1;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    lbl_803DCD6A++;
    lbl_803DCD69++;
}

void fn_80051B00(u8 *tex, f32 *mtx, int mode, int *kparam)
{
    int sel;
    int v1;
    int map;
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 4);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    if (mtx != NULL) {
        GXLoadTexMtxImm(mtx, lbl_803DCD80, 0);
        GXSetTexCoordGen2(lbl_803DCD88, 1, lbl_803DCD78, 0x3c, 0, lbl_803DCD80);
        lbl_803DCD80 = lbl_803DCD80 + 3;
    } else {
        GXSetTexCoordGen2(lbl_803DCD88, 1, lbl_803DCD78, 0x3c, 0, 0x7d);
    }
    gxTextureFn_8004bf88(kparam, 1, 0, &sel, &v1);
    GXSetTevKColorSel(lbl_803DCD90, sel);
    if (mode == 0) {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 0xe, 0xf);
    } else if (mode == 8) {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 0xe, 6);
    } else {
        GXSetTevColorIn(lbl_803DCD90, 8, 0, 1, 0xf);
    }
    if (lbl_803DCD6B != 0) {
        GXSetTevAlphaIn(lbl_803DCD90, 7, 4, 0, 7);
    } else {
        GXSetTevAlphaIn(lbl_803DCD90, 7, 4, 5, 7);
        lbl_803DCD6B = 1;
    }
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    map = lbl_803DCD8C;
    if (tex != NULL) {
        u8 *to = tex + 0x20;
        if (tex[0x48] != 0) {
            GXLoadTexObjPreLoaded(to, *(u32 **)(tex + 0x40), map);
        } else {
            GXLoadTexObj(to, map);
        }
    }
    lbl_803DCD78 = lbl_803DCD78 + 1;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    lbl_803DCD6A++;
    lbl_803DCD69++;
}

void fn_80051D5C(u8 *tex, f32 *mtx, int mode, int *kparam)
{
    int sel;
    int v1;
    int map;
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 4);
    GXSetTevSwapMode(lbl_803DCD90, 0, 0);
    if (mtx != NULL) {
        GXLoadTexMtxImm(mtx, lbl_803DCD80, 0);
        GXSetTexCoordGen2(lbl_803DCD88, 1, lbl_803DCD78, 0x3c, 0, lbl_803DCD80);
        lbl_803DCD80 = lbl_803DCD80 + 3;
    } else {
        GXSetTexCoordGen2(lbl_803DCD88, 1, lbl_803DCD78, 0x3c, 0, 0x7d);
    }
    gxTextureFn_8004bf88(kparam, 0, 1, &sel, &v1);
    GXSetTevKAlphaSel(lbl_803DCD90, v1);
    if (mode == 0) {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 0xa, 0xf);
    } else if (mode == 8) {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 0xa, 6);
    } else {
        GXSetTevColorIn(lbl_803DCD90, 8, 0, 1, 0xf);
    }
    if (lbl_803DCD6B != 0) {
        GXSetTevAlphaIn(lbl_803DCD90, 7, 4, 0, 7);
    } else {
        GXSetTevAlphaIn(lbl_803DCD90, 7, 4, 6, 7);
        lbl_803DCD6B = 1;
    }
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    map = lbl_803DCD8C;
    if (tex != NULL) {
        u8 *to = tex + 0x20;
        if (tex[0x48] != 0) {
            GXLoadTexObjPreLoaded(to, *(u32 **)(tex + 0x40), map);
        } else {
            GXLoadTexObj(to, map);
        }
    }
    lbl_803DCD78 = lbl_803DCD78 + 1;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    lbl_803DCD6A++;
    lbl_803DCD69++;
}
extern void GXSetTevSwapModeTable(int table, int r, int g, int b, int a);
extern void GXSetTevKColor(int id, int *color);
typedef struct TevSwapEntry {
    int r;
    int g;
    int b;
} TevSwapEntry;
extern TevSwapEntry lbl_8030CF04[];
extern u8 lbl_803779A0[];
void fn_80053C40(u8 *tex, u8 *obj);

void gxFn_80051fb8(u8 *tex, f32 *mtx, int mode, int *kparam, u8 swapsel, u8 useK)
{
    int sel;
    int v1;
    int color;
    int map;
    GXSetTevDirect(lbl_803DCD90);
    GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 0xff);
    GXSetTevSwapMode(lbl_803DCD90, 0, 1);
    GXSetTevSwapModeTable(1, lbl_8030CF04[swapsel].r, lbl_8030CF04[swapsel].g,
                          lbl_8030CF04[swapsel].b, 3);
    if (mtx != NULL) {
        GXLoadTexMtxImm(mtx, lbl_803DCD80, 0);
        GXSetTexCoordGen2(lbl_803DCD88, 1, lbl_803DCD78, 0x3c, 0, lbl_803DCD80);
        lbl_803DCD80 = lbl_803DCD80 + 3;
    } else {
        GXSetTexCoordGen2(lbl_803DCD88, 1, lbl_803DCD78, 0x3c, 0, 0x7d);
    }
    if (useK != 0) {
        gxTextureFn_8004bf88(kparam, 1, 1, &sel, &v1);
        GXSetTevKColorSel(lbl_803DCD90, sel);
        if (*(void **)(tex + 0x50) != NULL) {
            GXSetTevKAlphaSel(lbl_803DCD90 + 1, v1);
        } else {
            GXSetTevKAlphaSel(lbl_803DCD90, v1);
        }
    } else {
        color = *kparam;
        GXSetTevKColor(lbl_803DCD74, &color);
        GXSetTevKColorSel(lbl_803DCD90, lbl_803DCD70);
        if (*(void **)(tex + 0x50) != NULL) {
            GXSetTevKAlphaSel(lbl_803DCD90 + 1, lbl_803DCD6C);
        } else {
            GXSetTevKAlphaSel(lbl_803DCD90, lbl_803DCD6C);
        }
        lbl_803DCD74 = lbl_803DCD74 + 1;
        lbl_803DCD70 = lbl_803DCD70 + 1;
        lbl_803DCD6C = lbl_803DCD6C + 1;
    }
    if (mode == 0) {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 0xe, 0xf);
    } else if (mode == 8) {
        GXSetTevColorIn(lbl_803DCD90, 0xf, 8, 4, 6);
    } else {
        GXSetTevColorIn(lbl_803DCD90, 8, 0, 1, 0xf);
    }
    if (lbl_803DCD6B != 0) {
        GXSetTevAlphaIn(lbl_803DCD90, 7, 4, 0, 7);
    } else {
        GXSetTevAlphaIn(lbl_803DCD90, 7, 4, 6, 7);
    }
    GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    lbl_803DCD30 = 1;
    map = lbl_803DCD8C;
    if (tex != NULL) {
        u8 *to = tex + 0x20;
        if (tex[0x48] != 0) {
            GXLoadTexObjPreLoaded(to, *(u32 **)(tex + 0x40), map);
        } else {
            GXLoadTexObj(to, map);
        }
        if (*(void **)(tex + 0x50) != NULL) {
            fn_80053C40(tex, lbl_803779A0);
            GXLoadTexObj(lbl_803779A0, 1);
        }
    }
    if (*(void **)(tex + 0x50) != NULL) {
        lbl_803DCD6A++;
        lbl_803DCD90 = lbl_803DCD90 + 1;
        lbl_803DCD8C = lbl_803DCD8C + 1;
        GXSetTevDirect(lbl_803DCD90);
        GXSetTevOrder(lbl_803DCD90, lbl_803DCD88, lbl_803DCD8C, 0xff);
        GXSetTevSwapMode(lbl_803DCD90, 0, 0);
        GXSetTevColorIn(lbl_803DCD90, 0xf, 0xf, 0xf, 0);
        GXSetTevAlphaIn(lbl_803DCD90, 7, 4, 6, 7);
        GXSetTevColorOp(lbl_803DCD90, 0, 0, 0, 1, 0);
        GXSetTevAlphaOp(lbl_803DCD90, 0, 0, 0, 1, 0);
    }
    lbl_803DCD6B = 1;
    lbl_803DCD78 = lbl_803DCD78 + 1;
    lbl_803DCD88 = lbl_803DCD88 + 1;
    lbl_803DCD90 = lbl_803DCD90 + 1;
    lbl_803DCD8C = lbl_803DCD8C + 1;
    lbl_803DCD6A++;
    lbl_803DCD69++;
}

void fn_80053C40(u8 *tex, u8 *obj)
{
    u8 mipmap;
    if ((int)tex[0x1d] - (int)tex[0x1c] > 0) {
        mipmap = 1;
    } else {
        mipmap = 0;
    }
    GXInitTexObj(obj, &tex[*(int *)(tex + 0x50) + 0x60],
                 *(u16 *)(tex + 0xa), *(u16 *)(tex + 0xc),
                 0, tex[0x17], tex[0x18], mipmap);
    if (mipmap != 0) {
        GXInitTexObjLOD(obj, tex[0x19], tex[0x1a],
                        (f32)(u32)tex[0x1c], (f32)(s32)tex[0x1d],
                        lbl_803DEB98, 0, 0, 0);
    } else {
        GXInitTexObjLOD(obj, tex[0x19], tex[0x1a],
                        lbl_803DEB9C, lbl_803DEB9C, lbl_803DEB9C, 0, 0, 0);
    }
}

extern void GXSetMisc(int token, u32 val);
extern void DCInvalidateRange(void *addr, u32 nBytes);
extern void GXBeginDisplayList(void *list, u32 size);
extern u32 GXEndDisplayList(void);
extern void GXCallDisplayList(void *list, u32 nbytes);
extern void GXBegin(int prim, int vtxfmt, u16 nverts);
extern f32 sqrtf(f32 x);
extern u8 lbl_803DCD98;
extern u32 lbl_803DCD9C;
extern u8 lbl_803779C0[];
extern F32Pair LastReadFinished_803DEB50;
extern f32 lbl_803DEB64;

#pragma opt_loop_invariants off
void lightFn_80052974(f32 a, f32 b)
{
    f32 z;
    f32 scale;
    f32 half;
    f32 w;
    f32 x0;
    f32 y;
    f32 yy;
    f32 x1;
    f32 d;
    f32 r;
    f32 fa;
    f32 fb;
    u32 i;
    u32 j;

    if (lbl_803DCD98 == 0) {
        GXSetMisc(1, 0);
        DCInvalidateRange(lbl_803779C0, 0x6640);
        GXBeginDisplayList(lbl_803779C0, 0x6640);
        w = LastReadIssued_803DEB58.lo;
        half = LastReadIssued_803DEB58.hi;
        scale = LastReadFinished_803DEB50.hi;
        z = lbl_803DEB64;
        for (i = 0; i < 0x10; i++) {
            GXBegin(0x98, 4, 0x22);
            fa = scale * (f32)i;
            fb = scale * (f32)(i + 1);
            x0 = fa / w - half;
            x1 = fb / w - half;
            for (j = 0; j <= 0x10; j++) {
                y = (scale * (f32)j) / w - half;
                yy = y * y;
                d = x0 * x0 + yy;
                if (d < half) {
                    r = sqrtf(half - d);
                } else {
                    r = LastCommandWasRead_803DEB60;
                }
                *(volatile f32 *)0xCC008000 = x0;
                *(volatile f32 *)0xCC008000 = y;
                *(volatile f32 *)0xCC008000 = z;
                *(volatile f32 *)0xCC008000 = x0;
                *(volatile f32 *)0xCC008000 = y;
                *(volatile f32 *)0xCC008000 = r;
                d = x1 * x1 + yy;
                if (d < half) {
                    r = sqrtf(half - d);
                } else {
                    r = LastCommandWasRead_803DEB60;
                }
                *(volatile f32 *)0xCC008000 = x1;
                *(volatile f32 *)0xCC008000 = y;
                *(volatile f32 *)0xCC008000 = z;
                *(volatile f32 *)0xCC008000 = x1;
                *(volatile f32 *)0xCC008000 = y;
                *(volatile f32 *)0xCC008000 = r;
            }
        }
        lbl_803DCD9C = GXEndDisplayList();
        lbl_803DCD98 = 1;
        GXSetMisc(1, 8);
    }
    GXCallDisplayList(lbl_803779C0, lbl_803DCD9C);
}
#pragma opt_loop_invariants reset

extern void *fn_80089A58(void);
extern void *fn_80089A50(void);
extern void modelLightChannels_reset(int n);
extern void modelLightChannel_configure(int idx, int a, int b);
extern void modelLightStruct_setSpecularAttenuation(void *light, f32 a, f32 b);
extern void modelLightStruct_setAngularAttenuation(void *light, f32 a, f32 b, f32 c);
extern void modelLightStruct_setSpecularColor(void *light, int r, int g, int b, int a);
extern void modelLightStruct_loadChannelLight(int idx, void *light, int model);
extern void modelLightChannels_applyGXControls(void);
extern f32 lbl_803DEB70;
extern f32 lbl_803DEB74;

#pragma dont_inline on
int textureFn_80052bb4(int model, f32 *params)
{
    void *la;
    void *lb;
    la = fn_80089A58();
    lb = fn_80089A50();
    if (la == NULL || lb == NULL) {
        return 0;
    }
    modelLightChannels_reset(1);
    modelLightChannel_configure(0, 1, 0);
    modelLightChannel_configure(2, 0, 0);
    modelLightStruct_setSpecularAttenuation(la, params[0], LastCommandWasRead_803DEB60);
    modelLightStruct_setSpecularColor(la, 0xff, 0, 0, 0xff);
    modelLightStruct_loadChannelLight(0, la, model);
    modelLightStruct_setSpecularAttenuation(la, params[1], LastCommandWasRead_803DEB60);
    modelLightStruct_setSpecularColor(la, 0, 0, 0xff, 0xff);
    modelLightStruct_loadChannelLight(0, la, model);
    modelLightStruct_setAngularAttenuation(la, lbl_803DEB70, LastCommandWasRead_803DEB60, LastCommandWasRead_803DEB60);
    modelLightStruct_loadChannelLight(2, la, model);
    modelLightChannel_configure(1, 1, 0);
    modelLightChannel_configure(3, 0, 0);
    modelLightStruct_setSpecularAttenuation(lb, params[0], LastCommandWasRead_803DEB60);
    modelLightStruct_setSpecularColor(lb, 0xff, 0, 0, 0xff);
    modelLightStruct_loadChannelLight(1, lb, model);
    modelLightStruct_setSpecularAttenuation(lb, params[1], LastCommandWasRead_803DEB60);
    modelLightStruct_setSpecularColor(lb, 0, 0, 0xff, 0xff);
    modelLightStruct_loadChannelLight(1, lb, model);
    modelLightStruct_setAngularAttenuation(lb, lbl_803DEB74, LastCommandWasRead_803DEB60, LastCommandWasRead_803DEB60);
    modelLightStruct_loadChannelLight(3, lb, model);
    modelLightChannels_applyGXControls();
    modelLightStruct_setAngularAttenuation(la, LastReadIssued_803DEB58.hi, LastCommandWasRead_803DEB60, LastCommandWasRead_803DEB60);
    modelLightStruct_setAngularAttenuation(lb, LastReadIssued_803DEB58.hi, LastCommandWasRead_803DEB60, LastCommandWasRead_803DEB60);
    return 0;
}
#pragma dont_inline reset

extern f32 powfCoreHighPrecision(f32 base, f32 exp);
extern f32 lbl_803DEB48;
extern f32 lbl_803DEB4C;
extern u8 lbl_8030D028[];
extern u8 lbl_803DCDA5;
extern void *lbl_803DCDA0;

void initFn_800534f8(void)
{
    int i;
    u8 *p;
    u8 *q;
    int j;
    u32 half;
    u8 *slot;
    f32 scaleB;
    f32 scaleA;
    f32 v;
    f32 inv;

    i = 0;
    p = lbl_8037E000;
    for (; i < 6; i++) {
        *(void **)p = textureAlloc(0x20, 0x20, 6, 0, 0, 0, 0, 1, 1);
        p[0x1a] = 0;
        p += 0x1c;
    }
    lbl_803DCDA5 = 0;
    q = lbl_8030D028;
    scaleA = lbl_803DEB48;
    scaleB = LastReadFinished_803DEB50.lo;
    for (j = 0; j < 6; j++) {
        v = *(f32 *)(q + 4);
        slot = lbl_8037E000 + lbl_803DCDA5 * 0x1c;
        slot[0xc] = 0xff;
        slot[0xd] = 0xff;
        slot[0xe] = 0xff;
        inv = scaleA / powfCoreHighPrecision(*(f32 *)q, lbl_803DEB4C);
        slot = lbl_8037E000 + lbl_803DCDA5 * 0x1c;
        half = j & 1;
        *(f32 *)(slot + half * 4 + 0x10) = inv;
        *(s8 *)(slot + half + 0x18) = (int)(scaleB * v);
        slot[0x1b] = 1;
        if (half != 0) {
            lbl_803DCDA5 = lbl_803DCDA5 + 1;
        }
        q += 8;
    }
    (lbl_8037E000 + 0x1b)[lbl_803DCDA5++ * 0x1c] = 0;
    (lbl_8037E000 + 0x1b)[lbl_803DCDA5++ * 0x1c] = 0;
    (lbl_8037E000 + 0x1b)[lbl_803DCDA5++ * 0x1c] = 0;
    lbl_803DCDA0 = textureLoadAsset(0x5dc);
}

extern int *getCurrentDataFile(int id);
extern void loadAssetFileById(void *out, int id);
extern int *lbl_8037E0B4[3];
extern int lbl_8037E0A8[3];
extern u16 *lbl_803DCDC0;
extern void *lbl_803DCDB8;
void *textureLoad(int texId, u8 flag);

void loadTextureFiles(void)
{
    int *p;
    int **q;
    int *out;
    int n;

    lbl_803DCDC4 = (void *)mmAlloc(0x2bc0, 6, 0);
    n = 0;
    lbl_803DCDBC = n;
    p = getCurrentDataFile(0x24);
    lbl_8037E0B4[0] = p;
    if (lbl_8037E0B4 != NULL) {
        while (*p != -1) {
            p++;
            n++;
        }
        lbl_8037E0A8[0] = n - 1;
    }
    n = 0;
    p = getCurrentDataFile(0x21);
    lbl_8037E0B4[1] = p;
    if (lbl_8037E0B4 != NULL) {
        while (*p != -1) {
            p++;
            n++;
        }
        lbl_8037E0A8[1] = n - 1;
    }
    n = 0;
    p = getCurrentDataFile(0x50);
    lbl_8037E0B4[2] = p;
    while (*p != -1) {
        p++;
        n++;
    }
    lbl_8037E0A8[2] = n - 1;
    loadAssetFileById(&lbl_803DCDC0, 0x22);
    q = lbl_8037E0B4;
    out = lbl_8037E0A8;
    n = 0;
    p = *q;
    while (*p != -1) {
        p++;
        n++;
    }
    *out = n - 1;
    q++;
    out++;
    n = 0;
    p = *q;
    while (*p != -1) {
        p++;
        n++;
    }
    *out = n - 1;
    lbl_803DCDB8 = (void *)mmAlloc(0x120, 6, 0);
    textureLoad(0, 0);
}

extern void *gCloudActionInterface;
extern void *gSky2Interface;
extern void *gSHthorntailAnimationInterface;
extern void *gNewCloudsInterface;
extern s16 lbl_803DCEB8;
extern u8 lbl_803DCDE0;
extern u8 lbl_803DCA40;
extern void gameUiResetMenuState(void);
extern void mapReload(void);
extern void blankScreen(int);

void loadNextMap(void)
{
    u8 *pos;
    pos = (*gMapEventInterface)->getWarpPos();
    if (lbl_803DCEB8 != -1) {
        lbl_803DCDE0 -= 1;
        if ((s8)lbl_803DCDE0 < 0) {
            if (lbl_803DCEB8 > -1 && (s8)lbl_803DCEBC != 0) {
                (*(void (***)(int, int))gScreenTransitionInterface)[3](3, 1);
            }
            lbl_803DCEB8 = -1;
            Pause_SetDisabled(0);
        }
    }
    if ((s8)lbl_803DCEBD != 0) {
        if ((*(int (***)(void))gScreenTransitionInterface)[5]() != 0 || (s8)lbl_803DCEBC == 0) {
            (*(void (***)(void))gCloudActionInterface)[5]();
            (*(void (***)(void))gCloudActionInterface)[2]();
            (*(void (***)(void))gSky2Interface)[2]();
            (*(void (***)(void))gSHthorntailAnimationInterface)[2]();
            (*(void (***)(void))gNewCloudsInterface)[2]();
            gameUiResetMenuState();
            lbl_803DCEBD = 0;
            *(f32 *)(pos + 0) = *(f32 *)(lbl_803879A0 + 0);
            *(f32 *)(pos + 4) = *(f32 *)(lbl_803879A0 + 4);
            *(f32 *)(pos + 8) = *(f32 *)(lbl_803879A0 + 8);
            pos[0xd] = (s8)*(s16 *)(lbl_803879A0 + 0xc);
            pos[0xc] = (s8)*(s16 *)(lbl_803879A0 + 0xe);
            mapReload();
            lbl_803DCEB8 = lbl_803DCEBA;
            lbl_803DCEBA = -1;
            lbl_803DCDE0 = 8;
            lbl_803DCA40 = 1;
            blankScreen(1);
        }
    }
}

extern f32 fastFloorf(f32 x);
extern f32 gMapBlockWorldSize;
extern u8 *gMapBlockLayerTables[5];
extern f32 lbl_803DEBB8;
typedef struct WarpVec {
    f32 x;
    f32 y;
    f32 z;
    f32 pad;
} WarpVec;
extern WarpVec lbl_80386648[];

int objShouldUnload(u8 *obj)
{
    u8 *def;
    u8 *p;
    u8 *src;
    u8 **tp;
    int m;
    int keep;
    int bx;
    int bz;
    int k;
    int flags;
    int idx2;
    s8 found;
    f32 x;
    f32 y;
    f32 z;
    f32 dist;

    def = *(u8 **)(obj + 0x4c);
    if (def == NULL) {
        return 0;
    }
    if (def[4] & 2) {
        return 0;
    }
    m = (*gMapEventInterface)->getMode((s8)obj[0xac]);
    if (m == -1) {
        keep = 0;
    } else if (m == 0) {
        keep = 1;
    } else if (m < 9) {
        if ((def[3] >> (m - 1)) & 1) {
            keep = 0;
        } else {
            keep = 1;
        }
    } else if ((def[5] >> (0x10 - m)) & 1) {
        keep = 0;
    } else {
        keep = 1;
    }
    if (keep == 0) {
        return 1;
    }
    flags = def[4];
    if (flags & 1) {
        return 0;
    }
    if (flags & 0x10) {
        return !(*gMapEventInterface)->getAnimEvent((s8)obj[0xac], def[6]);
    }
    if (*(void **)(obj + 0xc0) != NULL && *(s16 *)(obj + 0xb4) < 0) {
        return 0;
    }
    if (*(void **)(obj + 0xc4) != NULL) {
        return 0;
    }
    if (*(void **)(obj + 0x30) == NULL) {
        bx = (int)fastFloorf((*(f32 *)(obj + 0xc) - playerMapOffsetX) / gMapBlockWorldSize);
        bz = (int)fastFloorf((*(f32 *)(obj + 0x14) - playerMapOffsetZ) / gMapBlockWorldSize);
        if (bx < 0 || bz < 0 || bx >= 0x10 || bz >= 0x10) {
            return 1;
        }
        found = 0;
        bx = bx + (bz << 4);
        tp = gMapBlockLayerTables;
        for (k = 0; k < 5; k++) {
            if (*(s8 *)(*tp + bx) >= 0) {
                found = 1;
            }
            tp++;
        }
        if (found == 0) {
            return 1;
        }
    }
    flags = def[4];
    if (flags & 0x20) {
        return 0;
    }
    if ((flags & 4) && (p = (u8 *)Obj_GetPlayerObject()) != NULL && *(void **)(obj + 0x30) == NULL) {
        x = *(f32 *)(p + 0x18);
        y = *(f32 *)(p + 0x1c);
        z = *(f32 *)(p + 0x20);
    } else {
        src = *(u8 **)(obj + 0x30);
        if (src != NULL) {
            idx2 = (s8)src[0x35] + 1;
        } else {
            idx2 = 0;
        }
        x = lbl_80386648[idx2].x;
        y = lbl_80386648[idx2].y;
        z = lbl_80386648[idx2].z;
    }
    dist = *(f32 *)(obj + 0x3c);
    if (*(void **)(obj + 0x30) != NULL) {
        x -= *(f32 *)(obj + 0xc);
        y -= *(f32 *)(obj + 0x10);
        z -= *(f32 *)(obj + 0x14);
    } else {
        x -= *(f32 *)(obj + 0x18);
        y -= *(f32 *)(obj + 0x1c);
        z -= *(f32 *)(obj + 0x20);
    }
    if (x * x + y * y + z * z < (lbl_803DEBB8 + dist) * (lbl_803DEBB8 + dist)) {
        return 0;
    }
    return 1;
}

typedef struct GXColor8 {
    u8 r;
    u8 g;
    u8 b;
    u8 a;
} GXColor8;
extern void PSMTXScale(f32 *m, f32 x, f32 y, f32 z);
extern void GXSetChanAmbColor(int chan, GXColor8 c);
extern void GXSetChanMatColor(int chan, GXColor8 c);
extern void GXSetTexCopyDst(int w, int h, int fmt, int mip);
extern void modelTextureFn_80089970(int n);
extern void textureFn_8004ff20(void *asset, f32 *mtx, void *out, int p4);
extern void GXCopyTex(void *dst, int clear);
extern void GXPreLoadEntireTexture(void *obj, u32 *region);
extern void modelLightFn_8001ec94(int model, int *lights, int max, int *count, int p5);
extern void lightGetColor(int idx, u8 *r, u8 *g, u8 *b);
extern void Camera_ApplyFullViewport(void);
extern u32 lbl_803DB600;
extern int lbl_803DB604;
extern u8 lbl_803DCDA4;
extern f32 lbl_803DEB80;
extern f32 lbl_803DEB84;
extern f32 lbl_803DEB88;
int textureFn_80052bb4(int model, f32 *params);

void gxTextureFn_80052efc(void)
{
    f32 mtx[12];
    int lights[8];
    GXColor8 c;
    GXColor8 c2;
    int count;
    int i;
    int sel;
    int k;
    int n;
    int model;
    u8 *e;
    u8 *tex;
    int *lp;

    gxFn_80052dc0();
    PSMTXScale(mtx, lbl_803DEB74, lbl_803DEB80, lbl_803DEB74);
    mtx[3] = lbl_803DEB74;
    mtx[7] = lbl_803DEB74;
    GXLoadTexMtxImm(mtx, 0x1e, 1);
    GXSetChanAmbColor(4, *(GXColor8 *)&lbl_803DB600);
    GXSetChanAmbColor(5, *(GXColor8 *)&lbl_803DB600);
    GXSetTexCopyDst(0x20, 0x20, 6, 0);
    modelTextureFn_80089970(2);
    i = 0;
    e = lbl_8037E000;
    for (; i < 6; i++) {
        tex = *(u8 **)e;
        if (*(u16 *)(tex + 0xe) != 0 && e[0x1b] == 1 && lbl_803DCDA4 == e[0x1a]) {
            c.r = (e[0xc] * e[0x18]) >> 8;
            c.g = 0;
            c.b = (e[0xe] * e[0x19]) >> 8;
            c.a = 0xff;
            GXSetChanMatColor(4, c);
            GXSetChanMatColor(5, c);
            textureFn_80052bb4(*(int *)(e + 4), (f32 *)(e + 0x10));
            resetLotsOfRenderVars();
            textureFn_8004ff20(lbl_803DCDA0, mtx, &c2, 0);
            textureFn_800528bc();
            lightFn_80052974((f32)(i * 0x20), LastCommandWasRead_803DEB60);
            GXCopyTex(*(u8 **)e + 0x60, 0);
            tex = *(u8 **)e;
            if (tex[0x48] != 0) {
                GXPreLoadEntireTexture(tex + 0x20, *(u32 **)(tex + 0x40));
            }
        }
        e += 0x1c;
    }
    resetLotsOfRenderVars();
    textureFn_800524ec(&lbl_803DB604);
    textureFn_800528bc();
    GXSetChanMatColor(0, *(GXColor8 *)&lbl_803DB604);
    sel = 5;
    e = lbl_8037E000 + 0x8c;
    for (k = 5; k >= 0; k--) {
        if (*(u16 *)(*(u8 **)e + 0xe) != 0 && e[0x1b] == 0 && lbl_803DCDA4 == e[0x1a]) {
            sel = k;
            break;
        }
        e -= 0x1c;
    }
    i = 0;
    e = lbl_8037E000;
    for (; i < 6; i++) {
        if (*(u16 *)(*(u8 **)e + 0xe) != 0 && e[0x1b] == 0 && lbl_803DCDA4 == e[0x1a]) {
            model = *(int *)(e + 4);
            modelTextureFn_80089970(2 - (i - 3));
            modelLightFn_8001ec94(model, lights, 8, &count, 4);
            modelLightChannels_reset(1);
            modelLightChannel_configure(0, 0, 0);
            lp = lights;
            for (n = 0; n < count; n++) {
                modelLightStruct_loadChannelLight(0, (void *)*lp, model);
                lp++;
            }
            modelLightChannels_applyGXControls();
            lightGetColor(0, &c2.r, &c2.g, &c2.b);
            GXSetChanAmbColor(0, c2);
            lightFn_80052974((f32)(i * 0x20), LastCommandWasRead_803DEB60);
            GXCopyTex(*(u8 **)e + 0x60, (i == sel) ? 1 : 0);
            tex = *(u8 **)e;
            if (tex[0x48] != 0) {
                GXPreLoadEntireTexture(tex + 0x20, *(u32 **)(tex + 0x40));
            }
        }
        e += 0x1c;
    }
    GXSetViewport(LastCommandWasRead_803DEB60, LastCommandWasRead_803DEB60, lbl_803DEB84,
                  lbl_803DEB88, LastCommandWasRead_803DEB60, LastReadIssued_803DEB58.hi);
    GXSetScissor(0, 0, 0x280, 0x1e0);
    GXSetDispCopySrc(0, 0, 0x280, 0x1e0);
    GXSetDispCopyDst(0x280, 0x1e0);
    GXSetTexCopySrc(0, 0, 0x280, 0x1e0);
    Camera_ApplyFullViewport();
    lbl_803DCDA4 = 0;
}

extern void texFlagFn_80023cbc(int flag);
extern void OSReport(char *fmt, ...);
extern void printHeapStats(int mode);
extern int testAndSet_onlyUseHeaps1and2(int val);
extern int mmGetRegionForPtr(void *p);
extern int getHeapItemSize(void *p);
extern int mmSetFreeDelay(int delay);
extern void DCStoreRange(void *p, u32 len);
extern void defragMemory(int mode);
extern char lbl_8030D058[];

void texRestructRefs(int mode)
{
    char *strs;
    u8 *ent;
    u8 *tex;
    u8 *na;
    int done;
    int pass;
    int i;
    int off;
    u32 size;
    int d;

    strs = lbl_8030D058;
    done = 0;
    pass = 0;
    texFlagFn_80023cbc(2);
    OSReport(strs + 0x1164);
    printHeapStats(1);
    OSReport(strs + 0x1194);
    testAndSet_onlyUseHeaps1and2(1);
    i = 0;
    off = 0;
    for (; i < lbl_803DCDBC; i++) {
        ent = (u8 *)lbl_803DCDC4 + off;
        tex = *(u8 **)(ent + 4);
        if (tex != NULL && *(u8 *)(ent + 8) != 0 && tex[0x49] == 0 && *(int *)(ent + 0xc) != -1 &&
            mmGetRegionForPtr(tex) == 0 && *(void **)tex == NULL) {
            size = *(u32 *)((u8 *)lbl_803DCDC4 + off + 0xc);
            na = (u8 *)mmAlloc(size, 0xa0a0a0a0, 0);
            if (na == NULL) {
                OSReport(strs + 0x11b4, tex, getHeapItemSize(tex));
            } else {
                OSReport(strs + 0x11f4, tex, na, getHeapItemSize(tex));
                done = 0;
                memcpy(na, tex, size);
                DCStoreRange(na, size);
                textureFn_80053d58(na);
                d = mmSetFreeDelay(0);
                mm_free(*(void **)((u8 *)lbl_803DCDC4 + off + 4));
                mmSetFreeDelay(d);
                *(u8 **)((u8 *)lbl_803DCDC4 + off + 4) = na;
            }
        }
        off += 0x10;
    }
    testAndSet_onlyUseHeaps1and2(-1);
    OSReport(strs + 0x1238);
    printHeapStats(1);
    defragMemory(2);
    while (done == 0 && pass < 4) {
        done = 1;
        i = 0;
        off = 0;
        for (; i < lbl_803DCDBC; i++) {
            ent = (u8 *)lbl_803DCDC4 + off;
            tex = *(u8 **)(ent + 4);
            if (tex != NULL && *(u8 *)(ent + 8) != 0 && tex[0x49] == 0 && *(int *)(ent + 0xc) != -1) {
                if (mmGetRegionForPtr(tex) == 0) {
                    if (*(void **)tex == NULL) {
                        size = *(u32 *)((u8 *)lbl_803DCDC4 + off + 0xc);
                        na = (u8 *)mmAlloc(size, 0xa0a0a0a0, 0);
                        if (na == NULL) {
                            OSReport(strs + 0x125c, tex, getHeapItemSize(tex));
                        } else if (mmGetRegionForPtr(na) != 0) {
                            OSReport(strs + 0x129c, tex, na, getHeapItemSize(tex));
                            d = mmSetFreeDelay(0);
                            mm_free(na);
                            mmSetFreeDelay(d);
                        } else if (na < tex) {
                            OSReport(strs + 0x12d8, tex, na, getHeapItemSize(tex));
                            d = mmSetFreeDelay(0);
                            mm_free(na);
                            mmSetFreeDelay(d);
                        } else if (na != NULL) {
                            OSReport(strs + 0x1320, tex, na, getHeapItemSize(tex));
                            done = 0;
                            memcpy(na, tex, size);
                            DCStoreRange(na, size);
                            textureFn_80053d58(na);
                            d = mmSetFreeDelay(0);
                            mm_free(*(void **)((u8 *)lbl_803DCDC4 + off + 4));
                            mmSetFreeDelay(d);
                            *(u8 **)((u8 *)lbl_803DCDC4 + off + 4) = na;
                        }
                    }
                } else if (mode == 0) {
                    if (mmGetRegionForPtr(tex) == 1 || mmGetRegionForPtr(tex) == 2) {
                        if (*(void **)tex == NULL && getHeapItemSize(tex) >= 0x3000) {
                            size = *(u32 *)((u8 *)lbl_803DCDC4 + off + 0xc);
                            na = (u8 *)mmAlloc(size, 0xa0a0a0a0, 0);
                            if (na == NULL) {
                                OSReport(strs + 0x125c, tex, getHeapItemSize(tex));
                            } else if (mmGetRegionForPtr(na) != 0) {
                                OSReport(strs + 0x1368, tex, na, getHeapItemSize(tex));
                                d = mmSetFreeDelay(0);
                                mm_free(na);
                                mmSetFreeDelay(d);
                            } else if (na != NULL) {
                                OSReport(strs + 0x13c8, tex, na, getHeapItemSize(tex));
                                done = 0;
                                memcpy(na, tex, size);
                                DCStoreRange(na, size);
                                textureFn_80053d58(na);
                                d = mmSetFreeDelay(0);
                                mm_free(*(void **)((u8 *)lbl_803DCDC4 + off + 4));
                                mmSetFreeDelay(d);
                                *(u8 **)((u8 *)lbl_803DCDC4 + off + 4) = na;
                            }
                        }
                    }
                }
            }
            off += 0x10;
        }
        printHeapStats(1);
        pass++;
    }
    OSReport(strs + 0x1420, pass);
    texFlagFn_80023cbc(0);
}

extern char sDebugIntLineFormat;
extern u8 lbl_803DCDAC;
extern u32 lbl_803DB608;
extern int OSDisableInterrupts(void);
extern void OSRestoreInterrupts(int level);
extern void tex0GetFrame(int word, int id, int *sizeOut, int *frameOut, int mip, void *hdr, int mode);
extern void tex1GetFrame(int word, int id, int *sizeOut, int *frameOut, int mip, void *hdr, int mode);
extern void texPreGetMipmap(int word, int id, int *sizeOut, int *frameOut, int mip, void *hdr, int mode);

void *textureLoad(int texId, u8 flag)
{
    int orig;
    int *p;
    u8 *walk;
    u8 *tex;
    u8 *first;
    u8 *prev;
    u8 *buf;
    int restore;
    int disabled;
    int n;
    int m;
    int bank;
    int file;
    int id16;
    int word;
    int mips;
    int k;
    int sz2;
    u32 size;
    int packed;
    int base19;
    int slot;
    int e18;
    int sizeOut;
    int frameOut;

    restore = 1;
    disabled = 0;
    if (texId < 0) {
        n = -texId;
        if ((n & 0x8000) && (n & 0x7fff) == 0x82e) {
            OSReport(&sDebugIntLineFormat);
        }
    }
    n = 0;
    walk = (u8 *)lbl_803DCDC4;
    for (; n < lbl_803DCDBC; n++) {
        if (*(int *)walk == texId) {
            tex = *(u8 **)((u8 *)lbl_803DCDC4 + (n << 4) + 4);
            *(u16 *)(tex + 0xe) += 1;
            if (flag != 0 && *(u8 *)((u8 *)lbl_803DCDC4 + (n << 4) + 8) != 0) {
                return (void *)(n + 1);
            }
            return tex;
        }
        walk += 0x10;
    }
    if (getLoadedFileFlags(0) != 0) {
        restore = OSDisableInterrupts();
        disabled = 1;
    }
    orig = texId;
    if (texId < 0) {
        texId = -texId;
    } else {
        if (texId >= 0xbb8) {
            m = lbl_803DCDC0[texId];
            if (m != 0) {
                texId = m + 1;
                goto resolved;
            }
        }
        texId = lbl_803DCDC0[texId];
    }
resolved:
    id16 = texId & 0xffff;
    if (texId & 0x8000) {
        bank = 1;
        file = 0x20;
        id16 = id16 & 0x7fff;
    } else if (orig >= 0xbb8) {
        bank = 2;
        file = 0x4f;
    } else {
        bank = 0;
        file = 0x23;
    }
    if (id16 >= lbl_8037E0A8[bank] || id16 < 0) {
        id16 = 0;
    }
    n = 0;
    p = getCurrentDataFile(0x24);
    lbl_8037E0B4[0] = p;
    if (lbl_8037E0B4 != NULL) {
        while (*p != -1) {
            p++;
            n++;
        }
        lbl_8037E0A8[0] = n - 1;
    }
    n = 0;
    p = getCurrentDataFile(0x21);
    lbl_8037E0B4[1] = p;
    if (lbl_8037E0B4 != NULL) {
        while (*p != -1) {
            p++;
            n++;
        }
        lbl_8037E0A8[1] = n - 1;
    }
    word = lbl_8037E0B4[bank][id16];
    mips = (word >> 24) & 0x3f;
    if (mips == 1) {
        if (bank == 0) {
            tex0GetFrame(word, id16, &sizeOut, &frameOut, mips, 0, 0);
        } else if (bank == 2) {
            texPreGetMipmap(word, id16, &sizeOut, &frameOut, mips, 0, 0);
        } else {
            tex1GetFrame(word, id16, &sizeOut, &frameOut, mips, 0, 0);
        }
        *(int *)lbl_803DCDB8 = 0;
        *((int *)lbl_803DCDB8 + 1) = sizeOut;
        if (frameOut == -1) {
            *((int *)lbl_803DCDB8 + 2) = sizeOut;
        } else {
            *((int *)lbl_803DCDB8 + 2) = frameOut;
        }
    } else if (bank == 0) {
        tex0GetFrame(word, id16, &sizeOut, &frameOut, mips, lbl_803DCDB8, 2);
    } else if (bank == 2) {
        texPreGetMipmap(word, id16, &sizeOut, &frameOut, mips, lbl_803DCDB8, 2);
    } else {
        tex1GetFrame(word, id16, &sizeOut, &frameOut, mips, lbl_803DCDB8, 2);
    }
    first = NULL;
    prev = NULL;
    k = 0;
    packed = mips << 8;
    base19 = (word & 0xffffff) << 1;
    for (; k < mips; k++) {
        if (mips > 1) {
            if (bank == 0) {
                tex0GetFrame(word, id16, &sizeOut, &frameOut, k, lbl_803DCDB8, 1);
            } else if (bank == 2) {
                texPreGetMipmap(word, id16, &sizeOut, &frameOut, k, lbl_803DCDB8, 1);
            } else {
                tex1GetFrame(word, id16, &sizeOut, &frameOut, k, lbl_803DCDB8, 1);
            }
        }
        size = sizeOut;
        if (frameOut == -1) {
            sz2 = sizeOut;
        } else {
            sz2 = frameOut;
            texFlagFn_80023cbc(1);
            buf = (u8 *)mmAlloc(size, lbl_803DB608, 0);
            texFlagFn_80023cbc(0);
            if (buf == NULL) {
                lbl_803DCDAC = 1;
                if (getLoadedFileFlags(0) != 0) {
                    if (disabled == 1) {
                        OSRestoreInterrupts(restore);
                    }
                } else if (disabled == 1) {
                    OSRestoreInterrupts(restore);
                }
                if (flag != 0) {
                    return (void *)1;
                }
                return *(void **)((u8 *)lbl_803DCDC4 + 4);
            }
        }
        if (frameOut != -1 && buf == NULL) {
            if (k != 0) {
                *(u16 *)(first + 0x10) = packed;
                k = mips;
                continue;
            }
            lbl_803DCDAC = 1;
            if (getLoadedFileFlags(0) != 0) {
                if (disabled == 1) {
                    OSRestoreInterrupts(restore);
                }
            } else if (disabled == 1) {
                OSRestoreInterrupts(restore);
            }
            if (flag != 0) {
                return (void *)1;
            }
            return *(void **)((u8 *)lbl_803DCDC4 + 4);
        }
        if (frameOut == -1) {
            buf = (u8 *)loadAndDecompressDataFile(file, 0, base19 + ((int *)lbl_803DCDB8)[k], sz2, 0,
                                                  id16, 0);
            buf[0x49] = 1;
            if (flag != 0) {
                flag = 0;
            }
            *(u16 *)(buf + 0xe) = 1;
        } else {
            loadAndDecompressDataFile(file, (int)buf, base19 + ((int *)lbl_803DCDB8)[k], sz2, 0, id16,
                                      0);
        }
        if (frameOut != -1) {
            DCStoreRange(buf, size);
        }
        *(void **)buf = NULL;
        if (prev != NULL) {
            *(u8 **)prev = buf;
        }
        prev = buf;
        if (k == 0) {
            first = buf;
            *(u16 *)(buf + 0x10) = packed;
        } else {
            *(u16 *)(buf + 0x10) = 1;
        }
    }
    walk = first;
    *(u32 *)(first + 0x4c) = size;
    slot = 0;
    p = (int *)lbl_803DCDC4;
    for (; slot < lbl_803DCDBC; slot++) {
        if (*p == -1) {
            break;
        }
        p += 4;
    }
    if (slot == lbl_803DCDBC) {
        lbl_803DCDBC += 1;
    }
    e18 = slot << 4;
    *(int *)((u8 *)lbl_803DCDC4 + e18) = orig;
    *(u8 **)((u8 *)lbl_803DCDC4 + e18 + 4) = first;
    *(u8 *)((u8 *)lbl_803DCDC4 + e18 + 8) = flag;
    *(u32 *)((u8 *)lbl_803DCDC4 + e18 + 0xc) =
        getHeapItemSize(*(void **)((u8 *)lbl_803DCDC4 + e18 + 4));
    if (lbl_803DCDBC > 0x2bc) {
        if (getLoadedFileFlags(0) != 0) {
            if (disabled == 1) {
                OSRestoreInterrupts(restore);
            }
        } else if (disabled == 1) {
            OSRestoreInterrupts(restore);
        }
        if (flag != 0) {
            return (void *)1;
        }
        return *(void **)((u8 *)lbl_803DCDC4 + 4);
    }
    while (walk != NULL) {
        textureFn_80053d58(walk);
        walk = *(u8 **)walk;
    }
    if (getLoadedFileFlags(0) != 0) {
        if (disabled == 1) {
            OSRestoreInterrupts(restore);
        }
    } else if (disabled == 1) {
        OSRestoreInterrupts(restore);
    }
    if (flag != 0) {
        return (void *)(slot + 1);
    }
    return first;
}

#pragma scheduling reset
#pragma peephole reset
