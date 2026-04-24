#include "ghidra_import.h"
#include "main/dll/FRONT/dll_3B.h"

extern undefined4 FUN_80009a28();
extern undefined4 FUN_80009a94();
extern undefined4 FUN_8000b6b4();
extern undefined4 FUN_800146a8();
extern int FUN_8001495c();
extern undefined4 FUN_800199a8();
extern undefined8 FUN_8005cf74();
extern undefined4 FUN_8005d024();
extern undefined4 FUN_8007dadc();
extern undefined4 FUN_80088a84();
extern undefined4 FUN_801164c0();
extern undefined4 FUN_80117e10();
extern undefined4 FUN_801307e8();
extern undefined4 FUN_80135ba8();
extern undefined4 FUN_80136c2c();

extern undefined4 DAT_8031ae28;
extern undefined4 DAT_8031ae64;
extern undefined4 DAT_8031ae7a;
extern undefined4 DAT_8031aeb6;
extern undefined4 DAT_8031aef2;
extern undefined4 DAT_8031af2e;
extern undefined4 DAT_803dc084;
extern undefined4* DAT_803dd6cc;
extern undefined4* DAT_803dd720;
extern undefined4 DAT_803de110;
extern undefined4 DAT_803de288;
extern undefined4 DAT_803de28c;
extern undefined4 DAT_803de28e;
extern undefined4 DAT_803de291;
extern undefined4 DAT_803de298;
extern undefined4 DAT_803de2c8;
extern undefined4 DAT_803de2cc;
extern undefined4 DAT_803de2cd;
extern undefined4 DAT_803de2ce;
extern undefined4 DAT_803de2cf;
extern undefined4 DAT_803de2d0;
extern undefined4 DAT_803de2d1;
extern undefined4 DAT_803de2d2;
extern undefined4 DAT_803de300;
extern undefined4 DAT_803de318;
extern f32 FLOAT_803e2990;
extern f32 FLOAT_803e2998;

/*
 * --INFO--
 *
 * Function: FUN_8011722c
 * EN v1.0 Address: TODO
 * EN v1.0 Size: TODO
 * EN v1.1 Address: 0x8011722C
 * EN v1.1 Size: 904b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_8011722c(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)
{
  int iVar1;
  undefined8 uVar2;
  double dVar3;
  
  DAT_803de298 = (*(byte *)(DAT_803de110 + 0x21) & 0x80) == 0;
  if (0xfd < DAT_803dc084) {
    param_1 = FUN_8007dadc('\0');
  }
  FUN_800199a8(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0x15);
  DAT_803de2d0 = 0;
  DAT_803de2d1 = 0;
  iVar1 = FUN_8001495c();
  if (iVar1 != 3) {
    (**(code **)(*DAT_803dd720 + 4))(&DAT_8031ae64,4,0,0,0,0,0x14,200,0xff,0xff,0xff,0xff);
  }
  else {
    (**(code **)(*DAT_803dd720 + 4))(&DAT_8031ae28,1,0,0,0,0,0x14,200,0xff,0xff,0xff,0xff);
  }
  DAT_803de2d2 = iVar1 != 3;
  (**(code **)(*DAT_803dd720 + 0x18))(DAT_803de28c);
  FUN_80136c2c('\0');
  iVar1 = FUN_8001495c();
  if ((((iVar1 == 0xd) || (iVar1 = FUN_8001495c(), iVar1 == 7)) ||
      (iVar1 = FUN_8001495c(), iVar1 == 6)) || (iVar1 = FUN_8001495c(), iVar1 == 5)) {
    (**(code **)(*DAT_803dd6cc + 0xc))(0x23,5);
  }
  else {
    FUN_80009a94(0xf);
    (**(code **)(*DAT_803dd6cc + 0xc))(0x3c,1);
  }
  FUN_801307e8();
  if (DAT_803de28c == '\0') {
    DAT_8031ae7a = DAT_8031ae7a & 0xbfff;
  }
  else {
    DAT_8031ae7a = DAT_8031ae7a | 0x4000;
  }
  if (DAT_803de28c == '\x01') {
    DAT_8031aeb6 = DAT_8031aeb6 & 0xbfff;
  }
  else {
    DAT_8031aeb6 = DAT_8031aeb6 | 0x4000;
  }
  if (DAT_803de28c == '\x02') {
    DAT_8031aef2 = DAT_8031aef2 & 0xbfff;
  }
  else {
    DAT_8031aef2 = DAT_8031aef2 | 0x4000;
  }
  if (DAT_803de28c == '\x03') {
    DAT_8031af2e = DAT_8031af2e & 0xbfff;
  }
  else {
    DAT_8031af2e = DAT_8031af2e | 0x4000;
  }
  uVar2 = (**(code **)(*DAT_803dd720 + 0x2c))(&DAT_8031ae64);
  DAT_803de291 = 0;
  DAT_803de2cd = 0;
  DAT_803de2cc = 1;
  DAT_803de2c8 = 0x3c;
  DAT_803de300 = 0;
  if ((DAT_803de298 == '\0') || ((DAT_803de288 != 0 && (DAT_803de288 != 4)))) {
    dVar3 = (double)FLOAT_803e2998;
    FUN_80135ba8((double)FLOAT_803e2990,dVar3);
    DAT_803de2cf = 0;
    FUN_80117e10(0,1);
  }
  else {
    FUN_801164c0(uVar2,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
    dVar3 = (double)FLOAT_803e2998;
    FUN_80135ba8((double)FLOAT_803e2990,dVar3);
    DAT_803de2cf = 1;
    FUN_80117e10(0,0);
    FUN_80009a28(0,10,1,0,0);
    DAT_803de28e = 0;
  }
  FUN_8005d024(0);
  uVar2 = FUN_8005cf74(0);
  DAT_803de2ce = 0;
  FUN_80088a84(uVar2,dVar3,param_3,param_4,param_5,param_6,param_7,param_8,0);
  FUN_800146a8();
  FUN_8000b6b4('\0');
  DAT_803de318 = 0;
  return;
}
