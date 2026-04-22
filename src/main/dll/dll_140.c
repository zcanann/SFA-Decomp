#include "ghidra_import.h"
#include "main/dll/dll_140.h"

extern uint FUN_80014b50();
extern uint FUN_80020078();
extern undefined4 FUN_800201ac();
extern int FUN_8002ba84();
extern int FUN_8002bac4();
extern undefined4 FUN_8002cc9c();
extern undefined4 FUN_80035f9c();
extern undefined4 FUN_80035ff8();
extern undefined4 FUN_80036018();
extern int FUN_8003811c();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_80179864();
extern undefined4 FUN_80179f40();
extern uint countLeadingZeros();

extern undefined4* DAT_803dd728;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803e4334;
extern f32 FLOAT_803e433c;
extern f32 FLOAT_803e4340;
extern f32 FLOAT_803e4344;

/*
 * --INFO--
 *
 * Function: FUN_80179b84
 * EN v1.0 Address: 0x80179B84
 * EN v1.0 Size: 160b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80179b84(double param_1,double param_2,double param_3,int param_4)
{
  int iVar1;
  
  iVar1 = *(int *)(param_4 + 0xb8);
  *(undefined *)(iVar1 + 0x274) = 3;
  *(float *)(iVar1 + 0x26c) = FLOAT_803e4334;
  *(float *)(param_4 + 0x24) = (float)param_1;
  *(float *)(param_4 + 0x28) = (float)param_2;
  *(float *)(param_4 + 0x2c) = (float)param_3;
  FUN_80036018(param_4);
  FUN_80035f9c(param_4);
  *(undefined *)(iVar1 + 0x25b) = 1;
  *(undefined4 *)(iVar1 + 0x2b0) = *(undefined4 *)(param_4 + 0xc);
  *(undefined4 *)(iVar1 + 0x2b4) = *(undefined4 *)(param_4 + 0x10);
  *(undefined4 *)(iVar1 + 0x2b8) = *(undefined4 *)(param_4 + 0x14);
  (**(code **)(*DAT_803dd728 + 0x20))(param_4,iVar1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80179c24
 * EN v1.0 Address: 0x80179C24
 * EN v1.0 Size: 40b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80179c24(void)
{
  FUN_800201ac(0x3f8,1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80179c4c
 * EN v1.0 Address: 0x80179C4C
 * EN v1.0 Size: 60b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80179c4c(int param_1)
{
  char in_r8;
  
  if ((*(int *)(param_1 + 0xf8) == 0) || (in_r8 == -1)) {
    FUN_8003b9ec(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_80179c88
 * EN v1.0 Address: 0x80179C88
 * EN v1.0 Size: 696b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_80179c88(double param_1,double param_2,double param_3,undefined8 param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,ushort *param_9,
                 undefined4 param_10,undefined4 param_11,undefined4 param_12,undefined4 param_13,
                 undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
  char cVar1;
  byte bVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined4 uVar6;
  undefined uVar7;
  int iVar8;
  double dVar9;
  double dVar10;
  
  iVar8 = *(int *)(param_9 + 0x5c);
  *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) | 8;
  *(undefined *)(iVar8 + 0x275) = 0;
  iVar4 = FUN_8002bac4();
  iVar5 = FUN_8002ba84();
  if ((((iVar4 == 0) || ((*(ushort *)(iVar4 + 0xb0) & 0x1000) != 0)) || (iVar5 == 0)) ||
     ((uVar3 = countLeadingZeros((uint)*(ushort *)(iVar5 + 0xb0)), (uVar3 >> 5 & 0x1000) != 0 ||
      (uVar3 = FUN_80020078(0xd00), uVar3 != 0)))) {
    FUN_8002cc9c(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
    return;
  }
  cVar1 = *(char *)(iVar8 + 0x274);
  if (((cVar1 == '\x03') || (cVar1 == '\x02')) || (cVar1 == '\x01')) {
    *(float *)(iVar8 + 0x26c) = *(float *)(iVar8 + 0x26c) + FLOAT_803dc074;
    param_1 = (double)*(float *)(iVar8 + 0x26c);
    if ((double)FLOAT_803e4340 <= param_1) {
      *(float *)(iVar8 + 0x26c) = FLOAT_803e4334;
      *(undefined *)(iVar8 + 0x274) = 5;
    }
  }
  bVar2 = *(byte *)(iVar8 + 0x274);
  if (bVar2 == 3) {
    uVar6 = FUN_80179f40(param_9);
    *(char *)(iVar8 + 0x274) = (char)uVar6;
    return;
  }
  if (bVar2 < 3) {
    if (bVar2 == 1) {
      FUN_80179f40(param_9);
    }
    else if (bVar2 == 0) {
      FUN_80179864(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,(uint)param_9,
                   iVar8,param_11,param_12,param_13,param_14,param_15,param_16);
      goto LAB_80179e98;
    }
    *(byte *)((int)param_9 + 0xaf) = *(byte *)((int)param_9 + 0xaf) & 0xf7;
    uVar7 = 0;
    uVar3 = FUN_80014b50(0);
    if ((((uVar3 & 0x100) == 0) && (*(int *)(param_9 + 0x7c) == 0)) &&
       (iVar4 = FUN_8003811c((int)param_9), iVar4 != 0)) {
      FUN_80035ff8((int)param_9);
      uVar7 = 1;
    }
    *(undefined *)(iVar8 + 0x2c9) = uVar7;
    if (*(char *)(iVar8 + 0x2c9) != '\0') {
      *(undefined *)(iVar8 + 0x2c8) = 0;
      *(undefined *)(iVar8 + 0x2c9) = 0;
      *(undefined *)(iVar8 + 0x274) = 0;
    }
  }
  else if (bVar2 == 5) {
    *(float *)(iVar8 + 0x26c) = *(float *)(iVar8 + 0x26c) + FLOAT_803dc074;
    dVar10 = (double)*(float *)(iVar8 + 0x26c);
    dVar9 = (double)FLOAT_803e433c;
    if (dVar9 <= dVar10) {
      FUN_8002cc9c(dVar9,dVar10,param_3,param_4,param_5,param_6,param_7,param_8,(int)param_9);
      return;
    }
    *(char *)(param_9 + 0x1b) =
         -1 - (char)(int)((double)(float)((double)FLOAT_803e4344 * dVar10) / dVar9);
  }
LAB_80179e98:
  if (*(char *)(*(int *)(param_9 + 0x5c) + 0x25b) == '\x01') {
    (**(code **)(*DAT_803dd728 + 0x10))((double)FLOAT_803dc074,param_9,iVar8);
    (**(code **)(*DAT_803dd728 + 0x14))(param_9,iVar8);
    (**(code **)(*DAT_803dd728 + 0x18))((double)FLOAT_803dc074,param_9,iVar8);
  }
  else {
    (**(code **)(*DAT_803dd728 + 0x20))(param_9);
  }
  return;
}
