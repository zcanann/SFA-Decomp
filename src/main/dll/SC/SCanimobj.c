#include "ghidra_import.h"
#include "main/dll/SC/SCanimobj.h"

extern undefined8 FUN_8000bb38();
extern undefined8 FUN_8000cf74();
extern undefined4 FUN_8000d0e0();
extern undefined4 FUN_80014964();
extern int FUN_8001496c();
extern undefined8 FUN_80014974();
extern undefined4 FUN_8001b7b4();
extern uint FUN_80020078();
extern undefined8 FUN_800201ac();
extern int FUN_8002b660();
extern int FUN_8002bac4();
extern undefined4 FUN_8002cc9c();
extern undefined8 FUN_8002fb40();
extern int FUN_80036868();
extern undefined8 FUN_80037da8();
extern undefined4 FUN_80038524();
extern undefined4 FUN_800394f0();
extern undefined4 FUN_8003b9ec();
extern undefined4 FUN_80043604();
extern undefined8 FUN_80043938();
extern undefined4 FUN_8004832c();
extern undefined8 FUN_80055464();
extern uint FUN_8008038c();
extern undefined4 FUN_80080474();
extern int FUN_800805cc();
extern undefined4 FUN_800805ec();
extern undefined4 FUN_8009a468();
extern undefined4 FUN_80130124();
extern undefined4 FUN_801d6f04();
extern int FUN_801d7348();
extern undefined4 FUN_801d7388();
extern undefined8 FUN_80286838();
extern int FUN_80286840();
extern undefined4 FUN_80286884();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_8029628c();
extern uint FUN_80296bc4();
extern undefined4 FUN_802b5830();

extern undefined4* DAT_803dd72c;
extern f32 FLOAT_803dc074;
extern f32 FLOAT_803dda58;
extern f32 FLOAT_803dda5c;

/*
 * --INFO--
 *
 * Function: FUN_801d76a4
 * EN v1.0 Address: 0x801D76A4
 * EN v1.0 Size: 36b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d76a4(void)
{
  FUN_80014974(1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d76c8
 * EN v1.0 Address: 0x801D76C8
 * EN v1.0 Size: 928b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d76c8(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801d7a68
 * EN v1.0 Address: 0x801D7A68
 * EN v1.0 Size: 76b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d7a68(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  int iVar1;
  int *piVar2;
  undefined8 uVar3;
  
  piVar2 = *(int **)(param_9 + 0xb8);
  iVar1 = *piVar2;
  if ((iVar1 != 0) && (param_10 == 0)) {
    uVar3 = FUN_80037da8(param_9,iVar1);
    FUN_8002cc9c(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar2);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d7ab4
 * EN v1.0 Address: 0x801D7AB4
 * EN v1.0 Size: 216b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d7ab4(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined8 uVar6;
  float local_38;
  float local_34;
  float local_30 [12];
  
  uVar6 = FUN_80286838();
  iVar1 = (int)((ulonglong)uVar6 >> 0x20);
  iVar5 = *(int *)(iVar1 + 0xb8);
  if (param_6 != '\0') {
    FUN_8003b9ec(iVar1);
    iVar2 = FUN_8002bac4();
    if ((iVar2 != 0) && (uVar3 = FUN_80296bc4(iVar2), uVar3 != 0)) {
      iVar4 = FUN_8002b660(iVar2);
      *(ushort *)(iVar4 + 0x18) = *(ushort *)(iVar4 + 0x18) & 0xfff7;
      FUN_80038524(iVar1,(uint)*(byte *)(iVar5 + 8),&local_38,&local_34,local_30,0);
      FUN_8029628c((double)local_38,(double)local_34,(double)local_30[0],iVar2);
      FUN_802b5830(iVar2,(int)uVar6,param_3,param_4,param_5,-1);
    }
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d7b8c
 * EN v1.0 Address: 0x801D7B8C
 * EN v1.0 Size: 216b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d7b8c(uint param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined auStack_28 [12];
  float local_1c;
  undefined4 uStack_18;
  float local_14 [3];
  
  iVar3 = *(int *)(param_1 + 0xb8);
  iVar1 = FUN_80036868(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0,&local_1c,&uStack_18,
                       local_14);
  if (iVar1 != 0) {
    local_1c = local_1c + FLOAT_803dda58;
    local_14[0] = local_14[0] + FLOAT_803dda5c;
    FUN_8009a468(param_1,auStack_28,1,(int *)0x0);
    uVar2 = FUN_8008038c(3);
    if (uVar2 == 0) {
      FUN_8000bb38(param_1,700);
    }
    else {
      FUN_8000bb38(param_1,700);
    }
    FUN_800394f0(param_1,iVar3 + 0x14,0xab,-0x500,0xffffffff,0);
  }
  return;
}
