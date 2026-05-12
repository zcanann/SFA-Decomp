#include "ghidra_import.h"
#include "main/dll/SC/SCanimobj.h"

extern undefined8 FUN_80006824();
extern undefined8 FUN_80006868();
extern undefined4 FUN_80006898();
extern undefined4 FUN_80006b74();
extern int FUN_80006b7c();
extern undefined8 FUN_80006b84();
extern undefined4 FUN_800174e8();
extern int FUN_80017a54();
extern int FUN_80017a98();
extern undefined4 FUN_80017ac8();
extern undefined8 FUN_8002fc3c();
extern int ObjHits_GetPriorityHitWithPosition();
extern undefined8 ObjLink_DetachChild();
extern undefined4 ObjPath_GetPointWorldPosition();
extern undefined4 FUN_80039468();
extern undefined4 FUN_8003b818();
extern undefined4 FUN_80042b9c();
extern undefined8 FUN_80043030();
extern undefined4 FUN_80044404();
extern undefined8 FUN_80053c98();
extern uint FUN_8007f66c();
extern undefined4 FUN_8007f7a4();
extern int FUN_8007f924();
extern undefined4 FUN_8007f944();
extern undefined4 FUN_80081120();
extern undefined4 FUN_801302a4();
extern undefined4 FUN_801d6d98();
extern int FUN_801d7198();
extern undefined4 FUN_801d71dc();
extern undefined8 FUN_80286838();
extern int FUN_80286840();
extern undefined4 FUN_80286884();
extern undefined4 FUN_8028688c();
extern undefined4 FUN_80294be0();
extern uint FUN_80294cb8();
extern undefined4 FUN_802950c8();

extern undefined4* DAT_803dd72c;
extern f32 lbl_803DC074;
extern f32 lbl_803DDA58;
extern f32 lbl_803DDA5C;

/*
 * --INFO--
 *
 * Function: FUN_801d7674
 * EN v1.0 Address: 0x801D7674
 * EN v1.0 Size: 36b
 * EN v1.1 Address: 0x801D76A4
 * EN v1.1 Size: 36b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d7674(void)
{
  FUN_80006b84(1);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d7698
 * EN v1.0 Address: 0x801D7698
 * EN v1.0 Size: 4b
 * EN v1.1 Address: 0x801D76C8
 * EN v1.1 Size: 928b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d7698(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,int param_11,int param_12,
                 undefined4 param_13,undefined4 param_14,undefined4 param_15,undefined4 param_16)
{
}

/*
 * --INFO--
 *
 * Function: FUN_801d769c
 * EN v1.0 Address: 0x801D769C
 * EN v1.0 Size: 204b
 * EN v1.1 Address: 0x801D7A68
 * EN v1.1 Size: 76b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d769c(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)
{
  int iVar1;
  int *piVar2;
  undefined8 uVar3;
  
  piVar2 = *(int **)(param_9 + 0xb8);
  iVar1 = *piVar2;
  if ((iVar1 != 0) && (param_10 == 0)) {
    uVar3 = ObjLink_DetachChild(param_9,iVar1);
    FUN_80017ac8(uVar3,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar2);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: warpstone_release
 * EN v1.0 Address: 0x801D7BA0
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void warpstone_release(void)
{
}

/*
 * --INFO--
 *
 * Function: warpstone_initialise
 * EN v1.0 Address: 0x801D7BA4
 * EN v1.0 Size: 4b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void warpstone_initialise(void)
{
}

/*
 * --INFO--
 *
 * Function: sh_levelcontrol_getExtraSize
 * EN v1.0 Address: 0x801D7BA8
 * EN v1.0 Size: 8b
 * EN v1.1 Address: TODO
 * EN v1.1 Size: TODO
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
int sh_levelcontrol_getExtraSize(void)
{
  return 0x14;
}

/*
 * --INFO--
 *
 * Function: FUN_801d7768
 * EN v1.0 Address: 0x801D7768
 * EN v1.0 Size: 220b
 * EN v1.1 Address: 0x801D7AB4
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d7768(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
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
    FUN_8003b818(iVar1);
    iVar2 = FUN_80017a98();
    if ((iVar2 != 0) && (uVar3 = FUN_80294cb8(iVar2), uVar3 != 0)) {
      iVar4 = FUN_80017a54(iVar2);
      *(ushort *)(iVar4 + 0x18) = *(ushort *)(iVar4 + 0x18) & 0xfff7;
      ObjPath_GetPointWorldPosition(iVar1,(uint)*(byte *)(iVar5 + 8),&local_38,&local_34,local_30,0);
      FUN_80294be0((double)local_38,(double)local_34,(double)local_30[0],iVar2);
      FUN_802950c8(iVar2,(int)uVar6,param_3,param_4,param_5,-1);
    }
  }
  FUN_80286884();
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801d7844
 * EN v1.0 Address: 0x801D7844
 * EN v1.0 Size: 212b
 * EN v1.1 Address: 0x801D7B8C
 * EN v1.1 Size: 216b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801d7844(uint param_1)
{
  int iVar1;
  uint uVar2;
  int iVar3;
  undefined auStack_28 [12];
  float local_1c;
  undefined4 uStack_18;
  float local_14 [3];
  
  iVar3 = *(int *)(param_1 + 0xb8);
  iVar1 = ObjHits_GetPriorityHitWithPosition(param_1,(undefined4 *)0x0,(int *)0x0,(uint *)0x0,&local_1c,&uStack_18,
                       local_14);
  if (iVar1 != 0) {
    local_1c = local_1c + lbl_803DDA58;
    local_14[0] = local_14[0] + lbl_803DDA5C;
    FUN_80081120(param_1,auStack_28,1,(int *)0x0);
    uVar2 = FUN_8007f66c(3);
    if (uVar2 == 0) {
      FUN_80006824(param_1,700);
    }
    else {
      FUN_80006824(param_1,700);
    }
    FUN_80039468(param_1,iVar3 + 0x14,0xab,-0x500,0xffffffff,0);
  }
  return;
}
