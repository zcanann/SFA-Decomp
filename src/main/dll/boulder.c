#include "ghidra_import.h"
#include "main/dll/boulder.h"

extern undefined4 FUN_80006824();
extern undefined4 FUN_80017a0c();
extern void* FUN_80017aa4();
extern int FUN_80017ae4();
extern uint FUN_80017ae8();
extern undefined4 ObjLink_DetachChild();
extern undefined4 ObjLink_AttachChild();
extern uint FUN_80286840();
extern undefined4 FUN_8028688c();

extern undefined4 DAT_803dc070;
extern undefined4* DAT_803dd708;
extern f32 lbl_803E6B30;
extern f32 lbl_803E6B34;
extern f32 lbl_803E6B38;

/*
 * --INFO--
 *
 * Function: FUN_801f4ecc
 * EN v1.0 Address: 0x801F4ECC
 * EN v1.0 Size: 976b
 * EN v1.1 Address: 0x801F4EF8
 * EN v1.1 Size: 652b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801f4ecc(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 undefined4 param_9,undefined4 param_10,ObjAnimUpdateState *animUpdate,undefined4 param_12,
                 undefined4 param_13,undefined *param_14,int param_15,undefined4 param_16)
{
  uint uVar1;
  uint uVar2;
  undefined2 *puVar3;
  int iVar4;
  int iVar5;
  float *pfVar6;
  double dVar7;
  undefined auStack_28 [40];
  
  uVar2 = FUN_80286840();
  pfVar6 = *(float **)(uVar2 + 0xb8);
  if (*(byte *)((int)pfVar6 + 5) == 0) {
    dVar7 = (double)FUN_80017a0c(uVar2,0);
  }
  else {
    uVar1 = (uint)*(byte *)((int)pfVar6 + 5) + (uint)DAT_803dc070;
    if (0xff < uVar1) {
      uVar1 = 0xff;
    }
    *(char *)((int)pfVar6 + 5) = (char)uVar1;
    dVar7 = (double)FUN_80017a0c(uVar2,(char)uVar1);
  }
  for (iVar5 = 0; iVar5 < (int)(uint)animUpdate->eventCount; iVar5 = iVar5 + 1) {
    switch(animUpdate->eventIds[iVar5]) {
    case 1:
      *(undefined *)(pfVar6 + 1) = 1;
      break;
    case 2:
      *(undefined *)(pfVar6 + 1) = 2;
      param_14 = auStack_28;
      param_15 = *DAT_803dd708;
      (**(code **)(param_15 + 8))(uVar2,0x556,0,2,0xffffffff);
      FUN_80006824(uVar2,0x7b);
      dVar7 = (double)FUN_80006824(uVar2,0x7c);
      *pfVar6 = lbl_803E6B30;
      break;
    case 3:
      *(undefined *)(pfVar6 + 1) = 3;
      param_14 = (undefined *)0x0;
      param_15 = *DAT_803dd708;
      (**(code **)(param_15 + 8))(uVar2,0x556,0,2,0xffffffff);
      FUN_80006824(uVar2,0x7b);
      dVar7 = (double)FUN_80006824(uVar2,0x7c);
      *pfVar6 = lbl_803E6B34;
      break;
    case 4:
      *(undefined *)(pfVar6 + 1) = 0;
      break;
    case 5:
      if ((*(int *)(uVar2 + 200) == 0) && (uVar1 = FUN_80017ae8(), (uVar1 & 0xff) != 0)) {
        puVar3 = FUN_80017aa4(0x24,0x1b8);
        *(undefined4 *)(puVar3 + 4) = *(undefined4 *)(uVar2 + 0xc);
        *(undefined4 *)(puVar3 + 6) = *(undefined4 *)(uVar2 + 0x10);
        *(undefined4 *)(puVar3 + 8) = *(undefined4 *)(uVar2 + 0x14);
        *(undefined *)(puVar3 + 2) = 0x20;
        *(undefined *)((int)puVar3 + 5) = 4;
        *(undefined *)((int)puVar3 + 7) = 0xff;
        iVar4 = FUN_80017ae4(dVar7,param_2,param_3,param_4,param_5,param_6,param_7,param_8,puVar3,5,
                             0xff,0xffffffff,(uint *)0x0,param_14,param_15,param_16);
        ObjLink_AttachChild(uVar2,iVar4,0);
        dVar7 = (double)*(float *)(*(int *)(uVar2 + 200) + 8);
        *(float *)(*(int *)(uVar2 + 200) + 8) = (float)(dVar7 * (double)lbl_803E6B38);
      }
      break;
    case 6:
      if (*(int *)(uVar2 + 200) != 0) {
        dVar7 = (double)ObjLink_DetachChild(uVar2,*(int *)(uVar2 + 200));
      }
      break;
    case 7:
      *(byte *)(*(int *)(uVar2 + 0x50) + 0x5f) = *(byte *)(*(int *)(uVar2 + 0x50) + 0x5f) | 0x10;
      *(undefined *)((int)pfVar6 + 5) = 1;
      break;
    case 8:
      *(byte *)(*(int *)(uVar2 + 0x50) + 0x5f) = *(byte *)(*(int *)(uVar2 + 0x50) + 0x5f) & 0xef;
      dVar7 = (double)FUN_80017a0c(uVar2,0);
      *(undefined *)((int)pfVar6 + 5) = 0;
    }
    animUpdate->eventIds[iVar5] = 0;
  }
  FUN_8028688c();
  return;
}
