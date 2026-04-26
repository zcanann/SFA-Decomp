#include "ghidra_import.h"
#include "main/dll/TREX/TREX_Lazerwall.h"

extern undefined8 FUN_80006728();
extern undefined4 FUN_800067c0();
extern uint FUN_80017690();
extern undefined4 FUN_80017698();
extern uint FUN_80017760();
extern int FUN_80017a98();
extern undefined8 ObjGroup_RemoveObject();
extern undefined4 ObjGroup_AddObject();
extern undefined4 FUN_8003b818();
extern undefined8 FUN_80080f14();
extern undefined4 FUN_80080f28();
extern undefined4 FUN_80294c30();
extern int FUN_80294cf8();

extern undefined DAT_80328c10;
extern undefined4 DAT_80328c16;
extern undefined4 DAT_80328c18;
extern undefined4* DAT_803dd6d4;
extern undefined4* DAT_803dd72c;

/*
 * --INFO--
 *
 * Function: FUN_801e67bc
 * EN v1.0 Address: 0x801E67BC
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x801E68E0
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801e67bc(undefined4 param_1,int param_2)
{
  uint uVar1;
  undefined4 uVar2;
  
  FUN_80017a98();
  uVar2 = 0;
  if (((int)*(short *)(&DAT_80328c18 + param_2 * 0xc) != 0xffffffff) &&
     (uVar1 = FUN_80017690((int)*(short *)(&DAT_80328c18 + param_2 * 0xc)), uVar1 != 0)) {
    uVar2 = 1;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_801e6818
 * EN v1.0 Address: 0x801E6818
 * EN v1.0 Size: 92b
 * EN v1.1 Address: 0x801E6948
 * EN v1.1 Size: 104b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
undefined4 FUN_801e6818(undefined4 param_1,int param_2)
{
  uint uVar1;
  undefined4 uVar2;
  
  FUN_80017a98();
  uVar2 = 0;
  if (((int)*(short *)(&DAT_80328c16 + param_2 * 0xc) == 0xffffffff) ||
     (uVar1 = FUN_80017690((int)*(short *)(&DAT_80328c16 + param_2 * 0xc)), uVar1 != 0)) {
    uVar2 = 1;
  }
  return uVar2;
}

/*
 * --INFO--
 *
 * Function: FUN_801e6874
 * EN v1.0 Address: 0x801E6874
 * EN v1.0 Size: 84b
 * EN v1.1 Address: 0x801E69B0
 * EN v1.1 Size: 116b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e6874(int param_1,int param_2,undefined4 param_3)
{
  **(undefined **)(param_1 + 0xb8) = (char)param_2;
  if (param_2 != 0) {
    (**(code **)(*DAT_803dd6d4 + 0x48))(param_3,param_1,0xffffffff);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e68c8
 * EN v1.0 Address: 0x801E68C8
 * EN v1.0 Size: 88b
 * EN v1.1 Address: 0x801E6A24
 * EN v1.1 Size: 88b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e68c8(int param_1)
{
  FUN_80080f28(7,'\0');
  ObjGroup_RemoveObject(param_1,9);
  FUN_800067c0((int *)0x90,0);
  FUN_80017698(0xefe,0);
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e6920
 * EN v1.0 Address: 0x801E6920
 * EN v1.0 Size: 40b
 * EN v1.1 Address: 0x801E6A7C
 * EN v1.1 Size: 52b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e6920(int param_1)
{
  char in_r8;
  
  if (in_r8 != '\0') {
    FUN_8003b818(param_1);
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e6948
 * EN v1.0 Address: 0x801E6948
 * EN v1.0 Size: 676b
 * EN v1.1 Address: 0x801E6AB0
 * EN v1.1 Size: 372b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e6948(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9)
{
  int iVar1;
  int iVar2;
  uint uVar3;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  undefined8 uVar4;
  
  iVar1 = FUN_80017a98();
  iVar2 = FUN_80294cf8(iVar1);
  if ((iVar2 != 0) && (uVar3 = FUN_80017690(0x18b), uVar3 == 0)) {
    param_1 = FUN_80294c30(iVar1,0);
  }
  if (*(int *)(param_9 + 0xf4) == 0) {
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),0,1);
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),5,1);
    (**(code **)(*DAT_803dd72c + 0x50))((int)*(char *)(param_9 + 0xac),6,1);
    FUN_80017698(0x617,1);
    param_1 = FUN_80080f28(7,'\x01');
    *(undefined4 *)(param_9 + 0xf4) = 1;
  }
  uVar3 = FUN_80017690(0xd21);
  if ((uVar3 == 0) || (*(int *)(param_9 + 0xf8) != 0)) {
    uVar3 = FUN_80017690(0xd21);
    if ((uVar3 == 0) && (*(int *)(param_9 + 0xf8) != 0)) {
      *(undefined4 *)(param_9 + 0xf8) = 0;
    }
  }
  else {
    uVar4 = FUN_80080f14(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,0);
    uVar4 = FUN_80006728(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,
                         param_9,0x1c8,0,in_r7,in_r8,in_r9,in_r10);
    FUN_80006728(uVar4,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,param_9,0x1cb
                 ,0,in_r7,in_r8,in_r9,in_r10);
    *(undefined4 *)(param_9 + 0xf8) = 1;
  }
  return;
}

/*
 * --INFO--
 *
 * Function: FUN_801e6bec
 * EN v1.0 Address: 0x801E6BEC
 * EN v1.0 Size: 156b
 * EN v1.1 Address: 0x801E6C24
 * EN v1.1 Size: 160b
 * JP Address: TODO
 * JP Size: TODO
 * PAL Address: TODO
 * PAL Size: TODO
 */
void FUN_801e6bec(int param_1)
{
  uint uVar1;
  undefined *puVar2;
  int iVar3;
  
  *(undefined *)(*(int *)(param_1 + 0xb8) + 1) = 0xff;
  ObjGroup_AddObject(param_1,9);
  iVar3 = 0;
  puVar2 = &DAT_80328c10;
  do {
    uVar1 = FUN_80017760(0,2);
    puVar2[5] = puVar2[uVar1 + 1];
    puVar2 = puVar2 + 0xc;
    iVar3 = iVar3 + 1;
  } while (iVar3 < 0x3c);
  FUN_800067c0((int *)0x90,1);
  *(undefined4 *)(param_1 + 0xf8) = 0;
  FUN_80017698(0xefe,1);
  return;
}
