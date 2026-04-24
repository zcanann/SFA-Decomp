// Function: FUN_80146604
// Entry: 80146604
// Size: 480 bytes

void FUN_80146604(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8,
                 int param_9,int param_10)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  
  iVar2 = *(int *)(param_9 + 0xb8);
  FUN_8004b710((uint *)(iVar2 + 0x538));
  FUN_8004b710((uint *)(iVar2 + 0x568));
  FUN_8004b710((uint *)(iVar2 + 0x598));
  FUN_8004b710((uint *)(iVar2 + 0x5c8));
  FUN_8004b710((uint *)(iVar2 + 0x5f8));
  FUN_8004b710((uint *)(iVar2 + 0x628));
  FUN_8004b710((uint *)(iVar2 + 0x658));
  FUN_8004b710((uint *)(iVar2 + 0x688));
  FUN_8004b710((uint *)(iVar2 + 0x6b8));
  FUN_8003709c(param_9,1);
  (**(code **)(*DAT_803dd6f8 + 0x14))(param_9);
  if ((param_10 == 0) && ((*(uint *)(iVar2 + 0x54) & 0x800) != 0)) {
    *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) & 0xfffff7ff;
    *(uint *)(iVar2 + 0x54) = *(uint *)(iVar2 + 0x54) | 0x1000;
    iVar4 = 0;
    iVar3 = iVar2;
    do {
      FUN_801784f8(*(int *)(iVar3 + 0x700));
      iVar3 = iVar3 + 4;
      iVar4 = iVar4 + 1;
    } while (iVar4 < 7);
    FUN_8000dbb0();
    iVar3 = *(int *)(param_9 + 0xb8);
    if (((*(byte *)(iVar3 + 0x58) >> 6 & 1) == 0) &&
       (((0x2f < *(short *)(param_9 + 0xa0) || (*(short *)(param_9 + 0xa0) < 0x29)) &&
        (bVar1 = FUN_8000b598(param_9,0x10), !bVar1)))) {
      FUN_800394f0(param_9,iVar3 + 0x3a8,0x29d,0,0xffffffff,0);
    }
  }
  uVar5 = FUN_800dd8c4();
  uVar5 = FUN_80138d68(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar2,
                       (int *)(iVar2 + 0x7a8));
  uVar5 = FUN_80138d68(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar2,
                       (int *)(iVar2 + 0x7b0));
  uVar5 = FUN_80138d68(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9,iVar2,
                       (int *)(iVar2 + 0x7b8));
  if (*(int *)(iVar2 + 0x7cc) != 0) {
    uVar5 = FUN_80037da8(param_9,*(int *)(iVar2 + 0x7cc));
    uVar5 = FUN_8002cc9c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                         *(int *)(iVar2 + 0x7cc));
  }
  if ((*(char *)(iVar2 + 0x58) < '\0') && (DAT_803de6c8 != 0)) {
    FUN_8002cc9c(uVar5,param_2,param_3,param_4,param_5,param_6,param_7,param_8,DAT_803de6c8);
    DAT_803de6c8 = 0;
  }
  return;
}

