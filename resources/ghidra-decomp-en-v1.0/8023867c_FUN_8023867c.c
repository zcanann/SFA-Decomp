// Function: FUN_8023867c
// Entry: 8023867c
// Size: 148 bytes

void FUN_8023867c(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5)

{
  int iVar1;
  int iVar2;
  undefined8 uVar3;
  
  uVar3 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar3 >> 0x20);
  iVar2 = *(int *)(*(int *)(iVar1 + 0xb8) + 4);
  if (((iVar2 != 0) && (*(char *)(iVar2 + 0x2f8) != '\0')) && (*(char *)(iVar2 + 0x4c) != '\0')) {
    FUN_800604b4();
  }
  if (*(int *)(iVar1 + 0xc4) == 0) {
    FUN_8003b8f4((double)FLOAT_803e7418,iVar1,(int)uVar3,param_3,param_4,param_5);
  }
  FUN_80286128();
  return;
}

