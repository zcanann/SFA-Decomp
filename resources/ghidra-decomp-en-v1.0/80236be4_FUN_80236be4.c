// Function: FUN_80236be4
// Entry: 80236be4
// Size: 184 bytes

void FUN_80236be4(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  int iVar4;
  undefined8 uVar5;
  
  uVar5 = FUN_802860d8();
  iVar1 = (int)((ulonglong)uVar5 >> 0x20);
  piVar2 = *(int **)(iVar1 + 0xb8);
  iVar4 = *(int *)(iVar1 + 0x4c);
  if (param_6 != '\0') {
    *(byte *)((int)piVar2 + 0x22) = *(byte *)((int)piVar2 + 0x22) | 1;
    iVar3 = *piVar2;
    if (((iVar3 != 0) && (*(char *)(iVar3 + 0x2f8) != '\0')) && (*(char *)(iVar3 + 0x4c) != '\0')) {
      FUN_800604b4();
    }
    if ((*(byte *)(iVar4 + 0x29) & 8) != 0) {
      FUN_8003b8f4((double)FLOAT_803e738c,iVar1,(int)uVar5,param_3,param_4,param_5);
    }
  }
  FUN_80286124();
  return;
}

