// Function: FUN_80228f80
// Entry: 80228f80
// Size: 200 bytes

void FUN_80228f80(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,char param_6)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_802860d8();
  iVar1 = (int)((ulonglong)uVar4 >> 0x20);
  piVar2 = *(int **)(iVar1 + 0xb8);
  if (param_6 == '\0') {
    *(byte *)((int)piVar2 + 7) = *(byte *)((int)piVar2 + 7) & 0xfe;
  }
  else {
    *(byte *)((int)piVar2 + 7) = *(byte *)((int)piVar2 + 7) | 1;
  }
  iVar3 = *piVar2;
  if (((iVar3 != 0) && (*(char *)(iVar3 + 0x2f8) != '\0')) && (*(char *)(iVar3 + 0x4c) != '\0')) {
    FUN_800604b4();
  }
  if (param_6 != '\0') {
    FUN_8003b8f4((double)FLOAT_803e6e2c,iVar1,(int)uVar4,param_3,param_4,param_5);
  }
  FUN_80286124();
  return;
}

