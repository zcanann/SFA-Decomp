// Function: FUN_801a1960
// Entry: 801a1960
// Size: 256 bytes

void FUN_801a1960(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_802860d4();
  iVar2 = (int)((ulonglong)uVar4 >> 0x20);
  iVar3 = *(int *)(iVar2 + 0xb8);
  if ((*(char *)(iVar3 + 0x17) == '\0') && ((*(byte *)(iVar3 + 0x4a) >> 5 & 1) == 0)) {
    if (*(char *)(iVar3 + 0x15) != '\0') {
      *(undefined2 *)(iVar2 + 4) = 0;
      *(undefined2 *)(iVar2 + 2) = 0;
    }
    iVar1 = (**(code **)(*DAT_803dcac0 + 0xc))(iVar2,(int)(char)param_6);
    if ((iVar1 != 0) || ((char)param_6 == -1)) {
      FUN_8003b8f4((double)FLOAT_803e42dc,iVar2,(int)uVar4,param_3,param_4,param_5);
    }
    iVar2 = *(int *)(iVar3 + 0x10);
    if (iVar2 != 0) {
      (**(code **)(**(int **)(iVar2 + 0x68) + 0x10))
                (iVar2,(int)uVar4,param_3,param_4,param_5,param_6);
    }
  }
  FUN_80286120();
  return;
}

