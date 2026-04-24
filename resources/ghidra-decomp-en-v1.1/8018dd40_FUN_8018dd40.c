// Function: FUN_8018dd40
// Entry: 8018dd40
// Size: 276 bytes

void FUN_8018dd40(undefined4 param_1,undefined4 param_2,int param_3)

{
  short sVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  
  iVar2 = FUN_80286840();
  sVar1 = *(short *)(iVar2 + 0x46);
  if (((sVar1 != 0xae) && (0xad < sVar1)) && (sVar1 == 0x2b7)) {
    uVar3 = FUN_80020078((int)*(short *)(*(int *)(iVar2 + 0xb8) + 0x3a));
    if (uVar3 != 0) {
      *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 4;
    }
    for (iVar4 = 0; iVar4 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar4 = iVar4 + 1) {
      if (*(char *)(param_3 + iVar4 + 0x81) == '\x01') {
        (**(code **)(*DAT_803dd708 + 8))(iVar2,0x44,0,2,0xffffffff,0);
      }
      *(undefined *)(param_3 + iVar4 + 0x81) = 0;
    }
  }
  FUN_8028688c();
  return;
}

