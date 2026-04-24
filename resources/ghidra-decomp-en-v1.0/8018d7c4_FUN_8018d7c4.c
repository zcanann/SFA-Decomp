// Function: FUN_8018d7c4
// Entry: 8018d7c4
// Size: 276 bytes

void FUN_8018d7c4(undefined4 param_1,undefined4 param_2,int param_3)

{
  short sVar1;
  int iVar2;
  int iVar3;
  
  iVar2 = FUN_802860dc();
  sVar1 = *(short *)(iVar2 + 0x46);
  if (((sVar1 != 0xae) && (0xad < sVar1)) && (sVar1 == 0x2b7)) {
    iVar3 = FUN_8001ffb4((int)*(short *)(*(int *)(iVar2 + 0xb8) + 0x3a));
    if (iVar3 != 0) {
      *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 4;
    }
    for (iVar3 = 0; iVar3 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar3 = iVar3 + 1) {
      if (*(char *)(param_3 + iVar3 + 0x81) == '\x01') {
        (**(code **)(*DAT_803dca88 + 8))(iVar2,0x44,0,2,0xffffffff,0);
      }
      *(undefined *)(param_3 + iVar3 + 0x81) = 0;
    }
  }
  FUN_80286128(0);
  return;
}

