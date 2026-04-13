// Function: FUN_8024173c
// Entry: 8024173c
// Size: 284 bytes

void FUN_8024173c(int *param_1)

{
  uint uVar1;
  int iVar2;
  longlong lVar3;
  
  FUN_80243e74();
  if (*param_1 == 0) {
    FUN_80243e9c();
  }
  else {
    iVar2 = param_1[5];
    if (iVar2 == 0) {
      iRam803dea8c = param_1[4];
    }
    else {
      *(int *)(iVar2 + 0x10) = param_1[4];
    }
    if (param_1[4] == 0) {
      DAT_803dea88 = iVar2;
      if (iVar2 != 0) {
        lVar3 = FUN_802473d4();
        uVar1 = *(int *)(iVar2 + 8) -
                ((uint)(*(uint *)(iVar2 + 0xc) < (uint)lVar3) + (int)((ulonglong)lVar3 >> 0x20)) ^
                0x80000000;
        if (uVar1 < 0x80000000) {
          FUN_80294da0();
        }
        else if (uVar1 < (*(uint *)(iVar2 + 0xc) - (uint)lVar3 < 0x80000000) + 0x80000000) {
          FUN_80294da0();
        }
        else {
          FUN_80294da0();
        }
      }
    }
    else {
      *(int *)(param_1[4] + 0x14) = iVar2;
    }
    *param_1 = 0;
    FUN_80243e9c();
  }
  return;
}

