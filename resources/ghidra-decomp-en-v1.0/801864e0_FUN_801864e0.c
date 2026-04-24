// Function: FUN_801864e0
// Entry: 801864e0
// Size: 364 bytes

void FUN_801864e0(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  uVar1 = FUN_8002b9ec();
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  iVar2 = FUN_802964f0(uVar1,3);
  if (iVar2 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
  }
  if (*(char *)(iVar4 + 0xc) < '\0') {
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
    iVar2 = FUN_80296ba0(uVar1);
    if (iVar2 == 0x5bd) {
      FUN_80296b78(uVar1,0xffffffff);
    }
    FUN_800200e8((int)*(short *)(iVar3 + 0x1e),1);
  }
  else {
    iVar2 = FUN_80296ba0(uVar1);
    if ((iVar2 == 0x5bd) && (*(int *)(iVar4 + 8) == -1)) {
      *(undefined4 *)(iVar4 + 8) = 0;
    }
  }
  if ((*(int *)(iVar4 + 8) != -1) &&
     (iVar2 = *(int *)(iVar4 + 8) - (uint)DAT_803db410, *(int *)(iVar4 + 8) = iVar2, iVar2 < 0)) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
    iVar2 = FUN_8002b9ac();
    if (iVar2 != 0) {
      FUN_80138ef8();
    }
    *(byte *)(iVar4 + 0xc) = *(byte *)(iVar4 + 0xc) & 0x7f | 0x80;
    *(undefined4 *)(iVar4 + 8) = 0xffffffff;
  }
  return;
}

