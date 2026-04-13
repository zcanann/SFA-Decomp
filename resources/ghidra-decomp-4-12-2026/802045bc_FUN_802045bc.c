// Function: FUN_802045bc
// Entry: 802045bc
// Size: 148 bytes

void FUN_802045bc(int param_1)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  uVar1 = FUN_80020078((int)*(short *)(iVar2 + 0x1e));
  if (uVar1 == 0) {
    uVar1 = FUN_80020078((int)*(short *)(iVar2 + 0x20));
    if (uVar1 != 0) {
      (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar2 + 0x19),param_1,0xffffffff);
    }
  }
  else {
    FUN_8002cf80(param_1);
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  }
  return;
}

