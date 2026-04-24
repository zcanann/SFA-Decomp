// Function: FUN_8019dcf8
// Entry: 8019dcf8
// Size: 312 bytes

void FUN_8019dcf8(int param_1)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  uVar1 = FUN_80020078((int)*(short *)(iVar3 + 2));
  if (uVar1 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
  }
  if (*(int *)(param_1 + 0xf4) != 0) {
    (**(code **)(*DAT_803dd6d4 + 0x54))(param_1,0xfa);
    (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar3 + 4),param_1,3);
    *(undefined4 *)(param_1 + 0xf4) = 0;
  }
  if (((*(byte *)(param_1 + 0xaf) & 1) != 0) &&
     (iVar2 = (**(code **)(*DAT_803dd6e8 + 0x20))((int)*(short *)(iVar3 + 2)), iVar2 != 0)) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    FUN_800201ac((int)*(short *)(iVar3 + 2),0);
    FUN_800201ac(0x973,0);
    (**(code **)(*DAT_803dd6d4 + 0x48))((int)*(char *)(iVar3 + 4),param_1,0xffffffff);
  }
  return;
}

