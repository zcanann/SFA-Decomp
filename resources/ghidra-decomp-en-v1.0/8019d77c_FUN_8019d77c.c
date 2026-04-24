// Function: FUN_8019d77c
// Entry: 8019d77c
// Size: 312 bytes

void FUN_8019d77c(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 2));
  if (iVar1 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
  }
  else {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
  }
  if (*(int *)(param_1 + 0xf4) != 0) {
    (**(code **)(*DAT_803dca54 + 0x54))(param_1,0xfa);
    (**(code **)(*DAT_803dca54 + 0x48))((int)*(char *)(iVar2 + 4),param_1,3);
    *(undefined4 *)(param_1 + 0xf4) = 0;
  }
  if (((*(byte *)(param_1 + 0xaf) & 1) != 0) &&
     (iVar1 = (**(code **)(*DAT_803dca68 + 0x20))((int)*(short *)(iVar2 + 2)), iVar1 != 0)) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
    FUN_800200e8((int)*(short *)(iVar2 + 2),0);
    FUN_800200e8(0x973,0);
    (**(code **)(*DAT_803dca54 + 0x48))((int)*(char *)(iVar2 + 4),param_1,0xffffffff);
  }
  return;
}

