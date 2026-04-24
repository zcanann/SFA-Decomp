// Function: FUN_80203f84
// Entry: 80203f84
// Size: 148 bytes

void FUN_80203f84(int param_1)

{
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0x4c);
  iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0x1e));
  if (iVar1 == 0) {
    iVar1 = FUN_8001ffb4((int)*(short *)(iVar2 + 0x20));
    if (iVar1 != 0) {
      (**(code **)(*DAT_803dca54 + 0x48))((int)*(char *)(iVar2 + 0x19),param_1,0xffffffff);
    }
  }
  else {
    FUN_8002ce88(param_1);
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  }
  return;
}

