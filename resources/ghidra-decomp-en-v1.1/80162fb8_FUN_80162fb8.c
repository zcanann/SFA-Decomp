// Function: FUN_80162fb8
// Entry: 80162fb8
// Size: 252 bytes

void FUN_80162fb8(int param_1)

{
  char in_r8;
  int iVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  iVar1 = *(int *)(iVar2 + 0x40c);
  if ((in_r8 != '\0') && (*(int *)(param_1 + 0xf4) == 0)) {
    FUN_8003b9ec(param_1);
    if (FLOAT_803e3b50 < *(float *)(iVar1 + 0x50)) {
      (**(code **)(*DAT_803dd734 + 0xc))(param_1,0x52a,0,100,0);
    }
    if ((*(ushort *)(iVar2 + 0x400) & 0x60) != 0) {
      FUN_8009a010((double)FLOAT_803e3b54,(double)*(float *)(iVar2 + 1000),param_1,3,(int *)0x0);
    }
    if ((*(ushort *)(iVar2 + 0x400) & 0x100) != 0) {
      FUN_8009a010((double)FLOAT_803e3b54,(double)*(float *)(iVar2 + 1000),param_1,4,(int *)0x0);
      *(ushort *)(iVar2 + 0x400) = *(ushort *)(iVar2 + 0x400) & 0xfeff;
    }
  }
  return;
}

