// Function: FUN_80026ef4
// Entry: 80026ef4
// Size: 144 bytes

undefined4 FUN_80026ef4(void)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = (int *)FUN_800436e4(0x2a);
  if (piVar1 == (int *)0x0) {
    uVar2 = 0;
  }
  else {
    DAT_803dcb68 = 0;
    for (; *piVar1 != -1; piVar1 = piVar1 + 1) {
      DAT_803dcb68 = DAT_803dcb68 + 1;
    }
    DAT_803dcb68 = DAT_803dcb68 + -1;
    DAT_803dcb4c = FUN_800436e4(0x2f);
    if (DAT_803dcb4c == 0) {
      uVar2 = 0;
    }
    else {
      DAT_803dcb58 = 0;
      uVar2 = 1;
    }
  }
  return uVar2;
}

