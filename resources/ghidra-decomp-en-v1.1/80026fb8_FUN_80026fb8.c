// Function: FUN_80026fb8
// Entry: 80026fb8
// Size: 144 bytes

undefined4 FUN_80026fb8(void)

{
  int *piVar1;
  undefined4 uVar2;
  
  piVar1 = (int *)FUN_80043860(0x2a);
  if (piVar1 == (int *)0x0) {
    uVar2 = 0;
  }
  else {
    DAT_803dd7e8 = 0;
    for (; *piVar1 != -1; piVar1 = piVar1 + 1) {
      DAT_803dd7e8 = DAT_803dd7e8 + 1;
    }
    DAT_803dd7e8 = DAT_803dd7e8 + -1;
    DAT_803dd7cc = FUN_80043860(0x2f);
    if (DAT_803dd7cc == (undefined *)0x0) {
      uVar2 = 0;
    }
    else {
      DAT_803dd7d8 = 0;
      uVar2 = 1;
    }
  }
  return uVar2;
}

