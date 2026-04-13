// Function: FUN_801f0804
// Entry: 801f0804
// Size: 96 bytes

void FUN_801f0804(int param_1,int param_2)

{
  if (*(short *)(param_1 + 0x46) != 0x188) {
    if ((*(char *)(*(int *)(param_1 + 0xb8) + 0xc) != '\0') && (param_2 == 0)) {
      *(undefined *)(*(int *)(param_1 + 0xb8) + 0xc) = 0;
    }
    if (DAT_803de8f4 != (undefined *)0x0) {
      FUN_80013e4c(DAT_803de8f4);
      DAT_803de8f4 = (undefined *)0x0;
    }
  }
  return;
}

