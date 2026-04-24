// Function: FUN_80094e2c
// Entry: 80094e2c
// Size: 112 bytes

void FUN_80094e2c(void)

{
  int iVar1;
  
  if ((DAT_8039b788 != 0) && (iVar1 = FUN_800395a4(DAT_8039b788,0), iVar1 != 0)) {
    *(ushort *)(iVar1 + 8) = *(short *)(iVar1 + 8) - (ushort)DAT_8039b7a0;
    if (*(short *)(iVar1 + 8) < -10000) {
      *(short *)(iVar1 + 8) = *(short *)(iVar1 + 8) + 10000;
    }
  }
  return;
}

