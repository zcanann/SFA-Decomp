// Function: FUN_80094ba0
// Entry: 80094ba0
// Size: 112 bytes

void FUN_80094ba0(void)

{
  int iVar1;
  
  if ((DAT_8039ab28 != 0) && (iVar1 = FUN_800394ac(DAT_8039ab28,0,0), iVar1 != 0)) {
    *(ushort *)(iVar1 + 8) = *(short *)(iVar1 + 8) - (ushort)DAT_8039ab40;
    if (*(short *)(iVar1 + 8) < -10000) {
      *(short *)(iVar1 + 8) = *(short *)(iVar1 + 8) + 10000;
    }
  }
  return;
}

