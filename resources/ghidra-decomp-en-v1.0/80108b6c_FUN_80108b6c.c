// Function: FUN_80108b6c
// Entry: 80108b6c
// Size: 192 bytes

void FUN_80108b6c(int param_1)

{
  int iVar1;
  int iVar2;
  int local_18 [5];
  
  *(ushort *)(*(int *)(param_1 + 0xa4) + 6) = *(ushort *)(*(int *)(param_1 + 0xa4) + 6) & 0xbfff;
  FUN_800550a4(0);
  iVar2 = *(int *)(param_1 + 0xa4);
  if (iVar2 != 0) {
    *(undefined *)(iVar2 + 0x36) = 0xff;
    iVar1 = FUN_8002b9ec();
    if (iVar1 == iVar2) {
      FUN_802966d4(iVar2,local_18);
      if (local_18[0] != 0) {
        *(undefined *)(local_18[0] + 0x36) = 0xff;
        if (*(char *)(local_18[0] + 0x36) == '\x01') {
          *(undefined *)(local_18[0] + 0x36) = 0;
        }
      }
    }
  }
  FUN_8000b824(0,0x3d8);
  FUN_80023800(DAT_803dd548);
  DAT_803dd548 = 0;
  FUN_80096994((double)FLOAT_803e17e0);
  return;
}

