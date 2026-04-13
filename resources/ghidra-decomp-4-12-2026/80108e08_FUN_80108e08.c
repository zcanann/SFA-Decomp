// Function: FUN_80108e08
// Entry: 80108e08
// Size: 192 bytes

void FUN_80108e08(int param_1)

{
  int iVar1;
  int iVar2;
  int local_18 [5];
  
  *(ushort *)(*(int *)(param_1 + 0xa4) + 6) = *(ushort *)(*(int *)(param_1 + 0xa4) + 6) & 0xbfff;
  FUN_80055220(0);
  iVar2 = *(int *)(param_1 + 0xa4);
  if (iVar2 != 0) {
    *(undefined *)(iVar2 + 0x36) = 0xff;
    iVar1 = FUN_8002bac4();
    if (iVar1 == iVar2) {
      FUN_80296e34(iVar2,local_18);
      if (local_18[0] != 0) {
        *(undefined *)(local_18[0] + 0x36) = 0xff;
        if (*(char *)(local_18[0] + 0x36) == '\x01') {
          *(undefined *)(local_18[0] + 0x36) = 0;
        }
      }
    }
  }
  FUN_8000b844(0,0x3d8);
  FUN_800238c4(DAT_803de1c0);
  DAT_803de1c0 = 0;
  FUN_80096c20((double)FLOAT_803e2460);
  return;
}

