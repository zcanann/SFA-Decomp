// Function: FUN_8013049c
// Entry: 8013049c
// Size: 380 bytes

void FUN_8013049c(int param_1)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  
  *(undefined *)(param_1 + 0x1f) = 0xff;
  *(undefined *)(param_1 + 0x20) = 0xff;
  *(undefined *)(param_1 + 0x21) = 0xff;
  *(undefined *)(param_1 + 0x22) = 0xff;
  *(undefined *)(param_1 + 0x23) = 0xff;
  *(undefined *)(param_1 + 0x24) = 0xff;
  *(undefined *)(param_1 + 0x25) = 0xff;
  *(undefined *)(param_1 + 0x26) = 0xff;
  *(undefined *)(param_1 + 0x27) = 0xff;
  *(undefined *)(param_1 + 0x28) = 0xff;
  *(undefined *)(param_1 + 0x29) = 0xff;
  *(undefined *)(param_1 + 0x2a) = 0xff;
  *(undefined *)(param_1 + 0x2b) = 0xff;
  *(undefined *)(param_1 + 0x2c) = 0xff;
  *(undefined *)(param_1 + 0x2d) = 0xff;
  *(undefined *)(param_1 + 0x2e) = 0xff;
  *(undefined *)(param_1 + 0x2f) = 0xff;
  *(undefined *)(param_1 + 0x30) = 0xff;
  *(undefined *)(param_1 + 0x31) = 0xff;
  *(undefined *)(param_1 + 0x32) = 0xff;
  *(undefined *)(param_1 + 0x33) = 0xff;
  *(undefined *)(param_1 + 0x34) = 0xff;
  *(undefined *)(param_1 + 0x35) = 0xff;
  *(undefined *)(param_1 + 0x36) = 0xff;
  *(undefined *)(param_1 + 0x37) = 0xff;
  iVar4 = 1;
  *(undefined *)(param_1 + 0x1f) = 0;
  for (iVar3 = (uint)*(ushort *)(param_1 + 0x14) - ((uint)DAT_8031ce0a + (uint)DAT_8031ce12);
      iVar3 != 0; iVar3 = iVar3 - (uint)(&DAT_8031ce0a)[*(char *)(param_1 + iVar1) * 8]) {
    if (iVar3 < 0x50) {
      if (iVar3 < 0x28) {
        *(undefined *)(param_1 + iVar4 + 0x1f) = 5;
      }
      else {
        uVar2 = FUN_80022264(4,5);
        *(char *)(param_1 + iVar4 + 0x1f) = (char)uVar2;
      }
    }
    else {
      uVar2 = FUN_80022264(2,5);
      *(char *)(param_1 + iVar4 + 0x1f) = (char)uVar2;
    }
    iVar1 = iVar4 + 0x1f;
    iVar4 = iVar4 + 1;
  }
  *(undefined *)(param_1 + iVar4 + 0x1f) = 1;
  if (0x18 < iVar4 + 1) {
    FUN_8007d858();
  }
  return;
}

