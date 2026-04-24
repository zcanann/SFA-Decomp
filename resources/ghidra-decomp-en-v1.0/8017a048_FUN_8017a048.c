// Function: FUN_8017a048
// Entry: 8017a048
// Size: 124 bytes

undefined4 FUN_8017a048(int param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  iVar2 = 0;
  uVar1 = (uint)*(byte *)(param_3 + 0x8b);
  while( true ) {
    if (uVar1 == 0) {
      return 0;
    }
    if (*(char *)(param_3 + iVar2 + 0x81) == '\x01') break;
    iVar2 = iVar2 + 1;
    uVar1 = uVar1 - 1;
  }
  iVar2 = (int)*(short *)(iVar3 + 0xe);
  if (iVar2 != -1) {
    FUN_800200e8(iVar2,1);
  }
  *(undefined *)(iVar3 + 0x14) = 1;
  return 4;
}

