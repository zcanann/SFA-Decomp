// Function: FUN_801a4524
// Entry: 801a4524
// Size: 160 bytes

undefined4 FUN_801a4524(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined4 uVar1;
  int iVar2;
  
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
    if (*(char *)(param_3 + iVar2 + 0x81) == '\x01') {
      FUN_800200e8(0xdcb,1);
      FUN_800200e8(0x4a3,0);
      FUN_80042f78(0x2b);
      FUN_8004350c(0,0,1);
      uVar1 = FUN_800481b0(0x2b);
      FUN_80043560(uVar1,0);
    }
  }
  return 0;
}

