// Function: FUN_801ce22c
// Entry: 801ce22c
// Size: 216 bytes

undefined4 FUN_801ce22c(int param_1,undefined4 param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  
  uVar1 = FUN_80020078(10);
  if (uVar1 != 0) {
    *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 4;
  }
  iVar2 = FUN_800395a4(param_1,0);
  FUN_800395a4(param_1,1);
  *(short *)(iVar2 + 10) = *(short *)(iVar2 + 10) + (short)(int)(FLOAT_803e5e98 * FLOAT_803dc074);
  if (0x4e80 < *(short *)(iVar2 + 10)) {
    *(short *)(iVar2 + 10) = *(short *)(iVar2 + 10) + -0x4e80;
  }
  *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x70) & 0xffbf;
  *(undefined *)(param_3 + 0x56) = 0;
  return 0;
}

