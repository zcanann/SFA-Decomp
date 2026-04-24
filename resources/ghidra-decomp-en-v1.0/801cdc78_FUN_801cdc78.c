// Function: FUN_801cdc78
// Entry: 801cdc78
// Size: 216 bytes

undefined4 FUN_801cdc78(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  
  iVar1 = FUN_8001ffb4(10);
  if (iVar1 != 0) {
    *(byte *)(param_3 + 0x90) = *(byte *)(param_3 + 0x90) | 4;
  }
  iVar1 = FUN_800394ac(param_1,0,0);
  FUN_800394ac(param_1,1,0);
  *(short *)(iVar1 + 10) = *(short *)(iVar1 + 10) + (short)(int)(FLOAT_803e5200 * FLOAT_803db414);
  if (0x4e80 < *(short *)(iVar1 + 10)) {
    *(short *)(iVar1 + 10) = *(short *)(iVar1 + 10) + -0x4e80;
  }
  *(ushort *)(param_3 + 0x6e) = *(ushort *)(param_3 + 0x70) & 0xffbf;
  *(undefined *)(param_3 + 0x56) = 0;
  return 0;
}

