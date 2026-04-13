// Function: FUN_801daf44
// Entry: 801daf44
// Size: 120 bytes

undefined4 FUN_801daf44(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(float *)(iVar1 + 4) = *(float *)(iVar1 + 4) + FLOAT_803dc074;
  if ((FLOAT_803e61c0 <= *(float *)(iVar1 + 4)) &&
     (*(float *)(iVar1 + 4) = *(float *)(iVar1 + 4) - FLOAT_803e61c0,
     (*(ushort *)(param_1 + 0xb0) & 0x800) != 0)) {
    FUN_80098da4(param_1,0,2,0,(undefined4 *)0x0);
  }
  return 0;
}

