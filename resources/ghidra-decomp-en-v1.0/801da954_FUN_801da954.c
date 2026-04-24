// Function: FUN_801da954
// Entry: 801da954
// Size: 120 bytes

undefined4 FUN_801da954(int param_1)

{
  int iVar1;
  
  iVar1 = *(int *)(param_1 + 0xb8);
  *(float *)(iVar1 + 4) = *(float *)(iVar1 + 4) + FLOAT_803db414;
  if ((FLOAT_803e5528 <= *(float *)(iVar1 + 4)) &&
     (*(float *)(iVar1 + 4) = *(float *)(iVar1 + 4) - FLOAT_803e5528,
     (*(ushort *)(param_1 + 0xb0) & 0x800) != 0)) {
    FUN_80098b18((double)*(float *)(param_1 + 8),param_1,0,2,0,0);
  }
  return 0;
}

