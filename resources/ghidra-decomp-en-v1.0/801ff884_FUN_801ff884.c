// Function: FUN_801ff884
// Entry: 801ff884
// Size: 212 bytes

undefined4 FUN_801ff884(int param_1,undefined4 param_2,int param_3)

{
  int *piVar1;
  int iVar2;
  
  piVar1 = *(int **)(param_1 + 0xb8);
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(param_3 + 0x8b); iVar2 = iVar2 + 1) {
    *(byte *)(piVar1 + 1) = *(char *)(param_3 + iVar2 + 0x81) << 7 | *(byte *)(piVar1 + 1) & 0x7f;
  }
  if (((*(char *)(piVar1 + 1) < '\0') && (*piVar1 < 2)) && (-1 < *piVar1)) {
    FUN_800972dc((double)FLOAT_803e6270,(double)FLOAT_803e6274,param_1,7,5,6,100,0,0x200000);
    FUN_800972dc((double)FLOAT_803e6270,(double)FLOAT_803e6274,param_1,6,1,6,100,0,0x200000);
  }
  return 0;
}

