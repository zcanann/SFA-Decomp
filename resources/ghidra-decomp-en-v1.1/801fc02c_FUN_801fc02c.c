// Function: FUN_801fc02c
// Entry: 801fc02c
// Size: 152 bytes

/* WARNING: Removing unreachable block (ram,0x801fc0a8) */
/* WARNING: Removing unreachable block (ram,0x801fc03c) */

void FUN_801fc02c(uint param_1)

{
  int iVar1;
  bool bVar2;
  double dVar3;
  
  iVar1 = FUN_8002bac4();
  dVar3 = (double)FUN_800217c8((float *)(iVar1 + 0x18),(float *)(param_1 + 0x18));
  bVar2 = FUN_8000b598(param_1,0x40);
  if (bVar2) {
    if (dVar3 < (double)FLOAT_803e6d98) {
      FUN_8000bb38(param_1,0x110);
    }
  }
  else if ((double)FLOAT_803e6d98 <= dVar3) {
    FUN_8000b7dc(param_1,0x40);
  }
  return;
}

