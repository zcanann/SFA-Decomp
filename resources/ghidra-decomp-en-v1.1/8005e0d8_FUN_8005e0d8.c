// Function: FUN_8005e0d8
// Entry: 8005e0d8
// Size: 240 bytes

/* WARNING: Removing unreachable block (ram,0x8005e49c) */
/* WARNING: Removing unreachable block (ram,0x8005e494) */
/* WARNING: Removing unreachable block (ram,0x8005e0f0) */
/* WARNING: Removing unreachable block (ram,0x8005e0e8) */

undefined4 FUN_8005e0d8(undefined4 param_1,float *param_2)

{
  undefined4 uVar1;
  int iVar2;
  uint uVar3;
  double dVar4;
  double dVar5;
  float local_58;
  float local_54;
  float local_50;
  
  uVar3 = 0;
  iVar2 = 0;
  dVar4 = (double)FLOAT_803df8a0;
  dVar5 = (double)FLOAT_803df8a8;
  while( true ) {
    if (uVar3 < 8) {
                    /* WARNING: Could not recover jumptable at 0x8005e134. Too many branches */
                    /* WARNING: Treating indirect jump as call */
      uVar1 = (**(code **)((int)&PTR_LAB_8030f404 + iVar2))();
      return uVar1;
    }
    local_58 = (float)((double)local_58 * dVar4);
    local_54 = (float)((double)local_54 * dVar4);
    local_50 = (float)((double)local_50 * dVar4);
    FUN_80247bf8(param_2,&local_58,&local_58);
    if (dVar5 <= (double)local_50) break;
    uVar3 = uVar3 + 1;
    iVar2 = iVar2 + 4;
    if (7 < (int)uVar3) {
      return 0;
    }
  }
  return 1;
}

