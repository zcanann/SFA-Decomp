// Function: FUN_801b4060
// Entry: 801b4060
// Size: 164 bytes

bool FUN_801b4060(int param_1)

{
  bool bVar1;
  int iVar2;
  float *pfVar3;
  
  iVar2 = FUN_8002bac4();
  pfVar3 = *(float **)(param_1 + 0xb8);
  bVar1 = pfVar3[3] +
          pfVar3[2] * *(float *)(iVar2 + 0x14) +
          *pfVar3 * *(float *)(iVar2 + 0xc) + pfVar3[1] * *(float *)(iVar2 + 0x10) < FLOAT_803e55a0;
  (**(code **)(*DAT_803dd6d4 + 0x48))(bVar1,param_1,0xffffffff);
  return bVar1;
}

