// Function: FUN_8013fec0
// Entry: 8013fec0
// Size: 248 bytes

void FUN_8013fec0(undefined4 param_1,int param_2)

{
  bool bVar1;
  int iVar2;
  
  iVar2 = FUN_8013b368((double)FLOAT_803e247c);
  if (iVar2 == 0) {
    if (FLOAT_803e23dc == *(float *)(param_2 + 0x2ac)) {
      bVar1 = false;
    }
    else if (FLOAT_803e2410 == *(float *)(param_2 + 0x2b0)) {
      bVar1 = true;
    }
    else if (*(float *)(param_2 + 0x2b4) - *(float *)(param_2 + 0x2b0) <= FLOAT_803e2414) {
      bVar1 = false;
    }
    else {
      bVar1 = true;
    }
    if (bVar1) {
      FUN_8013a3f0((double)FLOAT_803e243c,param_1,8,0);
      *(float *)(param_2 + 0x79c) = FLOAT_803e2440;
      *(float *)(param_2 + 0x838) = FLOAT_803e23dc;
      FUN_80148bc8(s_in_water_8031d46c);
    }
    else {
      FUN_8013a3f0((double)FLOAT_803e2444,param_1,0,0);
      FUN_80148bc8(s_out_of_water_8031d478);
    }
  }
  return;
}

