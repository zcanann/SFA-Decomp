// Function: FUN_80142eb0
// Entry: 80142eb0
// Size: 560 bytes

undefined4 FUN_80142eb0(int param_1,int param_2)

{
  short sVar1;
  bool bVar2;
  int iVar3;
  undefined auStack40 [8];
  float local_20;
  undefined4 local_1c;
  undefined4 local_18;
  undefined4 local_14;
  
  iVar3 = FUN_8014460c();
  if (iVar3 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
    sVar1 = *(short *)(param_1 + 0xa0);
    if (sVar1 == 0x2e) {
      if (((*(uint *)(param_2 + 0x54) & 0x8000000) != 0) &&
         ((((*(uint *)(param_2 + 0x54) & 0x10000) != 0 || (iVar3 = FUN_800221a0(0,2), iVar3 == 0))
          || (FLOAT_803e23dc < *(float *)(param_2 + 0x720))))) {
        FUN_8013a3f0((double)FLOAT_803e23ec,param_1,0x2f,0);
      }
      local_1c = *(undefined4 *)(param_1 + 0x18);
      local_18 = *(undefined4 *)(param_1 + 0x1c);
      local_14 = *(undefined4 *)(param_1 + 0x20);
      local_20 = FLOAT_803e23f0;
      (**(code **)(*DAT_803dca88 + 8))(param_1,0x7e6,auStack40,0x200001,0xffffffff,0);
    }
    else if (sVar1 < 0x2e) {
      if ((0x2b < sVar1) && ((*(uint *)(param_2 + 0x54) & 0x8000000) != 0)) {
        FUN_8013a3f0((double)FLOAT_803e249c,param_1,0x2e,0);
      }
    }
    else if ((sVar1 < 0x30) && ((*(uint *)(param_2 + 0x54) & 0x8000000) != 0)) {
      if (FLOAT_803e23dc == *(float *)(param_2 + 0x2ac)) {
        bVar2 = false;
      }
      else if (FLOAT_803e2410 == *(float *)(param_2 + 0x2b0)) {
        bVar2 = true;
      }
      else if (*(float *)(param_2 + 0x2b4) - *(float *)(param_2 + 0x2b0) <= FLOAT_803e2414) {
        bVar2 = false;
      }
      else {
        bVar2 = true;
      }
      if (bVar2) {
        FUN_8013a3f0((double)FLOAT_803e243c,param_1,8,0);
        *(float *)(param_2 + 0x79c) = FLOAT_803e2440;
        *(float *)(param_2 + 0x838) = FLOAT_803e23dc;
        FUN_80148bc8(s_in_water_8031d46c);
      }
      else {
        FUN_8013a3f0((double)FLOAT_803e2444,param_1,0,0);
        FUN_80148bc8(s_out_of_water_8031d478);
      }
      *(uint *)(param_2 + 0x54) = *(uint *)(param_2 + 0x54) & 0xffffffef;
      *(undefined *)(param_2 + 10) = 0;
    }
  }
  return 1;
}

