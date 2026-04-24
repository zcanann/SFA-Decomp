// Function: FUN_801434b0
// Entry: 801434b0
// Size: 804 bytes

undefined4 FUN_801434b0(int param_1,int param_2)

{
  char cVar1;
  short sVar2;
  float fVar3;
  bool bVar4;
  int iVar5;
  undefined auStack40 [12];
  undefined4 local_1c;
  float local_18;
  undefined4 local_14;
  
  iVar5 = FUN_8014460c();
  if (iVar5 == 0) {
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
    sVar2 = *(short *)(param_1 + 0xa0);
    if (sVar2 == 0x2a) {
      *(float *)(param_2 + 0x73c) = *(float *)(param_2 + 0x73c) - FLOAT_803db414;
      if (*(float *)(param_2 + 0x73c) <= FLOAT_803e23dc) {
        if (((*(uint *)(param_2 + 0x54) & 0x10000) != 0) ||
           (FLOAT_803e23dc < *(float *)(param_2 + 0x720))) {
          FUN_8013a3f0((double)FLOAT_803e23ec,param_1,0x2b,0);
        }
        else {
          iVar5 = (**(code **)(*DAT_803dca58 + 0x24))(0);
          if (iVar5 == 0) {
            FUN_8013a3f0((double)FLOAT_803e251c,param_1,0x2c,0);
            *(undefined *)(param_2 + 10) = 9;
          }
        }
      }
      for (iVar5 = 0; iVar5 < *(char *)(param_2 + 0x827); iVar5 = iVar5 + 1) {
        cVar1 = *(char *)(param_2 + iVar5 + 0x81f);
        if (cVar1 == '\0') {
          FUN_800393f8(param_1,param_2 + 0x3a8,0x390,0x500,0xffffffff,0);
        }
        else if (cVar1 == '\a') {
          FUN_800393f8(param_1,param_2 + 0x3a8,0x391,0x100,0xffffffff,0);
        }
      }
      fVar3 = *(float *)(param_2 + 0x744) - FLOAT_803db414;
      *(float *)(param_2 + 0x744) = fVar3;
      if (fVar3 <= FLOAT_803e23dc) {
        if ((*(ushort *)(param_1 + 0xb0) & 0x800) != 0) {
          local_1c = *(undefined4 *)(param_2 + 0x408);
          local_18 = FLOAT_803e23f8 + *(float *)(param_2 + 0x40c);
          local_14 = *(undefined4 *)(param_2 + 0x410);
          (**(code **)(*DAT_803dca88 + 8))(param_1,0x7f0,auStack40,0x200001,0xffffffff,0);
        }
        *(float *)(param_2 + 0x744) = FLOAT_803e24c8;
      }
    }
    else if (sVar2 < 0x2a) {
      if ((0x28 < sVar2) && ((*(uint *)(param_2 + 0x54) & 0x8000000) != 0)) {
        FUN_8013a3f0((double)FLOAT_803e2520,param_1,0x2a,0);
      }
    }
    else if ((sVar2 < 0x2c) && ((*(uint *)(param_2 + 0x54) & 0x8000000) != 0)) {
      if (FLOAT_803e23dc == *(float *)(param_2 + 0x2ac)) {
        bVar4 = false;
      }
      else if (FLOAT_803e2410 == *(float *)(param_2 + 0x2b0)) {
        bVar4 = true;
      }
      else if (*(float *)(param_2 + 0x2b4) - *(float *)(param_2 + 0x2b0) <= FLOAT_803e2414) {
        bVar4 = false;
      }
      else {
        bVar4 = true;
      }
      if (bVar4) {
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

