// Function: FUN_8013f9e4
// Entry: 8013f9e4
// Size: 512 bytes

void FUN_8013f9e4(int param_1,int param_2)

{
  short sVar1;
  bool bVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  
  iVar3 = FUN_8014460c();
  if ((iVar3 == 0) && (iVar3 = FUN_8013b368((double)FLOAT_803e2488,param_1,param_2), iVar3 == 0)) {
    *(float *)(param_2 + 0x740) = *(float *)(param_2 + 0x740) - FLOAT_803db414;
    if (*(float *)(param_2 + 0x740) <= FLOAT_803e23dc) {
      uVar4 = FUN_800221a0(500,0x2ee);
      *(float *)(param_2 + 0x740) =
           (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e2460);
      iVar3 = *(int *)(param_1 + 0xb8);
      if (((*(byte *)(iVar3 + 0x58) >> 6 & 1) == 0) &&
         (((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)) &&
          (iVar5 = FUN_8000b578(param_1,0x10), iVar5 == 0)))) {
        FUN_800393f8(param_1,iVar3 + 0x3a8,0x360,0x500,0xffffffff,0);
      }
    }
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
      sVar1 = *(short *)(param_1 + 0xa0);
      if (sVar1 != 0x31) {
        if ((sVar1 < 0x31) && (sVar1 == 0xd)) {
          if ((*(uint *)(param_2 + 0x54) & 0x8000000) != 0) {
            FUN_8013a3f0((double)FLOAT_803e243c,param_1,0x31,0);
          }
        }
        else {
          FUN_8013a3f0((double)FLOAT_803e2444,param_1,0xd,0);
        }
      }
      FUN_80148bc8(s_out_of_water_8031d478);
    }
  }
  return;
}

