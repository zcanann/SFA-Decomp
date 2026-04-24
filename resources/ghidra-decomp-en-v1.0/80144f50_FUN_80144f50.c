// Function: FUN_80144f50
// Entry: 80144f50
// Size: 648 bytes

void FUN_80144f50(short *param_1,int param_2)

{
  short sVar1;
  bool bVar2;
  int iVar3;
  uint uVar4;
  int iVar5;
  double dVar6;
  
  iVar3 = FUN_8014460c();
  if (iVar3 == 0) {
    dVar6 = (double)FUN_80293e80((double)((FLOAT_803e2454 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*param_1 ^ 0x80000000) -
                                                 DOUBLE_803e2460)) / FLOAT_803e2458));
    *(float *)(param_2 + 0x72c) = (float)((double)*(float *)(param_1 + 0xc) - dVar6);
    *(undefined4 *)(param_2 + 0x730) = *(undefined4 *)(param_1 + 0xe);
    dVar6 = (double)FUN_80294204((double)((FLOAT_803e2454 *
                                          (float)((double)CONCAT44(0x43300000,
                                                                   (int)*param_1 ^ 0x80000000) -
                                                 DOUBLE_803e2460)) / FLOAT_803e2458));
    *(float *)(param_2 + 0x734) = (float)((double)*(float *)(param_1 + 0x10) - dVar6);
    iVar3 = FUN_8013b368((double)FLOAT_803e247c,param_1,param_2);
    if (iVar3 != 1) {
      *(float *)(param_2 + 0x740) = *(float *)(param_2 + 0x740) - FLOAT_803db414;
      if (*(float *)(param_2 + 0x740) <= FLOAT_803e23dc) {
        uVar4 = FUN_800221a0(500,0x2ee);
        *(float *)(param_2 + 0x740) =
             (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e2460);
        iVar3 = *(int *)(param_1 + 0x5c);
        if (((*(byte *)(iVar3 + 0x58) >> 6 & 1) == 0) &&
           (((0x2f < param_1[0x50] || (param_1[0x50] < 0x29)) &&
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
        sVar1 = param_1[0x50];
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
  }
  return;
}

