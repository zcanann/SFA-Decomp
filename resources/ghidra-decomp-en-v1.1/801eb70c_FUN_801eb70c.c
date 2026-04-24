// Function: FUN_801eb70c
// Entry: 801eb70c
// Size: 608 bytes

/* WARNING: Removing unreachable block (ram,0x801eb94c) */
/* WARNING: Removing unreachable block (ram,0x801eb71c) */

void FUN_801eb70c(uint param_1,int param_2)

{
  float fVar1;
  float fVar2;
  double dVar3;
  uint uVar4;
  double dVar5;
  double dVar6;
  undefined8 local_28;
  undefined8 local_20;
  
  if ((*(byte *)(param_2 + 0x428) >> 5 & 1) != 0) {
    if (*(float *)(param_2 + 0x4bc) < FLOAT_803e6780) {
      FUN_8000b7dc(param_1,0x7f);
      if (*(float *)(param_2 + 0x464) <= FLOAT_803e67b8) {
        (**(code **)(*DAT_803dd6e8 + 0x60))();
        (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_1,0xffffffff);
        fVar2 = FLOAT_803e6824;
        *(float *)(param_2 + 0x464) = FLOAT_803e6824;
        *(float *)(param_2 + 0x468) = fVar2;
        *(float *)(param_2 + 0x46c) = fVar2;
      }
      else {
        uVar4 = FUN_80022264(0,10);
        if (uVar4 == 0) {
          FUN_8000bb38(0,0x117);
        }
        FUN_80247edc((double)FLOAT_803e6820,(float *)(param_2 + 0x464),(float *)(param_2 + 0x464));
        if ((*(char *)(param_2 + 0x428) < '\0') && (*(float *)(param_2 + 0x464) < FLOAT_803e67b8)) {
          *(float *)(param_2 + 0x464) = FLOAT_803e67b8;
        }
      }
    }
    else {
      dVar6 = (double)FLOAT_803dc074;
      dVar5 = FUN_80247f54((float *)(param_2 + 0x494));
      dVar3 = DOUBLE_803e6798;
      local_20 = (double)CONCAT44(0x43300000,
                                  (int)(*(float *)(param_2 + 0x4c0) * (float)(dVar6 * dVar5)) ^
                                  0x80000000);
      *(float *)(param_2 + 0x4bc) =
           *(float *)(param_2 + 0x4bc) -
           (float)(dVar6 * (double)FLOAT_803dcd40 + (double)(float)(local_20 - DOUBLE_803e6798));
      fVar1 = FLOAT_803e67ac;
      fVar2 = FLOAT_803e6780;
      if (FLOAT_803e6780 != *(float *)(param_2 + 0x4c4)) {
        *(float *)(param_2 + 0x4bc) = FLOAT_803e67ac * FLOAT_803dc074 + *(float *)(param_2 + 0x4bc);
        local_28 = (double)CONCAT44(0x43300000,(int)(fVar1 * FLOAT_803dc074) ^ 0x80000000);
        *(float *)(param_2 + 0x4c4) = *(float *)(param_2 + 0x4c4) - (float)(local_28 - dVar3);
        fVar1 = *(float *)(param_2 + 0x4c4);
        if ((fVar2 <= fVar1) && (fVar2 = fVar1, FLOAT_803e6818 < fVar1)) {
          fVar2 = FLOAT_803e6818;
        }
        *(float *)(param_2 + 0x4c4) = fVar2;
        fVar2 = *(float *)(param_2 + 0x4bc);
        fVar1 = FLOAT_803e6780;
        if ((FLOAT_803e6780 <= fVar2) && (fVar1 = fVar2, *(float *)(param_2 + 0x4b8) < fVar2)) {
          fVar1 = *(float *)(param_2 + 0x4b8);
        }
        *(float *)(param_2 + 0x4bc) = fVar1;
      }
      if (*(float *)(param_2 + 0x4bc) < FLOAT_803e681c) {
        FUN_8000da78(param_1,0x44e);
      }
      (**(code **)(*DAT_803dd6e8 + 0x5c))((int)*(float *)(param_2 + 0x4bc));
    }
  }
  return;
}

