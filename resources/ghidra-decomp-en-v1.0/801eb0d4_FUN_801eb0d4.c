// Function: FUN_801eb0d4
// Entry: 801eb0d4
// Size: 608 bytes

/* WARNING: Removing unreachable block (ram,0x801eb314) */

void FUN_801eb0d4(undefined4 param_1,int param_2)

{
  float fVar1;
  float fVar2;
  double dVar3;
  int iVar4;
  undefined4 uVar5;
  double dVar6;
  undefined8 in_f31;
  double dVar7;
  double local_28;
  double local_20;
  undefined auStack8 [8];
  
  uVar5 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  if ((*(byte *)(param_2 + 0x428) >> 5 & 1) != 0) {
    if (*(float *)(param_2 + 0x4bc) < FLOAT_803e5ae8) {
      FUN_8000b7bc(param_1,0x7f);
      if (*(float *)(param_2 + 0x464) <= FLOAT_803e5b20) {
        (**(code **)(*DAT_803dca68 + 0x60))();
        (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
        fVar2 = FLOAT_803e5b8c;
        *(float *)(param_2 + 0x464) = FLOAT_803e5b8c;
        *(float *)(param_2 + 0x468) = fVar2;
        *(float *)(param_2 + 0x46c) = fVar2;
      }
      else {
        iVar4 = FUN_800221a0(0,10);
        if (iVar4 == 0) {
          FUN_8000bb18(0,0x117);
        }
        FUN_80247778((double)FLOAT_803e5b88,param_2 + 0x464,param_2 + 0x464);
        if ((*(char *)(param_2 + 0x428) < '\0') && (*(float *)(param_2 + 0x464) < FLOAT_803e5b20)) {
          *(float *)(param_2 + 0x464) = FLOAT_803e5b20;
        }
      }
    }
    else {
      dVar7 = (double)FLOAT_803db414;
      dVar6 = (double)FUN_802477f0(param_2 + 0x494);
      dVar3 = DOUBLE_803e5b00;
      local_20 = (double)CONCAT44(0x43300000,
                                  (int)(*(float *)(param_2 + 0x4c0) * (float)(dVar7 * dVar6)) ^
                                  0x80000000);
      *(float *)(param_2 + 0x4bc) =
           *(float *)(param_2 + 0x4bc) -
           (float)(dVar7 * (double)FLOAT_803dc0d8 + (double)(float)(local_20 - DOUBLE_803e5b00));
      fVar1 = FLOAT_803e5b14;
      fVar2 = FLOAT_803e5ae8;
      if (FLOAT_803e5ae8 != *(float *)(param_2 + 0x4c4)) {
        *(float *)(param_2 + 0x4bc) = FLOAT_803e5b14 * FLOAT_803db414 + *(float *)(param_2 + 0x4bc);
        local_28 = (double)CONCAT44(0x43300000,(int)(fVar1 * FLOAT_803db414) ^ 0x80000000);
        *(float *)(param_2 + 0x4c4) = *(float *)(param_2 + 0x4c4) - (float)(local_28 - dVar3);
        fVar1 = *(float *)(param_2 + 0x4c4);
        if ((fVar2 <= fVar1) && (fVar2 = fVar1, FLOAT_803e5b80 < fVar1)) {
          fVar2 = FLOAT_803e5b80;
        }
        *(float *)(param_2 + 0x4c4) = fVar2;
        fVar2 = *(float *)(param_2 + 0x4bc);
        fVar1 = FLOAT_803e5ae8;
        if ((FLOAT_803e5ae8 <= fVar2) && (fVar1 = fVar2, *(float *)(param_2 + 0x4b8) < fVar2)) {
          fVar1 = *(float *)(param_2 + 0x4b8);
        }
        *(float *)(param_2 + 0x4bc) = fVar1;
      }
      if (*(float *)(param_2 + 0x4bc) < FLOAT_803e5b84) {
        FUN_8000da58(param_1,0x44e);
      }
      (**(code **)(*DAT_803dca68 + 0x5c))((int)*(float *)(param_2 + 0x4bc));
    }
  }
  __psq_l0(auStack8,uVar5);
  __psq_l1(auStack8,uVar5);
  return;
}

