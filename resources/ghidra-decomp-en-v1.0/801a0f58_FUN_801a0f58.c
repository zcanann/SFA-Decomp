// Function: FUN_801a0f58
// Entry: 801a0f58
// Size: 728 bytes

/* WARNING: Removing unreachable block (ram,0x801a1208) */
/* WARNING: Removing unreachable block (ram,0x801a1200) */
/* WARNING: Removing unreachable block (ram,0x801a1210) */

void FUN_801a0f58(undefined4 param_1,undefined4 param_2,short param_3)

{
  float fVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  short extraout_r4;
  uint uVar5;
  short sVar6;
  undefined4 uVar7;
  double dVar8;
  undefined8 in_f29;
  double dVar9;
  undefined8 in_f30;
  double dVar10;
  undefined8 in_f31;
  double dVar11;
  float local_68 [2];
  double local_60;
  undefined4 local_58;
  uint uStack84;
  undefined auStack40 [16];
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  __psq_st0(auStack40,(int)((ulonglong)in_f29 >> 0x20),0);
  __psq_st1(auStack40,(int)in_f29,0);
  iVar2 = FUN_802860dc();
  local_68[0] = FLOAT_803e42e0;
  iVar3 = FUN_8002b9ec();
  iVar4 = FUN_80036e58(0x1e,iVar2,local_68);
  if (iVar4 != 0) {
    fVar1 = *(float *)(iVar4 + 0x10) - *(float *)(iVar3 + 0x10);
    if (fVar1 < FLOAT_803e42c0) {
      fVar1 = -fVar1;
    }
    if (FLOAT_803e42e4 <= fVar1) {
      dVar11 = (double)(*(float *)(iVar4 + 0xc) - *(float *)(iVar2 + 0xc));
      dVar10 = (double)(*(float *)(iVar4 + 0x10) - *(float *)(iVar2 + 0x10));
      dVar8 = (double)FLOAT_803e42c0;
      if (dVar10 <= dVar8) {
        dVar9 = (double)(*(float *)(iVar4 + 0x14) - *(float *)(iVar2 + 0x14));
        if (dVar10 != dVar8) {
          dVar8 = (double)(float)((double)*(float *)(iVar2 + 0x28) / dVar10);
        }
        sVar6 = extraout_r4;
        if ((double)FLOAT_803e42dc <= dVar8) {
          FUN_8000bb18(iVar2,0xd2);
          dVar8 = (double)FLOAT_803e42dc;
          *(float *)(iVar2 + 0x28) = (float)dVar10;
          fVar1 = FLOAT_803e42e8;
          *(float *)(iVar4 + 0xc) = *(float *)(iVar4 + 0xc) + FLOAT_803e42e8;
          *(float *)(iVar4 + 0x2c) = *(float *)(iVar4 + 0x2c) + fVar1;
          if (FLOAT_803e42ec < *(float *)(iVar4 + 0x2c)) {
            *(float *)(iVar4 + 0xc) = *(float *)(iVar4 + 0xc) - *(float *)(iVar4 + 0x2c);
            *(float *)(iVar4 + 0x2c) = FLOAT_803e42c0;
          }
          *(undefined2 *)(iVar2 + 2) = 0;
          *(undefined2 *)(iVar2 + 4) = 0;
          sVar6 = 0;
          param_3 = 0;
        }
        *(float *)(iVar2 + 0x24) = (float)(dVar11 * dVar8);
        *(float *)(iVar2 + 0x2c) = (float)(dVar9 * dVar8);
        uVar5 = (uint)sVar6;
        if (uVar5 != 0) {
          if (uVar5 == 1) {
            local_60 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar2 + 2) & 0xffff);
            fVar1 = (float)((double)(FLOAT_803e42f0 - (float)(local_60 - DOUBLE_803e42f8)) * dVar8);
          }
          else {
            local_60 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar2 + 2) & 0xffff);
            fVar1 = (float)(local_60 - DOUBLE_803e42f8) *
                    (float)(dVar8 * (double)(float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000)
                                                   - DOUBLE_803e4300));
          }
          uStack84 = (int)*(short *)(iVar2 + 2) ^ 0x80000000;
          local_58 = 0x43300000;
          iVar3 = (int)((float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e4300) + fVar1);
          local_60 = (double)(longlong)iVar3;
          *(short *)(iVar2 + 2) = (short)iVar3;
        }
        uVar5 = (uint)param_3;
        if (uVar5 != 0) {
          fVar1 = FLOAT_803e42c0;
          if (uVar5 != 1) {
            local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
            fVar1 = (float)((double)CONCAT44(0x43300000,(int)*(short *)(iVar2 + 4) & 0xffff) -
                           DOUBLE_803e42f8) *
                    (float)(dVar8 * (double)(float)(local_60 - DOUBLE_803e4300));
          }
          uStack84 = (int)*(short *)(iVar2 + 4) ^ 0x80000000;
          local_58 = 0x43300000;
          iVar3 = (int)((float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e4300) + fVar1);
          local_60 = (double)(longlong)iVar3;
          *(short *)(iVar2 + 4) = (short)iVar3;
        }
      }
    }
  }
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  __psq_l0(auStack24,uVar7);
  __psq_l1(auStack24,uVar7);
  __psq_l0(auStack40,uVar7);
  __psq_l1(auStack40,uVar7);
  FUN_80286128();
  return;
}

