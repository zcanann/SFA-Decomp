// Function: FUN_801a14d4
// Entry: 801a14d4
// Size: 728 bytes

/* WARNING: Removing unreachable block (ram,0x801a178c) */
/* WARNING: Removing unreachable block (ram,0x801a1784) */
/* WARNING: Removing unreachable block (ram,0x801a177c) */
/* WARNING: Removing unreachable block (ram,0x801a14f4) */
/* WARNING: Removing unreachable block (ram,0x801a14ec) */
/* WARNING: Removing unreachable block (ram,0x801a14e4) */

void FUN_801a14d4(undefined4 param_1,undefined4 param_2,short param_3)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  int iVar4;
  short extraout_r4;
  uint uVar5;
  short sVar6;
  double dVar7;
  double in_f29;
  double dVar8;
  double in_f30;
  double dVar9;
  double in_f31;
  double dVar10;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  float local_68 [2];
  undefined8 local_60;
  undefined4 local_58;
  uint uStack_54;
  float local_28;
  float fStack_24;
  float local_18;
  float fStack_14;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  local_18 = (float)in_f30;
  fStack_14 = (float)in_ps30_1;
  local_28 = (float)in_f29;
  fStack_24 = (float)in_ps29_1;
  uVar2 = FUN_80286840();
  local_68[0] = FLOAT_803e4f78;
  iVar3 = FUN_8002bac4();
  iVar4 = FUN_80036f50(0x1e,uVar2,local_68);
  if (iVar4 != 0) {
    fVar1 = *(float *)(iVar4 + 0x10) - *(float *)(iVar3 + 0x10);
    if (fVar1 < FLOAT_803e4f58) {
      fVar1 = -fVar1;
    }
    if (FLOAT_803e4f7c <= fVar1) {
      dVar10 = (double)(*(float *)(iVar4 + 0xc) - *(float *)(uVar2 + 0xc));
      dVar9 = (double)(*(float *)(iVar4 + 0x10) - *(float *)(uVar2 + 0x10));
      dVar7 = (double)FLOAT_803e4f58;
      if (dVar9 <= dVar7) {
        dVar8 = (double)(*(float *)(iVar4 + 0x14) - *(float *)(uVar2 + 0x14));
        if (dVar9 != dVar7) {
          dVar7 = (double)(float)((double)*(float *)(uVar2 + 0x28) / dVar9);
        }
        sVar6 = extraout_r4;
        if ((double)FLOAT_803e4f74 <= dVar7) {
          FUN_8000bb38(uVar2,0xd2);
          dVar7 = (double)FLOAT_803e4f74;
          *(float *)(uVar2 + 0x28) = (float)dVar9;
          fVar1 = FLOAT_803e4f80;
          *(float *)(iVar4 + 0xc) = *(float *)(iVar4 + 0xc) + FLOAT_803e4f80;
          *(float *)(iVar4 + 0x2c) = *(float *)(iVar4 + 0x2c) + fVar1;
          if (FLOAT_803e4f84 < *(float *)(iVar4 + 0x2c)) {
            *(float *)(iVar4 + 0xc) = *(float *)(iVar4 + 0xc) - *(float *)(iVar4 + 0x2c);
            *(float *)(iVar4 + 0x2c) = FLOAT_803e4f58;
          }
          *(undefined2 *)(uVar2 + 2) = 0;
          *(undefined2 *)(uVar2 + 4) = 0;
          sVar6 = 0;
          param_3 = 0;
        }
        *(float *)(uVar2 + 0x24) = (float)(dVar10 * dVar7);
        *(float *)(uVar2 + 0x2c) = (float)(dVar8 * dVar7);
        uVar5 = (uint)sVar6;
        if (uVar5 != 0) {
          if (uVar5 == 1) {
            local_60 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(uVar2 + 2));
            fVar1 = (float)((double)(FLOAT_803e4f88 - (float)(local_60 - DOUBLE_803e4f90)) * dVar7);
          }
          else {
            local_60 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(uVar2 + 2));
            fVar1 = (float)(local_60 - DOUBLE_803e4f90) *
                    (float)(dVar7 * (double)(float)((double)CONCAT44(0x43300000,uVar5 ^ 0x80000000)
                                                   - DOUBLE_803e4f98));
          }
          uStack_54 = (int)*(short *)(uVar2 + 2) ^ 0x80000000;
          local_58 = 0x43300000;
          iVar3 = (int)((float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e4f98) + fVar1);
          local_60 = (double)(longlong)iVar3;
          *(short *)(uVar2 + 2) = (short)iVar3;
        }
        uVar5 = (uint)param_3;
        if (uVar5 != 0) {
          fVar1 = FLOAT_803e4f58;
          if (uVar5 != 1) {
            local_60 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
            fVar1 = (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(uVar2 + 4)) -
                           DOUBLE_803e4f90) *
                    (float)(dVar7 * (double)(float)(local_60 - DOUBLE_803e4f98));
          }
          uStack_54 = (int)*(short *)(uVar2 + 4) ^ 0x80000000;
          local_58 = 0x43300000;
          iVar3 = (int)((float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e4f98) + fVar1);
          local_60 = (double)(longlong)iVar3;
          *(short *)(uVar2 + 4) = (short)iVar3;
        }
      }
    }
  }
  FUN_8028688c();
  return;
}

