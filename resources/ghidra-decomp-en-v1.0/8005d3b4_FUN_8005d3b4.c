// Function: FUN_8005d3b4
// Entry: 8005d3b4
// Size: 312 bytes

/* WARNING: Removing unreachable block (ram,0x8005d40c) */
/* WARNING: Removing unreachable block (ram,0x8005d3f8) */
/* WARNING: Removing unreachable block (ram,0x8005d3f0) */
/* WARNING: Removing unreachable block (ram,0x8005d3f4) */
/* WARNING: Removing unreachable block (ram,0x8005d408) */
/* WARNING: Removing unreachable block (ram,0x8005d418) */

void FUN_8005d3b4(int param_1,int param_2,int param_3)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  undefined4 uVar4;
  undefined4 uVar5;
  undefined4 uVar6;
  double dVar7;
  undefined4 uVar8;
  undefined4 uVar9;
  float local_28;
  float local_24;
  float local_20;
  
  uVar9 = 0x70007;
  if (DAT_803dce30 == 1000) {
    FUN_8005db38();
    DAT_803dce30 = 0;
  }
  uVar3 = __psq_l0(param_1 + 0xc,uVar9);
  uVar4 = __psq_l0(param_1 + 6,uVar9);
  uVar5 = __psq_l0(param_1 + 0xe,uVar9);
  dVar7 = (double)FLOAT_803dec20;
  uVar8 = __psq_l0(param_1 + 8,uVar9);
  uVar6 = __psq_l0(param_1 + 0x10,uVar9);
  uVar9 = __psq_l0(param_1 + 10,uVar9);
  local_28 = FLOAT_803debfc *
             ((float)((double)CONCAT44(uVar4,0x3f800000) * dVar7 +
                     (double)*(float *)(param_2 + 0x18)) +
             (float)((double)CONCAT44(uVar3,0x3f800000) * dVar7 + (double)*(float *)(param_2 + 0x18)
                    ));
  local_24 = FLOAT_803debfc *
             ((float)((double)CONCAT44(uVar8,0x3f800000) * dVar7 +
                     (double)*(float *)(param_2 + 0x28)) +
             (float)((double)CONCAT44(uVar5,0x3f800000) * dVar7 + (double)*(float *)(param_2 + 0x28)
                    ));
  local_20 = FLOAT_803debfc *
             ((float)((double)CONCAT44(uVar9,0x3f800000) * dVar7 +
                     (double)*(float *)(param_2 + 0x38)) +
             (float)((double)CONCAT44(uVar6,0x3f800000) * dVar7 + (double)*(float *)(param_2 + 0x38)
                    ));
  uVar9 = FUN_8000f54c();
  FUN_80247494(uVar9,&local_28,&local_28);
  iVar1 = DAT_803dce30;
  uVar2 = (uint)-local_20;
  if ((int)uVar2 < 0) {
    uVar2 = 0;
  }
  else if (0x7ffffff < (int)uVar2) {
    uVar2 = 0x7ffffff;
  }
  (&DAT_8037e0c0)[DAT_803dce30 * 4] = param_1;
  (&DAT_8037e0c4)[iVar1 * 4] = param_2;
  (&DAT_8037e0c8)[iVar1 * 4] = uVar2 | param_3 << 0x1b;
  return;
}

