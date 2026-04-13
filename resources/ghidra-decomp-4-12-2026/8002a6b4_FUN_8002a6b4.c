// Function: FUN_8002a6b4
// Entry: 8002a6b4
// Size: 408 bytes

/* WARNING: Removing unreachable block (ram,0x8002a830) */
/* WARNING: Removing unreachable block (ram,0x8002a828) */
/* WARNING: Removing unreachable block (ram,0x8002a820) */
/* WARNING: Removing unreachable block (ram,0x8002a6d4) */
/* WARNING: Removing unreachable block (ram,0x8002a6cc) */
/* WARNING: Removing unreachable block (ram,0x8002a6c4) */

void FUN_8002a6b4(ushort *param_1)

{
  float fVar1;
  double dVar2;
  double dVar3;
  double dVar4;
  float afStack_c8 [3];
  float local_bc;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float afStack_a4 [4];
  float local_94;
  undefined4 local_90;
  undefined4 local_8c;
  float local_84;
  undefined4 local_80;
  undefined4 local_7c;
  float afStack_74 [3];
  float local_68;
  float local_58;
  float local_48;
  
  fVar1 = FLOAT_803df508 * *(float *)(param_1 + 0x54) * *(float *)(param_1 + 4);
  dVar3 = (double)(((*(float *)(param_1 + 0x44) - FLOAT_803ddb4c) -
                   (*(float *)(param_1 + 10) - FLOAT_803dda5c)) / fVar1);
  dVar4 = (double)(((*(float *)(param_1 + 6) - FLOAT_803ddb50) -
                   (*(float *)(param_1 + 0x40) - FLOAT_803dda58)) / fVar1);
  dVar2 = (double)(float)(dVar4 * dVar4 + (double)(float)(dVar3 * dVar3));
  if ((double)FLOAT_803df50c < dVar2) {
    dVar2 = FUN_80293900(dVar2);
    local_b0 = (float)(dVar4 / dVar2);
    local_ac = FLOAT_803df50c;
    local_a8 = (float)(-dVar3 / dVar2);
    local_bc = FLOAT_803df50c;
    local_b8 = FLOAT_803df510;
    local_b4 = FLOAT_803df50c;
    FUN_80247fb0(&local_b0,&local_bc,afStack_c8);
    FUN_80247944((double)(FLOAT_803df514 * (float)((double)FLOAT_803df518 * -dVar2)),afStack_a4,
                 afStack_c8);
    FUN_80021634(param_1,afStack_74);
    local_68 = FLOAT_803df50c;
    local_58 = FLOAT_803df50c;
    local_48 = FLOAT_803df50c;
    FUN_80247618(afStack_a4,afStack_74,afStack_a4);
    local_b0 = local_84;
    local_ac = (float)local_80;
    local_a8 = (float)local_7c;
    local_bc = local_94;
    local_b8 = (float)local_90;
    local_b4 = (float)local_8c;
    FUN_80021494(&local_b0,&local_bc,param_1 + 2,param_1 + 1,param_1);
  }
  return;
}

