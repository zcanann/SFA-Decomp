// Function: FUN_801551b8
// Entry: 801551b8
// Size: 680 bytes

/* WARNING: Removing unreachable block (ram,0x80155438) */
/* WARNING: Removing unreachable block (ram,0x80155430) */
/* WARNING: Removing unreachable block (ram,0x80155428) */
/* WARNING: Removing unreachable block (ram,0x801551d8) */
/* WARNING: Removing unreachable block (ram,0x801551d0) */
/* WARNING: Removing unreachable block (ram,0x801551c8) */

void FUN_801551b8(int param_1,int param_2,undefined2 *param_3,float *param_4)

{
  int iVar1;
  uint uVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  float local_b8;
  float local_b4;
  float local_b0;
  float local_ac;
  float local_a8;
  float local_a4;
  float local_a0 [2];
  float local_98;
  float local_94;
  float local_90;
  float local_8c;
  float afStack_88 [3];
  float local_7c [2];
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  float afStack_64 [3];
  float local_58;
  float local_54;
  float local_50;
  
  local_70 = *(float *)(param_2 + 0x360);
  local_6c = *(float *)(param_2 + 0x358);
  local_68 = *(float *)(param_2 + 0x364);
  FUN_80247eb8(&local_70,(float *)(param_1 + 0xc),afStack_64);
  dVar3 = FUN_80247f90(afStack_64,(float *)(param_2 + 0x344));
  local_70 = (float)((double)*(float *)(param_2 + 0x344) * dVar3 + (double)*(float *)(param_1 + 0xc)
                    );
  dVar6 = (double)*(float *)(param_1 + 0x10);
  local_6c = (float)((double)*(float *)(param_2 + 0x348) * dVar3 + dVar6);
  local_68 = (float)((double)*(float *)(param_2 + 0x34c) * dVar3 +
                    (double)*(float *)(param_1 + 0x14));
  local_ac = FLOAT_803e3698;
  local_a8 = FLOAT_803e369c;
  local_a4 = FLOAT_803e3698;
  FUN_80247fb0(&local_ac,(float *)(param_2 + 0x344),local_7c);
  FUN_80247ef8(local_7c,local_7c);
  if (FLOAT_803e3698 == local_7c[0]) {
    local_7c[0] = (*(float *)(param_1 + 0x14) - *(float *)(param_2 + 0x364)) / local_74;
  }
  else {
    local_7c[0] = (*(float *)(param_1 + 0xc) - *(float *)(param_2 + 0x360)) / local_7c[0];
  }
  dVar5 = (double)local_7c[0];
  iVar1 = *(int *)(param_2 + 0x29c);
  local_58 = *(float *)(iVar1 + 0xc);
  local_54 = FLOAT_803e36a0 + *(float *)(iVar1 + 0x10);
  local_50 = *(float *)(iVar1 + 0x14);
  local_94 = *(float *)(param_2 + 0x360);
  local_90 = *(float *)(param_2 + 0x358);
  local_8c = *(float *)(param_2 + 0x364);
  FUN_80247eb8(&local_94,&local_58,afStack_88);
  dVar3 = FUN_80247f90(afStack_88,(float *)(param_2 + 0x344));
  local_94 = (float)((double)*(float *)(param_2 + 0x344) * dVar3 + (double)local_58);
  dVar4 = (double)local_54;
  local_90 = (float)((double)*(float *)(param_2 + 0x348) * dVar3 + dVar4);
  local_8c = (float)((double)*(float *)(param_2 + 0x34c) * dVar3 + (double)local_50);
  local_b8 = FLOAT_803e3698;
  local_b4 = FLOAT_803e369c;
  local_b0 = FLOAT_803e3698;
  FUN_80247fb0(&local_b8,(float *)(param_2 + 0x344),local_a0);
  FUN_80247ef8(local_a0,local_a0);
  if (FLOAT_803e3698 == local_a0[0]) {
    local_a0[0] = (local_50 - *(float *)(param_2 + 0x364)) / local_98;
  }
  else {
    local_a0[0] = (local_58 - *(float *)(param_2 + 0x360)) / local_a0[0];
  }
  dVar5 = (double)(float)(dVar5 - (double)local_a0[0]);
  dVar3 = (double)(float)(dVar6 - dVar4);
  uVar2 = FUN_80021884();
  iVar1 = (uVar2 & 0xffff) - (uint)*(ushort *)(param_1 + 2);
  if (0x8000 < iVar1) {
    iVar1 = iVar1 + -0xffff;
  }
  if (iVar1 < -0x8000) {
    iVar1 = iVar1 + 0xffff;
  }
  if (iVar1 < 0) {
    iVar1 = -iVar1;
  }
  *param_3 = (short)iVar1;
  dVar3 = FUN_80293900((double)(float)(dVar5 * dVar5 + (double)(float)(dVar3 * dVar3)));
  *param_4 = (float)dVar3;
  return;
}

