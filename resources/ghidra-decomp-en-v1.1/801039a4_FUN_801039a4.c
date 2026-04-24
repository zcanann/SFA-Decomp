// Function: FUN_801039a4
// Entry: 801039a4
// Size: 584 bytes

/* WARNING: Removing unreachable block (ram,0x80103bc4) */
/* WARNING: Removing unreachable block (ram,0x80103bbc) */
/* WARNING: Removing unreachable block (ram,0x801039bc) */
/* WARNING: Removing unreachable block (ram,0x801039b4) */

undefined FUN_801039a4(int param_1,short *param_2,float *param_3,short *param_4)

{
  float fVar1;
  float fVar2;
  float fVar3;
  uint uVar4;
  int iVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  undefined auStack_d8 [4];
  float local_d4;
  undefined auStack_d0 [4];
  float local_cc;
  float local_c8;
  float local_c4;
  float local_c0;
  float local_bc;
  float local_b8;
  float local_b4;
  undefined auStack_b0 [110];
  undefined local_42;
  undefined4 local_40;
  uint uStack_3c;
  undefined4 local_38;
  uint uStack_34;
  
  uStack_3c = (int)*param_2 ^ 0x80000000;
  local_40 = 0x43300000;
  dVar6 = (double)FUN_802945e0();
  uStack_34 = (int)*param_2 ^ 0x80000000;
  local_38 = 0x43300000;
  dVar7 = (double)FUN_80294964();
  local_cc = *(float *)(DAT_803de1a8 + 4) * *(float *)(DAT_803de1a8 + 4) -
             *(float *)(DAT_803de1a8 + 8) * *(float *)(DAT_803de1a8 + 8);
  if (local_cc < FLOAT_803e2314) {
    local_cc = FLOAT_803e2314;
  }
  dVar8 = FUN_80293900((double)local_cc);
  local_cc = (float)dVar8;
  local_c8 = (float)(dVar6 * (double)(float)dVar8 + (double)*(float *)(param_2 + 0xc));
  fVar1 = *(float *)(param_2 + 0xe) + *(float *)(DAT_803de1a8 + 0x8c);
  local_c4 = *(float *)(DAT_803de1a8 + 8) + fVar1;
  local_c0 = (float)(dVar7 * (double)(float)dVar8 + (double)*(float *)(param_2 + 0x10));
  fVar2 = *(float *)(param_2 + 0xc);
  fVar3 = *(float *)(param_2 + 0x10);
  if (param_2[0x22] == 1) {
    FUN_80297334((int)param_2,&local_bc,&local_b8,&local_b4);
    fVar2 = local_bc;
    fVar1 = local_b8;
    fVar3 = local_b4;
  }
  local_b4 = fVar3;
  local_b8 = fVar1;
  local_bc = fVar2;
  FUN_801037c0((double)FLOAT_803e2308,&local_bc,&local_c8,param_3,(int)auStack_b0,3,'\x01','\x01');
  (**(code **)(*DAT_803dd6d0 + 0x38))
            ((double)*(float *)(DAT_803de1a8 + 0x8c),param_1,auStack_d0,&local_d4,auStack_d8,
             &local_cc,0);
  local_d4 = *(float *)(param_1 + 0x1c) -
             (*(float *)(param_2 + 0xe) + *(float *)(DAT_803de1a8 + 0x8c));
  uVar4 = FUN_80021884();
  iVar5 = (uVar4 & 0xffff) - (uint)*(ushort *)(param_1 + 2);
  if (0x8000 < iVar5) {
    iVar5 = iVar5 + -0xffff;
  }
  if (iVar5 < -0x8000) {
    iVar5 = iVar5 + 0xffff;
  }
  if (param_4 != (short *)0x0) {
    *param_4 = *(ushort *)(param_1 + 2) + (short)iVar5;
  }
  return local_42;
}

