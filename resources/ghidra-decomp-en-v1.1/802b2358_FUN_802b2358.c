// Function: FUN_802b2358
// Entry: 802b2358
// Size: 612 bytes

/* WARNING: Removing unreachable block (ram,0x802b2594) */
/* WARNING: Removing unreachable block (ram,0x802b258c) */
/* WARNING: Removing unreachable block (ram,0x802b2370) */
/* WARNING: Removing unreachable block (ram,0x802b2368) */

void FUN_802b2358(int param_1,int param_2,uint *param_3)

{
  double dVar1;
  double dVar2;
  double dVar3;
  float fStack_d8;
  ushort local_d4 [4];
  float local_cc;
  float local_c8;
  float local_c4;
  float local_c0;
  float afStack_bc [17];
  undefined4 local_78;
  uint uStack_74;
  longlong local_70;
  undefined4 local_68;
  uint uStack_64;
  longlong local_60;
  undefined4 local_58;
  uint uStack_54;
  undefined4 local_50;
  uint uStack_4c;
  undefined4 local_48;
  uint uStack_44;
  undefined4 local_40;
  uint uStack_3c;
  
  if (((*(byte *)(param_3 + 0xd3) & 2) == 0) && ((*(byte *)(param_3 + 0xd3) & 1) == 0)) {
    dVar3 = (double)(float)param_3[0xa0];
    dVar2 = (double)(float)param_3[0xa1];
    if ((*(byte *)(param_2 + 0x3f0) >> 5 & 1) != 0) {
      dVar3 = (double)(float)(dVar3 + (double)*(float *)(param_2 + 0x43c));
      dVar2 = (double)(float)(dVar2 + (double)*(float *)(param_2 + 0x440));
    }
    local_d4[0] = *(ushort *)(param_2 + 0x484);
    local_d4[1] = 0;
    local_d4[2] = 0;
    local_cc = FLOAT_803e8b78;
    local_c8 = FLOAT_803e8b3c;
    local_c4 = FLOAT_803e8b3c;
    local_c0 = FLOAT_803e8b3c;
    FUN_80021fac(afStack_bc,local_d4);
    FUN_80022790(dVar2,(double)FLOAT_803e8b3c,-dVar3,afStack_bc,(float *)(param_1 + 0x24),&fStack_d8
                 ,(float *)(param_1 + 0x2c));
    *(float *)(param_1 + 0x24) = *(float *)(param_1 + 0x24) + *(float *)(param_2 + 0x890);
    *(float *)(param_1 + 0x2c) = *(float *)(param_1 + 0x2c) + *(float *)(param_2 + 0x894);
  }
  else {
    uStack_74 = (int)*(short *)(param_2 + 0x484) ^ 0x80000000;
    local_78 = 0x43300000;
    dVar3 = (double)FUN_802945e0();
    local_70 = (longlong)(int)dVar3;
    uStack_64 = (int)*(short *)(param_2 + 0x484) ^ 0x80000000;
    local_68 = 0x43300000;
    dVar1 = (double)FUN_80294964();
    dVar2 = DOUBLE_803e8b58;
    local_60 = (longlong)(int)dVar1;
    uStack_54 = (int)dVar1 ^ 0x80000000;
    local_58 = 0x43300000;
    uStack_4c = (int)dVar3 ^ 0x80000000;
    local_50 = 0x43300000;
    param_3[0xa1] =
         (uint)(*(float *)(param_1 + 0x24) *
                (float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e8b58) -
               *(float *)(param_1 + 0x2c) *
               (float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e8b58));
    local_48 = 0x43300000;
    local_40 = 0x43300000;
    param_3[0xa0] =
         (uint)(-*(float *)(param_1 + 0x2c) *
                (float)((double)CONCAT44(0x43300000,uStack_54) - dVar2) -
               *(float *)(param_1 + 0x24) * (float)((double)CONCAT44(0x43300000,uStack_4c) - dVar2))
    ;
    uStack_44 = uStack_54;
    uStack_3c = uStack_4c;
  }
  if ((*param_3 & 0x200000) == 0) {
    dVar2 = (double)FUN_802932a4((double)FLOAT_803e8dd8,(double)FLOAT_803dc074);
    *(float *)(param_1 + 0x28) = (float)((double)*(float *)(param_1 + 0x28) * dVar2);
    *(float *)(param_1 + 0x28) =
         -((float)param_3[0xa9] * FLOAT_803dc074 - *(float *)(param_1 + 0x28));
  }
  return;
}

