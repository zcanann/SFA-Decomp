// Function: FUN_8015ce68
// Entry: 8015ce68
// Size: 560 bytes

/* WARNING: Removing unreachable block (ram,0x8015d074) */

void FUN_8015ce68(short *param_1,int param_2)

{
  float fVar1;
  undefined4 uVar2;
  int iVar3;
  undefined4 uVar4;
  double dVar5;
  double dVar6;
  undefined8 in_f31;
  float local_98;
  float local_94;
  float local_90;
  undefined auStack140 [12];
  float local_80;
  float local_7c;
  float local_78;
  undefined auStack116 [48];
  float local_44;
  float local_40;
  float local_3c;
  undefined4 local_30;
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  undefined auStack8 [8];
  
  uVar4 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar3 = *(int *)(param_2 + 0x40c);
  uVar2 = FUN_800383a0(param_1,1);
  FUN_80003494(auStack116,uVar2,0x40);
  local_3c = FLOAT_803e2d14;
  local_40 = FLOAT_803e2d14;
  local_44 = FLOAT_803e2d14;
  fVar1 = FLOAT_803e2d2c;
  if (param_1[0x23] == 99) {
    fVar1 = FLOAT_803e2d48;
  }
  dVar5 = (double)*(float *)(param_2 + 0x280);
  if (dVar5 < (double)fVar1) {
    dVar5 = (double)fVar1;
  }
  if (*(short *)(param_2 + 0x274) == 4) {
    FUN_8003842c(param_1,0,iVar3 + 0x2c,iVar3 + 0x30,iVar3 + 0x34,0);
  }
  else {
    FUN_8003842c(param_1,2,iVar3 + 0x2c,iVar3 + 0x30,iVar3 + 0x34,0);
  }
  *(float *)(iVar3 + 0x30) = FLOAT_803e2d90 + *(float *)(param_1 + 8);
  uStack44 = (int)*param_1 ^ 0x80000000;
  local_30 = 0x43300000;
  dVar6 = (double)FUN_80293e80((double)((FLOAT_803e2d98 *
                                        (float)((double)CONCAT44(0x43300000,uStack44) -
                                               DOUBLE_803e2d68)) / FLOAT_803e2d9c));
  *(float *)(iVar3 + 0x2c) =
       -(float)(dVar5 * (double)(float)((double)FLOAT_803e2d94 * dVar6) -
               (double)*(float *)(iVar3 + 0x2c));
  uStack36 = (int)*param_1 ^ 0x80000000;
  local_28 = 0x43300000;
  dVar6 = (double)FUN_80294204((double)((FLOAT_803e2d98 *
                                        (float)((double)CONCAT44(0x43300000,uStack36) -
                                               DOUBLE_803e2d68)) / FLOAT_803e2d9c));
  *(float *)(iVar3 + 0x34) =
       -(float)(dVar5 * (double)(float)((double)FLOAT_803e2d94 * dVar6) -
               (double)*(float *)(iVar3 + 0x34));
  local_80 = FLOAT_803e2d14;
  local_7c = FLOAT_803e2da0;
  local_78 = FLOAT_803e2da4;
  FUN_8003842c(param_1,0,&local_80,&local_7c,&local_78,1);
  if ((*(byte *)(iVar3 + 0x44) & 2) != 0) {
    local_98 = FLOAT_803e2da8;
    local_94 = FLOAT_803e2dac;
    local_90 = FLOAT_803e2da4;
    FUN_800226cc(auStack116,&local_98,&local_94,&local_90);
    FUN_80003494(iVar3 + 0x38,&local_98,0xc);
    FUN_80003494(iVar3 + 8,auStack140,0x18);
    *(byte *)(iVar3 + 0x44) = *(byte *)(iVar3 + 0x44) | 1;
  }
  __psq_l0(auStack8,uVar4);
  __psq_l1(auStack8,uVar4);
  return;
}

