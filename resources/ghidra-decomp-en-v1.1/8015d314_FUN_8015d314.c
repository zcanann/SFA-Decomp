// Function: FUN_8015d314
// Entry: 8015d314
// Size: 560 bytes

/* WARNING: Removing unreachable block (ram,0x8015d520) */
/* WARNING: Removing unreachable block (ram,0x8015d324) */

void FUN_8015d314(short *param_1,int param_2)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  float local_98;
  float local_94;
  float local_90;
  undefined auStack_8c [12];
  float local_80;
  float local_7c;
  float local_78;
  float afStack_74 [12];
  float local_44;
  float local_40;
  float local_3c;
  undefined4 local_30;
  uint uStack_2c;
  undefined4 local_28;
  uint uStack_24;
  
  iVar3 = *(int *)(param_2 + 0x40c);
  uVar2 = FUN_80038498((int)param_1,1);
  FUN_80003494((uint)afStack_74,uVar2,0x40);
  local_3c = FLOAT_803e39ac;
  local_40 = FLOAT_803e39ac;
  local_44 = FLOAT_803e39ac;
  fVar1 = FLOAT_803e39c4;
  if (param_1[0x23] == 99) {
    fVar1 = FLOAT_803e39e0;
  }
  dVar4 = (double)*(float *)(param_2 + 0x280);
  if (dVar4 < (double)fVar1) {
    dVar4 = (double)fVar1;
  }
  if (*(short *)(param_2 + 0x274) == 4) {
    FUN_80038524(param_1,0,(float *)(iVar3 + 0x2c),(undefined4 *)(iVar3 + 0x30),
                 (float *)(iVar3 + 0x34),0);
  }
  else {
    FUN_80038524(param_1,2,(float *)(iVar3 + 0x2c),(undefined4 *)(iVar3 + 0x30),
                 (float *)(iVar3 + 0x34),0);
  }
  *(float *)(iVar3 + 0x30) = FLOAT_803e3a28 + *(float *)(param_1 + 8);
  uStack_2c = (int)*param_1 ^ 0x80000000;
  local_30 = 0x43300000;
  dVar5 = (double)FUN_802945e0();
  *(float *)(iVar3 + 0x2c) =
       -(float)(dVar4 * (double)(float)((double)FLOAT_803e3a2c * dVar5) -
               (double)*(float *)(iVar3 + 0x2c));
  uStack_24 = (int)*param_1 ^ 0x80000000;
  local_28 = 0x43300000;
  dVar5 = (double)FUN_80294964();
  *(float *)(iVar3 + 0x34) =
       -(float)(dVar4 * (double)(float)((double)FLOAT_803e3a2c * dVar5) -
               (double)*(float *)(iVar3 + 0x34));
  local_80 = FLOAT_803e39ac;
  local_7c = FLOAT_803e3a38;
  local_78 = FLOAT_803e3a3c;
  FUN_80038524(param_1,0,&local_80,&local_7c,&local_78,1);
  if ((*(byte *)(iVar3 + 0x44) & 2) != 0) {
    local_98 = FLOAT_803e3a40;
    local_94 = FLOAT_803e3a44;
    local_90 = FLOAT_803e3a3c;
    FUN_80022790((double)FLOAT_803e3a40,(double)FLOAT_803e3a44,(double)FLOAT_803e3a3c,afStack_74,
                 &local_98,&local_94,&local_90);
    FUN_80003494(iVar3 + 0x38,(uint)&local_98,0xc);
    FUN_80003494(iVar3 + 8,(uint)auStack_8c,0x18);
    *(byte *)(iVar3 + 0x44) = *(byte *)(iVar3 + 0x44) | 1;
  }
  return;
}

