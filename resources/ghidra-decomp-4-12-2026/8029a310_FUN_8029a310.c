// Function: FUN_8029a310
// Entry: 8029a310
// Size: 660 bytes

/* WARNING: Removing unreachable block (ram,0x8029a584) */
/* WARNING: Removing unreachable block (ram,0x8029a444) */
/* WARNING: Removing unreachable block (ram,0x8029a320) */

void FUN_8029a310(undefined8 param_1,undefined8 param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  byte bVar1;
  float fVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar6;
  double dVar7;
  double in_f31;
  double in_ps31_1;
  undefined8 uVar8;
  float local_48;
  float local_44;
  float local_40;
  float local_3c;
  undefined4 local_38;
  uint uStack_34;
  undefined4 local_30;
  uint uStack_2c;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar8 = FUN_8028683c();
  iVar3 = (int)((ulonglong)uVar8 >> 0x20);
  iVar5 = (int)uVar8;
  iVar6 = *(int *)(iVar3 + 0xb8);
  local_48 = FLOAT_803e8bf4;
  iVar4 = FUN_80036f50(0x3e,iVar3,&local_48);
  *(byte *)(iVar6 + 0x3f4) = *(byte *)(iVar6 + 0x3f4) & 0xdf | 0x20;
  fVar2 = FLOAT_803e8b3c;
  dVar7 = (double)FLOAT_803e8b3c;
  *(float *)(iVar6 + 0x414) = FLOAT_803e8b3c;
  if (iVar4 == 0) {
    *(byte *)(iVar6 + 0x8aa) = *(byte *)(iVar6 + 0x8aa) ^ 1;
  }
  else {
    local_44 = *(float *)(iVar4 + 0xc) - *(float *)(iVar3 + 0xc);
    local_3c = *(float *)(iVar4 + 0x14) - *(float *)(iVar3 + 0x14);
    local_40 = fVar2;
    FUN_800228f0(&local_44);
    uStack_34 = (int)*(short *)(iVar6 + 0x478) ^ 0x80000000;
    local_38 = 0x43300000;
    FUN_802945e0();
    dVar7 = (double)FLOAT_803e8c2c;
    uStack_2c = (int)*(short *)(iVar6 + 0x478) ^ 0x80000000;
    local_30 = 0x43300000;
    FUN_80294964();
    bVar1 = *(byte *)(*(int *)(iVar4 + 0x50) + 0x75);
    if (bVar1 != 2) {
      if (bVar1 < 2) {
        if (bVar1 != 0) goto LAB_8029a4d4;
      }
      else if (bVar1 < 4) {
        dVar7 = (double)local_3c;
        goto LAB_8029a4d4;
      }
      *(byte *)(iVar6 + 0x8aa) = *(byte *)(iVar6 + 0x8aa) ^ 1;
    }
  }
LAB_8029a4d4:
  if ((*(char *)(iVar5 + 0x34b) != '\x02') || (*(float *)(iVar5 + 0x298) <= FLOAT_803e8b44)) {
    FUN_8003042c((double)FLOAT_803e8b3c,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,
                 (int)*(short *)(&DAT_8033431c + *(short *)(*(int *)(iVar6 + 0x3dc) + 0x11e2) * 2),0
                 ,in_r6,in_r7,in_r8,in_r9,in_r10);
    *(undefined *)(iVar6 + 0x8a9) = 0x1a;
    *(code **)(iVar5 + 0x308) = FUN_8029c368;
  }
  else {
    FUN_8003042c((double)FLOAT_803e8b3c,dVar7,param_3,param_4,param_5,param_6,param_7,param_8,iVar3,
                 (int)*(short *)(&DAT_8033431c + *(short *)(*(int *)(iVar6 + 0x3dc) + 0x11e2) * 2),0
                 ,in_r6,in_r7,in_r8,in_r9,in_r10);
    *(undefined *)(iVar6 + 0x8a9) = 0x1a;
    *(code **)(iVar5 + 0x308) = FUN_8029c368;
  }
  FUN_80286888();
  return;
}

