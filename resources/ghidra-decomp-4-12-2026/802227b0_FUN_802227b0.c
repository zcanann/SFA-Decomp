// Function: FUN_802227b0
// Entry: 802227b0
// Size: 504 bytes

/* WARNING: Removing unreachable block (ram,0x80222988) */
/* WARNING: Removing unreachable block (ram,0x80222980) */
/* WARNING: Removing unreachable block (ram,0x80222978) */
/* WARNING: Removing unreachable block (ram,0x802227d0) */
/* WARNING: Removing unreachable block (ram,0x802227c8) */
/* WARNING: Removing unreachable block (ram,0x802227c0) */

void FUN_802227b0(undefined8 param_1,double param_2,double param_3,undefined4 param_4,
                 undefined4 param_5,uint param_6,undefined4 *param_7)

{
  int iVar1;
  int iVar2;
  float *pfVar3;
  double extraout_f1;
  double dVar4;
  double dVar5;
  double in_f29;
  double in_f30;
  double in_f31;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  undefined8 uVar6;
  float local_68;
  float local_64;
  float local_60;
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
  uVar6 = FUN_80286840();
  iVar2 = (int)((ulonglong)uVar6 >> 0x20);
  pfVar3 = (float *)uVar6;
  local_68 = *(float *)(iVar2 + 0xc) - pfVar3[0x1a];
  local_60 = *(float *)(iVar2 + 0x14) - pfVar3[0x1c];
  dVar5 = extraout_f1;
  dVar4 = FUN_80293900((double)(local_68 * local_68 + local_60 * local_60));
  if (dVar4 < param_2) {
    iVar1 = FUN_80010340(dVar5,pfVar3);
    if ((iVar1 != 0) || (pfVar3[4] != 0.0)) {
      (**(code **)(*DAT_803dd71c + 0x9c))(pfVar3,*param_7);
      *param_7 = 0;
    }
    param_3 = (double)(float)((double)FLOAT_803e7910 * dVar5);
  }
  local_68 = pfVar3[0x1a] - *(float *)(iVar2 + 0xc);
  local_64 = pfVar3[0x1b] - *(float *)(iVar2 + 0x10);
  local_60 = pfVar3[0x1c] - *(float *)(iVar2 + 0x14);
  if ((param_6 & 0xff) == 0) {
    iVar1 = *(int *)(iVar2 + 0xb8);
    local_68 = *(float *)(iVar2 + 0xc) - pfVar3[0x1a];
    local_60 = *(float *)(iVar2 + 0x14) - pfVar3[0x1c];
    iVar2 = FUN_80021884();
    uStack_54 = -(int)(short)iVar2 ^ 0x80000000;
    local_58 = 0x43300000;
    dVar5 = (double)FUN_802945e0();
    *(float *)(iVar1 + 0x290) = (float)(param_3 * -dVar5);
    dVar5 = (double)FUN_80294964();
    *(float *)(iVar1 + 0x28c) = (float)(param_3 * -dVar5);
  }
  else {
    FUN_80222564(param_3,(double)(float)(param_3 / (double)FLOAT_803e7914),(double)FLOAT_803e7918,
                 iVar2,(float *)(iVar2 + 0x24),&local_68);
  }
  FUN_8028688c();
  return;
}

