// Function: FUN_8010de18
// Entry: 8010de18
// Size: 424 bytes

/* WARNING: Removing unreachable block (ram,0x8010dfa0) */
/* WARNING: Removing unreachable block (ram,0x8010df98) */
/* WARNING: Removing unreachable block (ram,0x8010df90) */
/* WARNING: Removing unreachable block (ram,0x8010df88) */
/* WARNING: Removing unreachable block (ram,0x8010de40) */
/* WARNING: Removing unreachable block (ram,0x8010de38) */
/* WARNING: Removing unreachable block (ram,0x8010de30) */
/* WARNING: Removing unreachable block (ram,0x8010de28) */

void FUN_8010de18(undefined4 param_1,undefined4 param_2,float *param_3,float *param_4)

{
  float fVar1;
  float *pfVar2;
  int iVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_8028683c();
  pfVar2 = DAT_803de1fc;
  iVar3 = (int)((ulonglong)uVar9 >> 0x20);
  dVar7 = (double)(*(float *)(iVar3 + 0x18) - *DAT_803de1fc);
  dVar5 = (double)(*(float *)(iVar3 + 0x20) - DAT_803de1fc[2]);
  dVar4 = FUN_80293900((double)(float)(dVar7 * dVar7 + (double)(float)(dVar5 * dVar5)));
  FUN_80021884();
  dVar8 = (double)((float)(dVar7 * (double)DAT_803de1fc[0x11]) + *pfVar2);
  dVar6 = (double)((float)(dVar5 * (double)DAT_803de1fc[0x11]) + pfVar2[2]);
  dVar5 = (double)FUN_802945e0();
  dVar7 = (double)FUN_80294964();
  if (dVar4 < (double)DAT_803de1fc[0x10]) {
    dVar4 = (double)DAT_803de1fc[0x10];
  }
  fVar1 = DAT_803de1fc[4];
  *(float *)uVar9 = (float)(dVar5 * (double)(float)(dVar4 + (double)fVar1) + dVar8);
  *param_3 = -(FLOAT_803e2658 * ((FLOAT_803e265c + *(float *)(iVar3 + 0x1c)) - pfVar2[1]) -
              (*(float *)(iVar3 + 0x1c) + DAT_803de1fc[0xc]));
  *param_4 = (float)(dVar7 * (double)(float)(dVar4 + (double)fVar1) + dVar6);
  FUN_80286888();
  return;
}

