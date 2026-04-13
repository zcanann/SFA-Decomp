// Function: FUN_8010f5c4
// Entry: 8010f5c4
// Size: 456 bytes

/* WARNING: Removing unreachable block (ram,0x8010f768) */
/* WARNING: Removing unreachable block (ram,0x8010f760) */
/* WARNING: Removing unreachable block (ram,0x8010f758) */
/* WARNING: Removing unreachable block (ram,0x8010f5e4) */
/* WARNING: Removing unreachable block (ram,0x8010f5dc) */
/* WARNING: Removing unreachable block (ram,0x8010f5d4) */

void FUN_8010f5c4(short *param_1)

{
  float fVar1;
  short sVar2;
  short *psVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  float local_68;
  float local_64;
  float local_60;
  float local_5c;
  longlong local_58;
  undefined4 local_50;
  uint uStack_4c;
  
  local_68 = FLOAT_803e2708;
  local_64 = FLOAT_803e270c;
  local_60 = FLOAT_803e2708;
  local_5c = FLOAT_803e2708;
  dVar4 = FUN_80010de0((double)*(float *)(DAT_803de208 + 4),&local_68,(float *)0x0);
  psVar3 = *(short **)(param_1 + 0x52);
  local_58 = (longlong)(int)((double)FLOAT_803e2710 * dVar4);
  sVar2 = (-0x8000 - *psVar3) + (short)(int)((double)FLOAT_803e2710 * dVar4);
  uStack_4c = (int)sVar2 ^ 0x80000000;
  local_50 = 0x43300000;
  dVar5 = (double)FUN_80294964();
  dVar6 = (double)FUN_802945e0();
  dVar8 = (double)FLOAT_803e271c;
  dVar7 = (double)FLOAT_803e2720;
  *(float *)(param_1 + 6) =
       *(float *)(psVar3 + 0xc) + (float)(dVar8 * dVar5 - (double)(float)(dVar7 * dVar6));
  *(float *)(param_1 + 10) =
       *(float *)(psVar3 + 0x10) + (float)(dVar8 * dVar6 + (double)(float)(dVar7 * dVar5));
  fVar1 = FLOAT_803e2724;
  *(float *)(param_1 + 8) =
       -(float)((double)FLOAT_803e2728 * dVar4 - (double)(FLOAT_803e2724 + *(float *)(psVar3 + 0xe))
               );
  param_1[1] = 0x11c6 - (short)(int)(fVar1 * (float)((double)FLOAT_803e272c * dVar4));
  *param_1 = sVar2 + 0x1ffe;
  param_1[2] = 0;
  *(undefined *)((int)param_1 + 0x13b) = 0;
  *(float *)(param_1 + 0x5a) = FLOAT_803e2730;
  *(float *)(DAT_803de208 + 4) = FLOAT_803e2734 * FLOAT_803dc074 + *(float *)(DAT_803de208 + 4);
  if (FLOAT_803e270c < *(float *)(DAT_803de208 + 4)) {
    *(float *)(DAT_803de208 + 4) = FLOAT_803e270c;
  }
  return;
}

