// Function: FUN_8005acec
// Entry: 8005acec
// Size: 892 bytes

/* WARNING: Removing unreachable block (ram,0x8005b040) */
/* WARNING: Removing unreachable block (ram,0x8005b038) */
/* WARNING: Removing unreachable block (ram,0x8005b030) */
/* WARNING: Removing unreachable block (ram,0x8005b028) */
/* WARNING: Removing unreachable block (ram,0x8005b020) */
/* WARNING: Removing unreachable block (ram,0x8005b018) */
/* WARNING: Removing unreachable block (ram,0x8005ad24) */
/* WARNING: Removing unreachable block (ram,0x8005ad1c) */
/* WARNING: Removing unreachable block (ram,0x8005ad14) */
/* WARNING: Removing unreachable block (ram,0x8005ad0c) */
/* WARNING: Removing unreachable block (ram,0x8005ad04) */
/* WARNING: Removing unreachable block (ram,0x8005acfc) */

void FUN_8005acec(void)

{
  float fVar1;
  undefined2 *puVar2;
  double dVar3;
  double dVar4;
  double dVar5;
  double dVar6;
  double dVar7;
  double dVar8;
  float local_e8;
  float local_e4;
  float local_e0;
  ushort local_dc;
  short local_da;
  undefined2 local_d8;
  float local_d4;
  float local_d0;
  float local_cc;
  float local_c8;
  float afStack_c4 [17];
  longlong local_80;
  
  puVar2 = FUN_8000facc();
  if (((DAT_803dda68 & 8) == 0) && ((DAT_803dda68 & 0x10000) == 0)) {
    dVar3 = FUN_8000fc54();
    dVar3 = dVar3 * (double)FLOAT_803df87c;
  }
  else {
    dVar3 = FUN_8000fc54();
    dVar3 = dVar3 / (double)FLOAT_803df878;
  }
  dVar3 = (double)(float)dVar3;
  dVar8 = (double)(*(float *)(puVar2 + 0x22) - FLOAT_803dda58);
  dVar7 = (double)*(float *)(puVar2 + 0x24);
  dVar6 = (double)(*(float *)(puVar2 + 0x26) - FLOAT_803dda5c);
  local_d0 = FLOAT_803df84c;
  local_cc = FLOAT_803df84c;
  local_c8 = FLOAT_803df84c;
  local_d4 = FLOAT_803df85c;
  local_dc = 0x8000 - puVar2[0x28];
  local_da = -puVar2[0x29];
  local_d8 = puVar2[0x2a];
  FUN_80021fac(afStack_c4,&local_dc);
  FUN_80022790((double)FLOAT_803df84c,(double)FLOAT_803df84c,(double)FLOAT_803df880,afStack_c4,
               &local_e0,&local_e4,&local_e8);
  DAT_8038859c = local_e0;
  DAT_803885a0 = local_e4;
  DAT_803885a4 = local_e8;
  DAT_803885a8 = -(float)(dVar6 * (double)local_e8 +
                         (double)(float)(dVar8 * (double)local_e0 +
                                        (double)(float)(dVar7 * (double)local_e4)));
  local_80 = (longlong)(int)((double)FLOAT_803df884 * dVar3);
  dVar3 = (double)FUN_80294224();
  dVar4 = (double)FUN_80293d0c();
  fVar1 = (float)(dVar4 / dVar3) * (float)(dVar4 / dVar3);
  FUN_80293900((double)(FLOAT_803df888 * FLOAT_803df888 * fVar1 + fVar1));
  FUN_802929a8();
  dVar3 = (double)FUN_802947f8();
  dVar4 = (double)FUN_80294b54();
  dVar3 = -dVar3;
  FUN_80022790(dVar4,(double)FLOAT_803df84c,dVar3,afStack_c4,&local_e0,&local_e4,&local_e8);
  DAT_803885b0 = local_e0;
  DAT_803885b4 = local_e4;
  DAT_803885b8 = local_e8;
  DAT_803885bc = -(float)(dVar6 * (double)local_e8 +
                         (double)(float)(dVar8 * (double)local_e0 +
                                        (double)(float)(dVar7 * (double)local_e4)));
  dVar5 = -dVar4;
  FUN_80022790(dVar5,(double)FLOAT_803df84c,dVar3,afStack_c4,&local_e0,&local_e4,&local_e8);
  DAT_803885c4 = local_e0;
  DAT_803885c8 = local_e4;
  DAT_803885cc = local_e8;
  DAT_803885d0 = -(float)(dVar6 * (double)local_e8 +
                         (double)(float)(dVar8 * (double)local_e0 +
                                        (double)(float)(dVar7 * (double)local_e4)));
  FUN_80022790((double)FLOAT_803df84c,dVar5,dVar3,afStack_c4,&local_e0,&local_e4,&local_e8);
  DAT_803885d8 = local_e0;
  DAT_803885dc = local_e4;
  DAT_803885e0 = local_e8;
  DAT_803885e4 = -(float)(dVar6 * (double)local_e8 +
                         (double)(float)(dVar8 * (double)local_e0 +
                                        (double)(float)(dVar7 * (double)local_e4)));
  FUN_80022790((double)FLOAT_803df84c,dVar4,dVar3,afStack_c4,&local_e0,&local_e4,&local_e8);
  DAT_803885ec = local_e0;
  DAT_803885f0 = local_e4;
  DAT_803885f4 = local_e8;
  DAT_803885f8 = -(float)(dVar6 * (double)local_e8 +
                         (double)(float)(dVar8 * (double)local_e0 +
                                        (double)(float)(dVar7 * (double)local_e4)));
  FUN_8005aa20(&DAT_8038859c,5);
  return;
}

