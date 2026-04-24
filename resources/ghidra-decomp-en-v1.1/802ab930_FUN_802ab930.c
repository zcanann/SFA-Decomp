// Function: FUN_802ab930
// Entry: 802ab930
// Size: 444 bytes

/* WARNING: Removing unreachable block (ram,0x802abacc) */
/* WARNING: Removing unreachable block (ram,0x802abac4) */
/* WARNING: Removing unreachable block (ram,0x802ababc) */
/* WARNING: Removing unreachable block (ram,0x802ab950) */
/* WARNING: Removing unreachable block (ram,0x802ab948) */
/* WARNING: Removing unreachable block (ram,0x802ab940) */

void FUN_802ab930(void)

{
  float fVar1;
  float fVar2;
  float fVar3;
  ushort *puVar4;
  undefined4 *puVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  double in_f29;
  double dVar9;
  double in_f30;
  double dVar10;
  double in_f31;
  double dVar11;
  double in_ps29_1;
  double in_ps30_1;
  double in_ps31_1;
  int local_58 [2];
  undefined4 local_50;
  uint uStack_4c;
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
  puVar4 = (ushort *)FUN_80286840();
  if (((puVar4[0x58] & 0x1000) == 0) && (*(int *)(*(int *)(puVar4 + 0x5c) + 0x2d0) == 0)) {
    puVar5 = FUN_80037048(8,local_58);
    iVar7 = 0;
    dVar10 = (double)FLOAT_803e8b3c;
    while (iVar7 < local_58[0]) {
      iVar6 = iVar7 + 1;
      iVar8 = puVar5[iVar7];
      iVar7 = iVar6;
      if ((((*(short *)(iVar8 + 0x44) == 0x1c) || (*(short *)(iVar8 + 0x44) == 0x2a)) &&
          (*(char *)(iVar8 + 0x36) == -1)) &&
         (fVar1 = *(float *)(iVar8 + 0x18) - *(float *)(puVar4 + 0xc),
         fVar2 = *(float *)(iVar8 + 0x1c) - *(float *)(puVar4 + 0xe),
         fVar3 = *(float *)(iVar8 + 0x20) - *(float *)(puVar4 + 0x10),
         dVar11 = (double)(fVar3 * fVar3 + fVar1 * fVar1 + fVar2 * fVar2),
         dVar11 < (double)FLOAT_803e8d80)) {
        if (dVar11 <= (double)FLOAT_803e8b3c) {
          uStack_4c = (int)*(char *)(*(int *)(iVar8 + 0x50) + 0x56) ^ 0x80000000;
          local_50 = 0x43300000;
          dVar9 = (double)(float)((double)CONCAT44(0x43300000,uStack_4c) - DOUBLE_803e8b58);
          if (dVar9 <= (double)FLOAT_803e8b3c) {
            dVar9 = (double)FLOAT_803e8b78;
          }
          dVar11 = FUN_80293900(dVar11);
          dVar11 = (double)(float)(dVar11 / dVar9);
        }
        iVar6 = FUN_800386e0(puVar4,iVar8,(float *)0x0);
        if ((((short)iVar6 < 0x5555) && (-0x5555 < (short)iVar6)) &&
           ((dVar11 < dVar10 || ((double)FLOAT_803e8b3c == dVar10)))) {
          dVar10 = dVar11;
        }
      }
    }
  }
  FUN_8028688c();
  return;
}

