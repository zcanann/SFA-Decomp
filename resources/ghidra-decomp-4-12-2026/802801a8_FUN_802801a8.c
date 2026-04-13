// Function: FUN_802801a8
// Entry: 802801a8
// Size: 196 bytes

void FUN_802801a8(void)

{
  float *pfVar1;
  float *pfVar2;
  float *pfVar3;
  float fVar4;
  double dVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  int iVar8;
  
  dVar5 = DOUBLE_803e8520;
  iVar8 = 0;
  for (puVar6 = DAT_803defd8; puVar6 != (undefined4 *)0x0; puVar6 = (undefined4 *)*puVar6) {
    iVar8 = iVar8 + 1;
  }
  puVar6 = DAT_803defdc;
  if (iVar8 != 0) {
    for (; puVar6 != (undefined4 *)0x0; puVar6 = (undefined4 *)*puVar6) {
      puVar7 = DAT_803defd8;
      fVar4 = FLOAT_803e8518;
      if (*(char *)(puVar6 + 7) != -1) {
        for (; puVar7 != (undefined4 *)0x0; puVar7 = (undefined4 *)*puVar7) {
          pfVar1 = (float *)(puVar7 + 4);
          pfVar2 = (float *)(puVar7 + 5);
          pfVar3 = (float *)(puVar7 + 6);
          fVar4 = fVar4 + ((float)puVar6[5] - *pfVar3) * ((float)puVar6[5] - *pfVar3) +
                          ((float)puVar6[3] - *pfVar1) * ((float)puVar6[3] - *pfVar1) +
                          ((float)puVar6[4] - *pfVar2) * ((float)puVar6[4] - *pfVar2);
        }
        puVar6[6] = fVar4 / (float)((double)CONCAT44(0x43300000,iVar8) - dVar5);
      }
    }
  }
  return;
}

