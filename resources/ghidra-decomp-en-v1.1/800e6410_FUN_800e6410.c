// Function: FUN_800e6410
// Entry: 800e6410
// Size: 872 bytes

void FUN_800e6410(void)

{
  float fVar1;
  ushort *puVar2;
  uint uVar3;
  uint *puVar4;
  uint *puVar5;
  float *pfVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  undefined8 uVar11;
  float fStack_90;
  float fStack_8c;
  ushort local_88;
  ushort local_86;
  ushort local_84;
  float local_80;
  int local_7c;
  int local_78;
  int local_74;
  float afStack_70 [16];
  undefined4 local_30;
  uint uStack_2c;
  
  uVar11 = FUN_80286838();
  puVar2 = (ushort *)((ulonglong)uVar11 >> 0x20);
  puVar4 = (uint *)uVar11;
  uVar9 = *(byte *)(puVar4 + 0x97) & 0xf;
  *(undefined *)((int)puVar4 + 0x25e) = 0;
  puVar5 = puVar4;
  for (iVar7 = 0; fVar1 = FLOAT_803e12e8, iVar7 < (int)uVar9; iVar7 = iVar7 + 1) {
    if ((*puVar4 & 0x200000) == 0) {
      pfVar6 = (float *)0x4;
    }
    else {
      pfVar6 = (float *)0x2;
    }
    iVar8 = FUN_80064248(puVar5 + 0x45,puVar5 + 0x39,pfVar6,(int *)(puVar4 + 0x51),(int *)puVar2,
                         (uint)*(byte *)((int)puVar4 + 0x25d),0xffffffff,0,*(byte *)(puVar4 + 0x99))
    ;
    *(byte *)((int)puVar4 + 0x25e) = *(byte *)((int)puVar4 + 0x25e) | (byte)(iVar8 << iVar7);
    if ((*puVar4 & 0x2000000) != 0) {
      if ((*puVar4 & 0x200000) == 0) {
        pfVar6 = (float *)0x4;
      }
      else {
        pfVar6 = (float *)0x2;
      }
      FUN_80064248(puVar5 + 0x45,puVar5 + 0x39,pfVar6,(int *)(puVar4 + 0x51),(int *)puVar2,
                   (uint)*(byte *)((int)puVar4 + 0x263),0xffffffff,0,*(byte *)(puVar4 + 0x99));
    }
    puVar5 = puVar5 + 3;
  }
  if (uVar9 < 2) {
    if ((*puVar4 & 0x100000) == 0) {
      *(uint *)(puVar2 + 6) = puVar4[0x39];
      *(uint *)(puVar2 + 10) = puVar4[0x3b];
    }
    goto LAB_800e6690;
  }
  if ((*puVar4 & 0x100000) != 0) goto LAB_800e6690;
  *(float *)(puVar2 + 6) = FLOAT_803e12e8;
  *(float *)(puVar2 + 10) = fVar1;
  uVar3 = (uVar9 * 3 + 2) / 3;
  if (uVar9 * 3 != 0) {
    uVar10 = uVar3 >> 2;
    puVar5 = puVar4;
    if (uVar10 != 0) {
      do {
        *(float *)(puVar2 + 6) = *(float *)(puVar2 + 6) + (float)puVar5[0x39];
        *(float *)(puVar2 + 10) = *(float *)(puVar2 + 10) + (float)puVar5[0x3b];
        *(float *)(puVar2 + 6) = *(float *)(puVar2 + 6) + (float)puVar5[0x3c];
        *(float *)(puVar2 + 10) = *(float *)(puVar2 + 10) + (float)puVar5[0x3e];
        *(float *)(puVar2 + 6) = *(float *)(puVar2 + 6) + (float)puVar5[0x3f];
        *(float *)(puVar2 + 10) = *(float *)(puVar2 + 10) + (float)puVar5[0x41];
        *(float *)(puVar2 + 6) = *(float *)(puVar2 + 6) + (float)puVar5[0x42];
        *(float *)(puVar2 + 10) = *(float *)(puVar2 + 10) + (float)puVar5[0x44];
        puVar5 = puVar5 + 0xc;
        uVar10 = uVar10 - 1;
      } while (uVar10 != 0);
      uVar3 = uVar3 & 3;
      if (uVar3 == 0) goto LAB_800e6630;
    }
    do {
      *(float *)(puVar2 + 6) = *(float *)(puVar2 + 6) + (float)puVar5[0x39];
      *(float *)(puVar2 + 10) = *(float *)(puVar2 + 10) + (float)puVar5[0x3b];
      uVar3 = uVar3 - 1;
      puVar5 = puVar5 + 3;
    } while (uVar3 != 0);
  }
LAB_800e6630:
  local_30 = 0x43300000;
  fVar1 = FLOAT_803e130c / (float)((double)CONCAT44(0x43300000,uVar9) - DOUBLE_803e1318);
  *(float *)(puVar2 + 6) = *(float *)(puVar2 + 6) * fVar1;
  *(float *)(puVar2 + 10) = *(float *)(puVar2 + 10) * fVar1;
  uStack_2c = uVar9;
LAB_800e6690:
  local_88 = *puVar2;
  if ((*puVar4 & 0x20) == 0) {
    local_86 = puVar2[1];
    local_84 = puVar2[2];
  }
  else {
    local_86 = 0;
    local_84 = 0;
  }
  local_80 = FLOAT_803e130c;
  local_7c = *(int *)(puVar2 + 6);
  local_78 = *(int *)(puVar2 + 8);
  local_74 = *(int *)(puVar2 + 10);
  FUN_80021fac(afStack_70,&local_88);
  iVar7 = 0;
  puVar5 = puVar4;
  for (iVar8 = 0; iVar8 < (int)(uVar9 * 3); iVar8 = iVar8 + 3) {
    puVar5[0x45] = puVar5[0x39];
    puVar5[0x47] = puVar5[0x3b];
    pfVar6 = (float *)(puVar4[0x37] + iVar7);
    FUN_80022790((double)*pfVar6,(double)pfVar6[1],(double)pfVar6[2],afStack_70,&fStack_8c,
                 (float *)(puVar4 + iVar8 + 0x46),&fStack_90);
    puVar5 = puVar5 + 3;
    iVar7 = iVar7 + 0xc;
  }
  FUN_80286884();
  return;
}

