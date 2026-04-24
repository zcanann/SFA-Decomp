// Function: FUN_800d955c
// Entry: 800d955c
// Size: 760 bytes

/* WARNING: Removing unreachable block (ram,0x800d9834) */
/* WARNING: Removing unreachable block (ram,0x800d956c) */

void FUN_800d955c(undefined4 param_1,undefined4 param_2,int param_3)

{
  short sVar1;
  bool bVar2;
  bool bVar3;
  double dVar4;
  float fVar5;
  int iVar6;
  int iVar7;
  undefined uVar8;
  uint *puVar9;
  undefined *puVar10;
  int iVar11;
  double extraout_f1;
  double in_f31;
  double dVar12;
  double in_ps31_1;
  undefined8 uVar13;
  undefined auStack_78 [19];
  char local_65 [8];
  char local_5d;
  undefined4 local_58;
  uint uStack_54;
  longlong local_50;
  undefined4 local_48;
  uint uStack_44;
  longlong local_40;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  uVar13 = FUN_80286838();
  iVar6 = (int)((ulonglong)uVar13 >> 0x20);
  puVar9 = (uint *)uVar13;
  bVar3 = false;
  iVar11 = 0;
  DAT_803de0d0 = 0;
  DAT_803de0c0 = '\0';
  dVar12 = extraout_f1;
  if (*(short *)(puVar9 + 0x9d) != *(short *)((int)puVar9 + 0x276)) {
    *(undefined *)((int)puVar9 + 0x27a) = 1;
    *(undefined2 *)(puVar9 + 0xce) = 0;
  }
  do {
    bVar2 = false;
    sVar1 = *(short *)(puVar9 + 0x9d);
    iVar7 = (**(code **)(param_3 + sVar1 * 4))(dVar12,iVar6,puVar9);
    if (iVar7 < 1) {
      if (iVar7 < 0) {
        *(short *)(puVar9 + 0x9d) = (short)-iVar7;
        if (-iVar7 != (int)sVar1) {
          *(short *)((int)puVar9 + 0x276) = sVar1;
          if ((code *)puVar9[0xc1] != (code *)0x0) {
            (*(code *)puVar9[0xc1])(iVar6,puVar9);
            puVar9[0xc1] = 0;
          }
          puVar9[0xc1] = puVar9[0xc2];
          *(undefined *)((int)puVar9 + 0x27a) = 1;
          *(undefined2 *)(puVar9 + 0xce) = 0;
          *(undefined *)((int)puVar9 + 0x34d) = 0;
          *(undefined *)(puVar9 + 0xd3) = 0;
          *(undefined *)((int)puVar9 + 0x356) = 0;
          *(undefined2 *)(puVar9 + 0x9e) = 0;
          if (*(int *)(iVar6 + 0x54) != 0) {
            *(undefined *)(*(int *)(iVar6 + 0x54) + 0x70) = 0;
          }
        }
        bVar2 = true;
        bVar3 = true;
      }
      else {
        bVar2 = true;
      }
    }
    else {
      *(undefined2 *)((int)puVar9 + 0x276) = *(undefined2 *)(puVar9 + 0x9d);
      *(short *)(puVar9 + 0x9d) = (short)iVar7 + -1;
      if ((code *)puVar9[0xc1] != (code *)0x0) {
        (*(code *)puVar9[0xc1])(iVar6,puVar9);
        puVar9[0xc1] = 0;
      }
      puVar9[0xc1] = puVar9[0xc2];
      *(undefined *)((int)puVar9 + 0x27a) = 1;
      *(undefined2 *)(puVar9 + 0xce) = 0;
      *(undefined *)((int)puVar9 + 0x34d) = 0;
      *(undefined *)(puVar9 + 0xd3) = 0;
      *(undefined *)((int)puVar9 + 0x356) = 0;
      *(undefined2 *)(puVar9 + 0x9e) = 0;
      if (*(int *)(iVar6 + 0x54) != 0) {
        *(undefined *)(*(int *)(iVar6 + 0x54) + 0x70) = 0;
      }
    }
    iVar11 = iVar11 + 1;
    if (0xff < iVar11) {
      bVar2 = true;
    }
  } while (!bVar2);
  if (!bVar3) {
    *(undefined *)((int)puVar9 + 0x27a) = 0;
  }
  *(undefined2 *)((int)puVar9 + 0x276) = *(undefined2 *)(puVar9 + 0x9d);
  if ((DAT_803de0c0 == '\0') && ((*(byte *)(puVar9 + 0xd3) & 1) == 0)) {
    local_5d = '\0';
    uVar8 = FUN_8002fb40((double)(float)puVar9[0xa8],dVar12);
    *(undefined *)((int)puVar9 + 0x346) = uVar8;
    puVar9[0xc5] = 0;
    puVar10 = auStack_78;
    for (iVar11 = 0; iVar11 < local_5d; iVar11 = iVar11 + 1) {
      puVar9[0xc5] = puVar9[0xc5] | 1 << (int)(char)puVar10[0x13];
      puVar10 = puVar10 + 1;
    }
    *puVar9 = *puVar9 & 0xfffeffff;
  }
  fVar5 = FLOAT_803e1240;
  dVar4 = DOUBLE_803e1218;
  if ((*puVar9 & 0x4000) == 0) {
    uStack_54 = (int)*(short *)(iVar6 + 2) ^ 0x80000000;
    local_58 = 0x43300000;
    iVar11 = (int)((float)((double)(float)((double)CONCAT44(0x43300000,uStack_54) - DOUBLE_803e1218)
                          * dVar12) * FLOAT_803e1240);
    local_50 = (longlong)iVar11;
    *(short *)(iVar6 + 2) = *(short *)(iVar6 + 2) - (short)iVar11;
    uStack_44 = (int)*(short *)(iVar6 + 4) ^ 0x80000000;
    local_48 = 0x43300000;
    iVar11 = (int)((float)((double)(float)((double)CONCAT44(0x43300000,uStack_44) - dVar4) * dVar12)
                  * fVar5);
    local_40 = (longlong)iVar11;
    *(short *)(iVar6 + 4) = *(short *)(iVar6 + 4) - (short)iVar11;
  }
  FUN_80286884();
  return;
}

