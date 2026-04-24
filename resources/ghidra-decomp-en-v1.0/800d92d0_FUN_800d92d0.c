// Function: FUN_800d92d0
// Entry: 800d92d0
// Size: 760 bytes

/* WARNING: Removing unreachable block (ram,0x800d95a8) */

void FUN_800d92d0(undefined4 param_1,undefined4 param_2,int param_3)

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
  undefined4 uVar12;
  double extraout_f1;
  undefined8 in_f31;
  double dVar13;
  undefined8 uVar14;
  undefined auStack120 [19];
  char local_65 [8];
  char local_5d;
  undefined4 local_58;
  uint uStack84;
  longlong local_50;
  undefined4 local_48;
  uint uStack68;
  longlong local_40;
  undefined auStack8 [8];
  
  uVar12 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  uVar14 = FUN_802860d4();
  iVar6 = (int)((ulonglong)uVar14 >> 0x20);
  puVar9 = (uint *)uVar14;
  bVar3 = false;
  iVar11 = 0;
  DAT_803dd450 = 0;
  DAT_803dd440 = '\0';
  dVar13 = extraout_f1;
  if (*(short *)(puVar9 + 0x9d) != *(short *)((int)puVar9 + 0x276)) {
    *(undefined *)((int)puVar9 + 0x27a) = 1;
    *(undefined2 *)(puVar9 + 0xce) = 0;
  }
  do {
    bVar2 = false;
    sVar1 = *(short *)(puVar9 + 0x9d);
    iVar7 = (**(code **)(param_3 + sVar1 * 4))(dVar13,iVar6,puVar9);
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
  if ((DAT_803dd440 == '\0') && ((*(byte *)(puVar9 + 0xd3) & 1) == 0)) {
    local_5d = '\0';
    uVar8 = FUN_8002fa48((double)(float)puVar9[0xa8],dVar13,iVar6,auStack120);
    *(undefined *)((int)puVar9 + 0x346) = uVar8;
    puVar9[0xc5] = 0;
    puVar10 = auStack120;
    for (iVar11 = 0; iVar11 < local_5d; iVar11 = iVar11 + 1) {
      puVar9[0xc5] = puVar9[0xc5] | 1 << (int)(char)puVar10[0x13];
      puVar10 = puVar10 + 1;
    }
    *puVar9 = *puVar9 & 0xfffeffff;
  }
  fVar5 = FLOAT_803e05c0;
  dVar4 = DOUBLE_803e0598;
  if ((*puVar9 & 0x4000) == 0) {
    uStack84 = (int)*(short *)(iVar6 + 2) ^ 0x80000000;
    local_58 = 0x43300000;
    iVar11 = (int)((float)((double)(float)((double)CONCAT44(0x43300000,uStack84) - DOUBLE_803e0598)
                          * dVar13) * FLOAT_803e05c0);
    local_50 = (longlong)iVar11;
    *(short *)(iVar6 + 2) = *(short *)(iVar6 + 2) - (short)iVar11;
    uStack68 = (int)*(short *)(iVar6 + 4) ^ 0x80000000;
    local_48 = 0x43300000;
    iVar11 = (int)((float)((double)(float)((double)CONCAT44(0x43300000,uStack68) - dVar4) * dVar13)
                  * fVar5);
    local_40 = (longlong)iVar11;
    *(short *)(iVar6 + 4) = *(short *)(iVar6 + 4) - (short)iVar11;
  }
  __psq_l0(auStack8,uVar12);
  __psq_l1(auStack8,uVar12);
  FUN_80286120();
  return;
}

