// Function: FUN_80170f70
// Entry: 80170f70
// Size: 808 bytes

/* WARNING: Removing unreachable block (ram,0x80171278) */

void FUN_80170f70(void)

{
  int iVar1;
  uint uVar2;
  undefined4 *puVar3;
  undefined4 *puVar4;
  float *pfVar5;
  int iVar6;
  int iVar7;
  int iVar8;
  float *pfVar9;
  undefined4 uVar10;
  double dVar11;
  undefined8 in_f31;
  double dVar12;
  double local_58;
  double local_50;
  undefined auStack8 [8];
  
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar1 = FUN_802860cc();
  pfVar9 = (float *)&DAT_80320a28;
  iVar8 = *(int *)(iVar1 + 0xb8);
  if (*(float *)(iVar8 + 4) != *(float *)(iVar8 + 8)) {
    *(float *)(iVar8 + 4) = *(float *)(iVar8 + 0xc) * FLOAT_803db414 + *(float *)(iVar8 + 4);
    if (*(float *)(iVar8 + 0xc) <= FLOAT_803e33ac) {
      if (*(float *)(iVar8 + 4) <= *(float *)(iVar8 + 8)) {
        *(float *)(iVar8 + 4) = *(float *)(iVar8 + 8);
        *(byte *)(iVar8 + 0x5c) = *(byte *)(iVar8 + 0x5c) | 1;
        *(byte *)(iVar8 + 0x5d) = *(byte *)(iVar8 + 0x5d) | 1;
        *(byte *)(iVar8 + 0x5e) = *(byte *)(iVar8 + 0x5e) | 1;
        *(byte *)(iVar8 + 0x5f) = *(byte *)(iVar8 + 0x5f) | 1;
      }
    }
    else {
      if (*(float *)(iVar8 + 8) <= *(float *)(iVar8 + 4)) {
        *(float *)(iVar8 + 4) = *(float *)(iVar8 + 8);
      }
      *(byte *)(iVar8 + 0x5c) = *(byte *)(iVar8 + 0x5c) & 0xfe;
      *(byte *)(iVar8 + 0x5d) = *(byte *)(iVar8 + 0x5d) & 0xfe;
      *(byte *)(iVar8 + 0x5e) = *(byte *)(iVar8 + 0x5e) & 0xfe;
      *(byte *)(iVar8 + 0x5f) = *(byte *)(iVar8 + 0x5f) & 0xfe;
    }
  }
  if (*(short *)(iVar1 + 0x46) == 0x836) {
    uVar2 = FUN_800221a0(0x60,0x7f);
    local_58 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    *(char *)(iVar1 + 0x36) =
         (char)(int)((*(float *)(iVar8 + 4) / *(float *)(iVar8 + 0x10)) *
                    (float)(local_58 - DOUBLE_803e33d0));
  }
  else {
    uVar2 = FUN_800221a0(0xc0,0xff);
    local_50 = (double)CONCAT44(0x43300000,uVar2 ^ 0x80000000);
    *(char *)(iVar1 + 0x36) =
         (char)(int)((*(float *)(iVar8 + 4) / *(float *)(iVar8 + 0x10)) *
                    (float)(local_50 - DOUBLE_803e33d0));
  }
  FUN_8000b99c((double)FLOAT_803e33a8,iVar1,0x42d,
               (int)(FLOAT_803e33e8 * (*(float *)(iVar8 + 4) / *(float *)(iVar8 + 0x10))));
  if (*(char *)(iVar1 + 0x36) == '\0') {
    *(ushort *)(iVar1 + 6) = *(ushort *)(iVar1 + 6) | 0x4000;
  }
  else {
    *(ushort *)(iVar1 + 6) = *(ushort *)(iVar1 + 6) & 0xbfff;
  }
  iVar7 = 0;
  pfVar5 = (float *)&DAT_80320a48;
  puVar4 = &DAT_80320a58;
  puVar3 = &DAT_80320a38;
  iVar6 = iVar8;
  dVar12 = DOUBLE_803e33d0;
  do {
    local_50 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x3c) ^ 0x80000000);
    local_58 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar6 + 0x34) ^ 0x80000000);
    *(short *)(iVar6 + 0x34) =
         (short)(int)((float)(local_50 - dVar12) * FLOAT_803db414 + (float)(local_58 - dVar12));
    if (*(short *)(iVar1 + 0x46) == 0x836) {
      dVar11 = (double)FUN_8029333c(*(undefined2 *)(iVar6 + 0x34));
      *(float *)(iVar8 + 0x24) =
           *pfVar5 * (float)(dVar11 * (double)FLOAT_803e33ec + (double)FLOAT_803e33c4);
      *(undefined4 *)(iVar8 + 0x14) = *puVar4;
    }
    else {
      dVar11 = (double)FUN_8029333c(*(undefined2 *)(iVar6 + 0x34));
      *(float *)(iVar8 + 0x24) = *pfVar9 * (float)((double)FLOAT_803e33c4 + dVar11) * FLOAT_803e33a8
      ;
      *(undefined4 *)(iVar8 + 0x14) = *puVar3;
    }
    iVar6 = iVar6 + 2;
    pfVar5 = pfVar5 + 1;
    iVar8 = iVar8 + 4;
    puVar4 = puVar4 + 1;
    pfVar9 = pfVar9 + 1;
    puVar3 = puVar3 + 1;
    iVar7 = iVar7 + 1;
  } while (iVar7 < 4);
  __psq_l0(auStack8,uVar10);
  __psq_l1(auStack8,uVar10);
  FUN_80286118();
  return;
}

