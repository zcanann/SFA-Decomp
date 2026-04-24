// Function: FUN_8019d314
// Entry: 8019d314
// Size: 1300 bytes

/* WARNING: Removing unreachable block (ram,0x8019d808) */
/* WARNING: Removing unreachable block (ram,0x8019d324) */

void FUN_8019d314(void)

{
  float fVar1;
  float fVar2;
  int iVar3;
  short *psVar4;
  uint uVar5;
  uint uVar6;
  uint *puVar7;
  uint *puVar8;
  uint uVar9;
  uint uVar10;
  undefined4 in_r9;
  undefined4 in_r10;
  uint *puVar11;
  int iVar12;
  double dVar13;
  undefined8 in_f4;
  undefined8 in_f5;
  undefined8 in_f6;
  undefined8 in_f7;
  undefined8 in_f8;
  double in_f31;
  double dVar14;
  double in_ps31_1;
  int local_48 [2];
  undefined8 local_40;
  undefined8 local_38;
  float local_8;
  float fStack_4;
  
  local_8 = (float)in_f31;
  fStack_4 = (float)in_ps31_1;
  psVar4 = (short *)FUN_80286840();
  puVar11 = *(uint **)(psVar4 + 0x5c);
  iVar12 = *(int *)(psVar4 + 0x26);
  if ((*(byte *)(puVar11 + 0x5d) >> 6 & 1) == 0) {
    dVar13 = (double)FLOAT_803e4e54;
    local_38 = (double)CONCAT44(0x43300000,*(byte *)(psVar4 + 0x1b) ^ 0x80000000);
    iVar3 = (int)-(float)(dVar13 * (double)FLOAT_803dc074 -
                         (double)(float)(local_38 - DOUBLE_803e4e58));
    local_40 = (double)(longlong)iVar3;
    if ((puVar11[3] != 0xffffffff) && (uVar5 = FUN_80020078(puVar11[3]), uVar5 != 0)) {
      *(byte *)(puVar11 + 0x5d) = *(byte *)(puVar11 + 0x5d) & 0xbf | 0x40;
    }
  }
  else {
    dVar13 = (double)FLOAT_803e4e54;
    local_40 = (double)CONCAT44(0x43300000,*(byte *)(psVar4 + 0x1b) ^ 0x80000000);
    iVar3 = (int)(dVar13 * (double)FLOAT_803dc074 + (double)(float)(local_40 - DOUBLE_803e4e58));
    local_38 = (double)(longlong)iVar3;
    if ((puVar11[3] != 0xffffffff) && (uVar5 = FUN_80020078(puVar11[3]), uVar5 == 0)) {
      *(byte *)(puVar11 + 0x5d) = *(byte *)(puVar11 + 0x5d) & 0xbf;
    }
  }
  if (iVar3 < 0) {
    iVar3 = 0;
  }
  else if (0xff < iVar3) {
    iVar3 = 0xff;
  }
  *(char *)(psVar4 + 0x1b) = (char)iVar3;
  uVar5 = FUN_80020078(0x57);
  if (((uVar5 != 0) || (10 < (int)*puVar11)) && ((*(byte *)(puVar11 + 0x5d) >> 6 & 1) != 0)) {
    uVar5 = puVar11[5];
    puVar11[5] = uVar5 + 1;
    if (((int)uVar5 < 0x3c) && (uVar5 = FUN_80020078(puVar11[1]), uVar5 == 0)) {
      iVar12 = (uint)DAT_803dc070 * 100 * puVar11[5] * puVar11[5];
      iVar12 = iVar12 / 0x3c + (iVar12 >> 0x1f);
      *psVar4 = *psVar4 - ((short)iVar12 - (short)(iVar12 >> 0x1f));
      FUN_8002b95c((int)psVar4,0);
    }
    else {
      FUN_8002b95c((int)psVar4,1);
      uVar5 = FUN_80020078(puVar11[2]);
      *psVar4 = *psVar4 - (ushort)DAT_803dc070 * 0xb6 * ((short)(uVar5 << 2) + 0xe);
      local_38 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar12 + 0x1a) ^ 0x80000000);
      dVar14 = (double)(float)(local_38 - DOUBLE_803e4e58);
      iVar12 = FUN_8002bac4();
      uVar6 = FUN_80020078(puVar11[1]);
      if (uVar6 == 0) {
        if (*(char *)(puVar11 + 0x5d) < '\0') {
          FUN_8000a538((int *)0xbd,0);
          *(byte *)(puVar11 + 0x5d) = *(byte *)(puVar11 + 0x5d) & 0x7f;
        }
        if ((*(byte *)(puVar11 + 10) & 0xe0) != 0) {
          FUN_80296980((double)FLOAT_803e4e04,iVar12);
          if ((*(byte *)(puVar11 + 10) & 0xe) != 0) {
            *(byte *)(puVar11 + 10) = *(byte *)(puVar11 + 10) | 2;
          }
          puVar11[9] = (uint)FLOAT_803e4e04;
          *(undefined *)((int)puVar11 + 0x29) = 0;
          *(byte *)(puVar11 + 10) = *(byte *)(puVar11 + 10) & 0xe;
        }
      }
      else {
        if (-1 < (char)*(byte *)(puVar11 + 0x5d)) {
          *(byte *)(puVar11 + 0x5d) = *(byte *)(puVar11 + 0x5d) & 0x7f | 0x80;
          FUN_8000a538((int *)0xbd,1);
        }
        if (iVar12 != 0) {
          FUN_8019cd00(dVar14,(double)(float)puVar11[0x5c],dVar13,in_f4,in_f5,in_f6,in_f7,in_f8,
                       psVar4,iVar12,(int)(puVar11 + 6),uVar5,1,*puVar11,in_r9,in_r10);
        }
      }
      puVar7 = FUN_80037048(0x16,local_48);
      local_48[0] = local_48[0] + 1;
      if (0xe < local_48[0]) {
        local_48[0] = 0xe;
      }
      puVar11[0x11] = 0xffffffff;
      puVar11[0x17] = 0xffffffff;
      puVar11[0x1d] = 0xffffffff;
      puVar11[0x23] = 0xffffffff;
      puVar11[0x29] = 0xffffffff;
      puVar11[0x2f] = 0xffffffff;
      puVar11[0x35] = 0xffffffff;
      puVar11[0x3b] = 0xffffffff;
      puVar11[0x41] = 0xffffffff;
      puVar11[0x47] = 0xffffffff;
      puVar11[0x4d] = 0xffffffff;
      puVar11[0x53] = 0xffffffff;
      puVar8 = puVar11 + 0x4e;
      iVar12 = 1;
      do {
        puVar8[0xb] = 0xffffffff;
        puVar8 = puVar8 + 6;
        iVar12 = iVar12 + -1;
      } while (iVar12 != 0);
      for (iVar12 = 1; fVar2 = FLOAT_803e4e04, fVar1 = FLOAT_803e4e00, iVar12 < local_48[0];
          iVar12 = iVar12 + 1) {
        uVar6 = 0xffffffff;
        uVar9 = 1;
        iVar3 = 0xd;
        puVar8 = puVar11;
        do {
          if (puVar8[0xc] == *puVar7) {
            uVar6 = uVar9;
          }
          uVar9 = uVar9 + 1;
          iVar3 = iVar3 + -1;
          puVar8 = puVar8 + 6;
        } while (iVar3 != 0);
        if (uVar6 == 0xffffffff) {
          uVar9 = 1;
          while ((int)uVar9 < 0xe) {
            uVar10 = uVar9;
            if (puVar11[uVar9 * 6 + 6] == 0) {
              *(undefined *)(puVar11 + uVar9 * 6 + 10) = 0;
              *(byte *)(puVar11 + uVar9 * 6 + 10) = *(byte *)(puVar11 + uVar9 * 6 + 10) & 0xe;
              puVar11[uVar9 * 6 + 7] = (uint)fVar1;
              puVar11[uVar9 * 6 + 9] = (uint)fVar2;
              puVar11[uVar9 * 6 + 8] = (uint)fVar2;
              puVar11[uVar9 * 6 + 6] = 0;
              *(undefined *)((int)puVar11 + uVar9 * 0x18 + 0x29) = 0;
              uVar10 = 2000;
              uVar6 = uVar9;
            }
            uVar9 = uVar10 + 1;
          }
          if (uVar6 == 0xffffffff) goto LAB_8019d808;
          puVar11[uVar6 * 6 + 6] = *puVar7;
        }
        puVar11[uVar6 * 6 + 0xb] = uVar6;
        uVar9 = *puVar7;
        if ((*(ushort *)(uVar9 + 0xb0) & 0x1000) == 0) {
          if (uVar9 != 0) {
            puVar7 = puVar7 + 1;
            FUN_8019cd00(dVar14,(double)(float)puVar11[0x5c],dVar13,in_f4,in_f5,in_f6,in_f7,in_f8,
                         psVar4,uVar9,(int)(puVar11 + uVar6 * 6 + 6),uVar5,0,*puVar11,in_r9,in_r10);
          }
        }
        else {
          puVar7 = puVar7 + 1;
        }
      }
      iVar12 = 0xd;
      do {
        if (puVar11[0x11] == 0xffffffff) {
          puVar11[0xc] = 0;
        }
        iVar12 = iVar12 + -1;
        puVar11 = puVar11 + 6;
      } while (iVar12 != 0);
    }
  }
LAB_8019d808:
  FUN_8028688c();
  return;
}

