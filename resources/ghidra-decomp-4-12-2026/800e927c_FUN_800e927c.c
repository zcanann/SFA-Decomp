// Function: FUN_800e927c
// Entry: 800e927c
// Size: 1056 bytes

void FUN_800e927c(undefined4 param_1,undefined4 param_2,int param_3)

{
  bool bVar1;
  char cVar2;
  uint uVar3;
  char cVar4;
  short *psVar5;
  char *pcVar6;
  uint *puVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  char *pcVar11;
  int iVar12;
  int iVar13;
  longlong lVar14;
  
  lVar14 = FUN_80286830();
  uVar10 = (uint)((ulonglong)lVar14 >> 0x20);
  uVar8 = (uint)lVar14;
  pcVar11 = &DAT_803a3be0;
  if (0x4fffffffff < lVar14) {
    uVar10 = (uint)(byte)(&DAT_803a3dac)[uVar10];
  }
  if ((int)uVar10 < 0x78) {
    if ((ushort)(&DAT_80312460)[uVar10] != 0) {
      if (param_3 == -1) {
        param_3 = 1;
      }
      bVar1 = param_3 == -2;
      if (bVar1) {
        param_3 = 0;
      }
      uVar3 = FUN_80020078((uint)(ushort)(&DAT_80312460)[uVar10]);
      if (param_3 == 0) {
        uVar9 = uVar3 & ~(1 << uVar8);
      }
      else {
        uVar9 = uVar3 | 1 << uVar8;
      }
      FUN_800201ac((uint)(ushort)(&DAT_80312460)[uVar10],uVar9);
      DAT_803de104 = uVar10;
      uRam803de108 = uVar9;
      if (param_3 == 0) {
        psVar5 = &DAT_80312460;
        puVar7 = &DAT_803a3c1c;
        uVar3 = ~(1 << uVar8);
        iVar12 = 0x14;
        do {
          if (*psVar5 == (&DAT_80312460)[uVar10]) {
            *puVar7 = *puVar7 & uVar3;
          }
          if (psVar5[1] == (&DAT_80312460)[uVar10]) {
            puVar7[1] = puVar7[1] & uVar3;
          }
          if (psVar5[2] == (&DAT_80312460)[uVar10]) {
            puVar7[2] = puVar7[2] & uVar3;
          }
          if (psVar5[3] == (&DAT_80312460)[uVar10]) {
            puVar7[3] = puVar7[3] & uVar3;
          }
          if (psVar5[4] == (&DAT_80312460)[uVar10]) {
            puVar7[4] = puVar7[4] & uVar3;
          }
          if (psVar5[5] == (&DAT_80312460)[uVar10]) {
            puVar7[5] = puVar7[5] & uVar3;
          }
          psVar5 = psVar5 + 6;
          puVar7 = puVar7 + 6;
          iVar12 = iVar12 + -1;
        } while (iVar12 != 0);
        if (!bVar1) {
          cVar4 = '\0';
          iVar12 = 4;
          pcVar6 = pcVar11;
          do {
            if ((((((uVar10 == (int)*pcVar6) && (cVar2 = cVar4, uVar8 == (byte)pcVar6[1])) ||
                  ((cVar2 = cVar4 + '\x01', uVar10 == (int)pcVar6[3] && (uVar8 == (byte)pcVar6[4])))
                  ) || ((cVar2 = cVar4 + '\x02', uVar10 == (int)pcVar6[6] &&
                        (uVar8 == (byte)pcVar6[7])))) ||
                ((cVar2 = cVar4 + '\x03', uVar10 == (int)pcVar6[9] && (uVar8 == (byte)pcVar6[10]))))
               || ((uVar10 == (int)pcVar6[0xc] &&
                   (cVar2 = cVar4 + '\x04', uVar8 == (byte)pcVar6[0xd])))) goto LAB_800e9628;
            pcVar6 = pcVar6 + 0xf;
            cVar4 = cVar4 + '\x05';
            iVar12 = iVar12 + -1;
          } while (iVar12 != 0);
          cVar2 = -1;
LAB_800e9628:
          if (cVar2 == -1) {
            iVar12 = 0;
            iVar13 = 0x14;
            do {
              if (*pcVar11 == -1) {
                iVar12 = iVar12 * 3;
                (&DAT_803a3be0)[iVar12] = (char)uVar10;
                (&DAT_803a3be1)[iVar12] = (char)lVar14;
                (&DAT_803a3be2)[iVar12] = 3;
                break;
              }
              pcVar11 = pcVar11 + 3;
              iVar12 = iVar12 + 1;
              iVar13 = iVar13 + -1;
            } while (iVar13 != 0);
          }
        }
      }
      else {
        uVar8 = 1 << uVar8;
        if ((uVar3 & uVar8) == 0) {
          psVar5 = &DAT_80312460;
          puVar7 = &DAT_803a3c1c;
          iVar12 = 0x14;
          do {
            if (*psVar5 == (&DAT_80312460)[uVar10]) {
              *puVar7 = *puVar7 | uVar8;
            }
            if (psVar5[1] == (&DAT_80312460)[uVar10]) {
              puVar7[1] = puVar7[1] | uVar8;
            }
            if (psVar5[2] == (&DAT_80312460)[uVar10]) {
              puVar7[2] = puVar7[2] | uVar8;
            }
            if (psVar5[3] == (&DAT_80312460)[uVar10]) {
              puVar7[3] = puVar7[3] | uVar8;
            }
            if (psVar5[4] == (&DAT_80312460)[uVar10]) {
              puVar7[4] = puVar7[4] | uVar8;
            }
            if (psVar5[5] == (&DAT_80312460)[uVar10]) {
              puVar7[5] = puVar7[5] | uVar8;
            }
            psVar5 = psVar5 + 6;
            puVar7 = puVar7 + 6;
            iVar12 = iVar12 + -1;
          } while (iVar12 != 0);
        }
      }
    }
  }
  FUN_8028687c();
  return;
}

