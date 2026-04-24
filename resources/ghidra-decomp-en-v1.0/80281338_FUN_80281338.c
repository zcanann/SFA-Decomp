// Function: FUN_80281338
// Entry: 80281338
// Size: 1488 bytes

void FUN_80281338(byte param_1,byte param_2,byte param_3,byte param_4)

{
  char *pcVar1;
  byte *pbVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  char cVar8;
  byte bVar9;
  int iVar7;
  
  uVar5 = (uint)param_2;
  if (uVar5 != 0xff) {
    uVar3 = (uint)param_3;
    if (uVar3 == 0xff) {
      if (param_1 != 0x26) {
        if (param_1 < 0x26) {
          if ((param_1 == 6) &&
             (CONCAT11(*(undefined *)(uVar5 * 0x86 + -0x7fbacfdb),
                       *(undefined *)(uVar5 * 0x86 + -0x7fbacfdc)) == 0)) {
            bVar9 = param_4;
            if (0x18 < param_4) {
              bVar9 = 0x18;
            }
            *(byte *)(uVar5 + 0x803d4e90) = bVar9;
            iVar7 = 0;
            for (uVar5 = 0; uVar5 < DAT_803bd360; uVar5 = uVar5 + 1) {
              iVar4 = DAT_803de268 + iVar7;
              if ((param_3 == *(byte *)(iVar4 + 0x122)) && (param_2 == *(byte *)(iVar4 + 0x121))) {
                *(byte *)(iVar4 + 0x1d7) = bVar9;
                *(byte *)(DAT_803de268 + iVar7 + 0x1d6) = bVar9;
              }
              iVar7 = iVar7 + 0x404;
            }
          }
        }
        else if (param_1 == 0x61) {
          if (CONCAT11(*(undefined *)(uVar5 * 0x86 + -0x7fbacfdb),
                       *(undefined *)(uVar5 * 0x86 + -0x7fbacfdc)) == 0) {
            bVar9 = *(byte *)(uVar5 + 0x803d4e90);
            if (bVar9 < 0x18) {
              bVar9 = bVar9 + 1;
            }
            *(byte *)(uVar5 + 0x803d4e90) = bVar9;
            iVar7 = 0;
            for (uVar5 = 0; uVar5 < DAT_803bd360; uVar5 = uVar5 + 1) {
              iVar4 = DAT_803de268 + iVar7;
              if ((param_3 == *(byte *)(iVar4 + 0x122)) && (param_2 == *(byte *)(iVar4 + 0x121))) {
                *(byte *)(iVar4 + 0x1d7) = bVar9;
                *(byte *)(DAT_803de268 + iVar7 + 0x1d6) = bVar9;
              }
              iVar7 = iVar7 + 0x404;
            }
          }
        }
        else if (((param_1 < 0x61) && (0x5f < param_1)) &&
                (CONCAT11(*(undefined *)(uVar5 * 0x86 + -0x7fbacfdb),
                          *(undefined *)(uVar5 * 0x86 + -0x7fbacfdc)) == 0)) {
          cVar8 = *(char *)(uVar5 + 0x803d4e90);
          if (cVar8 != '\0') {
            cVar8 = cVar8 + -1;
          }
          *(char *)(uVar5 + 0x803d4e90) = cVar8;
          iVar7 = 0;
          for (uVar5 = 0; uVar5 < DAT_803bd360; uVar5 = uVar5 + 1) {
            iVar4 = DAT_803de268 + iVar7;
            if ((param_3 == *(byte *)(iVar4 + 0x122)) && (param_2 == *(byte *)(iVar4 + 0x121))) {
              *(char *)(iVar4 + 0x1d7) = cVar8;
              *(char *)(DAT_803de268 + iVar7 + 0x1d6) = cVar8;
            }
            iVar7 = iVar7 + 0x404;
          }
        }
      }
      *(byte *)((uint)param_2 * 0x86 + (uint)param_1 + -0x7fc2e4e0) = param_4 & 0x7f;
      iVar7 = 0;
      for (uVar5 = 0; uVar5 < DAT_803bd360; uVar5 = uVar5 + 1) {
        iVar4 = DAT_803de268 + iVar7;
        if ((param_3 == *(byte *)(iVar4 + 0x122)) &&
           ((uint)param_2 == (uint)*(byte *)(iVar4 + 0x121))) {
          *(undefined4 *)(iVar4 + 0x214) = 0x1fff;
          FUN_80271370(DAT_803de268 + iVar7);
        }
        iVar7 = iVar7 + 0x404;
      }
    }
    else {
      if (param_1 != 0x26) {
        if (param_1 < 0x26) {
          if ((param_1 == 6) &&
             (iVar7 = uVar3 * 0x860 + -0x7fc328a0 + uVar5 * 0x86,
             CONCAT11(*(undefined *)(iVar7 + 0x125),*(undefined *)(iVar7 + 0x124)) == 0)) {
            bVar9 = param_4;
            if (0x18 < param_4) {
              bVar9 = 0x18;
            }
            *(byte *)(uVar3 * 0x10 + uVar5 + -0x7fc2c160) = bVar9;
            iVar7 = 0;
            for (uVar5 = 0; uVar5 < DAT_803bd360; uVar5 = uVar5 + 1) {
              iVar4 = DAT_803de268 + iVar7;
              if ((param_3 == *(byte *)(iVar4 + 0x122)) && (param_2 == *(byte *)(iVar4 + 0x121))) {
                *(byte *)(iVar4 + 0x1d7) = bVar9;
                *(byte *)(DAT_803de268 + iVar7 + 0x1d6) = bVar9;
              }
              iVar7 = iVar7 + 0x404;
            }
          }
        }
        else if (param_1 == 0x61) {
          iVar7 = uVar3 * 0x860 + -0x7fc328a0 + uVar5 * 0x86;
          if (CONCAT11(*(undefined *)(iVar7 + 0x125),*(undefined *)(iVar7 + 0x124)) == 0) {
            pbVar2 = (byte *)(uVar3 * 0x10 + uVar5 + -0x7fc2c160);
            bVar9 = *pbVar2;
            if (bVar9 < 0x18) {
              bVar9 = bVar9 + 1;
            }
            *pbVar2 = bVar9;
            iVar7 = 0;
            for (uVar5 = 0; uVar5 < DAT_803bd360; uVar5 = uVar5 + 1) {
              iVar4 = DAT_803de268 + iVar7;
              if ((param_3 == *(byte *)(iVar4 + 0x122)) && (param_2 == *(byte *)(iVar4 + 0x121))) {
                *(byte *)(iVar4 + 0x1d7) = bVar9;
                *(byte *)(DAT_803de268 + iVar7 + 0x1d6) = bVar9;
              }
              iVar7 = iVar7 + 0x404;
            }
          }
        }
        else if (((param_1 < 0x61) && (0x5f < param_1)) &&
                (iVar7 = uVar3 * 0x860 + -0x7fc328a0 + uVar5 * 0x86,
                CONCAT11(*(undefined *)(iVar7 + 0x125),*(undefined *)(iVar7 + 0x124)) == 0)) {
          pcVar1 = (char *)(uVar3 * 0x10 + uVar5 + -0x7fc2c160);
          cVar8 = *pcVar1;
          if (cVar8 != '\0') {
            cVar8 = cVar8 + -1;
          }
          *pcVar1 = cVar8;
          iVar7 = 0;
          for (uVar5 = 0; uVar5 < DAT_803bd360; uVar5 = uVar5 + 1) {
            iVar4 = DAT_803de268 + iVar7;
            if ((param_3 == *(byte *)(iVar4 + 0x122)) && (param_2 == *(byte *)(iVar4 + 0x121))) {
              *(char *)(iVar4 + 0x1d7) = cVar8;
              *(char *)(DAT_803de268 + iVar7 + 0x1d6) = cVar8;
            }
            iVar7 = iVar7 + 0x404;
          }
        }
      }
      uVar5 = (uint)param_3;
      uVar3 = (uint)param_2;
      *(byte *)(uVar5 * 0x860 + uVar3 * 0x86 + (uint)param_1 + -0x7fc327e0) = param_4 & 0x7f;
      iVar7 = 0;
      for (uVar6 = 0; uVar6 < DAT_803bd360; uVar6 = uVar6 + 1) {
        iVar4 = DAT_803de268 + iVar7;
        if ((uVar5 == *(byte *)(iVar4 + 0x122)) && (uVar3 == *(byte *)(iVar4 + 0x121))) {
          *(undefined4 *)(iVar4 + 0x214) = 0x1fff;
          FUN_80271370(DAT_803de268 + iVar7);
        }
        iVar7 = iVar7 + 0x404;
      }
      (&DAT_803d3ca0)[uVar3 + uVar5 * 0x10] = 0xff;
    }
  }
  return;
}

