// Function: FUN_80281a9c
// Entry: 80281a9c
// Size: 1488 bytes

void FUN_80281a9c(byte param_1,byte param_2,byte param_3,byte param_4)

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
             (*(char *)(uVar5 * 0x86 + -0x7fbac37b) == '\0' &&
              *(char *)(uVar5 * 0x86 + -0x7fbac37c) == '\0')) {
            bVar9 = param_4;
            if (0x18 < param_4) {
              bVar9 = 0x18;
            }
            *(byte *)(uVar5 + 0x803d5af0) = bVar9;
            iVar7 = 0;
            for (uVar5 = 0; uVar5 < DAT_803bdfc0; uVar5 = uVar5 + 1) {
              iVar4 = DAT_803deee8 + iVar7;
              if ((param_3 == *(byte *)(iVar4 + 0x122)) && (param_2 == *(byte *)(iVar4 + 0x121))) {
                *(byte *)(iVar4 + 0x1d7) = bVar9;
                *(byte *)(DAT_803deee8 + iVar7 + 0x1d6) = bVar9;
              }
              iVar7 = iVar7 + 0x404;
            }
          }
        }
        else if (param_1 == 0x61) {
          if (*(char *)(uVar5 * 0x86 + -0x7fbac37b) == '\0' &&
              *(char *)(uVar5 * 0x86 + -0x7fbac37c) == '\0') {
            bVar9 = *(byte *)(uVar5 + 0x803d5af0);
            if (bVar9 < 0x18) {
              bVar9 = bVar9 + 1;
            }
            *(byte *)(uVar5 + 0x803d5af0) = bVar9;
            iVar7 = 0;
            for (uVar5 = 0; uVar5 < DAT_803bdfc0; uVar5 = uVar5 + 1) {
              iVar4 = DAT_803deee8 + iVar7;
              if ((param_3 == *(byte *)(iVar4 + 0x122)) && (param_2 == *(byte *)(iVar4 + 0x121))) {
                *(byte *)(iVar4 + 0x1d7) = bVar9;
                *(byte *)(DAT_803deee8 + iVar7 + 0x1d6) = bVar9;
              }
              iVar7 = iVar7 + 0x404;
            }
          }
        }
        else if (((param_1 < 0x61) && (0x5f < param_1)) &&
                (*(char *)(uVar5 * 0x86 + -0x7fbac37b) == '\0' &&
                 *(char *)(uVar5 * 0x86 + -0x7fbac37c) == '\0')) {
          cVar8 = *(char *)(uVar5 + 0x803d5af0);
          if (cVar8 != '\0') {
            cVar8 = cVar8 + -1;
          }
          *(char *)(uVar5 + 0x803d5af0) = cVar8;
          iVar7 = 0;
          for (uVar5 = 0; uVar5 < DAT_803bdfc0; uVar5 = uVar5 + 1) {
            iVar4 = DAT_803deee8 + iVar7;
            if ((param_3 == *(byte *)(iVar4 + 0x122)) && (param_2 == *(byte *)(iVar4 + 0x121))) {
              *(char *)(iVar4 + 0x1d7) = cVar8;
              *(char *)(DAT_803deee8 + iVar7 + 0x1d6) = cVar8;
            }
            iVar7 = iVar7 + 0x404;
          }
        }
      }
      *(byte *)((uint)param_2 * 0x86 + (uint)param_1 + -0x7fc2d880) = param_4 & 0x7f;
      iVar7 = 0;
      for (uVar5 = 0; uVar5 < DAT_803bdfc0; uVar5 = uVar5 + 1) {
        iVar4 = DAT_803deee8 + iVar7;
        if ((param_3 == *(byte *)(iVar4 + 0x122)) &&
           ((uint)param_2 == (uint)*(byte *)(iVar4 + 0x121))) {
          *(undefined4 *)(iVar4 + 0x214) = 0x1fff;
          FUN_80271ad4((int *)(DAT_803deee8 + iVar7));
        }
        iVar7 = iVar7 + 0x404;
      }
    }
    else {
      if (param_1 != 0x26) {
        if (param_1 < 0x26) {
          if ((param_1 == 6) &&
             (iVar7 = uVar3 * 0x860 + -0x7fc31c40 + uVar5 * 0x86,
             *(char *)(iVar7 + 0x125) == '\0' && *(char *)(iVar7 + 0x124) == '\0')) {
            bVar9 = param_4;
            if (0x18 < param_4) {
              bVar9 = 0x18;
            }
            *(byte *)(uVar3 * 0x10 + uVar5 + -0x7fc2b500) = bVar9;
            iVar7 = 0;
            for (uVar5 = 0; uVar5 < DAT_803bdfc0; uVar5 = uVar5 + 1) {
              iVar4 = DAT_803deee8 + iVar7;
              if ((param_3 == *(byte *)(iVar4 + 0x122)) && (param_2 == *(byte *)(iVar4 + 0x121))) {
                *(byte *)(iVar4 + 0x1d7) = bVar9;
                *(byte *)(DAT_803deee8 + iVar7 + 0x1d6) = bVar9;
              }
              iVar7 = iVar7 + 0x404;
            }
          }
        }
        else if (param_1 == 0x61) {
          iVar7 = uVar3 * 0x860 + -0x7fc31c40 + uVar5 * 0x86;
          if (*(char *)(iVar7 + 0x125) == '\0' && *(char *)(iVar7 + 0x124) == '\0') {
            pbVar2 = (byte *)(uVar3 * 0x10 + uVar5 + -0x7fc2b500);
            bVar9 = *pbVar2;
            if (bVar9 < 0x18) {
              bVar9 = bVar9 + 1;
            }
            *pbVar2 = bVar9;
            iVar7 = 0;
            for (uVar5 = 0; uVar5 < DAT_803bdfc0; uVar5 = uVar5 + 1) {
              iVar4 = DAT_803deee8 + iVar7;
              if ((param_3 == *(byte *)(iVar4 + 0x122)) && (param_2 == *(byte *)(iVar4 + 0x121))) {
                *(byte *)(iVar4 + 0x1d7) = bVar9;
                *(byte *)(DAT_803deee8 + iVar7 + 0x1d6) = bVar9;
              }
              iVar7 = iVar7 + 0x404;
            }
          }
        }
        else if (((param_1 < 0x61) && (0x5f < param_1)) &&
                (iVar7 = uVar3 * 0x860 + -0x7fc31c40 + uVar5 * 0x86,
                *(char *)(iVar7 + 0x125) == '\0' && *(char *)(iVar7 + 0x124) == '\0')) {
          pcVar1 = (char *)(uVar3 * 0x10 + uVar5 + -0x7fc2b500);
          cVar8 = *pcVar1;
          if (cVar8 != '\0') {
            cVar8 = cVar8 + -1;
          }
          *pcVar1 = cVar8;
          iVar7 = 0;
          for (uVar5 = 0; uVar5 < DAT_803bdfc0; uVar5 = uVar5 + 1) {
            iVar4 = DAT_803deee8 + iVar7;
            if ((param_3 == *(byte *)(iVar4 + 0x122)) && (param_2 == *(byte *)(iVar4 + 0x121))) {
              *(char *)(iVar4 + 0x1d7) = cVar8;
              *(char *)(DAT_803deee8 + iVar7 + 0x1d6) = cVar8;
            }
            iVar7 = iVar7 + 0x404;
          }
        }
      }
      uVar5 = (uint)param_3;
      uVar3 = (uint)param_2;
      *(byte *)(uVar5 * 0x860 + uVar3 * 0x86 + (uint)param_1 + -0x7fc31b80) = param_4 & 0x7f;
      iVar7 = 0;
      for (uVar6 = 0; uVar6 < DAT_803bdfc0; uVar6 = uVar6 + 1) {
        iVar4 = DAT_803deee8 + iVar7;
        if ((uVar5 == *(byte *)(iVar4 + 0x122)) && (uVar3 == *(byte *)(iVar4 + 0x121))) {
          *(undefined4 *)(iVar4 + 0x214) = 0x1fff;
          FUN_80271ad4((int *)(DAT_803deee8 + iVar7));
        }
        iVar7 = iVar7 + 0x404;
      }
      (&DAT_803d4900)[uVar3 + uVar5 * 0x10] = 0xff;
    }
  }
  return;
}

