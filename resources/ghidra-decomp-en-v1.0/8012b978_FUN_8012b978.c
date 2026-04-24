// Function: FUN_8012b978
// Entry: 8012b978
// Size: 1292 bytes

void FUN_8012b978(char param_1)

{
  short sVar1;
  bool bVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  char local_18;
  char local_17 [11];
  
  iVar7 = -1;
  bVar2 = false;
  DAT_803dd8a4 = FUN_80014e70(0);
  if (DAT_803dd75c == 0) {
    fVar3 = FLOAT_803dd768 + FLOAT_803db414;
    if (DAT_803dd780 != 4) {
      if (DAT_803dd780 < 4) {
        if (2 < DAT_803dd780) {
          if ((FLOAT_803e2068 <= fVar3) && (FLOAT_803dd768 < FLOAT_803e2068)) {
            if (DAT_803dd7d6 == DAT_803dd8e0) {
              FLOAT_803dd768 = fVar3;
              FUN_8000d200(0x271a,FUN_8000d138);
              fVar3 = FLOAT_803dd768;
            }
            else {
              FLOAT_803dd768 = fVar3;
              FUN_8000d200(0x2715,FUN_8000d138);
              fVar3 = FLOAT_803dd768;
            }
          }
          FLOAT_803dd768 = fVar3;
          fVar3 = FLOAT_803dd768;
          if (FLOAT_803e2174 < FLOAT_803dd768) {
            iVar5 = FUN_800221a0(0,3);
            FUN_8000d200(iVar5 + 0x2716,FUN_8000d138);
            FLOAT_803dd768 = FLOAT_803e1e3c;
            fVar3 = FLOAT_803dd768;
          }
        }
      }
      else if (((DAT_803dd780 < 6) && (FLOAT_803e2068 <= fVar3)) &&
              (FLOAT_803dd768 < FLOAT_803e2068)) {
        FLOAT_803dd768 = fVar3;
        iVar5 = FUN_800221a0(0,3);
        iVar4 = iVar5 + 0x2730;
        iVar6 = 0x2731;
        if (DAT_803dd824 == &DAT_8031bd90) {
          iVar6 = 0x2732;
        }
        if (iVar6 <= iVar4) {
          iVar4 = iVar5 + 0x2731;
        }
        FUN_8000d200(iVar4,FUN_8000d138);
        FLOAT_803dd768 = FLOAT_803e1e3c;
        fVar3 = FLOAT_803dd768;
      }
    }
    FLOAT_803dd768 = fVar3;
    if (FLOAT_803e1e3c < FLOAT_803dd764) {
      FUN_80014b78(0,local_17,&local_18);
      if (local_18 == '\x01') {
        iVar7 = (int)(char)DAT_803dd824[DAT_803dd7d8 * 0x20 + 0xc];
      }
      if (local_18 == -1) {
        iVar7 = (int)(char)DAT_803dd824[DAT_803dd7d8 * 0x20 + 0xd];
      }
      if ((local_17[0] == -1) && (iVar7 == -1)) {
        iVar7 = (int)(char)DAT_803dd824[DAT_803dd7d8 * 0x20 + 0xe];
      }
      if ((local_17[0] == '\x01') && (iVar7 == -1)) {
        iVar7 = (int)(char)DAT_803dd824[DAT_803dd7d8 * 0x20 + 0xf];
      }
    }
    if (-1 < iVar7) {
      FUN_8000bb18(0,0x405);
      DAT_803dd7d8 = iVar7;
      if ((*(short *)(DAT_803dd824 + iVar7 * 0x20) < 0x4d) &&
         (0x4a < *(short *)(DAT_803dd824 + iVar7 * 0x20))) {
        FUN_8000d200(0x2714,FUN_8000d138);
      }
    }
    if (DAT_803dd824 == &DAT_8031bd90) {
      if ((&DAT_803a8b48)[*(short *)(&DAT_8031bd90 + DAT_803dd7d8 * 0x20)] != 0xbf0) {
        bVar2 = true;
      }
    }
    else {
      sVar1 = *(short *)(DAT_803dd824 + DAT_803dd7d8 * 0x20);
      if ((((-1 < sVar1) && (sVar1 != 0x25)) && (sVar1 != 0x24)) && (sVar1 != 0x49)) {
        bVar2 = true;
      }
    }
    if ((((DAT_803dd8a4 & 0x100) != 0) && (DAT_803dd824 != &DAT_8031bd30)) &&
       (FLOAT_803e1e3c == FLOAT_803dd7c0)) {
      if (bVar2) {
        FUN_8000bb18(0,0x41b);
        if (DAT_803dd780 != 4) {
          if (DAT_803dd780 < 4) {
            if (2 < DAT_803dd780) {
              iVar7 = FUN_800221a0(0,1);
              FUN_8000d200(iVar7 + 0x2712,FUN_8000d138);
              FLOAT_803dd768 = FLOAT_803e1e3c;
            }
          }
          else if (DAT_803dd780 < 6) {
            iVar7 = FUN_800221a0(0,1);
            FUN_8000d200(iVar7 + 0x2735,FUN_8000d138);
            FLOAT_803dd768 = FLOAT_803e1e3c;
          }
        }
        FUN_80014b3c(0,0x100);
        DAT_803dd75c = 1;
        DAT_803dd75e = 0x1e;
        return;
      }
      if (DAT_803dd780 == 5) {
        iVar5 = FUN_800221a0(0,1);
        FUN_8000d200(iVar5 + 0x2737,FUN_8000d138);
        FLOAT_803dd768 = FLOAT_803e1e3c;
      }
    }
    if (bVar2) {
      if ((((-1 < iVar7) || (param_1 != '\0')) ||
          ((DOUBLE_803e2160 == (double)FLOAT_803dd760 && (DOUBLE_803e2160 < (double)FLOAT_803dd764))
          )) && (*(int *)(DAT_803dd824 + DAT_803dd7d8 * 0x20 + 0x18) != 0)) {
        FUN_8012ddd8(*(int *)(DAT_803dd824 + DAT_803dd7d8 * 0x20 + 0x18),
                     DAT_803dd824[DAT_803dd7d8 * 0x20 + 0x1c],1,0);
      }
    }
    else {
      FUN_8012ddd8(*(undefined4 *)(DAT_803dd824 + DAT_803dd7d8 * 0x20 + 0x18),
                   DAT_803dd824[DAT_803dd7d8 * 0x20 + 0x1c],2,0);
    }
  }
  else {
    if ((DAT_803dd8a4 & 0x300) != 0) {
      FUN_8000bb18(0,0x41c);
      FUN_80014b3c(0,0x300);
      DAT_803dd75e = -0x28;
    }
    DAT_803dd75c = DAT_803dd75c + DAT_803dd75e;
    if (0x200 < DAT_803dd75c) {
      DAT_803dd75c = 0x200;
    }
    if (DAT_803dd75c < 0) {
      DAT_803dd75c = 0;
    }
  }
  return;
}

