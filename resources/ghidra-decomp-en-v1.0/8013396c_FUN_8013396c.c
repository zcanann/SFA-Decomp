// Function: FUN_8013396c
// Entry: 8013396c
// Size: 1336 bytes

/* WARNING: Removing unreachable block (ram,0x80133a78) */

void FUN_8013396c(void)

{
  bool bVar1;
  float fVar2;
  char cVar3;
  float fVar4;
  int iVar5;
  int iVar6;
  short sVar10;
  uint uVar7;
  uint uVar8;
  short *psVar9;
  undefined4 uVar11;
  double dVar12;
  float local_18 [3];
  
  local_18[0] = FLOAT_803e2294;
  uVar11 = 0;
  iVar5 = FUN_8002b9ec();
  if (((((iVar5 == 0) || (iVar6 = (**(code **)(*DAT_803dca50 + 0x10))(), iVar6 == 0x44)) ||
       (sVar10 = FUN_8000fae4(), sVar10 != 0)) ||
      (((*(ushort *)(iVar5 + 0xb0) & 0x1000) != 0 || (iVar6 = FUN_80295bc8(iVar5), iVar6 == 0)))) ||
     (DAT_803dd780 != '\0')) {
    if (DAT_803dd945 != '\0') {
      FUN_8000b824(0,0x3f0);
      DAT_803dd945 = '\0';
    }
  }
  else {
    if (DAT_803dd928 != '\0') {
      DAT_803dd928 = DAT_803dd928 + -1;
    }
    iVar6 = (**(code **)(*DAT_803dca68 + 0x20))(0xc8d);
    if (iVar6 != 0) {
      DAT_803dbbb0 = '\x01' - DAT_803dbbb0;
      if (DAT_803dbbb0 == '\x01') {
        uVar11 = 0x3eb;
      }
      else if (DAT_803dbbb0 == '\0') {
        uVar11 = 0x3ec;
      }
      FUN_8000bb18(0,uVar11);
    }
    iVar6 = 0;
    if ((DAT_803dbbb0 == '\0') && (DAT_803dd7ba == '\0')) {
      if (DAT_803dd945 != '\0') {
        FUN_8000b824(0,0x3f0);
        DAT_803dd945 = '\0';
      }
    }
    else {
      if (DAT_803dd929 == '\0') {
        DAT_803dd929 = '\x01';
        FUN_80133818();
      }
      uVar7 = FUN_80014ee8(0);
      uVar8 = FUN_80014e70(0);
      if ((uVar7 & 0xc) == 0) {
        if ((uVar8 & 1) == 0) {
          if ((uVar8 & 2) != 0) {
            DAT_803dd944 = DAT_803dd944 + '\x01';
            iVar6 = 0x3ed;
            if ('\x02' < DAT_803dd944) {
              DAT_803dd944 = '\0';
            }
          }
        }
        else {
          DAT_803dd944 = DAT_803dd944 + -1;
          iVar6 = 0x3ed;
          if (DAT_803dd944 < '\0') {
            DAT_803dd944 = '\x02';
          }
        }
      }
      if (DAT_803dd7ba == '\0') {
        if (DAT_803dbbb1 != -1) {
          DAT_803dd944 = DAT_803dbbb1;
          DAT_803dbbb1 = -1;
        }
      }
      else {
        if (DAT_803dbbb1 == -1) {
          DAT_803dbbb1 = DAT_803dd944;
        }
        DAT_803dd944 = '\x02';
      }
      if (DAT_803dd944 == '\x01') {
        if (DAT_803dd945 != '\0') {
          FUN_8000b824(0,0x3f0);
          DAT_803dd945 = '\0';
        }
        DAT_803dd934 = FUN_80036e58(0x4f,iVar5,local_18);
        if (DAT_803dd934 != 0) {
          if (FLOAT_803e2260 <= local_18[0]) {
            DAT_803dd92a = '\0';
            cVar3 = DAT_803dd92a;
          }
          else {
            cVar3 = DAT_803dd92a + '\x01';
            if (local_18[0] < FLOAT_803e229c) {
              cVar3 = DAT_803dd92a + '\x02';
            }
          }
          DAT_803dd92a = cVar3;
          psVar9 = (short *)FUN_8000faac();
          sVar10 = FUN_800217c0((double)(*(float *)(DAT_803dd934 + 0xc) - *(float *)(iVar5 + 0xc)),
                                (double)(*(float *)(DAT_803dd934 + 0x14) - *(float *)(iVar5 + 0x14))
                               );
          sVar10 = (*psVar9 + sVar10) - *(short *)(iRam803dbbcc + 4);
          if (0x8000 < sVar10) {
            sVar10 = sVar10 + 1;
          }
          if (sVar10 < -0x8000) {
            sVar10 = sVar10 + -1;
          }
          iVar5 = (int)sVar10 / 5 + ((int)sVar10 >> 0x1f);
          *(short *)(iRam803dbbcc + 4) =
               *(short *)(iRam803dbbcc + 4) + ((short)iVar5 - (short)(iVar5 >> 0x1f));
        }
      }
      else if (DAT_803dd944 < '\x01') {
        if (-1 < DAT_803dd944) {
          if ((uVar7 & 4) == 0) {
            if ((uVar7 & 8) == 0) {
              FLOAT_803dbbe4 = FLOAT_803e2298;
            }
            else {
              dVar12 = (double)FUN_802929cc((double)FLOAT_803dbbd8,(double)FLOAT_803db414);
              FLOAT_803dbbe4 = (float)((double)FLOAT_803dbbe4 * dVar12);
            }
          }
          else {
            dVar12 = (double)FUN_802929cc((double)FLOAT_803dbbd4,(double)FLOAT_803db414);
            FLOAT_803dbbe4 = (float)((double)FLOAT_803dbbe4 * dVar12);
          }
          fVar4 = FLOAT_803dbbdc;
          if ((FLOAT_803dbbdc <= FLOAT_803dbbe4) &&
             (fVar4 = FLOAT_803dbbe4, FLOAT_803dbbe0 < FLOAT_803dbbe4)) {
            fVar4 = FLOAT_803dbbe0;
          }
          FLOAT_803dbbe4 = fVar4;
          fVar4 = FLOAT_803dbbb4 * FLOAT_803dbbe4;
          fVar2 = FLOAT_803dbbb8;
          if ((FLOAT_803dbbb8 <= fVar4) && (fVar2 = fVar4, FLOAT_803dbbbc < fVar4)) {
            fVar2 = FLOAT_803dbbbc;
          }
          if (fVar2 == FLOAT_803dbbb4) {
            FLOAT_803dbbb4 = fVar2;
            if (DAT_803dd945 != '\0') {
              FUN_8000b824(0,0x3f0);
              DAT_803dd945 = '\0';
            }
          }
          else {
            FLOAT_803dbbb4 = fVar2;
            if (DAT_803dd945 == '\0') {
              FUN_8000bb18(0,0x3f0);
              DAT_803dd945 = '\x01';
            }
          }
        }
      }
      else if (DAT_803dd944 < '\x03') {
        if (DAT_803dd945 != '\0') {
          FUN_8000b824(0,0x3f0);
          DAT_803dd945 = '\0';
        }
        iVar5 = (int)DAT_803dba6e;
        bVar1 = iVar5 != DAT_803dbbe8;
        DAT_803dbbe8 = iVar5;
        if (bVar1) {
          if (iVar5 == -1) {
            iVar6 = 0x3ef;
          }
          else {
            iVar6 = 0x3ee;
          }
        }
      }
      if (iVar6 != 0) {
        FUN_8000bb18(0,iVar6);
      }
    }
  }
  return;
}

