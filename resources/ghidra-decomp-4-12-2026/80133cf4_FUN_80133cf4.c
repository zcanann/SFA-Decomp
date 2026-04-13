// Function: FUN_80133cf4
// Entry: 80133cf4
// Size: 1336 bytes

/* WARNING: Removing unreachable block (ram,0x80133e00) */

void FUN_80133cf4(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  bool bVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  char cVar5;
  short sVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  short *psVar11;
  ushort uVar12;
  undefined8 extraout_f1;
  undefined8 uVar13;
  double dVar14;
  float local_18 [3];
  
  local_18[0] = FLOAT_803e2f24;
  uVar12 = 0;
  iVar7 = FUN_8002bac4();
  if (((((iVar7 == 0) || (iVar8 = (**(code **)(*DAT_803dd6d0 + 0x10))(), iVar8 == 0x44)) ||
       (iVar8 = FUN_8000fb04(), (short)iVar8 != 0)) ||
      (((*(ushort *)(iVar7 + 0xb0) & 0x1000) != 0 || (uVar9 = FUN_80296328(iVar7), uVar9 == 0)))) ||
     (DAT_803de400 != '\0')) {
    if (DAT_803de5c5 != '\0') {
      FUN_8000b844(0,0x3f0);
      DAT_803de5c5 = '\0';
    }
  }
  else {
    if (DAT_803de5a8 != '\0') {
      DAT_803de5a8 = DAT_803de5a8 + -1;
    }
    iVar8 = (**(code **)(*DAT_803dd6e8 + 0x20))(0xc8d);
    uVar13 = extraout_f1;
    if (iVar8 != 0) {
      DAT_803dc818 = '\x01' - DAT_803dc818;
      if (DAT_803dc818 == '\x01') {
        uVar12 = 0x3eb;
      }
      else if (DAT_803dc818 == '\0') {
        uVar12 = 0x3ec;
      }
      uVar13 = FUN_8000bb38(0,uVar12);
    }
    uVar12 = 0;
    if ((DAT_803dc818 == '\0') && (DAT_803de43a == '\0')) {
      if (DAT_803de5c5 != '\0') {
        FUN_8000b844(0,0x3f0);
        DAT_803de5c5 = '\0';
      }
    }
    else {
      if (DAT_803de5a9 == '\0') {
        DAT_803de5a9 = '\x01';
        FUN_80133ba0(uVar13,param_2,param_3,param_4,param_5,param_6,param_7,param_8);
      }
      uVar9 = FUN_80014f14(0);
      uVar10 = FUN_80014e9c(0);
      if ((uVar9 & 0xc) == 0) {
        if ((uVar10 & 1) == 0) {
          if ((uVar10 & 2) != 0) {
            DAT_803de5c4 = DAT_803de5c4 + '\x01';
            uVar12 = 0x3ed;
            if ('\x02' < DAT_803de5c4) {
              DAT_803de5c4 = '\0';
            }
          }
        }
        else {
          DAT_803de5c4 = DAT_803de5c4 + -1;
          uVar12 = 0x3ed;
          if (DAT_803de5c4 < '\0') {
            DAT_803de5c4 = '\x02';
          }
        }
      }
      if (DAT_803de43a == '\0') {
        if (DAT_803dc819 != -1) {
          DAT_803de5c4 = DAT_803dc819;
          DAT_803dc819 = -1;
        }
      }
      else {
        if (DAT_803dc819 == -1) {
          DAT_803dc819 = DAT_803de5c4;
        }
        DAT_803de5c4 = '\x02';
      }
      if (DAT_803de5c4 == '\x01') {
        if (DAT_803de5c5 != '\0') {
          FUN_8000b844(0,0x3f0);
          DAT_803de5c5 = '\0';
        }
        DAT_803de5b4 = FUN_80036f50(0x4f,iVar7,local_18);
        if (DAT_803de5b4 != 0) {
          if (FLOAT_803e2ef0 <= local_18[0]) {
            DAT_803de5aa = '\0';
            cVar5 = DAT_803de5aa;
          }
          else {
            cVar5 = DAT_803de5aa + '\x01';
            if (local_18[0] < FLOAT_803e2f2c) {
              cVar5 = DAT_803de5aa + '\x02';
            }
          }
          DAT_803de5aa = cVar5;
          psVar11 = FUN_8000facc();
          iVar7 = FUN_80021884();
          sVar6 = (*psVar11 + (short)iVar7) - *(short *)(iRam803dc834 + 4);
          if (0x8000 < sVar6) {
            sVar6 = sVar6 + 1;
          }
          if (sVar6 < -0x8000) {
            sVar6 = sVar6 + -1;
          }
          iVar7 = (int)sVar6 / 5 + ((int)sVar6 >> 0x1f);
          *(short *)(iRam803dc834 + 4) =
               *(short *)(iRam803dc834 + 4) + ((short)iVar7 - (short)(iVar7 >> 0x1f));
        }
      }
      else if (DAT_803de5c4 < '\x01') {
        if (-1 < DAT_803de5c4) {
          if ((uVar9 & 4) == 0) {
            if ((uVar9 & 8) == 0) {
              FLOAT_803dc84c = FLOAT_803e2f28;
            }
            else {
              dVar14 = (double)FUN_8029312c((double)FLOAT_803dc840,(double)FLOAT_803dc074);
              FLOAT_803dc84c = (float)((double)FLOAT_803dc84c * dVar14);
            }
          }
          else {
            dVar14 = (double)FUN_8029312c((double)FLOAT_803dc83c,(double)FLOAT_803dc074);
            FLOAT_803dc84c = (float)((double)FLOAT_803dc84c * dVar14);
          }
          fVar2 = FLOAT_803dc844;
          if ((FLOAT_803dc844 <= FLOAT_803dc84c) &&
             (fVar2 = FLOAT_803dc84c, FLOAT_803dc848 < FLOAT_803dc84c)) {
            fVar2 = FLOAT_803dc848;
          }
          fVar3 = FLOAT_803dc81c * fVar2;
          fVar4 = FLOAT_803dc820;
          if ((FLOAT_803dc820 <= fVar3) && (fVar4 = fVar3, FLOAT_803dc824 < fVar3)) {
            fVar4 = FLOAT_803dc824;
          }
          FLOAT_803dc84c = fVar2;
          if (fVar4 == FLOAT_803dc81c) {
            FLOAT_803dc81c = fVar4;
            if (DAT_803de5c5 != '\0') {
              FUN_8000b844(0,0x3f0);
              DAT_803de5c5 = '\0';
            }
          }
          else {
            FLOAT_803dc81c = fVar4;
            if (DAT_803de5c5 == '\0') {
              FUN_8000bb38(0,0x3f0);
              DAT_803de5c5 = '\x01';
            }
          }
        }
      }
      else if (DAT_803de5c4 < '\x03') {
        if (DAT_803de5c5 != '\0') {
          FUN_8000b844(0,0x3f0);
          DAT_803de5c5 = '\0';
        }
        iVar7 = (int)DAT_803dc6d6;
        bVar1 = iVar7 != DAT_803dc850;
        DAT_803dc850 = iVar7;
        if (bVar1) {
          if (iVar7 == -1) {
            uVar12 = 0x3ef;
          }
          else {
            uVar12 = 0x3ee;
          }
        }
      }
      if (uVar12 != 0) {
        FUN_8000bb38(0,uVar12);
      }
    }
  }
  return;
}

