// Function: FUN_80131940
// Entry: 80131940
// Size: 948 bytes

/* WARNING: Removing unreachable block (ram,0x80131998) */

void FUN_80131940(int param_1)

{
  byte bVar1;
  short sVar2;
  ushort uVar3;
  char cVar5;
  uint uVar4;
  short sVar6;
  short sVar7;
  ushort uVar8;
  double local_20;
  double local_18;
  
  if ((*(byte *)(param_1 + 4) & 1) == 0) {
    return;
  }
  *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) & 0xe3;
  sVar2 = *(short *)(param_1 + 0xc);
  *(undefined *)(param_1 + 6) = 4;
  bVar1 = *(byte *)(param_1 + 5);
  if (bVar1 != 1) {
    if (bVar1 == 0) {
      cVar5 = FUN_80014cc0(0);
      uVar4 = (uint)cVar5;
      sVar7 = ((short)((int)uVar4 >> 4) + (ushort)((int)uVar4 < 0 && (uVar4 & 0xf) != 0)) * 0xa0;
      if (((sVar7 == 0) ||
          ((FLOAT_803dd91c <
            (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 8) ^ 0x80000000) -
                   DOUBLE_803e21e8) && (sVar7 < 0)))) ||
         (((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 10) ^ 0x80000000) -
                  DOUBLE_803e21e8) < FLOAT_803dd91c && (0 < sVar7)))) {
        DAT_803dd918 = 0;
      }
      else {
        local_20 = (double)CONCAT44(0x43300000,(int)DAT_803dd918 ^ 0x80000000);
        DAT_803dd918 = (short)(int)(FLOAT_803e21f0 *
                                    (float)((double)CONCAT44(0x43300000,
                                                             (int)(short)(sVar7 - DAT_803dd918) ^
                                                             0x80000000) - DOUBLE_803e21e8) +
                                   (float)(local_20 - DOUBLE_803e21e8));
        FUN_8000da58(0,0x3b9);
      }
      local_18 = (double)CONCAT44(0x43300000,(int)DAT_803dd918 ^ 0x80000000);
      FLOAT_803dd91c = FLOAT_803dd91c + (float)(local_18 - DOUBLE_803e21e8) / FLOAT_803e21f4;
      *(short *)(param_1 + 0xc) = (short)(int)(FLOAT_803e21f8 + FLOAT_803dd91c);
      if ((*(byte *)(param_1 + 4) & 0x40) != 0) {
        uVar8 = *(ushort *)(param_1 + 0xc);
        uVar3 = uVar8;
        if (0x7f < (short)uVar8) {
          uVar3 = 0x7f;
        }
        if ((short)uVar3 < 0) {
          uVar8 = 0;
        }
        else if (0x7f < (short)uVar8) {
          uVar8 = 0x7f;
        }
        FUN_8000b99c((double)FLOAT_803e21f8,0,0x3b9,uVar8 & 0xff);
      }
      goto LAB_80131c40;
    }
    if (bVar1 < 3) {
      cVar5 = FUN_80014cc0(0);
      if (cVar5 < '$') {
        if (cVar5 < -0x23) {
          sVar7 = -1;
        }
        else {
          sVar7 = 0;
        }
      }
      else {
        sVar7 = 1;
      }
      sVar6 = sVar7;
      if (DAT_803dd920 != '\0') {
        sVar6 = 0;
      }
      DAT_803dd920 = (char)sVar7;
      if (sVar6 < 0) {
        FUN_8000bb18(0,0xf3);
        *(short *)(param_1 + 0xc) = *(short *)(param_1 + 0xc) + -1;
        *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) | 4;
      }
      else if (0 < sVar6) {
        FUN_8000bb18(0,0xf3);
        *(short *)(param_1 + 0xc) = *(short *)(param_1 + 0xc) + 1;
        *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) | 8;
      }
      goto LAB_80131c40;
    }
  }
  if (((*(byte *)(param_1 + 4) & 0x20) == 0) && (uVar4 = FUN_80014e70(0), (uVar4 & 0x100) != 0)) {
    FUN_8000bb18(0,0xf4);
    *(ushort *)(param_1 + 0xc) = *(ushort *)(param_1 + 0xc) ^ 1;
  }
LAB_80131c40:
  sVar7 = *(short *)(param_1 + 10);
  if (sVar7 < *(short *)(param_1 + 0xc)) {
    if ((*(byte *)(param_1 + 4) & 2) == 0) {
      *(short *)(param_1 + 0xc) = sVar7;
    }
    else {
      *(undefined2 *)(param_1 + 0xc) = 0;
    }
  }
  else if (*(short *)(param_1 + 0xc) < *(short *)(param_1 + 8)) {
    if ((*(byte *)(param_1 + 4) & 2) == 0) {
      *(short *)(param_1 + 0xc) = *(short *)(param_1 + 8);
    }
    else {
      *(short *)(param_1 + 0xc) = sVar7;
    }
  }
  if (sVar2 != *(short *)(param_1 + 0xc)) {
    *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) | 0x10;
  }
  if (((*(byte *)(param_1 + 4) & 0x80) != 0) && ((*(byte *)(param_1 + 4) & 0x10) != 0)) {
    FUN_8000a2e4((int)*(short *)(param_1 + 0xc));
  }
  return;
}

