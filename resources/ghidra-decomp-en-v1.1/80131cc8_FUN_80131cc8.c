// Function: FUN_80131cc8
// Entry: 80131cc8
// Size: 948 bytes

/* WARNING: Removing unreachable block (ram,0x80131d20) */

void FUN_80131cc8(int param_1)

{
  byte bVar1;
  short sVar2;
  char cVar4;
  uint uVar3;
  short sVar5;
  short sVar6;
  undefined8 local_20;
  undefined8 local_18;
  
  if ((*(byte *)(param_1 + 4) & 1) == 0) {
    return;
  }
  *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) & 0xe3;
  sVar2 = *(short *)(param_1 + 0xc);
  *(undefined *)(param_1 + 6) = 4;
  bVar1 = *(byte *)(param_1 + 5);
  if (bVar1 != 1) {
    if (bVar1 == 0) {
      cVar4 = FUN_80014cec(0);
      uVar3 = (uint)cVar4;
      sVar6 = ((short)((int)uVar3 >> 4) + (ushort)((int)uVar3 < 0 && (uVar3 & 0xf) != 0)) * 0xa0;
      if (((sVar6 == 0) ||
          ((FLOAT_803de59c <
            (float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 8) ^ 0x80000000) -
                   DOUBLE_803e2e78) && (sVar6 < 0)))) ||
         (((float)((double)CONCAT44(0x43300000,(int)*(short *)(param_1 + 10) ^ 0x80000000) -
                  DOUBLE_803e2e78) < FLOAT_803de59c && (0 < sVar6)))) {
        DAT_803de598 = 0;
      }
      else {
        local_20 = (double)CONCAT44(0x43300000,(int)DAT_803de598 ^ 0x80000000);
        DAT_803de598 = (short)(int)(FLOAT_803e2e80 *
                                    (float)((double)CONCAT44(0x43300000,
                                                             (int)(short)(sVar6 - DAT_803de598) ^
                                                             0x80000000) - DOUBLE_803e2e78) +
                                   (float)(local_20 - DOUBLE_803e2e78));
        FUN_8000da78(0,0x3b9);
      }
      local_18 = (double)CONCAT44(0x43300000,(int)DAT_803de598 ^ 0x80000000);
      FLOAT_803de59c = FLOAT_803de59c + (float)(local_18 - DOUBLE_803e2e78) / FLOAT_803e2e84;
      *(short *)(param_1 + 0xc) = (short)(int)(FLOAT_803e2e88 + FLOAT_803de59c);
      if ((*(byte *)(param_1 + 4) & 0x40) != 0) {
        sVar6 = *(short *)(param_1 + 0xc);
        sVar5 = sVar6;
        if (0x7f < sVar6) {
          sVar5 = 0x7f;
        }
        if (sVar5 < 0) {
          sVar6 = 0;
        }
        else if (0x7f < sVar6) {
          sVar6 = 0x7f;
        }
        FUN_8000b9bc((double)FLOAT_803e2e88,0,0x3b9,(byte)sVar6);
      }
      goto LAB_80131fc8;
    }
    if (bVar1 < 3) {
      cVar4 = FUN_80014cec(0);
      if (cVar4 < '$') {
        if (cVar4 < -0x23) {
          sVar6 = -1;
        }
        else {
          sVar6 = 0;
        }
      }
      else {
        sVar6 = 1;
      }
      sVar5 = sVar6;
      if (DAT_803de5a0 != '\0') {
        sVar5 = 0;
      }
      DAT_803de5a0 = (char)sVar6;
      if (sVar5 < 0) {
        FUN_8000bb38(0,0xf3);
        *(short *)(param_1 + 0xc) = *(short *)(param_1 + 0xc) + -1;
        *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) | 4;
      }
      else if (0 < sVar5) {
        FUN_8000bb38(0,0xf3);
        *(short *)(param_1 + 0xc) = *(short *)(param_1 + 0xc) + 1;
        *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) | 8;
      }
      goto LAB_80131fc8;
    }
  }
  if (((*(byte *)(param_1 + 4) & 0x20) == 0) && (uVar3 = FUN_80014e9c(0), (uVar3 & 0x100) != 0)) {
    FUN_8000bb38(0,0xf4);
    *(ushort *)(param_1 + 0xc) = *(ushort *)(param_1 + 0xc) ^ 1;
  }
LAB_80131fc8:
  sVar6 = *(short *)(param_1 + 10);
  if (sVar6 < *(short *)(param_1 + 0xc)) {
    if ((*(byte *)(param_1 + 4) & 2) == 0) {
      *(short *)(param_1 + 0xc) = sVar6;
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
      *(short *)(param_1 + 0xc) = sVar6;
    }
  }
  if (sVar2 != *(short *)(param_1 + 0xc)) {
    *(byte *)(param_1 + 4) = *(byte *)(param_1 + 4) | 0x10;
  }
  if (((*(byte *)(param_1 + 4) & 0x80) != 0) && ((*(byte *)(param_1 + 4) & 0x10) != 0)) {
    FUN_8000a304((int)*(short *)(param_1 + 0xc));
  }
  return;
}

