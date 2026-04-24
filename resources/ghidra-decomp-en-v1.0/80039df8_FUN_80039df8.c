// Function: FUN_80039df8
// Entry: 80039df8
// Size: 880 bytes

/* WARNING: Removing unreachable block (ram,0x80039e74) */

void FUN_80039df8(double param_1,short *param_2,char *param_3,int param_4)

{
  float fVar1;
  ushort uVar2;
  float fVar3;
  undefined2 uVar4;
  short sVar5;
  uint uVar6;
  int iVar7;
  bool bVar8;
  
  bVar8 = (double)FLOAT_803de9e4 < param_1;
  if (((uint)(int)*(short *)(param_3 + 0x1a) >> 8 & 0xff) != (uint)bVar8) {
    *(ushort *)(param_3 + 0x1a) = (ushort)bVar8 << 8;
  }
  uVar2 = *(ushort *)(param_3 + 0x1a) & 0xff;
  if (uVar2 == 2) {
    if ((*param_3 != '\0') || (iVar7 = FUN_800399c0(param_3,param_4), iVar7 != 0)) {
      *(ushort *)(param_3 + 0x1a) = (ushort)bVar8 << 8;
    }
  }
  else if (uVar2 < 2) {
    if (uVar2 == 0) {
      if (*param_3 == '\0') {
        *(ushort *)(param_3 + 0x1a) = (ushort)bVar8 << 8 | 1;
        uVar4 = FUN_800221a0(100,400);
        *(undefined2 *)(param_3 + 0x1c) = uVar4;
        *(undefined2 *)(param_3 + 0x14) = *(undefined2 *)(param_4 + 2);
      }
      else {
        *(ushort *)(param_3 + 0x1a) = (ushort)bVar8 << 8 | 3;
        *(undefined2 *)(param_3 + 0x16) = *(undefined2 *)(param_4 + 2);
        *(float *)(param_3 + 0x10) = FLOAT_803de99c;
      }
    }
    else {
      *(ushort *)(param_3 + 0x1c) = *(short *)(param_3 + 0x1c) - (ushort)DAT_803db410;
      if (*(short *)(param_3 + 0x1c) < 0) {
        iVar7 = (int)*(short *)(param_3 + 0x14);
        uVar4 = FUN_800221a0(0,0x1fff);
        *(undefined2 *)(param_3 + 0x14) = uVar4;
        if (iVar7 < 1) {
          if (*(short *)(param_3 + 0x14) - iVar7 < 0xe38) {
            *(short *)(param_3 + 0x14) = *(short *)(param_3 + 0x14) + 0xe38;
          }
          if (0x1fff < *(short *)(param_3 + 0x14)) {
            *(undefined2 *)(param_3 + 0x14) = 0x1fff;
          }
        }
        else {
          if (iVar7 - *(short *)(param_3 + 0x14) < 0xe38) {
            *(short *)(param_3 + 0x14) = *(short *)(param_3 + 0x14) + 0xe38;
          }
          if (0x1fff < *(short *)(param_3 + 0x14)) {
            *(undefined2 *)(param_3 + 0x14) = 0x1fff;
          }
          *(short *)(param_3 + 0x14) = -*(short *)(param_3 + 0x14);
        }
        *(ushort *)(param_3 + 0x1a) = (ushort)bVar8 << 8 | 2;
        *(undefined2 *)(param_3 + 0x1c) = 0;
        *(undefined2 *)(param_3 + 0x16) = *(undefined2 *)(param_4 + 2);
      }
    }
  }
  else if (uVar2 < 4) {
    if (*param_3 == '\0') {
      *(ushort *)(param_3 + 0x1a) = (ushort)bVar8 << 8;
    }
    else {
      sVar5 = FUN_800217c0((double)(*(float *)(param_2 + 6) - *(float *)(param_3 + 4)),
                           (double)(*(float *)(param_2 + 10) - *(float *)(param_3 + 0xc)));
      *(short *)(param_3 + 0x14) = sVar5 - *param_2;
      if (0x8000 < *(short *)(param_3 + 0x14)) {
        *(short *)(param_3 + 0x14) = *(short *)(param_3 + 0x14) + 1;
      }
      if (*(short *)(param_3 + 0x14) < -0x8000) {
        *(short *)(param_3 + 0x14) = *(short *)(param_3 + 0x14) + -1;
      }
      fVar3 = FLOAT_803de9a4;
      uVar6 = (uint)*(short *)(param_3 + 0x14);
      if (((int)uVar6 < 0x2000) && (-0x2000 < (int)uVar6)) {
        if (*(float *)(param_3 + 0x10) <= FLOAT_803de9a4) {
          *(short *)(param_4 + 2) = *(short *)(param_3 + 0x14);
        }
        else {
          *(short *)(param_4 + 2) =
               (short)(int)(*(float *)(param_3 + 0x10) *
                            (float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(param_3 + 0x16) - uVar6 ^
                                                     0x80000000) - DOUBLE_803de9d0) +
                           (float)((double)CONCAT44(0x43300000,uVar6 ^ 0x80000000) - DOUBLE_803de9d0
                                  ));
          fVar1 = -(FLOAT_803de9e8 * FLOAT_803db414 - *(float *)(param_3 + 0x10));
          *(float *)(param_3 + 0x10) = fVar1;
          if (fVar1 < fVar3) {
            *(float *)(param_3 + 0x10) = fVar3;
          }
        }
      }
      else {
        *(ushort *)(param_3 + 0x1a) = (ushort)bVar8 << 8;
      }
    }
  }
  if (*(short *)(param_4 + 2) < -0x1fff) {
    *(undefined2 *)(param_4 + 2) = 0xe001;
  }
  else if (0x1fff < *(short *)(param_4 + 2)) {
    *(undefined2 *)(param_4 + 2) = 0x1fff;
  }
  return;
}

