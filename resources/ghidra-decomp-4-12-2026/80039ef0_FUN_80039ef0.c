// Function: FUN_80039ef0
// Entry: 80039ef0
// Size: 880 bytes

/* WARNING: Removing unreachable block (ram,0x80039f6c) */

void FUN_80039ef0(double param_1,short *param_2,char *param_3,int param_4)

{
  float fVar1;
  ushort uVar2;
  float fVar3;
  uint uVar4;
  int iVar5;
  bool bVar6;
  
  bVar6 = (double)FLOAT_803df664 < param_1;
  if (((uint)(int)*(short *)(param_3 + 0x1a) >> 8 & 0xff) != (uint)bVar6) {
    *(ushort *)(param_3 + 0x1a) = (ushort)bVar6 << 8;
  }
  uVar2 = *(ushort *)(param_3 + 0x1a) & 0xff;
  if (uVar2 == 2) {
    if ((*param_3 != '\0') || (iVar5 = FUN_80039ab8((int)param_3,param_4), iVar5 != 0)) {
      *(ushort *)(param_3 + 0x1a) = (ushort)bVar6 << 8;
    }
  }
  else if (uVar2 < 2) {
    if (uVar2 == 0) {
      if (*param_3 == '\0') {
        *(ushort *)(param_3 + 0x1a) = (ushort)bVar6 << 8 | 1;
        uVar4 = FUN_80022264(100,400);
        *(short *)(param_3 + 0x1c) = (short)uVar4;
        *(undefined2 *)(param_3 + 0x14) = *(undefined2 *)(param_4 + 2);
      }
      else {
        *(ushort *)(param_3 + 0x1a) = (ushort)bVar6 << 8 | 3;
        *(undefined2 *)(param_3 + 0x16) = *(undefined2 *)(param_4 + 2);
        *(float *)(param_3 + 0x10) = FLOAT_803df61c;
      }
    }
    else {
      *(ushort *)(param_3 + 0x1c) = *(short *)(param_3 + 0x1c) - (ushort)DAT_803dc070;
      if (*(short *)(param_3 + 0x1c) < 0) {
        iVar5 = (int)*(short *)(param_3 + 0x14);
        uVar4 = FUN_80022264(0,0x1fff);
        *(short *)(param_3 + 0x14) = (short)uVar4;
        if (iVar5 < 1) {
          if (*(short *)(param_3 + 0x14) - iVar5 < 0xe38) {
            *(short *)(param_3 + 0x14) = *(short *)(param_3 + 0x14) + 0xe38;
          }
          if (0x1fff < *(short *)(param_3 + 0x14)) {
            param_3[0x14] = '\x1f';
            param_3[0x15] = -1;
          }
        }
        else {
          if (iVar5 - *(short *)(param_3 + 0x14) < 0xe38) {
            *(short *)(param_3 + 0x14) = *(short *)(param_3 + 0x14) + 0xe38;
          }
          if (0x1fff < *(short *)(param_3 + 0x14)) {
            param_3[0x14] = '\x1f';
            param_3[0x15] = -1;
          }
          *(short *)(param_3 + 0x14) = -*(short *)(param_3 + 0x14);
        }
        *(ushort *)(param_3 + 0x1a) = (ushort)bVar6 << 8 | 2;
        param_3[0x1c] = '\0';
        param_3[0x1d] = '\0';
        *(undefined2 *)(param_3 + 0x16) = *(undefined2 *)(param_4 + 2);
      }
    }
  }
  else if (uVar2 < 4) {
    if (*param_3 == '\0') {
      *(ushort *)(param_3 + 0x1a) = (ushort)bVar6 << 8;
    }
    else {
      iVar5 = FUN_80021884();
      *(short *)(param_3 + 0x14) = (short)iVar5 - *param_2;
      if (0x8000 < *(short *)(param_3 + 0x14)) {
        *(short *)(param_3 + 0x14) = *(short *)(param_3 + 0x14) + 1;
      }
      if (*(short *)(param_3 + 0x14) < -0x8000) {
        *(short *)(param_3 + 0x14) = *(short *)(param_3 + 0x14) + -1;
      }
      fVar3 = FLOAT_803df624;
      uVar4 = (uint)*(short *)(param_3 + 0x14);
      if (((int)uVar4 < 0x2000) && (-0x2000 < (int)uVar4)) {
        if (*(float *)(param_3 + 0x10) <= FLOAT_803df624) {
          *(short *)(param_4 + 2) = *(short *)(param_3 + 0x14);
        }
        else {
          *(short *)(param_4 + 2) =
               (short)(int)(*(float *)(param_3 + 0x10) *
                            (float)((double)CONCAT44(0x43300000,
                                                     (int)*(short *)(param_3 + 0x16) - uVar4 ^
                                                     0x80000000) - DOUBLE_803df650) +
                           (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803df650
                                  ));
          fVar1 = -(FLOAT_803df668 * FLOAT_803dc074 - *(float *)(param_3 + 0x10));
          *(float *)(param_3 + 0x10) = fVar1;
          if (fVar1 < fVar3) {
            *(float *)(param_3 + 0x10) = fVar3;
          }
        }
      }
      else {
        *(ushort *)(param_3 + 0x1a) = (ushort)bVar6 << 8;
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

