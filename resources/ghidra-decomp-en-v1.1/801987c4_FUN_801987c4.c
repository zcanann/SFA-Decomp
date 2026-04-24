// Function: FUN_801987c4
// Entry: 801987c4
// Size: 1804 bytes

/* WARNING: Removing unreachable block (ram,0x801988c8) */

void FUN_801987c4(uint param_1)

{
  byte bVar1;
  ushort uVar2;
  int iVar3;
  uint uVar4;
  uint unaff_r28;
  float *pfVar5;
  int iVar6;
  
  pfVar5 = *(float **)(param_1 + 0xb8);
  iVar6 = *(int *)(param_1 + 0x4c);
  if ((*(byte *)(iVar6 + 0x1c) & 8) != 0) {
    iVar3 = FUN_80080490();
    if (iVar3 == 0) {
      iVar3 = FUN_8002bac4();
      (**(code **)(*DAT_803dd71c + 0x20))
                ((double)*(float *)(iVar3 + 0x18),(double)*(float *)(iVar3 + 0x1c),
                 (double)*(float *)(iVar3 + 0x20),7,(int)*(char *)(iVar6 + 0x20),param_1 + 0xc,
                 param_1 + 0x10,param_1 + 0x14);
    }
    else {
      iVar3 = (**(code **)(*DAT_803dd6d0 + 0xc))();
      (**(code **)(*DAT_803dd71c + 0x20))
                ((double)*(float *)(iVar3 + 0x18),(double)*(float *)(iVar3 + 0x1c),
                 (double)*(float *)(iVar3 + 0x20),7,(int)*(char *)(iVar6 + 0x20),param_1 + 0xc,
                 param_1 + 0x10,param_1 + 0x14);
    }
  }
  if (0 < *(short *)(iVar6 + 0x18)) {
    unaff_r28 = FUN_80020078((int)*(short *)(iVar6 + 0x18));
  }
  bVar1 = *(byte *)(iVar6 + 0x1d);
  if (bVar1 == 1) {
    if (((*(short *)(iVar6 + 0x18) == -1) ||
        (((*(byte *)(iVar6 + 0x1c) & 2) != 0 && (unaff_r28 != 0)))) ||
       (((*(byte *)(iVar6 + 0x1c) & 4) != 0 && (unaff_r28 == 0)))) {
      if ((*(byte *)(pfVar5 + 1) & 1) == 0) {
        uVar2 = *(ushort *)(iVar6 + 0x1a);
        if (uVar2 != 0) {
          *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) | 1;
          uVar4 = param_1;
          if ((*(byte *)(iVar6 + 0x1c) & 0x10) == 0) {
            uVar4 = 0;
          }
          if ((uVar4 == 0) || ((*(byte *)(iVar6 + 0x1c) & 1) != 0)) {
            if (*(char *)(iVar6 + 0x1d) == '\x01') {
              FUN_8000dcdc(uVar4,uVar2);
            }
            else {
              FUN_8000bb38(uVar4,uVar2);
            }
          }
          else {
            FUN_8000bb00((double)*(float *)(uVar4 + 0xc),(double)*(float *)(uVar4 + 0x10),
                         (double)*(float *)(uVar4 + 0x14),uVar4,uVar2);
          }
        }
        uVar2 = *(ushort *)(iVar6 + 0x22);
        if (uVar2 != 0) {
          *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) | 1;
          if ((*(byte *)(iVar6 + 0x1c) & 0x10) == 0) {
            param_1 = 0;
          }
          if ((param_1 == 0) || ((*(byte *)(iVar6 + 0x1c) & 1) != 0)) {
            if (*(char *)(iVar6 + 0x1d) == '\x01') {
              FUN_8000dcdc(param_1,uVar2);
            }
            else {
              FUN_8000bb38(param_1,uVar2);
            }
          }
          else {
            FUN_8000bb00((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                         (double)*(float *)(param_1 + 0x14),param_1,uVar2);
          }
        }
      }
    }
    else if ((*(byte *)(pfVar5 + 1) & 1) != 0) {
      *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) & 0xfe;
      if (*(char *)(iVar6 + 0x1d) == '\x01') {
        if (*(short *)(iVar6 + 0x1a) != 0) {
          FUN_8000dbb0();
        }
        if (*(short *)(iVar6 + 0x22) != 0) {
          FUN_8000dbb0();
        }
      }
      else {
        if (*(short *)(iVar6 + 0x1a) != 0) {
          FUN_8000b844(param_1,*(short *)(iVar6 + 0x1a));
        }
        if (*(short *)(iVar6 + 0x22) != 0) {
          FUN_8000b844(param_1,*(short *)(iVar6 + 0x22));
        }
      }
    }
  }
  else if (bVar1 == 0) {
    if (0 < *(short *)(iVar6 + 0x18)) {
      if (*pfVar5 == 0.0) {
        if ((unaff_r28 != 0) && (*pfVar5 = 1.4013e-45, (*(byte *)(iVar6 + 0x1c) & 2) != 0)) {
          uVar2 = *(ushort *)(iVar6 + 0x1a);
          if (uVar2 != 0) {
            *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) | 1;
            uVar4 = param_1;
            if ((*(byte *)(iVar6 + 0x1c) & 0x10) == 0) {
              uVar4 = 0;
            }
            if ((uVar4 == 0) || ((*(byte *)(iVar6 + 0x1c) & 1) != 0)) {
              if (*(char *)(iVar6 + 0x1d) == '\x01') {
                FUN_8000dcdc(uVar4,uVar2);
              }
              else {
                FUN_8000bb38(uVar4,uVar2);
              }
            }
            else {
              FUN_8000bb00((double)*(float *)(uVar4 + 0xc),(double)*(float *)(uVar4 + 0x10),
                           (double)*(float *)(uVar4 + 0x14),uVar4,uVar2);
            }
          }
          uVar2 = *(ushort *)(iVar6 + 0x22);
          if (uVar2 != 0) {
            *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) | 1;
            if ((*(byte *)(iVar6 + 0x1c) & 0x10) == 0) {
              param_1 = 0;
            }
            if ((param_1 == 0) || ((*(byte *)(iVar6 + 0x1c) & 1) != 0)) {
              if (*(char *)(iVar6 + 0x1d) == '\x01') {
                FUN_8000dcdc(param_1,uVar2);
              }
              else {
                FUN_8000bb38(param_1,uVar2);
              }
            }
            else {
              FUN_8000bb00((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                           (double)*(float *)(param_1 + 0x14),param_1,uVar2);
            }
          }
        }
      }
      else if ((unaff_r28 == 0) && (*pfVar5 = 0.0, (*(byte *)(iVar6 + 0x1c) & 4) != 0)) {
        uVar2 = *(ushort *)(iVar6 + 0x1a);
        if (uVar2 != 0) {
          *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) | 1;
          uVar4 = param_1;
          if ((*(byte *)(iVar6 + 0x1c) & 0x10) == 0) {
            uVar4 = 0;
          }
          if ((uVar4 == 0) || ((*(byte *)(iVar6 + 0x1c) & 1) != 0)) {
            if (*(char *)(iVar6 + 0x1d) == '\x01') {
              FUN_8000dcdc(uVar4,uVar2);
            }
            else {
              FUN_8000bb38(uVar4,uVar2);
            }
          }
          else {
            FUN_8000bb00((double)*(float *)(uVar4 + 0xc),(double)*(float *)(uVar4 + 0x10),
                         (double)*(float *)(uVar4 + 0x14),uVar4,uVar2);
          }
        }
        uVar2 = *(ushort *)(iVar6 + 0x22);
        if (uVar2 != 0) {
          *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) | 1;
          if ((*(byte *)(iVar6 + 0x1c) & 0x10) == 0) {
            param_1 = 0;
          }
          if ((param_1 == 0) || ((*(byte *)(iVar6 + 0x1c) & 1) != 0)) {
            if (*(char *)(iVar6 + 0x1d) == '\x01') {
              FUN_8000dcdc(param_1,uVar2);
            }
            else {
              FUN_8000bb38(param_1,uVar2);
            }
          }
          else {
            FUN_8000bb00((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                         (double)*(float *)(param_1 + 0x14),param_1,uVar2);
          }
        }
      }
    }
  }
  else if (bVar1 < 3) {
    if (((*(short *)(iVar6 + 0x18) == -1) ||
        (((*(byte *)(iVar6 + 0x1c) & 2) != 0 && (unaff_r28 != 0)))) ||
       (((*(byte *)(iVar6 + 0x1c) & 4) != 0 && (unaff_r28 == 0)))) {
      *pfVar5 = *pfVar5 - FLOAT_803dc074;
      if (*pfVar5 <= FLOAT_803e4d50) {
        uVar4 = FUN_80022264((uint)*(byte *)(iVar6 + 0x1e),(uint)*(byte *)(iVar6 + 0x1f));
        *pfVar5 = FLOAT_803e4d54 *
                  (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e4d58);
        uVar2 = *(ushort *)(iVar6 + 0x1a);
        if (uVar2 != 0) {
          *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) | 1;
          uVar4 = param_1;
          if ((*(byte *)(iVar6 + 0x1c) & 0x10) == 0) {
            uVar4 = 0;
          }
          if ((uVar4 == 0) || ((*(byte *)(iVar6 + 0x1c) & 1) != 0)) {
            if (*(char *)(iVar6 + 0x1d) == '\x01') {
              FUN_8000dcdc(uVar4,uVar2);
            }
            else {
              FUN_8000bb38(uVar4,uVar2);
            }
          }
          else {
            FUN_8000bb00((double)*(float *)(uVar4 + 0xc),(double)*(float *)(uVar4 + 0x10),
                         (double)*(float *)(uVar4 + 0x14),uVar4,uVar2);
          }
        }
        uVar2 = *(ushort *)(iVar6 + 0x22);
        if (uVar2 != 0) {
          *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) | 1;
          if ((*(byte *)(iVar6 + 0x1c) & 0x10) == 0) {
            param_1 = 0;
          }
          if ((param_1 == 0) || ((*(byte *)(iVar6 + 0x1c) & 1) != 0)) {
            if (*(char *)(iVar6 + 0x1d) == '\x01') {
              FUN_8000dcdc(param_1,uVar2);
            }
            else {
              FUN_8000bb38(param_1,uVar2);
            }
          }
          else {
            FUN_8000bb00((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                         (double)*(float *)(param_1 + 0x14),param_1,uVar2);
          }
        }
      }
    }
    else if ((*(byte *)(pfVar5 + 1) & 1) != 0) {
      *(byte *)(pfVar5 + 1) = *(byte *)(pfVar5 + 1) & 0xfe;
      if (*(char *)(iVar6 + 0x1d) == '\x01') {
        if (*(short *)(iVar6 + 0x1a) != 0) {
          FUN_8000dbb0();
        }
        if (*(short *)(iVar6 + 0x22) != 0) {
          FUN_8000dbb0();
        }
      }
      else {
        if (*(short *)(iVar6 + 0x1a) != 0) {
          FUN_8000b844(param_1,*(short *)(iVar6 + 0x1a));
        }
        if (*(short *)(iVar6 + 0x22) != 0) {
          FUN_8000b844(param_1,*(short *)(iVar6 + 0x22));
        }
      }
    }
  }
  return;
}

