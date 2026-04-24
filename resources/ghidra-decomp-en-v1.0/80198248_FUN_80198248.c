// Function: FUN_80198248
// Entry: 80198248
// Size: 1804 bytes

/* WARNING: Removing unreachable block (ram,0x8019834c) */

void FUN_80198248(int param_1)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  int unaff_r28;
  float *pfVar4;
  int iVar5;
  
  pfVar4 = *(float **)(param_1 + 0xb8);
  iVar5 = *(int *)(param_1 + 0x4c);
  if ((*(byte *)(iVar5 + 0x1c) & 8) != 0) {
    iVar2 = FUN_80080204();
    if (iVar2 == 0) {
      iVar2 = FUN_8002b9ec();
      (**(code **)(*DAT_803dca9c + 0x20))
                ((double)*(float *)(iVar2 + 0x18),(double)*(float *)(iVar2 + 0x1c),
                 (double)*(float *)(iVar2 + 0x20),7,(int)*(char *)(iVar5 + 0x20),param_1 + 0xc,
                 param_1 + 0x10,param_1 + 0x14);
    }
    else {
      iVar2 = (**(code **)(*DAT_803dca50 + 0xc))();
      (**(code **)(*DAT_803dca9c + 0x20))
                ((double)*(float *)(iVar2 + 0x18),(double)*(float *)(iVar2 + 0x1c),
                 (double)*(float *)(iVar2 + 0x20),7,(int)*(char *)(iVar5 + 0x20),param_1 + 0xc,
                 param_1 + 0x10,param_1 + 0x14);
    }
  }
  if (0 < *(short *)(iVar5 + 0x18)) {
    unaff_r28 = FUN_8001ffb4();
  }
  bVar1 = *(byte *)(iVar5 + 0x1d);
  if (bVar1 == 1) {
    if (((*(short *)(iVar5 + 0x18) == -1) ||
        (((*(byte *)(iVar5 + 0x1c) & 2) != 0 && (unaff_r28 != 0)))) ||
       (((*(byte *)(iVar5 + 0x1c) & 4) != 0 && (unaff_r28 == 0)))) {
      if ((*(byte *)(pfVar4 + 1) & 1) == 0) {
        if (*(short *)(iVar5 + 0x1a) != 0) {
          *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) | 1;
          iVar2 = param_1;
          if ((*(byte *)(iVar5 + 0x1c) & 0x10) == 0) {
            iVar2 = 0;
          }
          if ((iVar2 == 0) || ((*(byte *)(iVar5 + 0x1c) & 1) != 0)) {
            if (*(char *)(iVar5 + 0x1d) == '\x01') {
              FUN_8000dcbc();
            }
            else {
              FUN_8000bb18();
            }
          }
          else {
            FUN_8000bae0((double)*(float *)(iVar2 + 0xc),(double)*(float *)(iVar2 + 0x10),
                         (double)*(float *)(iVar2 + 0x14));
          }
        }
        if (*(short *)(iVar5 + 0x22) != 0) {
          *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) | 1;
          if ((*(byte *)(iVar5 + 0x1c) & 0x10) == 0) {
            param_1 = 0;
          }
          if ((param_1 == 0) || ((*(byte *)(iVar5 + 0x1c) & 1) != 0)) {
            if (*(char *)(iVar5 + 0x1d) == '\x01') {
              FUN_8000dcbc();
            }
            else {
              FUN_8000bb18();
            }
          }
          else {
            FUN_8000bae0((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                         (double)*(float *)(param_1 + 0x14));
          }
        }
      }
    }
    else if ((*(byte *)(pfVar4 + 1) & 1) != 0) {
      *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) & 0xfe;
      if (*(char *)(iVar5 + 0x1d) == '\x01') {
        if (*(short *)(iVar5 + 0x1a) != 0) {
          FUN_8000db90(param_1);
        }
        if (*(short *)(iVar5 + 0x22) != 0) {
          FUN_8000db90(param_1);
        }
      }
      else {
        if (*(short *)(iVar5 + 0x1a) != 0) {
          FUN_8000b824(param_1);
        }
        if (*(short *)(iVar5 + 0x22) != 0) {
          FUN_8000b824(param_1);
        }
      }
    }
  }
  else if (bVar1 == 0) {
    if (0 < *(short *)(iVar5 + 0x18)) {
      if (*pfVar4 == 0.0) {
        if ((unaff_r28 != 0) && (*pfVar4 = 1.401298e-45, (*(byte *)(iVar5 + 0x1c) & 2) != 0)) {
          if (*(short *)(iVar5 + 0x1a) != 0) {
            *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) | 1;
            iVar2 = param_1;
            if ((*(byte *)(iVar5 + 0x1c) & 0x10) == 0) {
              iVar2 = 0;
            }
            if ((iVar2 == 0) || ((*(byte *)(iVar5 + 0x1c) & 1) != 0)) {
              if (*(char *)(iVar5 + 0x1d) == '\x01') {
                FUN_8000dcbc();
              }
              else {
                FUN_8000bb18();
              }
            }
            else {
              FUN_8000bae0((double)*(float *)(iVar2 + 0xc),(double)*(float *)(iVar2 + 0x10),
                           (double)*(float *)(iVar2 + 0x14));
            }
          }
          if (*(short *)(iVar5 + 0x22) != 0) {
            *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) | 1;
            if ((*(byte *)(iVar5 + 0x1c) & 0x10) == 0) {
              param_1 = 0;
            }
            if ((param_1 == 0) || ((*(byte *)(iVar5 + 0x1c) & 1) != 0)) {
              if (*(char *)(iVar5 + 0x1d) == '\x01') {
                FUN_8000dcbc();
              }
              else {
                FUN_8000bb18();
              }
            }
            else {
              FUN_8000bae0((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                           (double)*(float *)(param_1 + 0x14));
            }
          }
        }
      }
      else if ((unaff_r28 == 0) && (*pfVar4 = 0.0, (*(byte *)(iVar5 + 0x1c) & 4) != 0)) {
        if (*(short *)(iVar5 + 0x1a) != 0) {
          *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) | 1;
          iVar2 = param_1;
          if ((*(byte *)(iVar5 + 0x1c) & 0x10) == 0) {
            iVar2 = 0;
          }
          if ((iVar2 == 0) || ((*(byte *)(iVar5 + 0x1c) & 1) != 0)) {
            if (*(char *)(iVar5 + 0x1d) == '\x01') {
              FUN_8000dcbc();
            }
            else {
              FUN_8000bb18();
            }
          }
          else {
            FUN_8000bae0((double)*(float *)(iVar2 + 0xc),(double)*(float *)(iVar2 + 0x10),
                         (double)*(float *)(iVar2 + 0x14));
          }
        }
        if (*(short *)(iVar5 + 0x22) != 0) {
          *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) | 1;
          if ((*(byte *)(iVar5 + 0x1c) & 0x10) == 0) {
            param_1 = 0;
          }
          if ((param_1 == 0) || ((*(byte *)(iVar5 + 0x1c) & 1) != 0)) {
            if (*(char *)(iVar5 + 0x1d) == '\x01') {
              FUN_8000dcbc();
            }
            else {
              FUN_8000bb18();
            }
          }
          else {
            FUN_8000bae0((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                         (double)*(float *)(param_1 + 0x14));
          }
        }
      }
    }
  }
  else if (bVar1 < 3) {
    if (((*(short *)(iVar5 + 0x18) == -1) ||
        (((*(byte *)(iVar5 + 0x1c) & 2) != 0 && (unaff_r28 != 0)))) ||
       (((*(byte *)(iVar5 + 0x1c) & 4) != 0 && (unaff_r28 == 0)))) {
      *pfVar4 = *pfVar4 - FLOAT_803db414;
      if (*pfVar4 <= FLOAT_803e40b8) {
        uVar3 = FUN_800221a0(*(undefined *)(iVar5 + 0x1e),*(undefined *)(iVar5 + 0x1f));
        *pfVar4 = FLOAT_803e40bc *
                  (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e40c0);
        if (*(short *)(iVar5 + 0x1a) != 0) {
          *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) | 1;
          iVar2 = param_1;
          if ((*(byte *)(iVar5 + 0x1c) & 0x10) == 0) {
            iVar2 = 0;
          }
          if ((iVar2 == 0) || ((*(byte *)(iVar5 + 0x1c) & 1) != 0)) {
            if (*(char *)(iVar5 + 0x1d) == '\x01') {
              FUN_8000dcbc();
            }
            else {
              FUN_8000bb18();
            }
          }
          else {
            FUN_8000bae0((double)*(float *)(iVar2 + 0xc),(double)*(float *)(iVar2 + 0x10),
                         (double)*(float *)(iVar2 + 0x14));
          }
        }
        if (*(short *)(iVar5 + 0x22) != 0) {
          *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) | 1;
          if ((*(byte *)(iVar5 + 0x1c) & 0x10) == 0) {
            param_1 = 0;
          }
          if ((param_1 == 0) || ((*(byte *)(iVar5 + 0x1c) & 1) != 0)) {
            if (*(char *)(iVar5 + 0x1d) == '\x01') {
              FUN_8000dcbc();
            }
            else {
              FUN_8000bb18();
            }
          }
          else {
            FUN_8000bae0((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                         (double)*(float *)(param_1 + 0x14));
          }
        }
      }
    }
    else if ((*(byte *)(pfVar4 + 1) & 1) != 0) {
      *(byte *)(pfVar4 + 1) = *(byte *)(pfVar4 + 1) & 0xfe;
      if (*(char *)(iVar5 + 0x1d) == '\x01') {
        if (*(short *)(iVar5 + 0x1a) != 0) {
          FUN_8000db90(param_1);
        }
        if (*(short *)(iVar5 + 0x22) != 0) {
          FUN_8000db90(param_1);
        }
      }
      else {
        if (*(short *)(iVar5 + 0x1a) != 0) {
          FUN_8000b824(param_1);
        }
        if (*(short *)(iVar5 + 0x22) != 0) {
          FUN_8000b824(param_1);
        }
      }
    }
  }
  return;
}

