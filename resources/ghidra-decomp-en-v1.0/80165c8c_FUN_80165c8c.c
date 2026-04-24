// Function: FUN_80165c8c
// Entry: 80165c8c
// Size: 1976 bytes

/* WARNING: Removing unreachable block (ram,0x80165cdc) */
/* WARNING: Removing unreachable block (ram,0x80166310) */

void FUN_80165c8c(short *param_1,int param_2)

{
  byte bVar1;
  short sVar2;
  
  FUN_8002b95c((double)*(float *)(param_1 + 0x12),(double)*(float *)(param_1 + 0x14),
               (double)*(float *)(param_1 + 0x16));
  bVar1 = *(byte *)(param_2 + 0x90);
  if (bVar1 == 3) {
    if (*(float *)(param_2 + 0x48) <= *(float *)(param_1 + 6)) {
      if (*(float *)(param_1 + 6) <= *(float *)(param_2 + 0x4c)) {
        if (*(float *)(param_2 + 0x5c) <= *(float *)(param_1 + 8)) {
          if (*(float *)(param_2 + 0x58) < *(float *)(param_1 + 8)) {
            *(float *)(param_1 + 8) = *(float *)(param_2 + 0x58);
            if ((*(byte *)(param_2 + 0x91) & 0x10) != 0) {
              *(undefined4 *)(param_1 + 0x16) = *(undefined4 *)(param_1 + 0x14);
              *(undefined *)(param_2 + 0x90) = 4;
            }
            *(float *)(param_1 + 0x14) = FLOAT_803e2fdc;
          }
        }
        else {
          *(float *)(param_1 + 8) = *(float *)(param_2 + 0x5c);
          if ((*(byte *)(param_2 + 0x91) & 0x20) != 0) {
            *(float *)(param_1 + 0x16) = -*(float *)(param_1 + 0x14);
            *(undefined *)(param_2 + 0x90) = 5;
          }
          *(float *)(param_1 + 0x14) = FLOAT_803e2fdc;
        }
      }
      else {
        *(float *)(param_1 + 6) = *(float *)(param_2 + 0x4c);
        if ((*(byte *)(param_2 + 0x91) & 2) != 0) {
          *(undefined4 *)(param_1 + 0x16) = *(undefined4 *)(param_1 + 0x12);
          *(undefined *)(param_2 + 0x90) = 1;
        }
        *(float *)(param_1 + 0x12) = FLOAT_803e2fdc;
      }
    }
    else {
      *(float *)(param_1 + 6) = *(float *)(param_2 + 0x48);
      if ((*(byte *)(param_2 + 0x91) & 1) != 0) {
        *(float *)(param_1 + 0x16) = -*(float *)(param_1 + 0x12);
        *(undefined *)(param_2 + 0x90) = 0;
      }
      *(float *)(param_1 + 0x12) = FLOAT_803e2fdc;
    }
  }
  else if (bVar1 < 3) {
    if (bVar1 == 1) {
      if (*(float *)(param_2 + 0x5c) <= *(float *)(param_1 + 8)) {
        if (*(float *)(param_1 + 8) <= *(float *)(param_2 + 0x58)) {
          if (*(float *)(param_1 + 10) <= *(float *)(param_2 + 0x50)) {
            if (*(float *)(param_1 + 10) < *(float *)(param_2 + 0x54)) {
              *(float *)(param_1 + 10) = *(float *)(param_2 + 0x54);
              if ((*(byte *)(param_2 + 0x91) & 8) != 0) {
                *(undefined4 *)(param_1 + 0x12) = *(undefined4 *)(param_1 + 0x16);
                *(undefined *)(param_2 + 0x90) = 3;
              }
              *(float *)(param_1 + 0x16) = FLOAT_803e2fdc;
            }
          }
          else {
            *(float *)(param_1 + 10) = *(float *)(param_2 + 0x50);
            if ((*(byte *)(param_2 + 0x91) & 4) != 0) {
              *(float *)(param_1 + 0x12) = -*(float *)(param_1 + 0x16);
              *(undefined *)(param_2 + 0x90) = 2;
            }
            *(float *)(param_1 + 0x16) = FLOAT_803e2fdc;
          }
        }
        else {
          *(float *)(param_1 + 8) = *(float *)(param_2 + 0x58);
          if ((*(byte *)(param_2 + 0x91) & 0x10) != 0) {
            *(float *)(param_1 + 0x12) = -*(float *)(param_1 + 0x14);
            *(undefined *)(param_2 + 0x90) = 4;
          }
          *(float *)(param_1 + 0x14) = FLOAT_803e2fdc;
        }
      }
      else {
        *(float *)(param_1 + 8) = *(float *)(param_2 + 0x5c);
        if ((*(byte *)(param_2 + 0x91) & 0x20) != 0) {
          *(undefined4 *)(param_1 + 0x12) = *(undefined4 *)(param_1 + 0x14);
          *(undefined *)(param_2 + 0x90) = 5;
        }
        *(float *)(param_1 + 0x14) = FLOAT_803e2fdc;
      }
    }
    else if (bVar1 == 0) {
      if (*(float *)(param_2 + 0x5c) <= *(float *)(param_1 + 8)) {
        if (*(float *)(param_1 + 8) <= *(float *)(param_2 + 0x58)) {
          if (*(float *)(param_1 + 10) <= *(float *)(param_2 + 0x50)) {
            if (*(float *)(param_1 + 10) < *(float *)(param_2 + 0x54)) {
              *(float *)(param_1 + 10) = *(float *)(param_2 + 0x54);
              if ((*(byte *)(param_2 + 0x91) & 8) != 0) {
                *(float *)(param_1 + 0x12) = -*(float *)(param_1 + 0x16);
                *(undefined *)(param_2 + 0x90) = 3;
              }
              *(float *)(param_1 + 0x16) = FLOAT_803e2fdc;
            }
          }
          else {
            *(float *)(param_1 + 10) = *(float *)(param_2 + 0x50);
            if ((*(byte *)(param_2 + 0x91) & 4) != 0) {
              *(undefined4 *)(param_1 + 0x12) = *(undefined4 *)(param_1 + 0x16);
              *(undefined *)(param_2 + 0x90) = 2;
            }
            *(float *)(param_1 + 0x16) = FLOAT_803e2fdc;
          }
        }
        else {
          *(float *)(param_1 + 8) = *(float *)(param_2 + 0x58);
          if ((*(byte *)(param_2 + 0x91) & 0x10) != 0) {
            *(undefined4 *)(param_1 + 0x12) = *(undefined4 *)(param_1 + 0x14);
            *(undefined *)(param_2 + 0x90) = 4;
          }
          *(float *)(param_1 + 0x14) = FLOAT_803e2fdc;
        }
      }
      else {
        *(float *)(param_1 + 8) = *(float *)(param_2 + 0x5c);
        if ((*(byte *)(param_2 + 0x91) & 0x20) != 0) {
          *(float *)(param_1 + 0x12) = -*(float *)(param_1 + 0x14);
          *(undefined *)(param_2 + 0x90) = 5;
        }
        *(float *)(param_1 + 0x14) = FLOAT_803e2fdc;
      }
    }
    else if (*(float *)(param_2 + 0x48) <= *(float *)(param_1 + 6)) {
      if (*(float *)(param_1 + 6) <= *(float *)(param_2 + 0x4c)) {
        if (*(float *)(param_2 + 0x5c) <= *(float *)(param_1 + 8)) {
          if (*(float *)(param_2 + 0x58) < *(float *)(param_1 + 8)) {
            *(float *)(param_1 + 8) = *(float *)(param_2 + 0x58);
            if ((*(byte *)(param_2 + 0x91) & 0x10) != 0) {
              *(float *)(param_1 + 0x16) = -*(float *)(param_1 + 0x14);
              *(undefined *)(param_2 + 0x90) = 4;
            }
            *(float *)(param_1 + 0x14) = FLOAT_803e2fdc;
          }
        }
        else {
          *(float *)(param_1 + 8) = *(float *)(param_2 + 0x5c);
          if ((*(byte *)(param_2 + 0x91) & 0x20) != 0) {
            *(undefined4 *)(param_1 + 0x16) = *(undefined4 *)(param_1 + 0x14);
            *(undefined *)(param_2 + 0x90) = 5;
          }
          *(float *)(param_1 + 0x14) = FLOAT_803e2fdc;
        }
      }
      else {
        *(float *)(param_1 + 6) = *(float *)(param_2 + 0x4c);
        if ((*(byte *)(param_2 + 0x91) & 2) != 0) {
          *(float *)(param_1 + 0x16) = -*(float *)(param_1 + 0x12);
          *(undefined *)(param_2 + 0x90) = 1;
        }
        *(float *)(param_1 + 0x12) = FLOAT_803e2fdc;
      }
    }
    else {
      *(float *)(param_1 + 6) = *(float *)(param_2 + 0x48);
      if ((*(byte *)(param_2 + 0x91) & 1) != 0) {
        *(undefined4 *)(param_1 + 0x16) = *(undefined4 *)(param_1 + 0x12);
        *(undefined *)(param_2 + 0x90) = 0;
      }
      *(float *)(param_1 + 0x12) = FLOAT_803e2fdc;
    }
  }
  else if (bVar1 == 5) {
    if (*(float *)(param_2 + 0x48) <= *(float *)(param_1 + 6)) {
      if (*(float *)(param_1 + 6) <= *(float *)(param_2 + 0x4c)) {
        if (*(float *)(param_1 + 10) <= *(float *)(param_2 + 0x50)) {
          if (*(float *)(param_1 + 10) < *(float *)(param_2 + 0x54)) {
            *(float *)(param_1 + 10) = *(float *)(param_2 + 0x54);
            if ((*(byte *)(param_2 + 0x91) & 8) != 0) {
              *(float *)(param_1 + 0x14) = -*(float *)(param_1 + 0x16);
              *(undefined *)(param_2 + 0x90) = 3;
            }
            *(float *)(param_1 + 0x16) = FLOAT_803e2fdc;
          }
        }
        else {
          *(float *)(param_1 + 10) = *(float *)(param_2 + 0x50);
          if ((*(byte *)(param_2 + 0x91) & 4) != 0) {
            *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_1 + 0x16);
            *(undefined *)(param_2 + 0x90) = 2;
          }
          *(float *)(param_1 + 0x16) = FLOAT_803e2fdc;
        }
      }
      else {
        *(float *)(param_1 + 6) = *(float *)(param_2 + 0x4c);
        if ((*(byte *)(param_2 + 0x91) & 2) != 0) {
          *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_1 + 0x12);
          *(undefined *)(param_2 + 0x90) = 1;
        }
        *(float *)(param_1 + 0x12) = FLOAT_803e2fdc;
      }
    }
    else {
      *(float *)(param_1 + 6) = *(float *)(param_2 + 0x48);
      if ((*(byte *)(param_2 + 0x91) & 1) != 0) {
        *(float *)(param_1 + 0x14) = -*(float *)(param_1 + 0x12);
        *(undefined *)(param_2 + 0x90) = 0;
      }
      *(float *)(param_1 + 0x12) = FLOAT_803e2fdc;
    }
  }
  else if (bVar1 < 5) {
    if (*(float *)(param_2 + 0x48) <= *(float *)(param_1 + 6)) {
      if (*(float *)(param_1 + 6) <= *(float *)(param_2 + 0x4c)) {
        if (*(float *)(param_1 + 10) <= *(float *)(param_2 + 0x50)) {
          if (*(float *)(param_1 + 10) < *(float *)(param_2 + 0x54)) {
            *(float *)(param_1 + 10) = *(float *)(param_2 + 0x54);
            if ((*(byte *)(param_2 + 0x91) & 8) != 0) {
              *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_1 + 0x16);
              *(undefined *)(param_2 + 0x90) = 3;
            }
            *(float *)(param_1 + 0x16) = FLOAT_803e2fdc;
          }
        }
        else {
          *(float *)(param_1 + 10) = *(float *)(param_2 + 0x50);
          if ((*(byte *)(param_2 + 0x91) & 4) != 0) {
            *(float *)(param_1 + 0x14) = -*(float *)(param_1 + 0x16);
            *(undefined *)(param_2 + 0x90) = 2;
          }
          *(float *)(param_1 + 0x16) = FLOAT_803e2fdc;
        }
      }
      else {
        *(float *)(param_1 + 6) = *(float *)(param_2 + 0x4c);
        if ((*(byte *)(param_2 + 0x91) & 2) != 0) {
          *(float *)(param_1 + 0x14) = -*(float *)(param_1 + 0x12);
          *(undefined *)(param_2 + 0x90) = 1;
        }
        *(float *)(param_1 + 0x12) = FLOAT_803e2fdc;
      }
    }
    else {
      *(float *)(param_1 + 6) = *(float *)(param_2 + 0x48);
      if ((*(byte *)(param_2 + 0x91) & 1) != 0) {
        *(undefined4 *)(param_1 + 0x14) = *(undefined4 *)(param_1 + 0x12);
        *(undefined *)(param_2 + 0x90) = 0;
      }
      *(float *)(param_1 + 0x12) = FLOAT_803e2fdc;
    }
  }
  bVar1 = *(byte *)(param_2 + 0x90);
  if (bVar1 == 3) {
    *param_1 = 0x4000;
    sVar2 = FUN_8002178c((double)*(float *)(param_1 + 0x12),(double)*(float *)(param_1 + 0x14));
    param_1[1] = sVar2 + 0x4000;
    param_1[2] = 0x4000;
  }
  else if (bVar1 < 3) {
    if (bVar1 == 1) {
      *param_1 = 0;
      sVar2 = FUN_8002178c((double)*(float *)(param_1 + 0x16),(double)*(float *)(param_1 + 0x14));
      param_1[1] = sVar2 + 0x4000;
      param_1[2] = 0x4000;
    }
    else if (bVar1 == 0) {
      *param_1 = 0;
      sVar2 = FUN_8002178c((double)*(float *)(param_1 + 0x16),(double)*(float *)(param_1 + 0x14));
      param_1[1] = sVar2 + 0x4000;
      param_1[2] = -0x4000;
    }
    else {
      *param_1 = 0x4000;
      sVar2 = FUN_8002178c((double)*(float *)(param_1 + 0x12),(double)*(float *)(param_1 + 0x14));
      param_1[1] = sVar2 + 0x4000;
      param_1[2] = -0x4000;
    }
  }
  else if (bVar1 == 5) {
    sVar2 = FUN_8002178c((double)*(float *)(param_1 + 0x12),(double)*(float *)(param_1 + 0x16));
    *param_1 = sVar2 + -0x8000;
    param_1[1] = 0;
    param_1[2] = 0;
  }
  else if (bVar1 < 5) {
    sVar2 = FUN_8002178c((double)*(float *)(param_1 + 0x12),(double)*(float *)(param_1 + 0x16));
    *param_1 = sVar2 + -0x8000;
    param_1[1] = 0;
    param_1[2] = -0x8000;
  }
  return;
}

