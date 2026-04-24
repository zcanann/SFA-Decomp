// Function: FUN_80205230
// Entry: 80205230
// Size: 1068 bytes

void FUN_80205230(uint param_1)

{
  short sVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  uint uVar5;
  bool bVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  
  iVar7 = *(int *)(param_1 + 0x4c);
  iVar8 = *(int *)(param_1 + 0xb8);
  iVar4 = FUN_8002bac4();
  fVar2 = FLOAT_803e7040;
  fVar3 = FLOAT_803e7038;
  if (iVar4 != 0) {
    sVar1 = *(short *)(iVar8 + 4);
    if (sVar1 == 2) {
      if (*(short *)(iVar8 + 10) == 0) {
        dVar9 = (double)FUN_80021754((float *)(param_1 + 0x18),(float *)(iVar4 + 0x18));
        if ((double)FLOAT_803e703c <= dVar9) {
          if (*(float *)(iVar7 + 0xc) <= *(float *)(iVar4 + 0x10)) {
            if ((*(float *)(iVar7 + 0xc) < *(float *)(iVar4 + 0x10)) &&
               (*(undefined2 *)(iVar8 + 4) = 4, *(char *)(iVar8 + 0xd) == '\x01')) {
              *(undefined *)(iVar8 + 0xd) = 0;
            }
          }
          else {
            *(undefined2 *)(iVar8 + 4) = 3;
            if (*(char *)(iVar8 + 0xd) == '\x01') {
              *(undefined *)(iVar8 + 0xd) = 0;
            }
          }
        }
        else if (*(float *)(param_1 + 0x10) == FLOAT_803e7038 + *(float *)(iVar7 + 0xc)) {
          *(undefined2 *)(iVar8 + 4) = 3;
          bVar6 = FUN_8000b598(param_1,8);
          if (!bVar6) {
            FUN_8000bb38(param_1,0x1cb);
            *(undefined *)(iVar8 + 0xd) = 1;
          }
        }
        else if (*(float *)(param_1 + 0x10) == *(float *)(iVar7 + 0xc) - FLOAT_803e7040) {
          *(undefined2 *)(iVar8 + 4) = 4;
          bVar6 = FUN_8000b598(param_1,8);
          if (!bVar6) {
            FUN_8000bb38(param_1,0x1cb);
            *(undefined *)(iVar8 + 0xd) = 1;
          }
        }
      }
      else {
        *(short *)(iVar8 + 10) = *(short *)(iVar8 + 10) - (short)(int)FLOAT_803dc074;
        if (*(short *)(iVar8 + 10) < 1) {
          *(undefined2 *)(iVar8 + 10) = 0;
        }
      }
    }
    else if (sVar1 < 2) {
      if (sVar1 == 0) {
        uVar5 = FUN_80020078((int)*(short *)(iVar8 + 6));
        if (((uVar5 == 0) || (*(char *)(iVar8 + 0xc) == '\x01')) ||
           (dVar9 = (double)FUN_80021754((float *)(param_1 + 0x18),(float *)(iVar4 + 0x18)),
           (double)FLOAT_803e7034 <= dVar9)) {
          if (((*(char *)(iVar8 + 0xc) == '\x01') &&
              (dVar9 = (double)FUN_80021754((float *)(param_1 + 0x18),(float *)(iVar4 + 0x18)),
              fVar2 = FLOAT_803e7038, dVar9 < (double)FLOAT_803e7034)) &&
             (*(float *)(param_1 + 0x10) < FLOAT_803e7038 + *(float *)(iVar7 + 0xc))) {
            *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + FLOAT_803dc074;
            fVar2 = fVar2 + *(float *)(iVar7 + 0xc);
            if (fVar2 <= *(float *)(param_1 + 0x10)) {
              *(float *)(param_1 + 0x10) = fVar2;
              *(undefined2 *)(iVar8 + 4) = 1;
            }
          }
        }
        else if (*(float *)(param_1 + 0x10) < FLOAT_803e7038 + *(float *)(iVar7 + 0xc)) {
          bVar6 = FUN_8000b598(param_1,8);
          if (!bVar6) {
            FUN_8000bb38(param_1,0x116);
            *(undefined *)(iVar8 + 0xd) = 1;
          }
          *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + FLOAT_803dc074;
          fVar2 = FLOAT_803e7038 + *(float *)(iVar7 + 0xc);
          if (fVar2 <= *(float *)(param_1 + 0x10)) {
            *(float *)(param_1 + 0x10) = fVar2;
            *(undefined2 *)(iVar8 + 4) = 1;
            FUN_8000b7dc(param_1,8);
          }
        }
      }
      else if (-1 < sVar1) {
        *(undefined2 *)(iVar8 + 4) = 2;
        *(undefined2 *)(iVar8 + 10) = 100;
      }
    }
    else if (sVar1 == 4) {
      if (FLOAT_803e7038 + *(float *)(iVar7 + 0xc) <= *(float *)(param_1 + 0x10)) {
        *(undefined2 *)(iVar8 + 4) = 2;
        *(undefined2 *)(iVar8 + 10) = 100;
        FUN_8000b7dc(param_1,8);
        FUN_80021754((float *)(param_1 + 0x18),(float *)(iVar4 + 0x18));
      }
      else {
        *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + FLOAT_803dc074;
        fVar3 = fVar3 + *(float *)(iVar7 + 0xc);
        if (fVar3 <= *(float *)(param_1 + 0x10)) {
          *(float *)(param_1 + 0x10) = fVar3;
          *(undefined2 *)(iVar8 + 4) = 2;
          *(undefined2 *)(iVar8 + 10) = 100;
          FUN_8000b7dc(param_1,8);
        }
        FUN_80021754((float *)(param_1 + 0x18),(float *)(iVar4 + 0x18));
      }
    }
    else if (sVar1 < 4) {
      if (*(float *)(param_1 + 0x10) <= *(float *)(iVar7 + 0xc) - FLOAT_803e7040) {
        FUN_8000b7dc(param_1,8);
        FUN_80021754((float *)(param_1 + 0x18),(float *)(iVar4 + 0x18));
        *(undefined2 *)(iVar8 + 4) = 2;
        *(undefined2 *)(iVar8 + 10) = 100;
      }
      else {
        *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) - FLOAT_803dc074;
        fVar2 = *(float *)(iVar7 + 0xc) - fVar2;
        if (*(float *)(param_1 + 0x10) <= fVar2) {
          *(float *)(param_1 + 0x10) = fVar2;
          *(undefined2 *)(iVar8 + 4) = 2;
          FUN_8000b7dc(param_1,8);
          *(undefined2 *)(iVar8 + 10) = 100;
        }
        FUN_80021754((float *)(param_1 + 0x18),(float *)(iVar4 + 0x18));
      }
    }
  }
  return;
}

