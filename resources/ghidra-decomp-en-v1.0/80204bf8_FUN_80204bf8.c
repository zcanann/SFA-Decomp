// Function: FUN_80204bf8
// Entry: 80204bf8
// Size: 1068 bytes

void FUN_80204bf8(int param_1)

{
  short sVar1;
  float fVar2;
  float fVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int iVar7;
  double dVar8;
  
  iVar6 = *(int *)(param_1 + 0x4c);
  iVar7 = *(int *)(param_1 + 0xb8);
  iVar4 = FUN_8002b9ec();
  fVar2 = FLOAT_803e63a8;
  fVar3 = FLOAT_803e63a0;
  if (iVar4 != 0) {
    sVar1 = *(short *)(iVar7 + 4);
    if (sVar1 == 2) {
      if (*(short *)(iVar7 + 10) == 0) {
        dVar8 = (double)FUN_80021690(param_1 + 0x18,iVar4 + 0x18);
        if ((double)FLOAT_803e63a4 <= dVar8) {
          if (*(float *)(iVar6 + 0xc) <= *(float *)(iVar4 + 0x10)) {
            if ((*(float *)(iVar6 + 0xc) < *(float *)(iVar4 + 0x10)) &&
               (*(undefined2 *)(iVar7 + 4) = 4, *(char *)(iVar7 + 0xd) == '\x01')) {
              *(undefined *)(iVar7 + 0xd) = 0;
            }
          }
          else {
            *(undefined2 *)(iVar7 + 4) = 3;
            if (*(char *)(iVar7 + 0xd) == '\x01') {
              *(undefined *)(iVar7 + 0xd) = 0;
            }
          }
        }
        else if (*(float *)(param_1 + 0x10) == FLOAT_803e63a0 + *(float *)(iVar6 + 0xc)) {
          *(undefined2 *)(iVar7 + 4) = 3;
          iVar4 = FUN_8000b578(param_1,8);
          if (iVar4 == 0) {
            FUN_8000bb18(param_1,0x1cb);
            *(undefined *)(iVar7 + 0xd) = 1;
          }
        }
        else if (*(float *)(param_1 + 0x10) == *(float *)(iVar6 + 0xc) - FLOAT_803e63a8) {
          *(undefined2 *)(iVar7 + 4) = 4;
          iVar4 = FUN_8000b578(param_1,8);
          if (iVar4 == 0) {
            FUN_8000bb18(param_1,0x1cb);
            *(undefined *)(iVar7 + 0xd) = 1;
          }
        }
      }
      else {
        *(short *)(iVar7 + 10) = *(short *)(iVar7 + 10) - (short)(int)FLOAT_803db414;
        if (*(short *)(iVar7 + 10) < 1) {
          *(undefined2 *)(iVar7 + 10) = 0;
        }
      }
    }
    else if (sVar1 < 2) {
      if (sVar1 == 0) {
        iVar5 = FUN_8001ffb4((int)*(short *)(iVar7 + 6));
        if (((iVar5 == 0) || (*(char *)(iVar7 + 0xc) == '\x01')) ||
           (dVar8 = (double)FUN_80021690(param_1 + 0x18,iVar4 + 0x18),
           (double)FLOAT_803e639c <= dVar8)) {
          if (((*(char *)(iVar7 + 0xc) == '\x01') &&
              (dVar8 = (double)FUN_80021690(param_1 + 0x18,iVar4 + 0x18), fVar2 = FLOAT_803e63a0,
              dVar8 < (double)FLOAT_803e639c)) &&
             (*(float *)(param_1 + 0x10) < FLOAT_803e63a0 + *(float *)(iVar6 + 0xc))) {
            *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + FLOAT_803db414;
            fVar2 = fVar2 + *(float *)(iVar6 + 0xc);
            if (fVar2 <= *(float *)(param_1 + 0x10)) {
              *(float *)(param_1 + 0x10) = fVar2;
              *(undefined2 *)(iVar7 + 4) = 1;
            }
          }
        }
        else if (*(float *)(param_1 + 0x10) < FLOAT_803e63a0 + *(float *)(iVar6 + 0xc)) {
          iVar4 = FUN_8000b578(param_1,8);
          if (iVar4 == 0) {
            FUN_8000bb18(param_1,0x116);
            *(undefined *)(iVar7 + 0xd) = 1;
          }
          *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + FLOAT_803db414;
          fVar2 = FLOAT_803e63a0 + *(float *)(iVar6 + 0xc);
          if (fVar2 <= *(float *)(param_1 + 0x10)) {
            *(float *)(param_1 + 0x10) = fVar2;
            *(undefined2 *)(iVar7 + 4) = 1;
            FUN_8000b7bc(param_1,8);
          }
        }
      }
      else if (-1 < sVar1) {
        *(undefined2 *)(iVar7 + 4) = 2;
        *(undefined2 *)(iVar7 + 10) = 100;
      }
    }
    else if (sVar1 == 4) {
      if (FLOAT_803e63a0 + *(float *)(iVar6 + 0xc) <= *(float *)(param_1 + 0x10)) {
        *(undefined2 *)(iVar7 + 4) = 2;
        *(undefined2 *)(iVar7 + 10) = 100;
        FUN_8000b7bc(param_1,8);
        FUN_80021690(param_1 + 0x18,iVar4 + 0x18);
      }
      else {
        *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) + FLOAT_803db414;
        fVar3 = fVar3 + *(float *)(iVar6 + 0xc);
        if (fVar3 <= *(float *)(param_1 + 0x10)) {
          *(float *)(param_1 + 0x10) = fVar3;
          *(undefined2 *)(iVar7 + 4) = 2;
          *(undefined2 *)(iVar7 + 10) = 100;
          FUN_8000b7bc(param_1,8);
        }
        FUN_80021690(param_1 + 0x18,iVar4 + 0x18);
      }
    }
    else if (sVar1 < 4) {
      if (*(float *)(param_1 + 0x10) <= *(float *)(iVar6 + 0xc) - FLOAT_803e63a8) {
        FUN_8000b7bc(param_1,8);
        FUN_80021690(param_1 + 0x18,iVar4 + 0x18);
        *(undefined2 *)(iVar7 + 4) = 2;
        *(undefined2 *)(iVar7 + 10) = 100;
      }
      else {
        *(float *)(param_1 + 0x10) = *(float *)(param_1 + 0x10) - FLOAT_803db414;
        fVar2 = *(float *)(iVar6 + 0xc) - fVar2;
        if (*(float *)(param_1 + 0x10) <= fVar2) {
          *(float *)(param_1 + 0x10) = fVar2;
          *(undefined2 *)(iVar7 + 4) = 2;
          FUN_8000b7bc(param_1,8);
          *(undefined2 *)(iVar7 + 10) = 100;
        }
        FUN_80021690(param_1 + 0x18,iVar4 + 0x18);
      }
    }
  }
  return;
}

