// Function: FUN_801b9444
// Entry: 801b9444
// Size: 804 bytes

/* WARNING: Removing unreachable block (ram,0x801b9484) */

void FUN_801b9444(int param_1)

{
  byte bVar1;
  int iVar2;
  undefined2 uVar4;
  int iVar3;
  float *pfVar5;
  int iVar6;
  float *pfVar7;
  int local_28 [7];
  
  iVar6 = *(int *)(param_1 + 0x4c);
  pfVar7 = *(float **)(param_1 + 0xb8);
  bVar1 = *(byte *)((int)pfVar7 + 6);
  if (bVar1 != 2) {
    if (bVar1 < 2) {
      if (bVar1 == 0) {
        iVar6 = FUN_8003687c(param_1,0,0,0);
        if (iVar6 != 0xe) {
          return;
        }
        uVar4 = FUN_800221a0(800,0x4b0);
        *(undefined2 *)(pfVar7 + 1) = uVar4;
        *(undefined *)((int)pfVar7 + 6) = 3;
        *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
             *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
        FUN_8000bb18(param_1,0xa4);
        return;
      }
      if (*(char *)((int)pfVar7 + 7) == '\0') {
        iVar3 = FUN_80065e50((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x10),
                             (double)*(float *)(param_1 + 0x14),param_1,local_28,0,0);
        *pfVar7 = FLOAT_803e4b70;
        for (iVar2 = 0; iVar2 < iVar3; iVar2 = iVar2 + 1) {
          pfVar5 = *(float **)(local_28[0] + iVar2 * 4);
          if (*(char *)(pfVar5 + 5) == '\x0e') {
            *pfVar7 = *pfVar5;
            iVar2 = iVar3;
          }
        }
        if (FLOAT_803e4b70 != *pfVar7) {
          *(undefined *)((int)pfVar7 + 7) = 1;
        }
      }
      if ((0 < *(short *)(pfVar7 + 2)) &&
         (*(ushort *)(pfVar7 + 2) = *(short *)(pfVar7 + 2) - (ushort)DAT_803db410,
         *(short *)(pfVar7 + 2) < 1)) {
        FUN_8000bb18(param_1,0xa5);
      }
      *(float *)(param_1 + 0x28) = -(FLOAT_803e4b74 * FLOAT_803db414 - *(float *)(param_1 + 0x28));
      if (*(float *)(param_1 + 0x28) < FLOAT_803e4b78) {
        *(float *)(param_1 + 0x28) = FLOAT_803e4b78;
      }
      *(float *)(param_1 + 0x10) =
           *(float *)(param_1 + 0x28) * FLOAT_803db414 + *(float *)(param_1 + 0x10);
      if (*pfVar7 <= *(float *)(param_1 + 0x10)) {
        return;
      }
      FUN_800200e8((int)*(short *)(iVar6 + 0x1e),1);
      *(undefined *)((int)pfVar7 + 6) = 2;
      (**(code **)(*DAT_803dca98 + 0x10))
                ((double)*(float *)(param_1 + 0xc),(double)*pfVar7,
                 (double)*(float *)(param_1 + 0x14),(double)FLOAT_803e4b7c,param_1);
      (**(code **)(*DAT_803dca98 + 0x14))
                ((double)*(float *)(param_1 + 0xc),(double)*pfVar7,
                 (double)*(float *)(param_1 + 0x14),(double)FLOAT_803e4b80,0,2);
      FUN_8000bb18(param_1,0xa6);
      *(undefined2 *)(pfVar7 + 2) = 0x96;
      return;
    }
    if (bVar1 < 4) {
      *(undefined2 *)(param_1 + 2) = *(undefined2 *)(pfVar7 + 1);
      *(short *)(pfVar7 + 1) =
           (short)(int)((float)((double)CONCAT44(0x43300000,(int)*(short *)(pfVar7 + 1) ^ 0x80000000
                                                ) - DOUBLE_803e4b88) * FLOAT_803e4b6c);
      if (9 < *(short *)(param_1 + 2)) {
        return;
      }
      *(undefined2 *)(param_1 + 2) = 0;
      *(undefined *)((int)pfVar7 + 6) = 1;
      *(undefined2 *)(pfVar7 + 2) = 0x3c;
      return;
    }
  }
  if ((0 < *(short *)(pfVar7 + 2)) &&
     (*(ushort *)(pfVar7 + 2) = *(short *)(pfVar7 + 2) - (ushort)DAT_803db410,
     *(short *)(pfVar7 + 2) < 1)) {
    FUN_8000bb18(param_1,0x155);
  }
  iVar2 = (uint)*(byte *)(param_1 + 0x36) + (uint)DAT_803db410 * -8;
  if (iVar2 < 0) {
    iVar2 = 0;
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(iVar6 + 0xc);
    *(float *)(param_1 + 0x28) = FLOAT_803e4b80;
  }
  *(char *)(param_1 + 0x36) = (char)iVar2;
  *(float *)(param_1 + 0x10) =
       *(float *)(param_1 + 0x28) * FLOAT_803db414 + *(float *)(param_1 + 0x10);
  return;
}

