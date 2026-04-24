// Function: FUN_801b7d90
// Entry: 801b7d90
// Size: 1344 bytes

void FUN_801b7d90(undefined2 *param_1)

{
  byte bVar1;
  char cVar2;
  float fVar3;
  float fVar4;
  uint uVar5;
  undefined4 uVar6;
  int iVar7;
  undefined2 uVar8;
  float *pfVar9;
  int *piVar10;
  int iVar11;
  int local_40;
  int local_3c;
  int local_38;
  undefined auStack52 [12];
  undefined4 local_28;
  undefined4 local_24;
  undefined4 local_20;
  
  iVar11 = *(int *)(param_1 + 0x5c);
  bVar1 = *(byte *)(iVar11 + 0xac);
  if ((bVar1 & 4) == 0) {
    if ((bVar1 & 8) != 0) {
      iVar7 = (uint)*(byte *)(param_1 + 0x1b) + (uint)DAT_803db410 * -2;
      if (iVar7 < 0) {
        iVar7 = 0;
        *(byte *)(iVar11 + 0xac) = bVar1 & 0xf7;
      }
      *(char *)(param_1 + 0x1b) = (char)iVar7;
    }
  }
  else {
    uVar5 = (uint)*(byte *)(param_1 + 0x1b) + (uint)DAT_803db410 * 2;
    if (0xff < uVar5) {
      uVar5 = 0xff;
      *(byte *)(iVar11 + 0xac) = bVar1 & 0xfb;
    }
    *(char *)(param_1 + 0x1b) = (char)uVar5;
  }
  if ((*(byte *)(iVar11 + 0xac) & 1) == 0) {
    uVar6 = (**(code **)(**(int **)(*(int *)(iVar11 + 0x9c) + 0x68) + 0x20))
                      (*(int *)(iVar11 + 0x9c),iVar11 + 0x84,iVar11 + 0x88,iVar11 + 0x8c,
                       iVar11 + 0xa8);
    *(undefined4 *)(iVar11 + 0x90) = uVar6;
    *(undefined4 *)(iVar11 + 0x80) = 0;
    *(code **)(iVar11 + 0x94) = FUN_80010dc0;
    *(undefined **)(iVar11 + 0x98) = &LAB_80010d54;
    FUN_80010a6c(iVar11);
    *(byte *)(iVar11 + 0xac) = *(byte *)(iVar11 + 0xac) | 1;
  }
  fVar4 = FLOAT_803e4ab0;
  fVar3 = FLOAT_803e4aa4;
  if ((*(byte *)(iVar11 + 0xac) & 2) == 0) {
    iVar7 = FUN_80010320((double)FLOAT_803e4ac0,iVar11);
    *(undefined4 *)(param_1 + 6) = *(undefined4 *)(iVar11 + 0x68);
    *(float *)(param_1 + 8) = (float)(DOUBLE_803e4ac8 + (double)*(float *)(iVar11 + 0x6c));
    *(undefined4 *)(param_1 + 10) = *(undefined4 *)(iVar11 + 0x70);
    uVar8 = FUN_800217c0((double)*(float *)(iVar11 + 0x74),(double)*(float *)(iVar11 + 0x7c));
    *param_1 = uVar8;
    param_1[1] = param_1[1] + (ushort)DAT_803db410 * 800;
    *(float *)(param_1 + 0x12) =
         FLOAT_803db418 * (*(float *)(param_1 + 6) - *(float *)(param_1 + 0x40));
    *(float *)(param_1 + 0x14) = FLOAT_803e4ad0;
    *(float *)(param_1 + 0x16) =
         FLOAT_803db418 * (*(float *)(param_1 + 10) - *(float *)(param_1 + 0x44));
    if (iVar7 != 0) {
      FUN_8002cbc4(param_1);
      return;
    }
    if ((*(char *)(*(int *)(iVar11 + 0xa8) + (*(int *)(iVar11 + 0x10) >> 2)) == ' ') &&
       (iVar7 = FUN_8001ffb4(0x288), iVar7 != 0)) {
      *(byte *)(iVar11 + 0xac) = *(byte *)(iVar11 + 0xac) | 2;
      iVar7 = FUN_80065e50((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                           (double)*(float *)(param_1 + 10),param_1,&local_38,0,0);
      *(undefined4 *)(iVar11 + 0xa4) = *(undefined4 *)(param_1 + 8);
      while (fVar3 = FLOAT_803e4abc, 0 < iVar7) {
        iVar7 = iVar7 + -1;
        pfVar9 = *(float **)(local_38 + iVar7 * 4);
        fVar3 = *pfVar9;
        if ((fVar3 < *(float *)(param_1 + 8)) &&
           ((cVar2 = *(char *)(pfVar9 + 5), cVar2 == '\x1a' || (cVar2 == '\b')))) {
          *(float *)(iVar11 + 0xa4) = fVar3;
          iVar7 = 0;
        }
      }
      *(float *)(param_1 + 0x12) = *(float *)(param_1 + 0x12) * FLOAT_803e4abc;
      *(float *)(param_1 + 0x16) = *(float *)(param_1 + 0x16) * fVar3;
    }
  }
  else if (*(float *)(iVar11 + 0xa4) <= *(float *)(param_1 + 8)) {
    *(float *)(param_1 + 0x12) = *(float *)(param_1 + 0x12) * FLOAT_803e4ab0;
    *(float *)(param_1 + 0x14) = -(FLOAT_803e4ab4 * FLOAT_803db414 - *(float *)(param_1 + 0x14));
    *(float *)(param_1 + 0x16) = *(float *)(param_1 + 0x16) * fVar4;
    FUN_8002b95c((double)(*(float *)(param_1 + 0x12) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x14) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x16) * FLOAT_803db414),param_1);
    iVar11 = FUN_800640cc((double)FLOAT_803e4ab8,param_1 + 0x40,param_1 + 6,0,0,param_1,8,0xffffffff
                          ,0,0);
    if (iVar11 != 0) {
      *(float *)(param_1 + 0x12) = -*(float *)(param_1 + 0x12);
      *(float *)(param_1 + 0x16) = -*(float *)(param_1 + 0x16);
      fVar3 = FLOAT_803e4abc;
      *(float *)(param_1 + 0x12) = *(float *)(param_1 + 0x12) * FLOAT_803e4abc;
      *(float *)(param_1 + 0x16) = *(float *)(param_1 + 0x16) * fVar3;
    }
  }
  else {
    *(float *)(param_1 + 0x12) = *(float *)(param_1 + 0x12) * FLOAT_803e4aa4;
    *(float *)(param_1 + 0x14) = FLOAT_803e4aa8;
    *(float *)(param_1 + 0x16) = *(float *)(param_1 + 0x16) * fVar3;
    fVar3 = FLOAT_803e4aac;
    if ((*(byte *)(iVar11 + 0xac) & 0x10) == 0) {
      *(float *)(param_1 + 0x12) = *(float *)(param_1 + 0x12) * FLOAT_803e4aac;
      *(float *)(param_1 + 0x16) = *(float *)(param_1 + 0x16) * fVar3;
      *(byte *)(iVar11 + 0xac) = *(byte *)(iVar11 + 0xac) | 0x18;
      iVar11 = FUN_8002e0fc(&local_40,&local_3c);
      piVar10 = (int *)(iVar11 + local_40 * 4);
      for (; local_40 < local_3c; local_40 = local_40 + 1) {
        if (*(short *)(*piVar10 + 0x46) == 0xd6) {
          iVar11 = *(int *)(iVar11 + local_40 * 4);
          goto LAB_801b7f80;
        }
        piVar10 = piVar10 + 1;
      }
      iVar11 = 0;
LAB_801b7f80:
      if (iVar11 != 0) {
        (**(code **)(**(int **)(iVar11 + 0x68) + 0x20))();
      }
      FUN_8000bb18(param_1,0x1fa);
    }
    local_28 = *(undefined4 *)(param_1 + 6);
    local_24 = *(undefined4 *)(param_1 + 8);
    local_20 = *(undefined4 *)(param_1 + 10);
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x206,auStack52,4,0xffffffff,0);
    if (*(char *)(param_1 + 0x1b) == '\0') {
      FUN_8002cbc4(param_1);
      return;
    }
    FUN_8002b95c((double)(*(float *)(param_1 + 0x12) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x14) * FLOAT_803db414),
                 (double)(*(float *)(param_1 + 0x16) * FLOAT_803db414),param_1);
  }
  if ((*(char *)(param_1 + 0x1b) == -1) && (iVar11 = *(int *)(param_1 + 0x2a), iVar11 != 0)) {
    *(ushort *)(iVar11 + 0x60) = *(ushort *)(iVar11 + 0x60) | 1;
    *(undefined *)(iVar11 + 0x6e) = 4;
    *(undefined *)(iVar11 + 0x6f) = 2;
    *(undefined4 *)(iVar11 + 0x48) = 0x10;
    *(undefined4 *)(iVar11 + 0x4c) = 0x10;
  }
  FUN_8000da58(param_1,0x493);
  return;
}

