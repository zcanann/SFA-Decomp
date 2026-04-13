// Function: FUN_8002bf60
// Entry: 8002bf60
// Size: 1252 bytes

void FUN_8002bf60(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  char cVar1;
  short sVar2;
  uint uVar3;
  uint uVar4;
  int *piVar5;
  int iVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  uint *puVar10;
  int iVar11;
  int iVar12;
  int in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  code *pcVar13;
  int iVar14;
  undefined8 uVar15;
  int local_b8 [46];
  
  uVar15 = FUN_80286840();
  uVar3 = (uint)((ulonglong)uVar15 >> 0x20);
  iVar6 = (int)uVar15;
  if (*(char *)(uVar3 + 0xe9) != '\0') {
    FUN_80037f3c(uVar3);
  }
  sVar2 = *(short *)(uVar3 + 0x46);
  if ((sVar2 == 0x1f) || ((sVar2 < 0x1f && (sVar2 == 0)))) {
    FUN_802b5540(uVar3);
  }
  else if (*(int **)(uVar3 + 0x68) != (int *)0x0) {
    pcVar13 = *(code **)(**(int **)(uVar3 + 0x68) + 0x14);
    if (pcVar13 != (code *)0x0) {
      (*pcVar13)(uVar3,iVar6);
    }
    FUN_80013e4c(*(undefined **)(uVar3 + 0x68));
    *(undefined4 *)(uVar3 + 0x68) = 0;
  }
  (**(code **)(*DAT_803dd6f0 + 0x48))(uVar3);
  uVar15 = (**(code **)(*DAT_803dd6f8 + 0x28))(uVar3);
  if (((*(uint *)(*(int *)(uVar3 + 0x50) + 0x44) & 0x40) != 0) &&
     (uVar15 = FUN_8003709c(uVar3,6), iVar6 == 0)) {
    iVar11 = 0;
    iVar9 = 0;
    for (iVar12 = 0; iVar12 < DAT_803dd804; iVar12 = iVar12 + 1) {
      iVar8 = *(int *)(DAT_803dd808 + iVar11);
      iVar14 = iVar9;
      if ((*(uint *)(iVar8 + 0x30) == uVar3) &&
         (*(undefined4 *)(iVar8 + 0x30) = 0, *(int *)(iVar8 + 0x4c) != 0)) {
        iVar14 = iVar9 + 1;
        local_b8[iVar9] = iVar8;
      }
      iVar11 = iVar11 + 4;
      iVar9 = iVar14;
    }
    piVar5 = local_b8;
    for (iVar11 = 0; iVar11 < iVar9; iVar11 = iVar11 + 1) {
      uVar15 = FUN_8002cc9c(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8,*piVar5);
      piVar5 = piVar5 + 1;
    }
    uVar15 = FUN_80059bcc((uint)*(byte *)(uVar3 + 0x34));
  }
  if ((iVar6 == 0) && (*(short *)(uVar3 + 0x44) == 0x10)) {
    iVar9 = 0;
    for (iVar11 = 0; iVar11 < DAT_803dd804; iVar11 = iVar11 + 1) {
      if (*(uint *)(*(int *)(DAT_803dd808 + iVar9) + 0xc0) == uVar3) {
        *(undefined4 *)(*(int *)(DAT_803dd808 + iVar9) + 0xc0) = 0;
      }
      iVar9 = iVar9 + 4;
    }
  }
  iVar9 = 0;
  for (iVar11 = 0; iVar11 < DAT_803dd804; iVar11 = iVar11 + 1) {
    if ((*(short *)(*(int *)(DAT_803dd808 + iVar9) + 0x44) == 0x10) &&
       (puVar10 = *(uint **)(*(int *)(DAT_803dd808 + iVar9) + 0xb8), *puVar10 == uVar3)) {
      *puVar10 = 0;
      *(undefined *)((int)puVar10 + 0x8f) = 1;
    }
    iVar9 = iVar9 + 4;
  }
  if ('\0' < *(char *)(*(int *)(uVar3 + 0x50) + 0x56)) {
    uVar15 = FUN_8003709c(uVar3,8);
  }
  if (*(int *)(uVar3 + 100) != 0) {
    if (*(short *)(*(int *)(uVar3 + 0x50) + 0x48) == 1) {
      uVar15 = FUN_80062a54(1);
    }
    if (*(int *)(*(int *)(uVar3 + 100) + 4) != 0) {
      uVar4 = FUN_8006c740();
      uVar7 = *(uint *)(*(int *)(uVar3 + 100) + 4);
      if (uVar7 != uVar4) {
        if ((*(byte *)(*(int *)(uVar3 + 0x50) + 0x5f) & 4) == 0) {
          uVar15 = FUN_80054484();
        }
        else {
          uVar15 = FUN_800238c4(uVar7);
        }
      }
    }
    uVar4 = *(uint *)(*(int *)(uVar3 + 100) + 8);
    if (uVar4 != 0) {
      uVar15 = FUN_800238c4(uVar4);
    }
    uVar4 = *(uint *)(*(int *)(uVar3 + 100) + 0x10);
    if ((uVar4 != 0) && (uVar4 != 0xffffffff)) {
      uVar15 = FUN_800238c4(uVar4);
    }
  }
  if (*(uint *)(uVar3 + 0xdc) != 0) {
    uVar15 = FUN_800238c4(*(uint *)(uVar3 + 0xdc));
    *(undefined4 *)(uVar3 + 0xdc) = 0;
  }
  cVar1 = *(char *)(*(int *)(uVar3 + 0x50) + 0x55);
  iVar14 = 0;
  for (iVar12 = 0; iVar12 < cVar1; iVar12 = iVar12 + 1) {
    piVar5 = *(int **)(*(int *)(uVar3 + 0x7c) + iVar14);
    if (piVar5 != (int *)0x0) {
      uVar15 = FUN_80029440(piVar5);
    }
    iVar14 = iVar14 + 4;
  }
  if ((*(byte *)(uVar3 + 0xe5) & 1) != 0) {
    *(undefined2 *)(uVar3 + 0xe6) = 0;
    *(byte *)(uVar3 + 0xe5) = *(byte *)(uVar3 + 0xe5) & 0xfe;
    *(undefined *)(uVar3 + 0xf0) = 0;
    FUN_80028500(*(int *)(*(int *)(uVar3 + 0x7c) + *(char *)(uVar3 + 0xad) * 4));
    (**(code **)(*DAT_803dd734 + 0xc))(uVar3,0x7fb,0,0x50,0);
    iVar9 = 0x32;
    iVar11 = 0;
    in_r8 = *DAT_803dd734;
    uVar15 = (**(code **)(in_r8 + 0xc))(uVar3,0x7fc,0);
  }
  if ((*(byte *)(uVar3 + 0xe5) & 2) != 0) {
    uVar15 = FUN_8002a8ec();
  }
  iVar12 = FUN_8003728c(uVar3);
  if (iVar12 != 0) {
    uVar15 = FUN_8003709c(uVar3,iVar12 + -1);
  }
  iVar12 = (int)*(short *)(uVar3 + 0x48);
  if (*(char *)(DAT_803dd824 + iVar12) == '\0') {
    FUN_80137c30(uVar15,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                 s_objFreeObjdef__Error_____d__802cb880,iVar12,DAT_803dd824,iVar9,iVar11,in_r8,in_r9
                 ,in_r10);
  }
  else {
    *(char *)(DAT_803dd824 + iVar12) = *(char *)(DAT_803dd824 + iVar12) + -1;
    if (*(char *)(DAT_803dd824 + iVar12) == '\0') {
      uVar4 = *(uint *)(DAT_803dd828 + iVar12 * 4);
      if (*(uint *)(uVar4 + 0x30) != 0) {
        FUN_800238c4(*(uint *)(uVar4 + 0x30));
      }
      if (*(uint *)(uVar4 + 0x34) != 0) {
        FUN_800238c4(*(uint *)(uVar4 + 0x34));
      }
      FUN_800238c4(uVar4);
    }
  }
  if (-1 < *(short *)(uVar3 + 0xb4)) {
    if (iVar6 == 0) {
      (**(code **)(*DAT_803dd6d4 + 0x4c))();
    }
    *(undefined2 *)(uVar3 + 0xb4) = 0xffff;
  }
  if (((*(ushort *)(uVar3 + 6) & 0x2000) != 0) && (*(uint *)(uVar3 + 0x4c) != 0)) {
    FUN_800238c4(*(uint *)(uVar3 + 0x4c));
  }
  FUN_800238c4(uVar3);
  FUN_8028688c();
  return;
}

