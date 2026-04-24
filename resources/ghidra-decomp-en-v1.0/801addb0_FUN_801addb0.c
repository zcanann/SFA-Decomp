// Function: FUN_801addb0
// Entry: 801addb0
// Size: 728 bytes

void FUN_801addb0(int param_1)

{
  float fVar1;
  float fVar2;
  char cVar5;
  undefined4 uVar3;
  int iVar4;
  int iVar6;
  int iVar7;
  short sVar8;
  int *piVar9;
  double dVar10;
  undefined auStack56 [4];
  float local_34;
  undefined auStack48 [4];
  undefined4 local_2c;
  undefined4 local_28;
  undefined4 local_24;
  undefined2 local_20;
  double local_18;
  
  piVar9 = *(int **)(param_1 + 0xb8);
  local_28 = DAT_802c2308;
  local_24 = DAT_802c230c;
  local_20 = DAT_802c2310;
  if (*(char *)((int)piVar9 + 0x21) != *(char *)((int)piVar9 + 0x22)) {
    if (*(int *)(param_1 + 200) != 0) {
      FUN_8002cbc4();
      *(undefined4 *)(param_1 + 200) = 0;
      *(undefined *)(param_1 + 0xeb) = 0;
    }
    cVar5 = FUN_8002e04c();
    if (cVar5 == '\0') {
      *(undefined *)((int)piVar9 + 0x22) = 0;
    }
    else {
      if (0 < *(char *)((int)piVar9 + 0x21)) {
        uVar3 = FUN_8002bdf4(0x18,(int)*(short *)((int)&local_2c +
                                                 *(char *)((int)piVar9 + 0x21) * 2 + 2));
        uVar3 = FUN_8002df90(uVar3,4,0xffffffff,0xffffffff,*(undefined4 *)(param_1 + 0x30));
        *(undefined4 *)(param_1 + 200) = uVar3;
        *(undefined *)(param_1 + 0xeb) = 1;
      }
      *(undefined *)((int)piVar9 + 0x22) = *(undefined *)((int)piVar9 + 0x21);
    }
  }
  if (*piVar9 == 0) {
    iVar4 = FUN_80036f50(10,&local_2c);
    if (*(short *)(param_1 + 0x46) == 0x170) {
      sVar8 = 0x16f;
    }
    else {
      sVar8 = 0x16c;
    }
    for (iVar7 = 0; iVar7 < local_2c; iVar7 = iVar7 + 1) {
      iVar6 = *(int *)(iVar4 + iVar7 * 4);
      if (sVar8 == *(short *)(iVar6 + 0x46)) {
        *piVar9 = iVar6;
        iVar7 = local_2c;
      }
    }
  }
  if ((*(short *)(param_1 + 0x46) == 0x373) || (iVar4 = FUN_8001ffb4(0x3a2), iVar4 != 0)) {
    iVar4 = *piVar9;
    if (*(short *)(param_1 + 0xa0) != 0x100) {
      FUN_80030334((double)FLOAT_803e4748,param_1,0x100,0);
    }
    (**(code **)(**(int **)(iVar4 + 0x68) + 0x44))(iVar4,&local_34);
    local_34 = FLOAT_803e474c;
    (**(code **)(**(int **)(iVar4 + 0x68) + 0x40))(iVar4,auStack56,auStack48);
    local_18 = (double)CONCAT44(0x43300000,(uint)DAT_803db410);
    FUN_8002fa48((double)local_34,(double)(float)(local_18 - DOUBLE_803e4750),param_1,0);
    if (*piVar9 == 0) {
      *(undefined *)(piVar9 + 8) = 0xff;
      iVar4 = *(int *)(param_1 + 100);
      if (iVar4 != 0) {
        *(uint *)(iVar4 + 0x30) = *(uint *)(iVar4 + 0x30) & 0xffffefff;
      }
    }
    else {
      iVar4 = FUN_8002b9ec();
      dVar10 = (double)FUN_80021704(*piVar9 + 0x18,iVar4 + 0x18);
      fVar1 = (float)(dVar10 - (double)FLOAT_803e475c) / FLOAT_803e4760;
      fVar2 = FLOAT_803e4748;
      if ((FLOAT_803e4748 <= fVar1) && (fVar2 = fVar1, FLOAT_803e4758 < fVar1)) {
        fVar2 = FLOAT_803e4758;
      }
      *(char *)(piVar9 + 8) = (char)(int)(FLOAT_803e4764 * (FLOAT_803e4758 - fVar2));
      iVar4 = *(int *)(param_1 + 100);
      if (iVar4 != 0) {
        *(uint *)(iVar4 + 0x30) = *(uint *)(iVar4 + 0x30) | 0x1000;
      }
    }
  }
  return;
}

