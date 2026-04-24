// Function: FUN_80140c24
// Entry: 80140c24
// Size: 320 bytes

undefined4 FUN_80140c24(int param_1)

{
  int *piVar1;
  int iVar2;
  undefined4 uVar3;
  int iVar4;
  short sVar5;
  double dVar6;
  double in_f30;
  int local_28 [2];
  
  iVar4 = 0;
  piVar1 = FUN_80037048(3,local_28);
  for (sVar5 = 0; sVar5 < local_28[0]; sVar5 = sVar5 + 1) {
    dVar6 = FUN_80021730((float *)(*piVar1 + 0x18),(float *)(param_1 + 0x71c));
    if (iVar4 == 0) {
      iVar2 = FUN_800dbf88((float *)(*piVar1 + 0x18),(undefined *)0x0);
      if (*(int *)(param_1 + 0x730) == iVar2) {
        iVar4 = *piVar1;
        in_f30 = dVar6;
      }
    }
    else if ((dVar6 < in_f30) &&
            (iVar2 = FUN_800dbf88((float *)(*piVar1 + 0x18),(undefined *)0x0),
            *(int *)(param_1 + 0x730) == iVar2)) {
      iVar4 = *piVar1;
      in_f30 = dVar6;
    }
    piVar1 = piVar1 + 1;
  }
  if (iVar4 == 0) {
    uVar3 = 0;
  }
  else {
    *(int *)(param_1 + 0x72c) = iVar4;
    if (*(int *)(param_1 + 0x28) != iVar4 + 0x18) {
      *(int *)(param_1 + 0x28) = iVar4 + 0x18;
      *(uint *)(param_1 + 0x54) = *(uint *)(param_1 + 0x54) & 0xfffffbff;
      *(undefined2 *)(param_1 + 0xd2) = 0;
    }
    *(undefined *)(param_1 + 10) = 4;
    uVar3 = 1;
  }
  return uVar3;
}

