// Function: FUN_80081bf0
// Entry: 80081bf0
// Size: 264 bytes

int FUN_80081bf0(int param_1)

{
  float fVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  int iVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  undefined auStack24 [4];
  int local_14 [4];
  
  if (*(int *)(*(int *)(param_1 + 0xb8) + 0x10c) == 0) {
    piVar6 = (int *)FUN_8002e0fc(auStack24,local_14);
    iVar5 = (int)*(short *)(*(int *)(param_1 + 0x4c) + 0x1c);
    iVar7 = iVar5 + -4;
    if ((iVar7 == 0x1f) || (iVar5 == 4)) {
      iVar5 = FUN_8002b9ec();
    }
    else if ((iVar7 == 0x24) || (iVar7 == 0x25)) {
      iVar5 = FUN_8002b9ac();
    }
    else {
      iVar5 = 0;
      fVar1 = FLOAT_803deff0;
      if (0 < local_14[0]) {
        do {
          iVar8 = *piVar6;
          if ((*(short *)(iVar8 + 0x46) == iVar7) &&
             ((fVar2 = *(float *)(param_1 + 0xc) - *(float *)(iVar8 + 0xc),
              fVar3 = *(float *)(param_1 + 0x10) - *(float *)(iVar8 + 0x10),
              fVar4 = *(float *)(param_1 + 0x14) - *(float *)(iVar8 + 0x14),
              fVar2 = fVar4 * fVar4 + fVar2 * fVar2 + fVar3 * fVar3, fVar1 < FLOAT_803defb0 ||
              (fVar2 < fVar1)))) {
            iVar5 = iVar8;
            fVar1 = fVar2;
          }
          piVar6 = piVar6 + 1;
          local_14[0] = local_14[0] + -1;
        } while (local_14[0] != 0);
      }
    }
  }
  else {
    iVar5 = FUN_8002e0b4();
  }
  return iVar5;
}

