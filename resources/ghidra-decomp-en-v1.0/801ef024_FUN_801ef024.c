// Function: FUN_801ef024
// Entry: 801ef024
// Size: 652 bytes

void FUN_801ef024(int param_1)

{
  char cVar1;
  double dVar2;
  float fVar3;
  char cVar5;
  int iVar4;
  int iVar6;
  int iVar7;
  int iVar8;
  int local_38 [2];
  undefined4 local_30;
  uint uStack44;
  undefined4 local_28;
  uint uStack36;
  longlong local_20;
  
  iVar8 = *(int *)(param_1 + 0xb8);
  if ((*(char *)(iVar8 + 0x6e) == '\0') && (*(char *)(param_1 + 0xac) != '\v')) {
    FUN_8011f3ec(6);
    cVar5 = FUN_80014cc0(0);
    *(int *)(iVar8 + 0x70) = (int)cVar5;
    cVar5 = FUN_80014c6c(0);
    *(int *)(iVar8 + 0x74) = (int)cVar5;
    if (*(int *)(iVar8 + 0x10) == 0) {
      iVar4 = FUN_80036f50(3,local_38);
      for (iVar6 = 0; iVar6 < local_38[0]; iVar6 = iVar6 + 1) {
        iVar7 = *(int *)(iVar4 + iVar6 * 4);
        if (*(short *)(iVar7 + 0x46) == 0x8e) {
          *(int *)(iVar8 + 0x10) = iVar7;
          iVar6 = local_38[0];
        }
      }
    }
    *(undefined4 *)(param_1 + 0xf4) = 0;
    cVar5 = *(char *)(iVar8 + 0x65);
    *(byte *)(iVar8 + 100) = *(char *)(iVar8 + 100) - DAT_803db410;
    if (*(char *)(iVar8 + 100) < '\0') {
      *(undefined *)(iVar8 + 100) = 0;
    }
    cVar1 = *(char *)(iVar8 + 0x65);
    if (cVar1 == '\x01') {
      FUN_801ee3b4(param_1,iVar8);
    }
    else if (cVar1 < '\x01') {
      if (-1 < cVar1) {
        FUN_801ee668(param_1,iVar8);
        FUN_801eeb50(param_1,iVar8);
      }
    }
    else if (cVar1 < '\x04') {
      *(undefined4 *)(param_1 + 0xf4) = 1;
    }
    fVar3 = FLOAT_803e5cbc;
    dVar2 = DOUBLE_803e5ca0;
    uStack44 = (int)*(short *)(param_1 + 4) ^ 0x80000000;
    local_30 = 0x43300000;
    *(float *)(iVar8 + 0x5c) =
         *(float *)(iVar8 + 0x5c) +
         ((float)((double)CONCAT44(0x43300000,uStack44) - DOUBLE_803e5ca0) * FLOAT_803db414) /
         FLOAT_803e5cbc;
    uStack36 = (int)*(short *)(param_1 + 2) ^ 0x80000000;
    local_28 = 0x43300000;
    *(float *)(iVar8 + 0x58) =
         *(float *)(iVar8 + 0x58) +
         ((float)((double)CONCAT44(0x43300000,uStack36) - dVar2) * FLOAT_803db414) / fVar3;
    fVar3 = FLOAT_803e5cc0;
    *(float *)(iVar8 + 0x5c) =
         -(FLOAT_803db414 * *(float *)(iVar8 + 0x5c) * FLOAT_803e5cc0 - *(float *)(iVar8 + 0x5c));
    *(float *)(iVar8 + 0x58) =
         -(FLOAT_803db414 * *(float *)(iVar8 + 0x58) * fVar3 - *(float *)(iVar8 + 0x58));
    fVar3 = FLOAT_803e5cb8;
    iVar6 = (int)(FLOAT_803e5cb8 * *(float *)(iVar8 + 0x58));
    local_20 = (longlong)iVar6;
    *(short *)(param_1 + 2) = *(short *)(param_1 + 2) - (short)iVar6;
    *(float *)(param_1 + 0x10) = fVar3 * *(float *)(iVar8 + 0x58) + *(float *)(iVar8 + 0x50);
    *(float *)(param_1 + 0x14) = fVar3 * *(float *)(iVar8 + 0x5c) + *(float *)(iVar8 + 0x54);
    *(ushort *)(iVar8 + 0x6c) = *(short *)(iVar8 + 0x6c) + (ushort)DAT_803db410;
    if (*(char *)(iVar8 + 0x65) != cVar5) {
      *(undefined2 *)(iVar8 + 0x6c) = 0;
    }
    FUN_801ee248(param_1,iVar8);
  }
  else {
    *(ushort *)(param_1 + 6) = *(ushort *)(param_1 + 6) | 0x4000;
  }
  return;
}

