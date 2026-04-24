// Function: FUN_8013a4ec
// Entry: 8013a4ec
// Size: 464 bytes

void FUN_8013a4ec(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4)

{
  uint uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  int iVar5;
  ushort uVar6;
  ushort uVar7;
  ushort uVar8;
  uint uVar9;
  double dVar10;
  double dVar11;
  undefined8 uVar12;
  int local_38 [14];
  
  uVar12 = FUN_802860d0();
  iVar4 = (int)((ulonglong)uVar12 >> 0x20);
  iVar5 = (int)uVar12;
  uVar7 = 0;
  uVar9 = 1;
  for (uVar8 = 0; uVar8 < 4; uVar8 = uVar8 + 1) {
    if ((-1 < *(int *)(iVar5 + (uint)uVar8 * 4 + 0x1c)) &&
       (param_4 == ((int)*(char *)(iVar5 + 0x1b) & uVar9))) {
      iVar2 = (**(code **)(*DAT_803dca9c + 0x1c))();
      uVar1 = (uint)uVar7;
      local_38[uVar1] = iVar2;
      iVar2 = local_38[uVar1];
      if ((((iVar2 != 0) && ((param_3 == 0 || (*(byte *)(iVar5 + uVar1 + 4) == param_3)))) &&
          ((*(short *)(iVar2 + 0x30) == -1 || (iVar3 = FUN_8001ffb4(), iVar3 != 0)))) &&
         (((*(short *)(iVar2 + 0x32) == -1 || (iVar3 = FUN_8001ffb4(), iVar3 == 0)) &&
          ((*(char *)(iVar5 + 0x1a) != '\t' || (*(char *)(iVar2 + 0x1a) != '\b')))))) {
        uVar7 = uVar7 + 1;
      }
    }
    uVar9 = (uVar9 & 0x7fff) << 1;
    param_4 = param_4 << 1;
  }
  if (uVar7 == 0) {
    iVar4 = 0;
  }
  else {
    dVar10 = (double)FUN_8002166c(*(int *)(iVar4 + 4) + 0x18,local_38[0] + 8);
    uVar8 = 0;
    for (uVar6 = 1; uVar6 < uVar7; uVar6 = uVar6 + 1) {
      dVar11 = (double)FUN_8002166c(*(int *)(iVar4 + 4) + 0x18,local_38[uVar6] + 8);
      if (dVar11 < dVar10) {
        dVar10 = dVar11;
        uVar8 = uVar6;
      }
    }
    iVar4 = local_38[uVar8];
  }
  FUN_8028611c(iVar4);
  return;
}

