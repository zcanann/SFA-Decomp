// Function: FUN_8013a874
// Entry: 8013a874
// Size: 464 bytes

void FUN_8013a874(undefined4 param_1,undefined4 param_2,uint param_3,uint param_4)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  ushort uVar5;
  ushort uVar6;
  uint uVar7;
  double dVar8;
  double dVar9;
  undefined8 uVar10;
  int local_38 [14];
  
  uVar10 = FUN_80286834();
  iVar1 = (int)((ulonglong)uVar10 >> 0x20);
  iVar4 = (int)uVar10;
  uVar5 = 0;
  uVar7 = 1;
  for (uVar6 = 0; uVar6 < 4; uVar6 = uVar6 + 1) {
    if ((-1 < *(int *)(iVar4 + (uint)uVar6 * 4 + 0x1c)) &&
       (param_4 == ((int)*(char *)(iVar4 + 0x1b) & uVar7))) {
      iVar2 = (**(code **)(*DAT_803dd71c + 0x1c))();
      uVar3 = (uint)uVar5;
      local_38[uVar3] = iVar2;
      iVar2 = local_38[uVar3];
      if ((((iVar2 != 0) && ((param_3 == 0 || (*(byte *)(iVar4 + uVar3 + 4) == param_3)))) &&
          (((int)*(short *)(iVar2 + 0x30) == 0xffffffff ||
           (uVar3 = FUN_80020078((int)*(short *)(iVar2 + 0x30)), uVar3 != 0)))) &&
         ((((int)*(short *)(iVar2 + 0x32) == 0xffffffff ||
           (uVar3 = FUN_80020078((int)*(short *)(iVar2 + 0x32)), uVar3 == 0)) &&
          ((*(char *)(iVar4 + 0x1a) != '\t' || (*(char *)(iVar2 + 0x1a) != '\b')))))) {
        uVar5 = uVar5 + 1;
      }
    }
    uVar7 = (uVar7 & 0x7fff) << 1;
    param_4 = param_4 << 1;
  }
  if (uVar5 != 0) {
    dVar8 = FUN_80021730((float *)(*(int *)(iVar1 + 4) + 0x18),(float *)(local_38[0] + 8));
    for (uVar6 = 1; uVar6 < uVar5; uVar6 = uVar6 + 1) {
      dVar9 = FUN_80021730((float *)(*(int *)(iVar1 + 4) + 0x18),(float *)(local_38[uVar6] + 8));
      if (dVar9 < dVar8) {
        dVar8 = dVar9;
      }
    }
  }
  FUN_80286880();
  return;
}

