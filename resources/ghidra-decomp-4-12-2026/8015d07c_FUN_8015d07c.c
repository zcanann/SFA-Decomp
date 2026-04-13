// Function: FUN_8015d07c
// Entry: 8015d07c
// Size: 664 bytes

/* WARNING: Removing unreachable block (ram,0x8015d2f4) */
/* WARNING: Removing unreachable block (ram,0x8015d08c) */

void FUN_8015d07c(undefined8 param_1,double param_2,double param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  float fVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  int iVar5;
  undefined *puVar6;
  int iVar7;
  undefined8 extraout_f1;
  double dVar8;
  undefined8 uVar9;
  
  uVar9 = FUN_8028683c();
  fVar1 = FLOAT_803e39e0;
  iVar2 = (int)((ulonglong)uVar9 >> 0x20);
  iVar5 = (int)uVar9;
  iVar7 = *(int *)(iVar5 + 0x40c);
  if (*(short *)(iVar2 + 0x46) == 99) {
    *(float *)(iVar7 + 0x28) = FLOAT_803e3a1c;
    fVar1 = FLOAT_803e3a20;
  }
  else {
    *(float *)(iVar7 + 0x28) = FLOAT_803e39e0;
  }
  dVar8 = (double)fVar1;
  uVar3 = 0;
  if ((*(char *)(iVar5 + 0x25f) != '\0') &&
     (uVar3 = (uint)(byte)(&DAT_80320a98)[*(char *)(iVar5 + 0xbc)], 0x1e < uVar3)) {
    uVar3 = 0;
  }
  puVar6 = &DAT_80320a88 + uVar3 * 3;
  if ((*(byte *)(iVar7 + 0x44) & 1) != 0) {
    FUN_8015cfb8(extraout_f1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,iVar2,iVar7);
    *(byte *)(iVar7 + 0x44) = *(byte *)(iVar7 + 0x44) & 0xfe;
  }
  if (((*(byte *)(iVar7 + 0x44) & 4) != 0) && ((*(byte *)(iVar5 + 0x404) & 0x40) == 0)) {
    iVar4 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(iVar2,0x56,iVar7 + 0x20,0x200001,0xffffffff,puVar6);
      iVar4 = iVar4 + 1;
    } while (iVar4 < 4);
  }
  if (((*(byte *)(iVar7 + 0x44) & 8) != 0) && ((*(byte *)(iVar5 + 0x404) & 0x40) == 0)) {
    (**(code **)(*DAT_803dd708 + 8))(iVar2,0x57,iVar7 + 0x20,0x200001,0xffffffff,puVar6);
  }
  if ((*(byte *)(iVar7 + 0x44) & 0x10) != 0) {
    FUN_8000faf8();
    FUN_8000e69c((double)(float)((double)FLOAT_803e3a20 * dVar8));
    iVar5 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(iVar2,0x57,iVar7 + 0x20,0x200001,0xffffffff,puVar6);
      iVar5 = iVar5 + 1;
    } while (iVar5 < 0x28);
  }
  if ((*(byte *)(iVar7 + 0x44) & 0x20) != 0) {
    FUN_8000faf8();
    FUN_8000e69c((double)(float)((double)FLOAT_803e3a24 * dVar8));
    iVar5 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(iVar2,0x57,iVar7 + 0x20,0x200001,0xffffffff,puVar6);
      iVar5 = iVar5 + 1;
    } while (iVar5 < 0x28);
    iVar5 = 0;
    do {
      (**(code **)(*DAT_803dd708 + 8))(iVar2,0x58,iVar7 + 0x20,0x200001,0xffffffff,puVar6);
      iVar5 = iVar5 + 1;
    } while (iVar5 < 10);
  }
  *(undefined *)(iVar7 + 0x44) = 0;
  FUN_80286888();
  return;
}

