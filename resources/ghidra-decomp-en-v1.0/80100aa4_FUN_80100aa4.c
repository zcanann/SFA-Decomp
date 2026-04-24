// Function: FUN_80100aa4
// Entry: 80100aa4
// Size: 492 bytes

void FUN_80100aa4(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,undefined4 param_6)

{
  int iVar1;
  int iVar2;
  byte bVar4;
  uint uVar3;
  int iVar5;
  undefined uVar6;
  undefined4 *puVar7;
  undefined unaff_r30;
  undefined unaff_r31;
  
  iVar5 = FUN_802860d4();
  uVar6 = DAT_803dd4ca;
  iVar1 = DAT_803dd4bc;
  iVar2 = *(int *)(DAT_803dd524 + 0x120);
  if (iVar2 != 0) {
    DAT_803dd4ca = 3;
    unaff_r30 = *(undefined *)(DAT_803dd4bc + 0x36);
    *(undefined *)(DAT_803dd4bc + 0x36) = 0xff;
    iVar5 = iVar2;
    unaff_r31 = uVar6;
  }
  if (iVar5 == 0) {
    *(undefined4 *)(iVar1 + 0x30) = 0;
  }
  else {
    if (*(int *)(iVar5 + 0x74) == 0) goto LAB_80100c78;
    puVar7 = (undefined4 *)(*(int *)(iVar5 + 0x74) + (uint)*(byte *)(iVar5 + 0xe4) * 0x18);
    bVar4 = *(byte *)(*(int *)(iVar5 + 0x78) + (uint)*(byte *)(iVar5 + 0xe4) * 5 + 4) & 0xf;
    if (bVar4 == 4) {
LAB_80100b5c:
      uVar6 = 2;
    }
    else {
      if (bVar4 < 4) {
        if (bVar4 == 1) {
          uVar6 = 0;
          goto LAB_80100b68;
        }
      }
      else if (bVar4 == 9) goto LAB_80100b5c;
      uVar6 = 1;
    }
LAB_80100b68:
    uVar3 = (uint)*(byte *)(iVar5 + 0xe8);
    if (3 < uVar3) {
      uVar3 = 0;
    }
    DAT_803db990 = *(undefined2 *)(*(int *)(iVar5 + 0x50) + uVar3 * 2 + 0x7c);
    *(undefined4 *)(iVar1 + 0x18) = *puVar7;
    *(undefined4 *)(iVar1 + 0x1c) = puVar7[1];
    *(undefined4 *)(iVar1 + 0x20) = puVar7[2];
    *(undefined *)(iVar1 + 0xad) = uVar6;
    *(undefined4 *)(iVar1 + 0x30) = *(undefined4 *)(iVar5 + 0x30);
    if (*(int *)(iVar1 + 0x30) == 0) {
      *(undefined4 *)(iVar1 + 0xc) = *(undefined4 *)(iVar1 + 0x18);
      *(undefined4 *)(iVar1 + 0x10) = *(undefined4 *)(iVar1 + 0x1c);
      *(undefined4 *)(iVar1 + 0x14) = *(undefined4 *)(iVar1 + 0x20);
    }
    else {
      FUN_8000e034((double)*(float *)(iVar1 + 0x18),(double)*(float *)(iVar1 + 0x1c),
                   (double)*(float *)(iVar1 + 0x20),iVar1 + 0xc,iVar1 + 0x10,iVar1 + 0x14);
    }
    *(undefined2 *)(iVar1 + 2) = 0;
    *(undefined2 *)(iVar1 + 4) = 0;
    *(float *)(iVar1 + 8) = FLOAT_803e1628;
    *(undefined *)(iVar1 + 0x37) = *(undefined *)(iVar1 + 0x36);
    FUN_8003b8f4((double)FLOAT_803e162c,iVar1,param_3,param_4,param_5,param_6);
  }
  iVar5 = *(int *)(*(int *)(iVar1 + 0x7c) + *(char *)(iVar1 + 0xad) * 4);
  *(ushort *)(iVar5 + 0x18) = *(ushort *)(iVar5 + 0x18) & 0xfff7;
  if (*(int *)(DAT_803dd524 + 0x120) != 0) {
    DAT_803dd4ca = unaff_r31;
    *(undefined *)(iVar1 + 0x36) = unaff_r30;
  }
LAB_80100c78:
  FUN_80286120();
  return;
}

