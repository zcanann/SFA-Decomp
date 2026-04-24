// Function: FUN_801aeb50
// Entry: 801aeb50
// Size: 708 bytes

void FUN_801aeb50(void)

{
  uint uVar1;
  short *psVar2;
  undefined uVar6;
  char cVar7;
  int iVar3;
  undefined2 uVar5;
  int iVar4;
  int iVar8;
  int *piVar9;
  int iVar10;
  int local_28;
  int local_24 [9];
  
  psVar2 = (short *)FUN_802860d8();
  iVar10 = *(int *)(psVar2 + 0x26);
  piVar9 = *(int **)(psVar2 + 0x5c);
  if ((*piVar9 == 0) || (piVar9[1] == 0)) {
    iVar10 = FUN_8002e0fc(local_24,&local_28);
    for (local_24[0] = 0; local_24[0] < local_28; local_24[0] = local_24[0] + 1) {
      iVar8 = *(int *)(iVar10 + local_24[0] * 4);
      if (*(short *)(iVar8 + 0x46) == 0x164) {
        *piVar9 = iVar8;
      }
      if (*(short *)(iVar8 + 0x46) == 0x168) {
        piVar9[1] = iVar8;
      }
    }
  }
  else {
    uVar6 = (**(code **)(**(int **)(piVar9[1] + 0x68) + 0x24))();
    *(undefined *)(piVar9 + 2) = uVar6;
    if (*(char *)(piVar9 + 2) == '\0') {
      uVar1 = (uint)*(byte *)(psVar2 + 0x1b) + (uint)DAT_803db410 * -8;
      if ((int)uVar1 < 0) {
        uVar1 = 0;
      }
    }
    else {
      uVar1 = (uint)*(byte *)(psVar2 + 0x1b) + (uint)DAT_803db410 * 8;
      if (0xff < uVar1) {
        uVar1 = 0xff;
      }
    }
    *(char *)(psVar2 + 0x1b) = (char)uVar1;
    if ((*(int *)(psVar2 + 0x7a) == 0) && (cVar7 = FUN_8002e04c(), cVar7 != '\0')) {
      iVar8 = 0;
      do {
        iVar3 = FUN_8002bdf4(0x24,0x301);
        *(undefined4 *)(iVar3 + 8) = *(undefined4 *)(psVar2 + 6);
        *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(psVar2 + 8);
        *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(psVar2 + 10);
        uVar6 = FUN_800221a0(0,0xffff);
        *(undefined *)(iVar3 + 0x18) = uVar6;
        uVar5 = FUN_800221a0(200,400);
        *(undefined2 *)(iVar3 + 0x1a) = uVar5;
        iVar4 = FUN_800221a0(0,1);
        if (iVar4 == 0) {
          *(short *)(iVar3 + 0x1a) = -*(short *)(iVar3 + 0x1a);
        }
        uVar5 = FUN_800221a0(200,400);
        *(undefined2 *)(iVar3 + 0x1c) = uVar5;
        iVar4 = FUN_800221a0(0,1);
        if (iVar4 == 0) {
          *(short *)(iVar3 + 0x1c) = -*(short *)(iVar3 + 0x1c);
        }
        *(undefined *)(iVar3 + 4) = *(undefined *)(iVar10 + 4);
        *(undefined *)(iVar3 + 6) = *(undefined *)(iVar10 + 6);
        *(undefined *)(iVar3 + 5) = 1;
        *(undefined *)(iVar3 + 7) = 0xff;
        FUN_8002df90(iVar3,5,(int)*(char *)(psVar2 + 0x56),0xffffffff,*(undefined4 *)(psVar2 + 0x18)
                    );
        iVar8 = iVar8 + 1;
      } while (iVar8 < 10);
      *(undefined4 *)(psVar2 + 0x7a) = 1;
    }
    iVar10 = *piVar9;
    FUN_8002b95c((double)(*(float *)(iVar10 + 0xc) - *(float *)(psVar2 + 6)),
                 (double)((FLOAT_803e47c4 + *(float *)(iVar10 + 0x10)) - *(float *)(psVar2 + 8)),
                 (double)(*(float *)(iVar10 + 0x14) - *(float *)(psVar2 + 10)),psVar2);
    *psVar2 = *psVar2 + (ushort)DAT_803db410 * 0x100;
    psVar2[1] = psVar2[1] + (ushort)DAT_803db410 * 0x20;
    psVar2[2] = psVar2[2] + (ushort)DAT_803db410 * 0x40;
    *(undefined4 *)(psVar2 + 0x18) = 0;
  }
  FUN_80286124();
  return;
}

