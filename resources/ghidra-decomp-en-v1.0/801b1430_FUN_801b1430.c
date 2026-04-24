// Function: FUN_801b1430
// Entry: 801b1430
// Size: 360 bytes

void FUN_801b1430(int param_1)

{
  short sVar1;
  ushort uVar2;
  char cVar5;
  int iVar3;
  uint uVar4;
  int iVar6;
  short *psVar7;
  
  cVar5 = FUN_8002e04c();
  if (cVar5 != '\0') {
    psVar7 = *(short **)(param_1 + 0xb8);
    sVar1 = *psVar7;
    uVar2 = (ushort)DAT_803db410;
    *psVar7 = sVar1 - uVar2;
    if ((short)(sVar1 - uVar2) < 1) {
      FUN_8002b9ec();
      iVar3 = FUN_802972a8();
      if (iVar3 == 0) {
        iVar6 = *(int *)(param_1 + 0x4c);
        iVar3 = FUN_8002bdf4(0x24,0x196);
        *(undefined *)(iVar3 + 4) = *(undefined *)(iVar6 + 4);
        *(undefined *)(iVar3 + 6) = *(undefined *)(iVar6 + 6);
        *(undefined *)(iVar3 + 5) = *(undefined *)(iVar6 + 5);
        *(undefined *)(iVar3 + 7) = *(undefined *)(iVar6 + 7);
        *(undefined4 *)(iVar3 + 8) = *(undefined4 *)(param_1 + 0xc);
        *(undefined4 *)(iVar3 + 0xc) = *(undefined4 *)(param_1 + 0x10);
        *(undefined4 *)(iVar3 + 0x10) = *(undefined4 *)(param_1 + 0x14);
        *(undefined4 *)(iVar3 + 0x14) = *(undefined4 *)(iVar6 + 0x14);
        *(undefined *)(iVar3 + 0x18) = *(undefined *)(iVar6 + 0x1c);
        *(ushort *)(iVar3 + 0x1a) = (ushort)*(byte *)(iVar6 + 0x1a);
        uVar4 = FUN_800221a0(0,100);
        *(short *)(iVar3 + 0x1c) =
             (short)(int)((float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar6 + 0x1b)) -
                                 DOUBLE_803e4870) +
                         (float)((double)CONCAT44(0x43300000,uVar4 ^ 0x80000000) - DOUBLE_803e4868)
                         / FLOAT_803e4864);
        FUN_8002df90(iVar3,5,(int)*(char *)(param_1 + 0xac),0xffffffff,0);
        *psVar7 = psVar7[1];
      }
    }
  }
  return;
}

