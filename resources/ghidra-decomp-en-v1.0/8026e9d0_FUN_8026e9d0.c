// Function: FUN_8026e9d0
// Entry: 8026e9d0
// Size: 628 bytes

undefined4 FUN_8026e9d0(uint param_1,undefined4 param_2)

{
  int iVar1;
  undefined4 uVar2;
  uint uVar3;
  int *piVar4;
  int iVar5;
  int iVar6;
  double dVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  int local_74;
  double local_70;
  undefined4 local_68;
  undefined4 uStack100;
  undefined4 local_60;
  undefined4 uStack92;
  
  iVar6 = (param_1 & 0xff) * 0x38;
  dVar13 = (double)FLOAT_803e7788;
  dVar14 = ABS(dVar13);
  dVar10 = (double)FLOAT_803e7780;
  iVar5 = DAT_803de218 + iVar6 + 0x14e8;
  local_74 = 0;
  dVar12 = (double)FLOAT_803e7784;
  dVar11 = DOUBLE_803e7790;
  while( true ) {
    piVar4 = *(int **)(iVar5 + 0x1c);
    if (piVar4 == (int *)0x0) {
      uVar3 = 0;
    }
    else {
      uVar3 = piVar4[2];
    }
    if (*(uint *)(iVar5 + (uint)*(byte *)(iVar5 + 0x30) * 8 + 0x24) < uVar3) break;
    if ((piVar4 != (int *)0x0) && (iVar1 = *piVar4, *(int *)(iVar5 + 0x1c) = iVar1, iVar1 != 0)) {
      *(undefined4 *)(*(int *)(iVar5 + 0x1c) + 4) = 0;
    }
    if (piVar4 == (int *)0x0) {
      if (local_74 == 0) {
        return 0;
      }
      local_74 = 0;
      *(byte *)(iVar5 + 0x30) = *(byte *)(iVar5 + 0x30) ^ 1;
      *(undefined4 *)(iVar5 + (uint)*(byte *)(iVar5 + 0x30) * 8 + 0x24) =
           *(undefined4 *)((param_1 & 0xff) * 4 + *(int *)(DAT_803de218 + 0x118) + 0x14);
      *(undefined4 *)(iVar5 + (uint)*(byte *)(iVar5 + 0x30) * 8 + 0x20) =
           *(undefined4 *)(iVar5 + (*(byte *)(iVar5 + 0x30) ^ 1) * 8 + 0x20);
      iVar1 = *(int *)(iVar6 + DAT_803de218 + 0x14e8);
      if (iVar1 != 0) {
        *(int *)(iVar6 + DAT_803de218 + 0x14ec) = iVar1;
        FUN_8026cf78(param_1);
        iVar1 = DAT_803de218 + iVar6 + 0x14e8;
        uStack92 = *(undefined4 *)(iVar1 + 8);
        local_60 = 0x43300000;
        local_68 = 0x43300000;
        local_70 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar1 + 0x32));
        dVar9 = (double)((float)(dVar10 * (double)((float)((double)CONCAT44(0x43300000,uStack92) -
                                                          dVar11) *
                                                  (float)((double)CONCAT44(0x43300000,param_2) -
                                                         dVar11))) *
                        (float)(dVar12 * (double)(float)(local_70 - dVar11)));
        dVar8 = (double)(float)(dVar13 * dVar9);
        uStack100 = param_2;
        if (dVar14 <= ABS(dVar8)) {
          FUN_8028660c((double)(float)(dVar8 / dVar13));
          dVar7 = (double)FUN_802864b8();
          dVar8 = (double)(float)(dVar8 - (double)(float)(dVar13 * dVar7));
        }
        uVar2 = FUN_80285fb4(dVar8);
        *(undefined4 *)(iVar1 + (uint)*(byte *)(iVar1 + 0x30) * 8 + 0xc) = uVar2;
        dVar8 = (double)FUN_80294724(dVar9);
        local_70 = (double)(longlong)(int)dVar8;
        *(int *)(iVar1 + (uint)*(byte *)(iVar1 + 0x30) * 8 + 0x10) = (int)dVar8;
      }
      *(short *)(iVar5 + 0x34) = *(short *)(iVar5 + 0x34) + 1;
      FUN_8026e90c(param_1);
    }
    else {
      iVar1 = FUN_8026e0e4(piVar4,param_1,&local_74);
      if (iVar1 != 0) {
        FUN_8026e070(iVar5);
      }
    }
  }
  return 1;
}

