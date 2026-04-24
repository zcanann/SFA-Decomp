// Function: FUN_8026f134
// Entry: 8026f134
// Size: 628 bytes

undefined4 FUN_8026f134(uint param_1,undefined4 param_2)

{
  int iVar1;
  int iVar2;
  undefined4 *puVar3;
  uint uVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  double dVar8;
  double dVar9;
  double dVar10;
  double dVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  double dVar15;
  undefined8 uVar16;
  uint local_74;
  undefined8 local_70;
  undefined4 local_68;
  undefined4 uStack_64;
  undefined4 local_60;
  undefined4 uStack_5c;
  
  iVar7 = (param_1 & 0xff) * 0x38;
  dVar14 = (double)FLOAT_803e8420;
  dVar15 = ABS(dVar14);
  dVar11 = (double)FLOAT_803e8418;
  iVar6 = DAT_803dee98 + iVar7 + 0x14e8;
  local_74 = 0;
  dVar13 = (double)FLOAT_803e841c;
  dVar12 = DOUBLE_803e8428;
  while( true ) {
    piVar5 = *(int **)(iVar6 + 0x1c);
    if (piVar5 == (int *)0x0) {
      uVar4 = 0;
    }
    else {
      uVar4 = piVar5[2];
    }
    if (*(uint *)(iVar6 + (uint)*(byte *)(iVar6 + 0x30) * 8 + 0x24) < uVar4) break;
    if ((piVar5 != (int *)0x0) && (iVar1 = *piVar5, *(int *)(iVar6 + 0x1c) = iVar1, iVar1 != 0)) {
      *(undefined4 *)(*(int *)(iVar6 + 0x1c) + 4) = 0;
    }
    if (piVar5 == (int *)0x0) {
      if (local_74 == 0) {
        return 0;
      }
      local_74 = 0;
      *(byte *)(iVar6 + 0x30) = *(byte *)(iVar6 + 0x30) ^ 1;
      *(undefined4 *)(iVar6 + (uint)*(byte *)(iVar6 + 0x30) * 8 + 0x24) =
           *(undefined4 *)((param_1 & 0xff) * 4 + *(int *)(DAT_803dee98 + 0x118) + 0x14);
      *(undefined4 *)(iVar6 + (uint)*(byte *)(iVar6 + 0x30) * 8 + 0x20) =
           *(undefined4 *)(iVar6 + (*(byte *)(iVar6 + 0x30) ^ 1) * 8 + 0x20);
      iVar1 = *(int *)(iVar7 + DAT_803dee98 + 0x14e8);
      if (iVar1 != 0) {
        *(int *)(iVar7 + DAT_803dee98 + 0x14ec) = iVar1;
        FUN_8026d6dc(param_1);
        iVar1 = DAT_803dee98 + iVar7 + 0x14e8;
        uStack_5c = *(undefined4 *)(iVar1 + 8);
        local_60 = 0x43300000;
        local_68 = 0x43300000;
        local_70 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar1 + 0x32));
        dVar10 = (double)((float)(dVar11 * (double)((float)((double)CONCAT44(0x43300000,uStack_5c) -
                                                           dVar12) *
                                                   (float)((double)CONCAT44(0x43300000,param_2) -
                                                          dVar12))) *
                         (float)(dVar13 * (double)(float)(local_70 - dVar12)));
        dVar9 = (double)(float)(dVar14 * dVar10);
        uStack_64 = param_2;
        if (dVar15 <= ABS(dVar9)) {
          uVar16 = FUN_80286d70((ulonglong)(double)(float)(dVar9 / dVar14));
          dVar8 = FUN_80286c1c((uint)((ulonglong)uVar16 >> 0x20),(uint)uVar16);
          dVar9 = (double)(float)(dVar9 - (double)(float)(dVar14 * dVar8));
        }
        iVar2 = FUN_80286718(dVar9);
        *(int *)(iVar1 + (uint)*(byte *)(iVar1 + 0x30) * 8 + 0xc) = iVar2;
        dVar9 = FUN_80294e84(dVar10);
        local_70 = (double)(longlong)(int)dVar9;
        *(int *)(iVar1 + (uint)*(byte *)(iVar1 + 0x30) * 8 + 0x10) = (int)dVar9;
      }
      *(short *)(iVar6 + 0x34) = *(short *)(iVar6 + 0x34) + 1;
      FUN_8026f070(param_1);
    }
    else {
      puVar3 = (undefined4 *)FUN_8026e848((int)piVar5,(byte)param_1,&local_74);
      if (puVar3 != (undefined4 *)0x0) {
        FUN_8026e7d4(iVar6,puVar3);
      }
    }
  }
  return 1;
}

