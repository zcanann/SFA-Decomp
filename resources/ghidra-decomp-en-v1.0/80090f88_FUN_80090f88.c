// Function: FUN_80090f88
// Entry: 80090f88
// Size: 1848 bytes

void FUN_80090f88(void)

{
  int iVar1;
  byte bVar2;
  int iVar3;
  short sVar8;
  int iVar4;
  short *psVar5;
  int iVar6;
  uint uVar7;
  undefined2 uVar9;
  int iVar10;
  int iVar11;
  float local_94;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  float local_80;
  float local_7c;
  float local_78;
  float local_74;
  float local_70;
  float local_6c;
  float local_68;
  short local_64;
  undefined2 local_62;
  undefined2 local_60;
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  double local_48;
  double local_40;
  double local_38;
  double local_30;
  undefined4 local_28;
  uint uStack36;
  undefined4 local_20;
  uint uStack28;
  
  iVar3 = FUN_802860d8();
  local_70 = DAT_802c1fc0;
  local_6c = DAT_802c1fc4;
  local_68 = DAT_802c1fc8;
  sVar8 = FUN_80008b4c(0xffffffff);
  if (sVar8 != 1) {
    FUN_800221a0(1,0xffff);
    FUN_80292de4();
    iVar10 = 0;
    if ((((((DAT_8039a828 == 0) || (iVar3 != *(int *)(DAT_8039a828 + 0x13f0))) &&
          ((iVar10 = 1, DAT_8039a82c == 0 || (iVar3 != *(int *)(DAT_8039a82c + 0x13f0))))) &&
         (((iVar10 = 2, DAT_8039a830 == 0 || (iVar3 != *(int *)(DAT_8039a830 + 0x13f0))) &&
          ((iVar10 = 3, DAT_8039a834 == 0 || (iVar3 != *(int *)(DAT_8039a834 + 0x13f0))))))) &&
        ((((iVar10 = 4, DAT_8039a838 == 0 || (iVar3 != *(int *)(DAT_8039a838 + 0x13f0))) &&
          ((iVar10 = 5, DAT_8039a83c == 0 || (iVar3 != *(int *)(DAT_8039a83c + 0x13f0))))) &&
         ((iVar10 = 6, DAT_8039a840 == 0 || (iVar3 != *(int *)(DAT_8039a840 + 0x13f0))))))) &&
       ((iVar10 = 7, DAT_8039a844 == 0 || (iVar3 != *(int *)(DAT_8039a844 + 0x13f0))))) {
      iVar10 = 8;
    }
    iVar4 = (&DAT_8039a828)[iVar10];
    if ((iVar4 != 0) && (iVar10 != 8)) {
      if (iVar3 == *(int *)(iVar4 + 0x13f0)) {
        iVar11 = *(int *)(iVar4 + 4);
        psVar5 = (short *)FUN_8000faac();
        iVar6 = (&DAT_8039a828)[iVar10];
        iVar4 = (int)(*(float *)(psVar5 + 0x22) - *(float *)(iVar6 + 0x140c));
        local_48 = (double)(longlong)iVar4;
        iVar1 = (int)(*(float *)(psVar5 + 0x24) - *(float *)(iVar6 + 0x1410));
        local_40 = (double)(longlong)iVar1;
        iVar6 = (int)(*(float *)(psVar5 + 0x26) - *(float *)(iVar6 + 0x1414));
        local_38 = (double)(longlong)iVar6;
        uVar7 = iVar4 * iVar4 + iVar1 * iVar1 + iVar6 * iVar6 ^ 0x80000000;
        local_30 = (double)CONCAT44(0x43300000,uVar7);
        if (FLOAT_803df1a0 < (float)(local_30 - DOUBLE_803df1a8)) {
          local_38 = (double)CONCAT44(0x43300000,uVar7);
          local_40 = (double)CONCAT44(0x43300000,uVar7);
          local_48 = (double)CONCAT44(0x43300000,uVar7);
        }
        uStack36 = (int)*(short *)((&DAT_8039a828)[iVar10] + 0x1448) ^ 0x80000000;
        local_28 = 0x43300000;
        iVar4 = (int)((float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803df1a8) -
                     FLOAT_803db414);
        local_30 = (double)(longlong)iVar4;
        *(short *)((&DAT_8039a828)[iVar10] + 0x1448) = (short)iVar4;
        iVar4 = (&DAT_8039a828)[iVar3];
        if ((((*(int *)(iVar4 + 0x13f4) == 4) && ((*(byte *)(iVar4 + 0x144b) & 0x38) != 0)) &&
            (*(short *)(iVar4 + 0x1448) < 1)) &&
           ((*(char *)(iVar4 + 0x144d) == '\0' && (DAT_803dd19c == 0)))) {
          if ((*(char *)(iVar4 + 0x1452) != '\0') && (psVar5 != (short *)0x0)) {
            local_70 = FLOAT_803df1a0;
            local_6c = FLOAT_803df1a0;
            local_68 = FLOAT_803df228;
            local_58 = FLOAT_803df1a0;
            local_54 = FLOAT_803df1a0;
            local_50 = FLOAT_803df1a0;
            local_5c = FLOAT_803df1a4;
            local_60 = 0;
            local_62 = 0;
            sVar8 = FUN_800221a0(0xffffec78,5000);
            local_64 = -1 - (*psVar5 + sVar8);
            FUN_80021ac8(&local_64,&local_70);
          }
          local_58 = local_70;
          local_54 = local_6c;
          local_50 = local_68;
          local_5c = FLOAT_803df1a4;
          local_64 = 0;
          local_60 = 0;
          local_62 = 0;
          iVar4 = FUN_8000f54c();
          local_7c = *(float *)(iVar4 + 0x20);
          local_78 = *(float *)(iVar4 + 0x24);
          local_74 = *(float *)(iVar4 + 0x28);
          FUN_80247794(&local_7c,&local_7c);
          uStack36 = FUN_800221a0(0xfffff448,3000);
          uStack36 = uStack36 ^ 0x80000000;
          local_28 = 0x43300000;
          local_88 = -(FLOAT_803df22c * local_7c -
                      (*(float *)(psVar5 + 0x22) +
                      (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803df1a8)));
          uVar7 = FUN_800221a0(2000,4000);
          local_30 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_84 = -(FLOAT_803df22c * local_78 -
                      (*(float *)(psVar5 + 0x24) + (float)(local_30 - DOUBLE_803df1a8)));
          uVar7 = FUN_800221a0(0xfffff448,3000);
          local_38 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_80 = -(FLOAT_803df22c * local_74 -
                      (*(float *)(psVar5 + 0x26) + (float)(local_38 - DOUBLE_803df1a8)));
          uVar7 = FUN_800221a0(0xfffff448,3000);
          local_40 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_94 = -(FLOAT_803df22c * local_7c -
                      (*(float *)(psVar5 + 0x22) + (float)(local_40 - DOUBLE_803df1a8)));
          uVar7 = FUN_800221a0(2000,4000);
          local_48 = (double)CONCAT44(0x43300000,uVar7 ^ 0x80000000);
          local_90 = -(FLOAT_803df22c * local_78 -
                      (*(float *)(psVar5 + 0x24) - (float)(local_48 - DOUBLE_803df1a8)));
          uStack28 = FUN_800221a0(0xfffff448,3000);
          uStack28 = uStack28 ^ 0x80000000;
          local_20 = 0x43300000;
          local_8c = -(FLOAT_803df22c * local_74 -
                      (*(float *)(psVar5 + 0x26) +
                      (float)((double)CONCAT44(0x43300000,uStack28) - DOUBLE_803df1a8)));
          DAT_803dd19c = FUN_8008fb20((double)FLOAT_803df230,(double)FLOAT_803df1bc,&local_88,
                                      &local_94,0xf,0xc0,0);
          FUN_8000bae0((double)local_88,(double)local_84,(double)local_80,0,0x2c9);
          bVar2 = *(byte *)((&DAT_8039a828)[iVar3] + 0x144b);
          if ((bVar2 & 8) == 0) {
            if ((bVar2 & 0x10) == 0) {
              if ((bVar2 & 0x20) != 0) {
                uVar9 = FUN_800221a0(0x5a,0xb4);
                *(undefined2 *)((&DAT_8039a828)[iVar3] + 0x1448) = uVar9;
              }
            }
            else {
              uVar9 = FUN_800221a0(0x78,0xf0);
              *(undefined2 *)((&DAT_8039a828)[iVar3] + 0x1448) = uVar9;
            }
          }
          else {
            uVar9 = FUN_800221a0(0x78,0xf0);
            *(undefined2 *)((&DAT_8039a828)[iVar3] + 0x1448) = uVar9;
          }
        }
        FUN_80090c0c((&DAT_8039a828)[iVar10]);
        for (iVar3 = 0; iVar3 < *(int *)((&DAT_8039a828)[iVar10] + 0x13fc); iVar3 = iVar3 + 1) {
          iVar4 = *(int *)((&DAT_8039a828)[iVar10] + 0x13f4);
          if (iVar4 == 0) {
            *(ushort *)(iVar11 + 0x10) =
                 *(short *)(iVar11 + 0x10) + (short)*(char *)(iVar11 + 0x14) * (ushort)DAT_803db410;
            if (0x3ff < *(ushort *)(iVar11 + 0x10)) {
              *(ushort *)(iVar11 + 0x10) = *(ushort *)(iVar11 + 0x10) - 0x3ff;
            }
          }
          else if (iVar4 == 4) {
            *(ushort *)(iVar11 + 0x10) =
                 *(short *)(iVar11 + 0x10) + (ushort)DAT_803db410 * *(char *)(iVar11 + 0x14) * 2;
            if (0x3ff < *(ushort *)(iVar11 + 0x10)) {
              *(ushort *)(iVar11 + 0x10) = *(ushort *)(iVar11 + 0x10) - 0x3ff;
            }
          }
          iVar11 = iVar11 + 0x18;
        }
      }
      else {
        FUN_801378a8(s_____Error_non_existant_cloud_id___8030f670,iVar3);
      }
    }
  }
  FUN_80286124();
  return;
}

