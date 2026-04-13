// Function: FUN_80091214
// Entry: 80091214
// Size: 1848 bytes

void FUN_80091214(undefined8 param_1,undefined8 param_2,undefined8 param_3,undefined8 param_4,
                 undefined8 param_5,undefined8 param_6,undefined8 param_7,undefined8 param_8)

{
  int iVar1;
  byte bVar2;
  int iVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  short *psVar7;
  int iVar8;
  undefined *puVar9;
  undefined4 in_r6;
  undefined4 in_r7;
  undefined4 in_r8;
  undefined4 in_r9;
  undefined4 in_r10;
  int iVar10;
  undefined8 uVar11;
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
  ushort local_64 [4];
  float local_5c;
  float local_58;
  float local_54;
  float local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined4 local_28;
  uint uStack_24;
  undefined4 local_20;
  uint uStack_1c;
  
  iVar3 = FUN_8028683c();
  local_70 = DAT_802c2740;
  local_6c = DAT_802c2744;
  local_68 = DAT_802c2748;
  iVar4 = FUN_80008b4c(-1);
  if ((short)iVar4 != 1) {
    uVar5 = FUN_80022264(1,0xffff);
    uVar11 = FUN_80293544(uVar5);
    iVar4 = 0;
    if ((((((DAT_8039b488 == 0) || (iVar3 != *(int *)(DAT_8039b488 + 0x13f0))) &&
          ((iVar4 = 1, DAT_8039b48c == 0 || (iVar3 != *(int *)(DAT_8039b48c + 0x13f0))))) &&
         (((iVar4 = 2, DAT_8039b490 == 0 || (iVar3 != *(int *)(DAT_8039b490 + 0x13f0))) &&
          ((iVar4 = 3, DAT_8039b494 == 0 || (iVar3 != *(int *)(DAT_8039b494 + 0x13f0))))))) &&
        ((((iVar4 = 4, DAT_8039b498 == 0 || (iVar3 != *(int *)(DAT_8039b498 + 0x13f0))) &&
          ((iVar4 = 5, DAT_8039b49c == 0 || (iVar3 != *(int *)(DAT_8039b49c + 0x13f0))))) &&
         ((iVar4 = 6, DAT_8039b4a0 == 0 || (iVar3 != *(int *)(DAT_8039b4a0 + 0x13f0))))))) &&
       ((iVar4 = 7, DAT_8039b4a4 == 0 || (iVar3 != *(int *)(DAT_8039b4a4 + 0x13f0))))) {
      iVar4 = 8;
    }
    iVar6 = (&DAT_8039b488)[iVar4];
    if ((iVar6 != 0) && (iVar4 != 8)) {
      if (iVar3 == *(int *)(iVar6 + 0x13f0)) {
        iVar10 = *(int *)(iVar6 + 4);
        psVar7 = FUN_8000facc();
        iVar8 = (&DAT_8039b488)[iVar4];
        iVar6 = (int)(*(float *)(psVar7 + 0x22) - *(float *)(iVar8 + 0x140c));
        local_48 = (double)(longlong)iVar6;
        iVar1 = (int)(*(float *)(psVar7 + 0x24) - *(float *)(iVar8 + 0x1410));
        local_40 = (double)(longlong)iVar1;
        iVar8 = (int)(*(float *)(psVar7 + 0x26) - *(float *)(iVar8 + 0x1414));
        local_38 = (double)(longlong)iVar8;
        uVar5 = iVar6 * iVar6 + iVar1 * iVar1 + iVar8 * iVar8 ^ 0x80000000;
        local_30 = (double)CONCAT44(0x43300000,uVar5);
        if (FLOAT_803dfe20 < (float)(local_30 - DOUBLE_803dfe28)) {
          local_38 = (double)CONCAT44(0x43300000,uVar5);
          local_40 = (double)CONCAT44(0x43300000,uVar5);
          local_48 = (double)CONCAT44(0x43300000,uVar5);
        }
        uStack_24 = (int)*(short *)((&DAT_8039b488)[iVar4] + 0x1448) ^ 0x80000000;
        local_28 = 0x43300000;
        iVar6 = (int)((float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803dfe28) -
                     FLOAT_803dc074);
        local_30 = (double)(longlong)iVar6;
        *(short *)((&DAT_8039b488)[iVar4] + 0x1448) = (short)iVar6;
        iVar6 = (&DAT_8039b488)[iVar3];
        if ((((*(int *)(iVar6 + 0x13f4) == 4) && ((*(byte *)(iVar6 + 0x144b) & 0x38) != 0)) &&
            (*(short *)(iVar6 + 0x1448) < 1)) &&
           ((*(char *)(iVar6 + 0x144d) == '\0' && (DAT_803dde1c == 0)))) {
          if ((*(char *)(iVar6 + 0x1452) != '\0') && (psVar7 != (short *)0x0)) {
            local_70 = FLOAT_803dfe20;
            local_6c = FLOAT_803dfe20;
            local_68 = FLOAT_803dfea8;
            local_58 = FLOAT_803dfe20;
            local_54 = FLOAT_803dfe20;
            local_50 = FLOAT_803dfe20;
            local_5c = FLOAT_803dfe24;
            local_64[2] = 0;
            local_64[1] = 0;
            uVar5 = FUN_80022264(0xffffec78,5000);
            local_64[0] = -(*psVar7 + (short)uVar5) - 1;
            FUN_80021b8c(local_64,&local_70);
          }
          local_58 = local_70;
          local_54 = local_6c;
          local_50 = local_68;
          local_5c = FLOAT_803dfe24;
          local_64[0] = 0;
          local_64[2] = 0;
          local_64[1] = 0;
          puVar9 = FUN_8000f56c();
          local_7c = *(float *)(puVar9 + 0x20);
          local_78 = *(float *)(puVar9 + 0x24);
          local_74 = *(float *)(puVar9 + 0x28);
          FUN_80247ef8(&local_7c,&local_7c);
          uStack_24 = FUN_80022264(0xfffff448,3000);
          uStack_24 = uStack_24 ^ 0x80000000;
          local_28 = 0x43300000;
          local_88 = -(FLOAT_803dfeac * local_7c -
                      (*(float *)(psVar7 + 0x22) +
                      (float)((double)CONCAT44(0x43300000,uStack_24) - DOUBLE_803dfe28)));
          uVar5 = FUN_80022264(2000,4000);
          local_30 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          local_84 = -(FLOAT_803dfeac * local_78 -
                      (*(float *)(psVar7 + 0x24) + (float)(local_30 - DOUBLE_803dfe28)));
          uVar5 = FUN_80022264(0xfffff448,3000);
          local_38 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          local_80 = -(FLOAT_803dfeac * local_74 -
                      (*(float *)(psVar7 + 0x26) + (float)(local_38 - DOUBLE_803dfe28)));
          uVar5 = FUN_80022264(0xfffff448,3000);
          local_40 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          local_94 = -(FLOAT_803dfeac * local_7c -
                      (*(float *)(psVar7 + 0x22) + (float)(local_40 - DOUBLE_803dfe28)));
          uVar5 = FUN_80022264(2000,4000);
          local_48 = (double)CONCAT44(0x43300000,uVar5 ^ 0x80000000);
          local_90 = -(FLOAT_803dfeac * local_78 -
                      (*(float *)(psVar7 + 0x24) - (float)(local_48 - DOUBLE_803dfe28)));
          uStack_1c = FUN_80022264(0xfffff448,3000);
          uStack_1c = uStack_1c ^ 0x80000000;
          local_20 = 0x43300000;
          local_8c = -(FLOAT_803dfeac * local_74 -
                      (*(float *)(psVar7 + 0x26) +
                      (float)((double)CONCAT44(0x43300000,uStack_1c) - DOUBLE_803dfe28)));
          DAT_803dde1c = FUN_8008fdac((double)FLOAT_803dfeb0,(double)FLOAT_803dfe3c,&local_88,
                                      &local_94,0xf,0xc0,0);
          FUN_8000bb00((double)local_88,(double)local_84,(double)local_80,0,0x2c9);
          bVar2 = *(byte *)((&DAT_8039b488)[iVar3] + 0x144b);
          if ((bVar2 & 8) == 0) {
            if ((bVar2 & 0x10) == 0) {
              if ((bVar2 & 0x20) != 0) {
                uVar5 = FUN_80022264(0x5a,0xb4);
                *(short *)((&DAT_8039b488)[iVar3] + 0x1448) = (short)uVar5;
              }
            }
            else {
              uVar5 = FUN_80022264(0x78,0xf0);
              *(short *)((&DAT_8039b488)[iVar3] + 0x1448) = (short)uVar5;
            }
          }
          else {
            uVar5 = FUN_80022264(0x78,0xf0);
            *(short *)((&DAT_8039b488)[iVar3] + 0x1448) = (short)uVar5;
          }
        }
        FUN_80090e98();
        for (iVar3 = 0; iVar3 < *(int *)((&DAT_8039b488)[iVar4] + 0x13fc); iVar3 = iVar3 + 1) {
          iVar6 = *(int *)((&DAT_8039b488)[iVar4] + 0x13f4);
          if (iVar6 == 0) {
            *(ushort *)(iVar10 + 0x10) =
                 *(short *)(iVar10 + 0x10) + (short)*(char *)(iVar10 + 0x14) * (ushort)DAT_803dc070;
            if (0x3ff < *(ushort *)(iVar10 + 0x10)) {
              *(ushort *)(iVar10 + 0x10) = *(ushort *)(iVar10 + 0x10) - 0x3ff;
            }
          }
          else if (iVar6 == 4) {
            *(ushort *)(iVar10 + 0x10) =
                 *(short *)(iVar10 + 0x10) + (ushort)DAT_803dc070 * *(char *)(iVar10 + 0x14) * 2;
            if (0x3ff < *(ushort *)(iVar10 + 0x10)) {
              *(ushort *)(iVar10 + 0x10) = *(ushort *)(iVar10 + 0x10) - 0x3ff;
            }
          }
          iVar10 = iVar10 + 0x18;
        }
      }
      else {
        FUN_80137c30(uVar11,param_2,param_3,param_4,param_5,param_6,param_7,param_8,
                     s_____Error_non_existant_cloud_id___80310230,iVar3,iVar4,in_r6,in_r7,in_r8,
                     in_r9,in_r10);
      }
    }
  }
  FUN_80286888();
  return;
}

