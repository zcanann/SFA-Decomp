// Function: FUN_802b2bfc
// Entry: 802b2bfc
// Size: 2312 bytes

/* WARNING: Removing unreachable block (ram,0x802b34dc) */
/* WARNING: Removing unreachable block (ram,0x802b34d4) */
/* WARNING: Removing unreachable block (ram,0x802b2c14) */
/* WARNING: Removing unreachable block (ram,0x802b2c0c) */

void FUN_802b2bfc(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,uint param_9,int param_10
                 ,int param_11,undefined4 param_12,undefined4 param_13,undefined4 param_14,
                 undefined4 param_15,undefined4 param_16)

{
  float fVar1;
  float fVar2;
  ushort uVar3;
  uint uVar4;
  int *piVar5;
  int iVar6;
  int iVar7;
  char *pcVar8;
  double dVar9;
  undefined8 uVar10;
  double dVar11;
  double dVar12;
  uint local_48;
  uint local_44;
  uint local_40 [2];
  undefined4 local_38;
  uint uStack_34;
  
  local_44 = 0;
  do {
    while( true ) {
      do {
        while( true ) {
          while( true ) {
            while( true ) {
              while( true ) {
                iVar6 = FUN_800375e4(param_9,&local_48,local_40,&local_44);
                if (iVar6 == 0) {
                  return;
                }
                if (local_48 != 0x80002) break;
                *(short *)(param_10 + 0x80c) = (short)local_44;
                if ((*(int *)(param_11 + 0x2d0) != 0) && ((local_44 == 0x2d || (local_44 == 0x5ce)))
                   ) {
                  *(short *)(param_10 + 0x80e) = (short)local_44;
                  *(undefined2 *)(param_10 + 0x80c) = 0xffff;
                }
              }
              if ((int)local_48 < 0x80002) break;
              if (local_48 == 0x100010) {
                *(undefined *)(param_10 + 0x800) = 1;
                if (*(int *)(param_10 + 0x7f8) == 0) {
                  *(uint *)(param_10 + 0x7f8) = local_40[0];
                  piVar5 = (int *)FUN_8002b660(*(int *)(param_10 + 0x7f8));
                  if (((piVar5 != (int *)0x0) && (*piVar5 != 0)) &&
                     ((*(ushort *)(*piVar5 + 2) & 0x8000) == 0)) {
                    *(undefined *)(*(int *)(param_10 + 0x7f8) + 0xf2) =
                         *(undefined *)(param_9 + 0xf2);
                  }
                  uStack_34 = (int)local_44 >> 0x10 ^ 0x80000000;
                  local_38 = 0x43300000;
                  *(float *)(param_10 + 0x7fc) =
                       (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e8b58);
                  param_1 = (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_11,5);
                  *(undefined **)(param_11 + 0x304) = &LAB_802a52ac;
                  if ((DAT_803df0cc != 0) && ((*(byte *)(param_10 + 0x3f4) >> 6 & 1) != 0)) {
                    *(undefined *)(param_10 + 0x8b4) = 1;
                    *(byte *)(param_10 + 0x3f4) = *(byte *)(param_10 + 0x3f4) & 0xf7 | 8;
                  }
                }
              }
              else if ((((int)local_48 < 0x100010) && (local_48 == 0x100008)) &&
                      (*(undefined *)(param_10 + 0x800) = 1, *(int *)(param_10 + 0x7f8) == 0)) {
                *(uint *)(param_10 + 0x7f8) = local_40[0];
                piVar5 = (int *)FUN_8002b660(*(int *)(param_10 + 0x7f8));
                if (((piVar5 != (int *)0x0) && (*piVar5 != 0)) &&
                   ((*(ushort *)(*piVar5 + 2) & 0x8000) == 0)) {
                  *(undefined *)(*(int *)(param_10 + 0x7f8) + 0xf2) = *(undefined *)(param_9 + 0xf2)
                  ;
                }
                uStack_34 = (int)local_44 >> 0x10 ^ 0x80000000;
                local_38 = 0x43300000;
                *(float *)(param_10 + 0x7fc) =
                     (float)((double)CONCAT44(0x43300000,uStack_34) - DOUBLE_803e8b58) /
                     FLOAT_803e8b70;
                param_1 = (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_11,5);
                *(undefined **)(param_11 + 0x304) = &LAB_802a52ac;
                if ((DAT_803df0cc != 0) && ((*(byte *)(param_10 + 0x3f4) >> 6 & 1) != 0)) {
                  *(undefined *)(param_10 + 0x8b4) = 1;
                  *(byte *)(param_10 + 0x3f4) = *(byte *)(param_10 + 0x3f4) & 0xf7 | 8;
                }
              }
            }
            if (local_48 != 0x60005) break;
            dVar12 = (double)(*(float *)(local_40[0] + 0xc) - *(float *)(param_9 + 0xc));
            dVar11 = (double)(*(float *)(local_40[0] + 0x14) - *(float *)(param_9 + 0x14));
            dVar9 = FUN_80293900((double)(float)(dVar12 * dVar12 + (double)(float)(dVar11 * dVar11))
                                );
            fVar2 = FLOAT_803e8c34;
            if ((double)FLOAT_803e8b78 < dVar9) {
              dVar12 = (double)(float)(dVar12 / dVar9);
              dVar11 = (double)(float)(dVar11 / dVar9);
            }
            dVar9 = (double)FLOAT_803e8c34;
            *(float *)(param_9 + 0x24) = (float)(dVar9 * -dVar12);
            *(float *)(param_9 + 0x2c) = (float)(dVar9 * -dVar11);
            *(float *)(param_9 + 0x28) = fVar2;
            iVar6 = *DAT_803dd70c;
            (**(code **)(iVar6 + 0x14))(param_9,param_11,0x21);
            *(undefined4 *)(param_11 + 0x304) = 0;
            param_1 = FUN_8003042c((double)FLOAT_803e8b3c,param_2,param_3,param_4,param_5,param_6,
                                   param_7,param_8,param_9,0x450,0,iVar6,param_13,param_14,param_15,
                                   param_16);
            iVar7 = *(int *)(param_9 + 0xb8);
            pcVar8 = *(char **)(iVar7 + 0x35c);
            iVar6 = (int)*pcVar8 - local_44;
            if (iVar6 < 0) {
              iVar6 = 0;
            }
            else if (pcVar8[1] < iVar6) {
              iVar6 = (int)pcVar8[1];
            }
            *pcVar8 = (char)iVar6;
            if (**(char **)(iVar7 + 0x35c) < '\x01') {
              param_1 = FUN_802ab1e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                     ,param_9);
            }
            *(undefined *)(param_10 + 0x800) = 0;
            iVar6 = *(int *)(param_10 + 0x7f8);
            if (iVar6 != 0) {
              if ((*(short *)(iVar6 + 0x46) == 0x3cf) || (*(short *)(iVar6 + 0x46) == 0x662)) {
                param_1 = FUN_80182a5c(iVar6);
              }
              else {
                param_1 = FUN_800ea9f8(iVar6);
              }
              *(ushort *)(*(int *)(param_10 + 0x7f8) + 6) =
                   *(ushort *)(*(int *)(param_10 + 0x7f8) + 6) & 0xbfff;
              *(undefined4 *)(*(int *)(param_10 + 0x7f8) + 0xf8) = 0;
              *(undefined4 *)(param_10 + 0x7f8) = 0;
            }
          }
          if (0x60004 < (int)local_48) break;
          if (local_48 == 0x60003) {
            dVar11 = (double)(*(float *)(local_40[0] + 0xc) - *(float *)(param_9 + 0xc));
            dVar12 = (double)(*(float *)(local_40[0] + 0x14) - *(float *)(param_9 + 0x14));
            dVar9 = FUN_80293900((double)(float)(dVar11 * dVar11 + (double)(float)(dVar12 * dVar12))
                                );
            fVar2 = FLOAT_803e8c34;
            if ((double)FLOAT_803e8b78 < dVar9) {
              dVar11 = (double)(float)(dVar11 / dVar9);
              dVar12 = (double)(float)(dVar12 / dVar9);
            }
            dVar9 = (double)FLOAT_803e8c34;
            *(float *)(param_9 + 0x24) = (float)(dVar9 * dVar11);
            *(float *)(param_9 + 0x2c) = (float)(dVar9 * dVar12);
            *(float *)(param_9 + 0x28) = fVar2;
            param_1 = (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_11,0x21);
            *(undefined4 *)(param_11 + 0x304) = 0;
            iVar7 = *(int *)(param_9 + 0xb8);
            pcVar8 = *(char **)(iVar7 + 0x35c);
            iVar6 = (int)*pcVar8 - local_44;
            if (iVar6 < 0) {
              iVar6 = 0;
            }
            else if (pcVar8[1] < iVar6) {
              iVar6 = (int)pcVar8[1];
            }
            *pcVar8 = (char)iVar6;
            if (**(char **)(iVar7 + 0x35c) < '\x01') {
              param_1 = FUN_802ab1e0(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8
                                     ,param_9);
            }
            *(undefined *)(param_10 + 0x800) = 0;
            iVar6 = *(int *)(param_10 + 0x7f8);
            if (iVar6 != 0) {
              if ((*(short *)(iVar6 + 0x46) == 0x3cf) || (*(short *)(iVar6 + 0x46) == 0x662)) {
                param_1 = FUN_80182a5c(iVar6);
              }
              else {
                param_1 = FUN_800ea9f8(iVar6);
              }
              *(ushort *)(*(int *)(param_10 + 0x7f8) + 6) =
                   *(ushort *)(*(int *)(param_10 + 0x7f8) + 6) & 0xbfff;
              *(undefined4 *)(*(int *)(param_10 + 0x7f8) + 0xf8) = 0;
              *(undefined4 *)(param_10 + 0x7f8) = 0;
            }
          }
          else if (0x60002 < (int)local_48) {
            dVar12 = (double)(*(float *)(local_40[0] + 0xc) - *(float *)(param_9 + 0xc));
            dVar11 = (double)(*(float *)(local_40[0] + 0x14) - *(float *)(param_9 + 0x14));
            dVar9 = FUN_80293900((double)(float)(dVar12 * dVar12 + (double)(float)(dVar11 * dVar11))
                                );
            fVar2 = FLOAT_803e8c34;
            if ((double)FLOAT_803e8b78 < dVar9) {
              dVar12 = (double)(float)(dVar12 / dVar9);
              dVar11 = (double)(float)(dVar11 / dVar9);
            }
            dVar9 = (double)FLOAT_803e8c34;
            *(float *)(param_9 + 0x24) = (float)(dVar9 * -dVar12);
            *(float *)(param_9 + 0x2c) = (float)(dVar9 * -dVar11);
            *(float *)(param_9 + 0x28) = fVar2;
            uVar10 = (**(code **)(*DAT_803dd70c + 0x14))(param_9,param_11,0x21);
            *(undefined4 *)(param_11 + 0x304) = 0;
            iVar7 = *(int *)(param_9 + 0xb8);
            pcVar8 = *(char **)(iVar7 + 0x35c);
            iVar6 = (int)*pcVar8 - local_44;
            if (iVar6 < 0) {
              iVar6 = 0;
            }
            else if (pcVar8[1] < iVar6) {
              iVar6 = (int)pcVar8[1];
            }
            *pcVar8 = (char)iVar6;
            if (**(char **)(iVar7 + 0x35c) < '\x01') {
              FUN_802ab1e0(uVar10,param_2,param_3,param_4,param_5,param_6,param_7,param_8,param_9);
            }
            *(undefined *)(param_10 + 0x800) = 0;
            iVar6 = *(int *)(param_10 + 0x7f8);
            if (iVar6 != 0) {
              if ((*(short *)(iVar6 + 0x46) == 0x3cf) || (*(short *)(iVar6 + 0x46) == 0x662)) {
                FUN_80182a5c(iVar6);
              }
              else {
                FUN_800ea9f8(iVar6);
              }
              *(ushort *)(*(int *)(param_10 + 0x7f8) + 6) =
                   *(ushort *)(*(int *)(param_10 + 0x7f8) + 6) & 0xbfff;
              *(undefined4 *)(*(int *)(param_10 + 0x7f8) + 0xf8) = 0;
              *(undefined4 *)(param_10 + 0x7f8) = 0;
            }
            if (*(short *)(param_10 + 0x81a) == 0) {
              uVar3 = 0x1f;
            }
            else {
              uVar3 = 0x24;
            }
            param_1 = FUN_8000bb38(param_9,uVar3);
          }
        }
      } while (local_48 != 0x7000a);
      *(uint *)(param_10 + 0x8dc) = local_44;
      iVar6 = *(int *)(local_40[0] + 100);
      if (iVar6 != 0) {
        *(uint *)(iVar6 + 0x30) = *(uint *)(iVar6 + 0x30) & 0xfffffffb;
      }
      fVar2 = FLOAT_803e8bc8;
      if (0 < **(short **)(param_10 + 0x8dc)) break;
      fVar1 = *(float *)(local_40[0] + 8) / *(float *)(*(int *)(local_40[0] + 0x50) + 4);
      param_3 = (double)FLOAT_803e8c00;
      while( true ) {
        param_4 = (double)fVar1;
        param_2 = (double)*(float *)(param_9 + 0xa8);
        if ((float)(param_4 * (double)(float)(param_2 * (double)*(float *)(param_9 + 8))) <= fVar2)
        break;
        *(float *)(local_40[0] + 8) = (float)((double)*(float *)(local_40[0] + 8) * param_3);
        fVar1 = *(float *)(local_40[0] + 8) / *(float *)(*(int *)(local_40[0] + 0x50) + 4);
      }
      (**(code **)(*DAT_803dd6d4 + 0x7c))((int)*(short *)(local_40[0] + 0x46),0,0);
      param_1 = (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
LAB_802b329c:
      *(uint *)(param_10 + 0x684) = local_40[0];
      *(undefined2 *)(param_10 + 0x688) = *(undefined2 *)(*(int *)(param_10 + 0x8dc) + 2);
      iVar6 = *(int *)(*(int *)(param_10 + 0x684) + 100);
      if (iVar6 != 0) {
        *(undefined4 *)(iVar6 + 0x30) = 0x1000;
      }
      if ((DAT_803df0cc != 0) && ((*(byte *)(param_10 + 0x3f4) >> 6 & 1) != 0)) {
        *(undefined *)(param_10 + 0x8b4) = 1;
        *(byte *)(param_10 + 0x3f4) = *(byte *)(param_10 + 0x3f4) & 0xf7 | 8;
      }
    }
    uVar4 = FUN_80020078((int)**(short **)(param_10 + 0x8dc));
    fVar2 = FLOAT_803e8bc8;
    if (uVar4 == 0) {
      fVar1 = *(float *)(local_40[0] + 8) / *(float *)(*(int *)(local_40[0] + 0x50) + 4);
      param_3 = (double)FLOAT_803e8c00;
      while( true ) {
        param_4 = (double)fVar1;
        param_2 = (double)*(float *)(param_9 + 0xa8);
        if ((float)(param_4 * (double)(float)(param_2 * (double)*(float *)(param_9 + 8))) <= fVar2)
        break;
        *(float *)(local_40[0] + 8) = (float)((double)*(float *)(local_40[0] + 8) * param_3);
        fVar1 = *(float *)(local_40[0] + 8) / *(float *)(*(int *)(local_40[0] + 0x50) + 4);
      }
      FUN_800201ac((int)**(short **)(param_10 + 0x8dc),1);
      (**(code **)(*DAT_803dd6d4 + 0x7c))((int)*(short *)(local_40[0] + 0x46),0,0);
      param_1 = (**(code **)(*DAT_803dd6d4 + 0x48))(0,param_9,0xffffffff);
      goto LAB_802b329c;
    }
    FUN_800379bc(param_1,param_2,param_3,param_4,param_5,param_6,param_7,param_8,local_40[0],0x7000b
                 ,param_9,0,param_13,param_14,param_15,param_16);
  } while( true );
}

