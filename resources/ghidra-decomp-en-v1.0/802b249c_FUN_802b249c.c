// Function: FUN_802b249c
// Entry: 802b249c
// Size: 2312 bytes

/* WARNING: Removing unreachable block (ram,0x802b2d74) */
/* WARNING: Removing unreachable block (ram,0x802b2d7c) */

void FUN_802b249c(int param_1,int param_2,int param_3)

{
  short sVar1;
  float fVar2;
  float fVar3;
  float fVar4;
  undefined4 uVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  char *pcVar9;
  undefined4 uVar10;
  double dVar11;
  undefined8 in_f30;
  double dVar12;
  undefined8 in_f31;
  double dVar13;
  int local_48;
  int local_44;
  int local_40 [2];
  undefined4 local_38;
  uint uStack52;
  undefined auStack24 [16];
  undefined auStack8 [8];
  
  uVar10 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  __psq_st0(auStack24,(int)((ulonglong)in_f30 >> 0x20),0);
  __psq_st1(auStack24,(int)in_f30,0);
  local_44 = 0;
  do {
    while( true ) {
      do {
        while( true ) {
          while( true ) {
            while( true ) {
              while( true ) {
                iVar7 = FUN_800374ec(param_1,&local_48,local_40,&local_44);
                if (iVar7 == 0) {
                  __psq_l0(auStack8,uVar10);
                  __psq_l1(auStack8,uVar10);
                  __psq_l0(auStack24,uVar10);
                  __psq_l1(auStack24,uVar10);
                  return;
                }
                if (local_48 != 0x80002) break;
                *(short *)(param_2 + 0x80c) = (short)local_44;
                if ((*(int *)(param_3 + 0x2d0) != 0) && ((local_44 == 0x2d || (local_44 == 0x5ce))))
                {
                  *(short *)(param_2 + 0x80e) = (short)local_44;
                  *(undefined2 *)(param_2 + 0x80c) = 0xffff;
                }
              }
              if (local_48 < 0x80002) break;
              if (local_48 == 0x100010) {
                *(undefined *)(param_2 + 0x800) = 1;
                if (*(int *)(param_2 + 0x7f8) == 0) {
                  *(int *)(param_2 + 0x7f8) = local_40[0];
                  piVar6 = (int *)FUN_8002b588(*(undefined4 *)(param_2 + 0x7f8));
                  if (((piVar6 != (int *)0x0) && (*piVar6 != 0)) &&
                     ((*(ushort *)(*piVar6 + 2) & 0x8000) == 0)) {
                    *(undefined *)(*(int *)(param_2 + 0x7f8) + 0xf2) =
                         *(undefined *)(param_1 + 0xf2);
                  }
                  uStack52 = local_44 >> 0x10 ^ 0x80000000;
                  local_38 = 0x43300000;
                  *(float *)(param_2 + 0x7fc) =
                       (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e7ec0);
                  (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_3,5);
                  *(undefined **)(param_3 + 0x304) = &LAB_802a4b4c;
                  if ((DAT_803de44c != 0) && ((*(byte *)(param_2 + 0x3f4) >> 6 & 1) != 0)) {
                    *(undefined *)(param_2 + 0x8b4) = 1;
                    *(byte *)(param_2 + 0x3f4) = *(byte *)(param_2 + 0x3f4) & 0xf7 | 8;
                  }
                }
              }
              else if (((local_48 < 0x100010) && (local_48 == 0x100008)) &&
                      (*(undefined *)(param_2 + 0x800) = 1, *(int *)(param_2 + 0x7f8) == 0)) {
                *(int *)(param_2 + 0x7f8) = local_40[0];
                piVar6 = (int *)FUN_8002b588(*(undefined4 *)(param_2 + 0x7f8));
                if (((piVar6 != (int *)0x0) && (*piVar6 != 0)) &&
                   ((*(ushort *)(*piVar6 + 2) & 0x8000) == 0)) {
                  *(undefined *)(*(int *)(param_2 + 0x7f8) + 0xf2) = *(undefined *)(param_1 + 0xf2);
                }
                uStack52 = local_44 >> 0x10 ^ 0x80000000;
                local_38 = 0x43300000;
                *(float *)(param_2 + 0x7fc) =
                     (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e7ec0) /
                     FLOAT_803e7ed8;
                (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_3,5);
                *(undefined **)(param_3 + 0x304) = &LAB_802a4b4c;
                if ((DAT_803de44c != 0) && ((*(byte *)(param_2 + 0x3f4) >> 6 & 1) != 0)) {
                  *(undefined *)(param_2 + 0x8b4) = 1;
                  *(byte *)(param_2 + 0x3f4) = *(byte *)(param_2 + 0x3f4) & 0xf7 | 8;
                }
              }
            }
            if (local_48 != 0x60005) break;
            dVar13 = (double)(*(float *)(local_40[0] + 0xc) - *(float *)(param_1 + 0xc));
            dVar12 = (double)(*(float *)(local_40[0] + 0x14) - *(float *)(param_1 + 0x14));
            dVar11 = (double)FUN_802931a0((double)(float)(dVar13 * dVar13 +
                                                         (double)(float)(dVar12 * dVar12)));
            fVar3 = FLOAT_803e7f9c;
            if ((double)FLOAT_803e7ee0 < dVar11) {
              dVar13 = (double)(float)(dVar13 / dVar11);
              dVar12 = (double)(float)(dVar12 / dVar11);
            }
            dVar11 = (double)FLOAT_803e7f9c;
            *(float *)(param_1 + 0x24) = (float)(dVar11 * -dVar13);
            *(float *)(param_1 + 0x2c) = (float)(dVar11 * -dVar12);
            *(float *)(param_1 + 0x28) = fVar3;
            (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_3,0x21);
            *(undefined4 *)(param_3 + 0x304) = 0;
            FUN_80030334((double)FLOAT_803e7ea4,param_1,0x450,0);
            iVar8 = *(int *)(param_1 + 0xb8);
            pcVar9 = *(char **)(iVar8 + 0x35c);
            iVar7 = *pcVar9 - local_44;
            if (iVar7 < 0) {
              iVar7 = 0;
            }
            else if (pcVar9[1] < iVar7) {
              iVar7 = (int)pcVar9[1];
            }
            *pcVar9 = (char)iVar7;
            if (**(char **)(iVar8 + 0x35c) < '\x01') {
              FUN_802aaa80(param_1);
            }
            *(undefined *)(param_2 + 0x800) = 0;
            if (*(int *)(param_2 + 0x7f8) != 0) {
              sVar1 = *(short *)(*(int *)(param_2 + 0x7f8) + 0x46);
              if ((sVar1 == 0x3cf) || (sVar1 == 0x662)) {
                FUN_80182504();
              }
              else {
                FUN_800ea774();
              }
              *(ushort *)(*(int *)(param_2 + 0x7f8) + 6) =
                   *(ushort *)(*(int *)(param_2 + 0x7f8) + 6) & 0xbfff;
              *(undefined4 *)(*(int *)(param_2 + 0x7f8) + 0xf8) = 0;
              *(undefined4 *)(param_2 + 0x7f8) = 0;
            }
          }
          if (0x60004 < local_48) break;
          if (local_48 == 0x60003) {
            dVar12 = (double)(*(float *)(local_40[0] + 0xc) - *(float *)(param_1 + 0xc));
            dVar13 = (double)(*(float *)(local_40[0] + 0x14) - *(float *)(param_1 + 0x14));
            dVar11 = (double)FUN_802931a0((double)(float)(dVar12 * dVar12 +
                                                         (double)(float)(dVar13 * dVar13)));
            fVar3 = FLOAT_803e7f9c;
            if ((double)FLOAT_803e7ee0 < dVar11) {
              dVar12 = (double)(float)(dVar12 / dVar11);
              dVar13 = (double)(float)(dVar13 / dVar11);
            }
            dVar11 = (double)FLOAT_803e7f9c;
            *(float *)(param_1 + 0x24) = (float)(dVar11 * dVar12);
            *(float *)(param_1 + 0x2c) = (float)(dVar11 * dVar13);
            *(float *)(param_1 + 0x28) = fVar3;
            (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_3,0x21);
            *(undefined4 *)(param_3 + 0x304) = 0;
            iVar8 = *(int *)(param_1 + 0xb8);
            pcVar9 = *(char **)(iVar8 + 0x35c);
            iVar7 = *pcVar9 - local_44;
            if (iVar7 < 0) {
              iVar7 = 0;
            }
            else if (pcVar9[1] < iVar7) {
              iVar7 = (int)pcVar9[1];
            }
            *pcVar9 = (char)iVar7;
            if (**(char **)(iVar8 + 0x35c) < '\x01') {
              FUN_802aaa80(param_1);
            }
            *(undefined *)(param_2 + 0x800) = 0;
            if (*(int *)(param_2 + 0x7f8) != 0) {
              sVar1 = *(short *)(*(int *)(param_2 + 0x7f8) + 0x46);
              if ((sVar1 == 0x3cf) || (sVar1 == 0x662)) {
                FUN_80182504();
              }
              else {
                FUN_800ea774();
              }
              *(ushort *)(*(int *)(param_2 + 0x7f8) + 6) =
                   *(ushort *)(*(int *)(param_2 + 0x7f8) + 6) & 0xbfff;
              *(undefined4 *)(*(int *)(param_2 + 0x7f8) + 0xf8) = 0;
              *(undefined4 *)(param_2 + 0x7f8) = 0;
            }
          }
          else if (0x60002 < local_48) {
            dVar13 = (double)(*(float *)(local_40[0] + 0xc) - *(float *)(param_1 + 0xc));
            dVar12 = (double)(*(float *)(local_40[0] + 0x14) - *(float *)(param_1 + 0x14));
            dVar11 = (double)FUN_802931a0((double)(float)(dVar13 * dVar13 +
                                                         (double)(float)(dVar12 * dVar12)));
            fVar3 = FLOAT_803e7f9c;
            if ((double)FLOAT_803e7ee0 < dVar11) {
              dVar13 = (double)(float)(dVar13 / dVar11);
              dVar12 = (double)(float)(dVar12 / dVar11);
            }
            dVar11 = (double)FLOAT_803e7f9c;
            *(float *)(param_1 + 0x24) = (float)(dVar11 * -dVar13);
            *(float *)(param_1 + 0x2c) = (float)(dVar11 * -dVar12);
            *(float *)(param_1 + 0x28) = fVar3;
            (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_3,0x21);
            *(undefined4 *)(param_3 + 0x304) = 0;
            iVar8 = *(int *)(param_1 + 0xb8);
            pcVar9 = *(char **)(iVar8 + 0x35c);
            iVar7 = *pcVar9 - local_44;
            if (iVar7 < 0) {
              iVar7 = 0;
            }
            else if (pcVar9[1] < iVar7) {
              iVar7 = (int)pcVar9[1];
            }
            *pcVar9 = (char)iVar7;
            if (**(char **)(iVar8 + 0x35c) < '\x01') {
              FUN_802aaa80(param_1);
            }
            *(undefined *)(param_2 + 0x800) = 0;
            if (*(int *)(param_2 + 0x7f8) != 0) {
              sVar1 = *(short *)(*(int *)(param_2 + 0x7f8) + 0x46);
              if ((sVar1 == 0x3cf) || (sVar1 == 0x662)) {
                FUN_80182504();
              }
              else {
                FUN_800ea774();
              }
              *(ushort *)(*(int *)(param_2 + 0x7f8) + 6) =
                   *(ushort *)(*(int *)(param_2 + 0x7f8) + 6) & 0xbfff;
              *(undefined4 *)(*(int *)(param_2 + 0x7f8) + 0xf8) = 0;
              *(undefined4 *)(param_2 + 0x7f8) = 0;
            }
            if (*(short *)(param_2 + 0x81a) == 0) {
              uVar5 = 0x1f;
            }
            else {
              uVar5 = 0x24;
            }
            FUN_8000bb18(param_1,uVar5);
          }
        }
      } while (local_48 != 0x7000a);
      *(int *)(param_2 + 0x8dc) = local_44;
      iVar7 = *(int *)(local_40[0] + 100);
      if (iVar7 != 0) {
        *(uint *)(iVar7 + 0x30) = *(uint *)(iVar7 + 0x30) & 0xfffffffb;
      }
      fVar4 = FLOAT_803e7f68;
      fVar3 = FLOAT_803e7f30;
      if (0 < **(short **)(param_2 + 0x8dc)) break;
      fVar2 = *(float *)(local_40[0] + 8) / *(float *)(*(int *)(local_40[0] + 0x50) + 4);
      while (fVar3 < fVar2 * *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8)) {
        *(float *)(local_40[0] + 8) = *(float *)(local_40[0] + 8) * fVar4;
        fVar2 = *(float *)(local_40[0] + 8) / *(float *)(*(int *)(local_40[0] + 0x50) + 4);
      }
      (**(code **)(*DAT_803dca54 + 0x7c))((int)*(short *)(local_40[0] + 0x46),0,0);
      (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
LAB_802b2b3c:
      *(int *)(param_2 + 0x684) = local_40[0];
      *(undefined2 *)(param_2 + 0x688) = *(undefined2 *)(*(int *)(param_2 + 0x8dc) + 2);
      iVar7 = *(int *)(*(int *)(param_2 + 0x684) + 100);
      if (iVar7 != 0) {
        *(undefined4 *)(iVar7 + 0x30) = 0x1000;
      }
      if ((DAT_803de44c != 0) && ((*(byte *)(param_2 + 0x3f4) >> 6 & 1) != 0)) {
        *(undefined *)(param_2 + 0x8b4) = 1;
        *(byte *)(param_2 + 0x3f4) = *(byte *)(param_2 + 0x3f4) & 0xf7 | 8;
      }
    }
    iVar7 = FUN_8001ffb4();
    fVar4 = FLOAT_803e7f68;
    fVar3 = FLOAT_803e7f30;
    if (iVar7 == 0) {
      fVar2 = *(float *)(local_40[0] + 8) / *(float *)(*(int *)(local_40[0] + 0x50) + 4);
      while (fVar3 < fVar2 * *(float *)(param_1 + 0xa8) * *(float *)(param_1 + 8)) {
        *(float *)(local_40[0] + 8) = *(float *)(local_40[0] + 8) * fVar4;
        fVar2 = *(float *)(local_40[0] + 8) / *(float *)(*(int *)(local_40[0] + 0x50) + 4);
      }
      FUN_800200e8((int)**(short **)(param_2 + 0x8dc),1);
      (**(code **)(*DAT_803dca54 + 0x7c))((int)*(short *)(local_40[0] + 0x46),0,0);
      (**(code **)(*DAT_803dca54 + 0x48))(0,param_1,0xffffffff);
      goto LAB_802b2b3c;
    }
    FUN_800378c4(local_40[0],0x7000b,param_1,0);
  } while( true );
}

