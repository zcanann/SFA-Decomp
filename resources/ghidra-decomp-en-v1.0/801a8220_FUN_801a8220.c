// Function: FUN_801a8220
// Entry: 801a8220
// Size: 1736 bytes

/* WARNING: Removing unreachable block (ram,0x801a88c8) */

void FUN_801a8220(void)

{
  float fVar1;
  ushort uVar2;
  bool bVar3;
  float fVar4;
  float fVar5;
  int iVar6;
  int iVar7;
  char cVar10;
  uint uVar8;
  int *piVar9;
  undefined uVar11;
  int iVar12;
  undefined4 uVar13;
  int iVar14;
  undefined4 uVar15;
  double dVar16;
  undefined8 in_f31;
  double dVar17;
  int local_58;
  int local_54;
  double local_50;
  longlong local_48;
  undefined4 local_40;
  uint uStack60;
  longlong local_38;
  longlong local_30;
  undefined auStack8 [8];
  
  uVar15 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  iVar6 = FUN_802860dc();
  iVar14 = *(int *)(iVar6 + 0xb8);
  iVar12 = *(int *)(iVar6 + 0x4c);
  iVar7 = FUN_8005b2fc((double)*(float *)(iVar6 + 0xc),(double)*(float *)(iVar6 + 0x10),
                       (double)*(float *)(iVar6 + 0x14));
  fVar1 = FLOAT_803e4554;
  if ((iVar7 != -1) && ((*(ushort *)(iVar14 + 0x24) & 4) == 0)) {
    if ((*(ushort *)(iVar14 + 0x24) & 0x200) == 0) {
      FUN_800972dc((double)FLOAT_803e457c,(double)FLOAT_803e454c,iVar6,1,5,1,10,0,0);
      FUN_800972dc((double)FLOAT_803e457c,(double)FLOAT_803e454c,iVar6,5,5,1,0x14,0,0);
      if ((*(ushort *)(iVar14 + 0x24) & 0x40) == 0) {
        bVar3 = false;
        if (((*(ushort *)(iVar14 + 0x24) & 8) == 0) ||
           (cVar10 = (**(code **)(*DAT_803dcaac + 0x4c))(0x12,6), cVar10 != '\0')) {
          if ((*(ushort *)(iVar14 + 0x24) & 0x400) == 0) {
            if ((*(short *)(iVar12 + 0x20) == -1) || (iVar7 = FUN_8001ffb4(), iVar7 != 0)) {
              iVar7 = (**(code **)(*DAT_803dcac0 + 8))(iVar6,*(undefined4 *)(iVar6 + 0xb8));
              if (iVar7 != 0) {
                bVar3 = true;
              }
            }
            else {
              *(byte *)(iVar6 + 0xaf) = *(byte *)(iVar6 + 0xaf) | 8;
            }
          }
          else {
            *(byte *)(iVar6 + 0xaf) = *(byte *)(iVar6 + 0xaf) | 8;
          }
        }
        else {
          *(ushort *)(iVar14 + 0x24) = *(ushort *)(iVar14 + 0x24) | 1;
        }
        *(ushort *)(iVar14 + 0x24) = *(ushort *)(iVar14 + 0x24) & 0xfff7;
        if (bVar3) {
          FUN_8002b9ec();
          uVar8 = FUN_8029729c();
          if ((uVar8 & 0x4000) == 0) {
            FUN_8011f3ec(4);
            *(ushort *)(iVar14 + 0x24) = *(ushort *)(iVar14 + 0x24) | 0x28;
            *(ushort *)(iVar14 + 0x24) = *(ushort *)(iVar14 + 0x24) & 0xffef;
          }
          else {
            FUN_8011f3ec(5);
            *(ushort *)(iVar14 + 0x24) = *(ushort *)(iVar14 + 0x24) | 0x18;
            *(ushort *)(iVar14 + 0x24) = *(ushort *)(iVar14 + 0x24) & 0xffdf;
          }
          uVar13 = *(undefined4 *)(iVar6 + 0xb8);
          (**(code **)(*DAT_803dcac0 + 0x24))(uVar13,0);
          piVar9 = (int *)FUN_80036f50(0x10,&local_58);
          dVar17 = (double)FLOAT_803e4580;
          for (iVar7 = 0; iVar7 < local_58; iVar7 = iVar7 + 1) {
            iVar12 = *piVar9;
            if (((iVar12 != iVar6) && (*(short *)(iVar12 + 0x46) == 0x519)) &&
               (dVar16 = (double)FUN_80021690(iVar6 + 0x18,iVar12 + 0x18), dVar16 < dVar17)) {
              (**(code **)(*DAT_803dcac0 + 0x24))(uVar13,1);
              bVar3 = false;
              goto LAB_801a85ac;
            }
            piVar9 = piVar9 + 1;
          }
          bVar3 = true;
LAB_801a85ac:
          if (bVar3) {
            *(ushort *)(iVar14 + 0x24) = *(ushort *)(iVar14 + 0x24) | 1;
          }
          if ((*(ushort *)(iVar14 + 0x24) & 2) != 0) {
            FUN_801a7d74(iVar6,0,0);
            *(ushort *)(iVar14 + 0x24) = *(ushort *)(iVar14 + 0x24) & 0xfffd;
          }
        }
        else {
          uVar2 = *(ushort *)(iVar14 + 0x24);
          if (((uVar2 & 0x400) == 0) && ((uVar2 & 1) != 0)) {
            if ((uVar2 & 0x20) == 0) {
              FUN_801a7d74(iVar6,1,0);
            }
            else {
              FUN_801a7cc4(iVar6);
            }
            *(ushort *)(iVar14 + 0x24) = *(ushort *)(iVar14 + 0x24) & 0xfffe;
          }
          *(ushort *)(iVar14 + 0x24) = *(ushort *)(iVar14 + 0x24) | 2;
          if (*(char *)(iVar14 + 0x2e) != '\0') {
            if ((*(ushort *)(iVar14 + 0x24) & 0x400) == 0) {
              *(undefined *)(iVar14 + 0x2f) = 0;
            }
            else {
              uVar11 = FUN_8001ffb4(0x894);
              *(undefined *)(iVar14 + 0x2f) = uVar11;
            }
            FUN_8000bb18(iVar6,0x108);
            FUN_8000b888((double)FLOAT_803e4588,iVar6,0x40,*(char *)(iVar14 + 0x2f) * ' ' + ' ');
            fVar1 = *(float *)(iVar6 + 0x28);
            local_50 = (double)CONCAT44(0x43300000,(uint)*(byte *)(iVar14 + 0x2f));
            if (FLOAT_803e458c *
                ((FLOAT_803e4568 * (float)(local_50 - DOUBLE_803e45a8) + *(float *)(iVar14 + 0xc)) -
                *(float *)(iVar6 + 0x10)) <= fVar1) {
              *(float *)(iVar6 + 0x28) = fVar1 - FLOAT_803e4594;
            }
            else {
              *(float *)(iVar6 + 0x28) = fVar1 + FLOAT_803e4590;
            }
            *(short *)(iVar14 + 0x26) = *(short *)(iVar14 + 0x26) + 0x1000;
            *(short *)(iVar14 + 0x28) = *(short *)(iVar14 + 0x28) + 0xdac;
            *(short *)(iVar14 + 0x2a) = *(short *)(iVar14 + 0x2a) + 0x800;
            FUN_8002b95c((double)FLOAT_803e4554,(double)(*(float *)(iVar6 + 0x28) * FLOAT_803db414),
                         (double)FLOAT_803e4554,iVar6);
            local_50 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar14 + 0x26));
            dVar17 = (double)FUN_80293e80((double)((FLOAT_803e4598 *
                                                   (float)(local_50 - DOUBLE_803e45a8)) /
                                                  FLOAT_803e459c));
            *(float *)(iVar6 + 0x10) = (float)((double)*(float *)(iVar6 + 0x10) + dVar17);
            if (*(float *)(iVar6 + 0x10) < *(float *)(iVar14 + 0xc)) {
              *(float *)(iVar6 + 0x10) = *(float *)(iVar14 + 0xc);
            }
            local_50 = (double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar14 + 0x28));
            dVar17 = (double)FUN_80293e80((double)((FLOAT_803e4598 *
                                                   (float)(local_50 - DOUBLE_803e45a8)) /
                                                  FLOAT_803e459c));
            local_48 = (longlong)(int)((double)FLOAT_803e45a0 * dVar17);
            *(short *)(iVar6 + 4) =
                 *(short *)(iVar6 + 4) + (short)(int)((double)FLOAT_803e45a0 * dVar17);
            uStack60 = (uint)*(ushort *)(iVar14 + 0x2a);
            local_40 = 0x43300000;
            dVar17 = (double)FUN_80293e80((double)((FLOAT_803e4598 *
                                                   (float)((double)CONCAT44(0x43300000,uStack60) -
                                                          DOUBLE_803e45a8)) / FLOAT_803e459c));
            local_38 = (longlong)(int)((double)FLOAT_803e45a0 * dVar17);
            *(short *)(iVar6 + 2) =
                 *(short *)(iVar6 + 2) + (short)(int)((double)FLOAT_803e45a0 * dVar17);
            DAT_803ac920 = FLOAT_803e457c;
            DAT_803ac924 = *(undefined4 *)(iVar6 + 0xc);
            DAT_803ac928 = *(float *)(iVar14 + 0xc);
            DAT_803ac92c = *(undefined4 *)(iVar6 + 0x14);
            local_54 = (int)(*(float *)(iVar6 + 0x10) - DAT_803ac928);
            local_30 = (longlong)local_54;
            (**(code **)(*DAT_803dca88 + 8))
                      (iVar6,0x723,&DAT_803ac918,0x200001,0xffffffff,&local_54);
          }
        }
      }
      else {
        FUN_801a7b10(iVar6);
        FUN_801a79e0(iVar6);
      }
    }
    else if (FLOAT_803e4554 < *(float *)(iVar14 + 0x14)) {
      *(float *)(iVar14 + 0x14) = *(float *)(iVar14 + 0x14) - FLOAT_803db414;
      fVar5 = FLOAT_803e457c;
      fVar4 = FLOAT_803e4558;
      if (fVar1 < *(float *)(iVar14 + 0x14)) {
        iVar7 = (int)(FLOAT_803e4584 * (FLOAT_803e457c - *(float *)(iVar14 + 0x14) / FLOAT_803e4558)
                     );
        local_50 = (double)(longlong)iVar7;
        *(char *)(iVar6 + 0x36) = (char)iVar7;
        FUN_80099d84((double)FLOAT_803e4588,(double)(fVar5 - *(float *)(iVar14 + 0x14) / fVar4),
                     iVar6,2,0);
        FUN_80099d84((double)FLOAT_803e4588,
                     (double)(FLOAT_803e457c - *(float *)(iVar14 + 0x14) / FLOAT_803e4558),iVar6,2,0
                    );
      }
      else {
        *(undefined2 *)(iVar14 + 0x24) = 0;
        *(undefined *)(iVar6 + 0x36) = 0xff;
        FUN_80035f00(iVar6);
        FUN_801a7d74(iVar6,1,1);
      }
    }
  }
  __psq_l0(auStack8,uVar15);
  __psq_l1(auStack8,uVar15);
  FUN_80286128();
  return;
}

