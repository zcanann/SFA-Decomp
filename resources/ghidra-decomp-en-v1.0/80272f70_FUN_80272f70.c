// Function: FUN_80272f70
// Entry: 80272f70
// Size: 2168 bytes

/* WARNING: Removing unreachable block (ram,0x802733a0) */
/* WARNING: Removing unreachable block (ram,0x8027354c) */
/* WARNING: Removing unreachable block (ram,0x802731f4) */
/* WARNING: Removing unreachable block (ram,0x80273068) */

void FUN_80272f70(void)

{
  byte bVar1;
  undefined uVar2;
  char cVar3;
  uint uVar4;
  int iVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  uint uVar10;
  uint uVar11;
  double dVar12;
  double dVar13;
  double dVar14;
  uint local_88;
  undefined4 local_84;
  int local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined local_6c;
  undefined4 local_68;
  uint uStack100;
  undefined4 local_60;
  uint uStack92;
  undefined4 local_58;
  uint uStack84;
  longlong local_50;
  undefined4 local_48;
  undefined4 uStack68;
  undefined4 local_40;
  undefined4 uStack60;
  
  if (DAT_803de280 == '\0') {
    iVar5 = -0x7fc41c88;
    DAT_803de280 = DAT_803de281;
    dVar13 = (double)FLOAT_803e77e8;
    dVar14 = (double)FLOAT_803e77d8;
    dVar12 = DOUBLE_803e77e0;
    for (uVar11 = 0; uVar11 < DAT_803bd360; uVar11 = uVar11 + 1) {
      bVar1 = *(byte *)(iVar5 + 8);
      if (bVar1 == 2) {
        uVar7 = FUN_80283c08(*(undefined4 *)(iVar5 + 0x48));
        cVar3 = *(char *)(iVar5 + 9);
        if (cVar3 == '\x01') {
          uVar7 = (uVar7 / 0xe) * 0xe;
        }
        uVar6 = *(uint *)(iVar5 + 0x1c);
        if (uVar6 != uVar7) {
          if (uVar6 < uVar7) {
            if (cVar3 == '\x01') {
              uVar4 = (uint)((ulonglong)uVar6 * 0x124924925 >> 0x21) & 0xfffffff8;
              iVar8 = (**(code **)(iVar5 + 0xc))
                                (*(int *)(iVar5 + 0x10) + uVar4,uVar7 - uVar6,0,0,
                                 *(undefined4 *)(iVar5 + 0x4c));
              if ((iVar8 != 0) && (*(char *)(iVar5 + 8) == '\x02')) {
                uVar7 = *(int *)(iVar5 + 0x1c) + iVar8;
                iVar8 = uVar7 - (uVar7 / *(uint *)(iVar5 + 0x14)) * *(uint *)(iVar5 + 0x14);
                if ((*(uint *)(iVar5 + 4) & 0x20000) == 0) {
                  if (iVar8 == 0) {
                    FUN_80283cac(*(undefined4 *)(iVar5 + 0x10),uVar4,*(int *)(iVar5 + 0x18) - uVar4,
                                 *(undefined *)(iVar5 + 0x5d),0,0);
                  }
                  else {
                    FUN_80283cac(*(undefined4 *)(iVar5 + 0x10),uVar4,
                                 ((uint)((ulonglong)(iVar8 + 0xd) * 0x124924925 >> 0x21) &
                                 0xfffffff8) - uVar4,*(undefined *)(iVar5 + 0x5d),0,0);
                  }
                }
                *(int *)(iVar5 + 0x1c) = iVar8;
              }
            }
            else if (((cVar3 == '\0') &&
                     (iVar8 = (**(code **)(iVar5 + 0xc))
                                        (*(int *)(iVar5 + 0x10) + uVar6 * 2,uVar7 - uVar6,0,0,
                                         *(undefined4 *)(iVar5 + 0x4c)), iVar8 != 0)) &&
                    (*(char *)(iVar5 + 8) == '\x02')) {
              iVar9 = *(int *)(iVar5 + 0x1c);
              uVar7 = *(uint *)(iVar5 + 0x14);
              iVar8 = (iVar9 + iVar8) - ((uint)(iVar9 + iVar8) / uVar7) * uVar7;
              if ((*(uint *)(iVar5 + 4) & 0x20000) == 0) {
                if (iVar8 == 0) {
                  FUN_80283cac(*(undefined4 *)(iVar5 + 0x10),iVar9 << 1,(uVar7 - iVar9) * 2,
                               *(undefined *)(iVar5 + 0x5d),0,0);
                }
                else {
                  FUN_80283cac(*(undefined4 *)(iVar5 + 0x10),iVar9 << 1,(iVar8 - iVar9) * 2,
                               *(undefined *)(iVar5 + 0x5d),0,0);
                }
              }
              *(int *)(iVar5 + 0x1c) = iVar8;
            }
          }
          else if (uVar7 == 0) {
            if (cVar3 == '\x01') {
              uVar7 = (uint)((ulonglong)uVar6 * 0x124924925 >> 0x21) & 0xfffffff8;
              iVar8 = (**(code **)(iVar5 + 0xc))
                                (*(int *)(iVar5 + 0x10) + uVar7,*(int *)(iVar5 + 0x14) - uVar6,0,0,
                                 *(undefined4 *)(iVar5 + 0x4c));
              if ((iVar8 != 0) && (*(char *)(iVar5 + 8) == '\x02')) {
                uVar6 = *(int *)(iVar5 + 0x1c) + iVar8;
                iVar8 = uVar6 - (uVar6 / *(uint *)(iVar5 + 0x14)) * *(uint *)(iVar5 + 0x14);
                if ((*(uint *)(iVar5 + 4) & 0x20000) == 0) {
                  if (iVar8 == 0) {
                    FUN_80283cac(*(undefined4 *)(iVar5 + 0x10),uVar7,*(int *)(iVar5 + 0x18) - uVar7,
                                 *(undefined *)(iVar5 + 0x5d),0,0);
                  }
                  else {
                    FUN_80283cac(*(undefined4 *)(iVar5 + 0x10),uVar7,
                                 ((uint)((ulonglong)(iVar8 + 0xd) * 0x124924925 >> 0x21) &
                                 0xfffffff8) - uVar7,*(undefined *)(iVar5 + 0x5d),0,0);
                  }
                }
                *(int *)(iVar5 + 0x1c) = iVar8;
              }
            }
            else if (((cVar3 == '\0') &&
                     (iVar8 = (**(code **)(iVar5 + 0xc))
                                        (*(int *)(iVar5 + 0x10) + uVar6 * 2,
                                         *(int *)(iVar5 + 0x14) - uVar6,0,0,
                                         *(undefined4 *)(iVar5 + 0x4c)), iVar8 != 0)) &&
                    (*(char *)(iVar5 + 8) == '\x02')) {
              iVar9 = *(int *)(iVar5 + 0x1c);
              iVar8 = (iVar9 + iVar8) -
                      ((uint)(iVar9 + iVar8) / *(uint *)(iVar5 + 0x14)) * *(uint *)(iVar5 + 0x14);
              if ((*(uint *)(iVar5 + 4) & 0x20000) == 0) {
                if (iVar8 == 0) {
                  FUN_80283cac(*(undefined4 *)(iVar5 + 0x10),iVar9 * 2,
                               *(int *)(iVar5 + 0x18) + iVar9 * -2,*(undefined *)(iVar5 + 0x5d),0,0)
                  ;
                }
                else {
                  FUN_80283cac(*(undefined4 *)(iVar5 + 0x10),iVar9 << 1,(iVar8 - iVar9) * 2,
                               *(undefined *)(iVar5 + 0x5d),0,0);
                }
              }
              *(int *)(iVar5 + 0x1c) = iVar8;
            }
          }
          else if (cVar3 == '\x01') {
            uVar4 = (uint)((ulonglong)uVar6 * 0x124924925 >> 0x21) & 0xfffffff8;
            uVar7 = (**(code **)(iVar5 + 0xc))
                              (*(int *)(iVar5 + 0x10) + uVar4,*(int *)(iVar5 + 0x14) - uVar6,
                               *(int *)(iVar5 + 0x10),uVar7,*(undefined4 *)(iVar5 + 0x4c));
            if ((uVar7 != 0) && (*(char *)(iVar5 + 8) == '\x02')) {
              uVar10 = *(uint *)(iVar5 + 0x14);
              uVar6 = *(int *)(iVar5 + 0x1c) + uVar7;
              uVar6 = uVar6 - (uVar6 / uVar10) * uVar10;
              if ((*(uint *)(iVar5 + 4) & 0x20000) == 0) {
                if (uVar10 - *(int *)(iVar5 + 0x1c) < uVar7) {
                  FUN_80283cac(*(undefined4 *)(iVar5 + 0x10),uVar4,*(int *)(iVar5 + 0x18) - uVar4,
                               *(undefined *)(iVar5 + 0x5d),0,0);
                  FUN_80283cac(*(undefined4 *)(iVar5 + 0x10),0,
                               (uint)((ulonglong)uVar6 * 0x124924925 >> 0x21) & 0xfffffff8,
                               *(undefined *)(iVar5 + 0x5d),0,0);
                }
                else if (uVar6 == 0) {
                  FUN_80283cac(*(undefined4 *)(iVar5 + 0x10),uVar4,*(int *)(iVar5 + 0x18) - uVar4,
                               *(undefined *)(iVar5 + 0x5d),0,0);
                }
                else {
                  FUN_80283cac(*(undefined4 *)(iVar5 + 0x10),uVar4,
                               ((uint)((ulonglong)(uVar6 + 0xd) * 0x124924925 >> 0x21) & 0xfffffff8)
                               - uVar4,*(undefined *)(iVar5 + 0x5d),0,0);
                }
              }
              *(uint *)(iVar5 + 0x1c) = uVar6;
            }
          }
          else if (((cVar3 == '\0') &&
                   (uVar7 = (**(code **)(iVar5 + 0xc))
                                      (*(int *)(iVar5 + 0x10) + uVar6 * 2,
                                       *(int *)(iVar5 + 0x14) - uVar6,*(int *)(iVar5 + 0x10),uVar7,
                                       *(undefined4 *)(iVar5 + 0x4c)), uVar7 != 0)) &&
                  (*(char *)(iVar5 + 8) == '\x02')) {
            iVar8 = *(int *)(iVar5 + 0x1c);
            uVar6 = *(uint *)(iVar5 + 0x14);
            iVar9 = (iVar8 + uVar7) - ((iVar8 + uVar7) / uVar6) * uVar6;
            if ((*(uint *)(iVar5 + 4) & 0x20000) == 0) {
              if (uVar6 - iVar8 < uVar7) {
                FUN_80283cac(*(undefined4 *)(iVar5 + 0x10),iVar8 * 2,
                             *(int *)(iVar5 + 0x18) + iVar8 * -2,*(undefined *)(iVar5 + 0x5d),0,0);
                FUN_80283cac(*(undefined4 *)(iVar5 + 0x10),0,iVar9 * 2,*(undefined *)(iVar5 + 0x5d),
                             0,0);
              }
              else if (iVar9 == 0) {
                FUN_80283cac(*(undefined4 *)(iVar5 + 0x10),iVar8 * 2,
                             *(int *)(iVar5 + 0x18) + iVar8 * -2,*(undefined *)(iVar5 + 0x5d),0,0);
              }
              else {
                FUN_80283cac(*(undefined4 *)(iVar5 + 0x10),iVar8 << 1,(iVar9 - iVar8) * 2,
                             *(undefined *)(iVar5 + 0x5d),0,0);
              }
            }
            *(int *)(iVar5 + 0x1c) = iVar9;
          }
          if (((*(char *)(iVar5 + 8) == '\x02') && ((*(uint *)(iVar5 + 4) & 0x20000) == 0)) &&
             (*(char *)(iVar5 + 9) == '\x01')) {
            FUN_80283698(*(undefined4 *)(iVar5 + 0x48),
                         *(uint *)(*(int *)(iVar5 + 0x10) + 0x40000000) >> 0x18);
          }
        }
      }
      else if ((bVar1 < 2) && (bVar1 != 0)) {
        local_88 = *(uint *)(iVar5 + 0x50) | 0x40000000;
        local_84 = FUN_80283d34(*(undefined *)(iVar5 + 0x5d));
        local_7c = 0;
        local_78 = *(undefined4 *)(iVar5 + 0x14);
        local_74 = 0;
        local_70 = *(undefined4 *)(iVar5 + 0x14);
        uVar2 = **(undefined **)(iVar5 + 0x10);
        *(undefined *)(iVar5 + 0x22) = uVar2;
        *(undefined *)(iVar5 + 0x23) = uVar2;
        FUN_802419b8(*(undefined4 *)(iVar5 + 0x10),1);
        if (*(char *)(iVar5 + 9) == '\x01') {
          local_80 = iVar5 + 0x20;
          local_6c = 4;
        }
        else if (*(char *)(iVar5 + 9) == '\0') {
          local_6c = 2;
        }
        FUN_80283290(*(int *)(iVar5 + 0x48),0xffff,&local_88,1,0xffffffff,
                     *(undefined4 *)(DAT_803de268 + *(int *)(iVar5 + 0x48) * 0x404 + 0xf4),1,1);
        uStack60 = *(undefined4 *)(iVar5 + 0x50);
        uStack68 = DAT_803bd150;
        local_40 = 0x43300000;
        local_48 = 0x43300000;
        iVar8 = (int)(dVar13 * (double)((float)((double)CONCAT44(0x43300000,uStack60) - dVar12) /
                                       (float)((double)CONCAT44(0x43300000,DAT_803bd150) - dVar12)))
        ;
        local_50 = (longlong)iVar8;
        FUN_80283710(*(undefined4 *)(iVar5 + 0x48),iVar8);
        uStack84 = (uint)*(byte *)(iVar5 + 0x55);
        uStack92 = (uint)*(byte *)(iVar5 + 0x58);
        uStack100 = (uint)*(byte *)(iVar5 + 0x59);
        local_58 = 0x43300000;
        local_60 = 0x43300000;
        local_68 = 0x43300000;
        FUN_8028383c((double)(float)(dVar14 * (double)(float)((double)CONCAT44(0x43300000,uStack84)
                                                             - dVar12)),
                     (double)(float)(dVar14 * (double)(float)((double)CONCAT44(0x43300000,uStack92)
                                                             - dVar12)),
                     (double)(float)(dVar14 * (double)(float)((double)CONCAT44(0x43300000,uStack100)
                                                             - dVar12)),
                     *(undefined4 *)(iVar5 + 0x48),0,(uint)*(byte *)(iVar5 + 0x56) << 0x10,
                     (uint)*(byte *)(iVar5 + 0x57) << 0x10);
        FUN_802836ac(*(undefined4 *)(iVar5 + 0x48),*(undefined *)(iVar5 + 0x5c));
        *(undefined *)(iVar5 + 8) = 2;
        if ((*(uint *)(iVar5 + 4) & 0x20000) == 0) {
          FUN_80283cac(*(undefined4 *)(iVar5 + 0x10),0,*(undefined4 *)(iVar5 + 0x18),
                       *(undefined *)(iVar5 + 0x5d),0,0);
        }
      }
      iVar5 = iVar5 + 100;
    }
  }
  else {
    DAT_803de280 = DAT_803de280 + -1;
  }
  return;
}

