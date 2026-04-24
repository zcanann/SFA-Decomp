// Function: FUN_8026d880
// Entry: 8026d880
// Size: 1332 bytes

void FUN_8026d880(uint *param_1,uint *param_2,char param_3)

{
  byte bVar1;
  undefined2 uVar2;
  uint uVar3;
  ushort uVar4;
  int iVar5;
  undefined4 *puVar6;
  undefined4 *puVar7;
  uint uVar8;
  uint uVar9;
  uint local_38;
  uint local_34;
  uint local_30;
  undefined2 local_2c;
  undefined2 local_2a;
  undefined local_28;
  undefined local_20;
  
  uVar8 = *param_1;
  for (puVar6 = DAT_803de234; puVar7 = DAT_803de230, puVar6 != (undefined4 *)0x0;
      puVar6 = (undefined4 *)*puVar6) {
    if (puVar6[3] == (uVar8 & 0x7fffffff)) {
      uVar3 = (uint)*(byte *)((int)puVar6 + 9);
      goto LAB_8026d908;
    }
  }
  for (; puVar7 != (undefined4 *)0x0; puVar7 = (undefined4 *)*puVar7) {
    if (puVar7[3] == (uVar8 & 0x7fffffff)) {
      uVar3 = (uint)*(byte *)((int)puVar7 + 9);
      goto LAB_8026d908;
    }
  }
  uVar3 = 0xffffffff;
LAB_8026d908:
  bVar1 = *(byte *)((int)param_1 + 0x26);
  if ((bVar1 & 4) == 0) {
    if (param_3 == '\0') {
      if ((bVar1 & 1) == 0) {
        if ((bVar1 & 0x40) == 0) {
          FUN_80272720(0,*(undefined2 *)(param_1 + 1),uVar8,1);
        }
        else {
          FUN_80272720(0,*(undefined2 *)(param_1 + 1),uVar8,3);
        }
      }
      else {
        FUN_80272720(0,*(undefined2 *)(param_1 + 1),uVar8,2);
      }
    }
    else {
      uVar4 = *(ushort *)(param_1 + 1);
      if (uVar4 < 5) {
        uVar4 = 5;
      }
      if ((bVar1 & 1) == 0) {
        if ((bVar1 & 0x40) == 0) {
          FUN_8026d6e4(0,uVar4,uVar8,1);
        }
        else {
          FUN_8026d6e4(0,uVar4,uVar8,3);
        }
      }
      else {
        FUN_8026d6e4(0,uVar4,uVar8,2);
      }
    }
    if (param_2 != (uint *)0x0) {
      if ((*(byte *)((int)param_1 + 0x26) & 2) == 0) {
        local_38 = 4;
        if ((*(byte *)((int)param_1 + 0x26) & 8) != 0) {
          local_38 = 0x14;
        }
        if ((*(byte *)((int)param_1 + 0x26) & 0x20) != 0) {
          local_38 = local_38 | 2;
          local_2c = *(undefined2 *)(param_1 + 9);
        }
        if ((*(byte *)((int)param_1 + 0x26) & 0x10) != 0) {
          local_38 = local_38 | 1;
          local_34 = param_1[7];
          local_30 = param_1[8];
        }
        local_2a = *(undefined2 *)(param_1 + 3);
        local_28 = *(undefined *)(param_1 + 6);
        local_20 = 0;
        if (param_3 == '\0') {
          uVar8 = FUN_8027b9dc(*(undefined2 *)(param_1 + 5),*(undefined2 *)((int)param_1 + 0x16),
                               param_1[4],&local_38,*(undefined *)((int)param_1 + 0x19));
          *param_2 = uVar8;
          if ((uVar8 != 0xffffffff) && ((*(byte *)((int)param_1 + 0x26) & 0x80) != 0)) {
            FUN_802726c8(*param_2,0,0);
          }
        }
        else {
          uVar8 = FUN_8027b89c(*(undefined2 *)(param_1 + 5),*(undefined2 *)((int)param_1 + 0x16),
                               param_1[4],&local_38,1,*(undefined *)((int)param_1 + 0x19));
          *param_2 = uVar8;
          if (((uVar8 != 0xffffffff) && ((*(byte *)((int)param_1 + 0x26) & 0x80) != 0)) &&
             (uVar8 = FUN_8026c41c(*param_2), uVar8 != 0xffffffff)) {
            if ((uVar8 & 0x80000000) == 0) {
              *(undefined4 *)(&DAT_803b0a6c + uVar8 * 0x1868) = 0;
              *(undefined4 *)(&DAT_803b0a70 + uVar8 * 0x1868) = 0;
            }
            else {
              iVar5 = (uVar8 & 0x7fffffff) * 0x1868;
              (&DAT_803b182a)[iVar5] = (&DAT_803b182a)[iVar5] | 0x10;
              *(undefined4 *)(&DAT_803b1820 + iVar5) = 0;
              *(undefined4 *)(&DAT_803b1824 + iVar5) = 0;
            }
          }
        }
      }
      else {
        uVar8 = param_1[2];
        for (puVar6 = DAT_803de234; puVar7 = DAT_803de230, puVar6 != (undefined4 *)0x0;
            puVar6 = (undefined4 *)*puVar6) {
          if (puVar6[3] == (uVar8 & 0x7fffffff)) {
            uVar8 = uVar8 & 0x80000000 | (uint)*(byte *)((int)puVar6 + 9);
            goto LAB_8026dac8;
          }
        }
        for (; puVar7 != (undefined4 *)0x0; puVar7 = (undefined4 *)*puVar7) {
          if (puVar7[3] == (uVar8 & 0x7fffffff)) {
            uVar8 = uVar8 & 0x80000000 | (uint)*(byte *)((int)puVar7 + 9);
            goto LAB_8026dac8;
          }
        }
        uVar8 = 0xffffffff;
LAB_8026dac8:
        if (uVar8 == 0xffffffff) {
          *param_2 = 0xffffffff;
        }
        else {
          if (param_3 == '\0') {
            FUN_80272690();
            FUN_80272720(*(undefined *)(param_1 + 6),*(undefined2 *)(param_1 + 3),param_1[2],0);
            if ((*(byte *)((int)param_1 + 0x26) & 0x10) != 0) {
              FUN_802726c8(param_1[2],param_1[7],param_1[8]);
            }
            if ((*(byte *)((int)param_1 + 0x26) & 0x20) != 0) {
              FUN_80272648(param_1[2],*(undefined2 *)(param_1 + 9));
            }
          }
          else {
            FUN_8026d524();
            FUN_8026d6e4(*(undefined *)(param_1 + 6),*(undefined2 *)(param_1 + 3),param_1[2],0);
            if ((*(byte *)((int)param_1 + 0x26) & 0x10) != 0) {
              uVar3 = param_1[8];
              uVar9 = param_1[7];
              uVar8 = FUN_8026c41c(param_1[2]);
              if (uVar8 != 0xffffffff) {
                if ((uVar8 & 0x80000000) == 0) {
                  *(uint *)(&DAT_803b0a6c + uVar8 * 0x1868) = uVar9;
                  *(uint *)(&DAT_803b0a70 + uVar8 * 0x1868) = uVar3;
                }
                else {
                  iVar5 = (uVar8 & 0x7fffffff) * 0x1868;
                  (&DAT_803b182a)[iVar5] = (&DAT_803b182a)[iVar5] | 0x10;
                  *(uint *)(&DAT_803b1820 + iVar5) = uVar9;
                  *(uint *)(&DAT_803b1824 + iVar5) = uVar3;
                }
              }
            }
            if ((*(byte *)((int)param_1 + 0x26) & 0x20) != 0) {
              uVar2 = *(undefined2 *)(param_1 + 9);
              uVar8 = FUN_8026c41c(param_1[2]);
              if ((uVar8 & 0x80000000) == 0) {
                iVar5 = uVar8 * 0x1868;
                *(undefined2 *)(&DAT_803b1e6a + iVar5) = uVar2;
                *(undefined2 *)(&DAT_803b1ea2 + iVar5) = uVar2;
                *(undefined2 *)(&DAT_803b1eda + iVar5) = uVar2;
                *(undefined2 *)(&DAT_803b1f12 + iVar5) = uVar2;
                *(undefined2 *)(&DAT_803b1f4a + iVar5) = uVar2;
                *(undefined2 *)(&DAT_803b1f82 + iVar5) = uVar2;
                *(undefined2 *)(&DAT_803b1fba + iVar5) = uVar2;
                *(undefined2 *)(&DAT_803b1ff2 + iVar5) = uVar2;
                *(undefined2 *)(&DAT_803b202a + iVar5) = uVar2;
                *(undefined2 *)(&DAT_803b2062 + iVar5) = uVar2;
                *(undefined2 *)(&DAT_803b209a + iVar5) = uVar2;
                *(undefined2 *)(&DAT_803b20d2 + iVar5) = uVar2;
                *(undefined2 *)(&DAT_803b210a + iVar5) = uVar2;
                *(undefined2 *)(&DAT_803b2142 + iVar5) = uVar2;
                *(undefined2 *)(&DAT_803b217a + iVar5) = uVar2;
                *(undefined2 *)(&DAT_803b21b2 + iVar5) = uVar2;
              }
              else {
                iVar5 = (uVar8 & 0x7fffffff) * 0x1868;
                (&DAT_803b182a)[iVar5] = (&DAT_803b182a)[iVar5] | 0x20;
                *(undefined2 *)(&DAT_803b1828 + iVar5) = uVar2;
              }
            }
          }
          *param_2 = param_1[2];
        }
      }
    }
  }
  else {
    iVar5 = uVar3 * 0x1868;
    uVar8 = param_1[1];
    *(uint *)(iVar5 + -0x7fc4e7fc) = *param_1;
    *(uint *)(iVar5 + -0x7fc4e7f8) = uVar8;
    uVar8 = param_1[3];
    *(uint *)(iVar5 + -0x7fc4e7f4) = param_1[2];
    *(uint *)(iVar5 + -0x7fc4e7f0) = uVar8;
    uVar8 = param_1[5];
    *(uint *)(iVar5 + -0x7fc4e7ec) = param_1[4];
    *(uint *)(iVar5 + -0x7fc4e7e8) = uVar8;
    uVar8 = param_1[7];
    *(uint *)(iVar5 + -0x7fc4e7e4) = param_1[6];
    *(uint *)(&DAT_803b1820 + iVar5) = uVar8;
    uVar8 = param_1[9];
    *(uint *)(&DAT_803b1824 + iVar5) = param_1[8];
    *(uint *)(&DAT_803b1828 + iVar5) = uVar8;
    *(undefined *)(iVar5 + -0x7fc4e7d0) = 1;
    *(uint **)(iVar5 + -0x7fc4e7d4) = param_2;
    (&DAT_803b182a)[iVar5] = (&DAT_803b182a)[iVar5] & 0xfb;
    *param_2 = *param_1 | 0x80000000;
  }
  return;
}

