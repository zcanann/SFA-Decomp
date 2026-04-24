// Function: FUN_8026dfe4
// Entry: 8026dfe4
// Size: 1332 bytes

void FUN_8026dfe4(uint *param_1,uint *param_2,char param_3)

{
  byte bVar1;
  undefined2 uVar2;
  uint uVar3;
  int iVar4;
  undefined4 *puVar5;
  undefined4 *puVar6;
  uint uVar7;
  uint uVar8;
  uint local_38;
  uint local_34;
  uint local_30;
  undefined2 local_2c;
  undefined2 local_2a;
  undefined local_28;
  undefined local_20;
  
  uVar7 = *param_1;
  for (puVar5 = DAT_803deeb4; puVar6 = DAT_803deeb0, puVar5 != (undefined4 *)0x0;
      puVar5 = (undefined4 *)*puVar5) {
    if (puVar5[3] == (uVar7 & 0x7fffffff)) {
      uVar3 = (uint)*(byte *)((int)puVar5 + 9);
      goto LAB_8026e06c;
    }
  }
  for (; puVar6 != (undefined4 *)0x0; puVar6 = (undefined4 *)*puVar6) {
    if (puVar6[3] == (uVar7 & 0x7fffffff)) {
      uVar3 = (uint)*(byte *)((int)puVar6 + 9);
      goto LAB_8026e06c;
    }
  }
  uVar3 = 0xffffffff;
LAB_8026e06c:
  bVar1 = *(byte *)((int)param_1 + 0x26);
  if ((bVar1 & 4) == 0) {
    if (param_3 == '\0') {
      if ((bVar1 & 1) == 0) {
        if ((bVar1 & 0x40) == 0) {
          FUN_80272e84(0,(uint)*(ushort *)(param_1 + 1),uVar7,1);
        }
        else {
          FUN_80272e84(0,(uint)*(ushort *)(param_1 + 1),uVar7,3);
        }
      }
      else {
        FUN_80272e84(0,(uint)*(ushort *)(param_1 + 1),uVar7,2);
      }
    }
    else {
      uVar3 = (uint)*(ushort *)(param_1 + 1);
      if (uVar3 < 5) {
        uVar3 = 5;
      }
      if ((bVar1 & 1) == 0) {
        if ((bVar1 & 0x40) == 0) {
          FUN_8026de48(0,uVar3,uVar7,1);
        }
        else {
          FUN_8026de48(0,uVar3,uVar7,3);
        }
      }
      else {
        FUN_8026de48(0,uVar3,uVar7,2);
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
          uVar7 = FUN_8027c140(*(short *)(param_1 + 5),*(short *)((int)param_1 + 0x16),
                               (int *)param_1[4],&local_38,*(undefined *)((int)param_1 + 0x19));
          *param_2 = uVar7;
          if ((uVar7 != 0xffffffff) && ((*(byte *)((int)param_1 + 0x26) & 0x80) != 0)) {
            FUN_80272e2c(*param_2,0,0);
          }
        }
        else {
          uVar7 = FUN_8027c000(*(short *)(param_1 + 5),*(short *)((int)param_1 + 0x16),
                               (int *)param_1[4],&local_38,'\x01',
                               *(undefined *)((int)param_1 + 0x19));
          *param_2 = uVar7;
          if (((uVar7 != 0xffffffff) && ((*(byte *)((int)param_1 + 0x26) & 0x80) != 0)) &&
             (uVar7 = FUN_8026cb80(*param_2), uVar7 != 0xffffffff)) {
            if ((uVar7 & 0x80000000) == 0) {
              *(undefined4 *)(&DAT_803b16cc + uVar7 * 0x1868) = 0;
              *(undefined4 *)(&DAT_803b16d0 + uVar7 * 0x1868) = 0;
            }
            else {
              iVar4 = (uVar7 & 0x7fffffff) * 0x1868;
              (&DAT_803b248a)[iVar4] = (&DAT_803b248a)[iVar4] | 0x10;
              *(undefined4 *)(&DAT_803b2480 + iVar4) = 0;
              *(undefined4 *)(&DAT_803b2484 + iVar4) = 0;
            }
          }
        }
      }
      else {
        uVar7 = param_1[2];
        for (puVar5 = DAT_803deeb4; puVar6 = DAT_803deeb0, puVar5 != (undefined4 *)0x0;
            puVar5 = (undefined4 *)*puVar5) {
          if (puVar5[3] == (uVar7 & 0x7fffffff)) {
            uVar3 = uVar7 & 0x80000000 | (uint)*(byte *)((int)puVar5 + 9);
            goto LAB_8026e22c;
          }
        }
        for (; puVar6 != (undefined4 *)0x0; puVar6 = (undefined4 *)*puVar6) {
          if (puVar6[3] == (uVar7 & 0x7fffffff)) {
            uVar3 = uVar7 & 0x80000000 | (uint)*(byte *)((int)puVar6 + 9);
            goto LAB_8026e22c;
          }
        }
        uVar3 = 0xffffffff;
LAB_8026e22c:
        if (uVar3 == 0xffffffff) {
          *param_2 = 0xffffffff;
        }
        else {
          if (param_3 == '\0') {
            FUN_80272df4(uVar7);
            FUN_80272e84((uint)*(byte *)(param_1 + 6),(uint)*(ushort *)(param_1 + 3),param_1[2],0);
            if ((*(byte *)((int)param_1 + 0x26) & 0x10) != 0) {
              FUN_80272e2c(param_1[2],param_1[7],param_1[8]);
            }
            if ((*(byte *)((int)param_1 + 0x26) & 0x20) != 0) {
              FUN_80272dac(param_1[2],*(undefined2 *)(param_1 + 9));
            }
          }
          else {
            FUN_8026dc88(uVar7);
            FUN_8026de48((uint)*(byte *)(param_1 + 6),(uint)*(ushort *)(param_1 + 3),param_1[2],0);
            if ((*(byte *)((int)param_1 + 0x26) & 0x10) != 0) {
              uVar3 = param_1[8];
              uVar8 = param_1[7];
              uVar7 = FUN_8026cb80(param_1[2]);
              if (uVar7 != 0xffffffff) {
                if ((uVar7 & 0x80000000) == 0) {
                  *(uint *)(&DAT_803b16cc + uVar7 * 0x1868) = uVar8;
                  *(uint *)(&DAT_803b16d0 + uVar7 * 0x1868) = uVar3;
                }
                else {
                  iVar4 = (uVar7 & 0x7fffffff) * 0x1868;
                  (&DAT_803b248a)[iVar4] = (&DAT_803b248a)[iVar4] | 0x10;
                  *(uint *)(&DAT_803b2480 + iVar4) = uVar8;
                  *(uint *)(&DAT_803b2484 + iVar4) = uVar3;
                }
              }
            }
            if ((*(byte *)((int)param_1 + 0x26) & 0x20) != 0) {
              uVar2 = *(undefined2 *)(param_1 + 9);
              uVar7 = FUN_8026cb80(param_1[2]);
              if ((uVar7 & 0x80000000) == 0) {
                iVar4 = uVar7 * 0x1868;
                *(undefined2 *)(&DAT_803b2aca + iVar4) = uVar2;
                *(undefined2 *)(&DAT_803b2b02 + iVar4) = uVar2;
                *(undefined2 *)(&DAT_803b2b3a + iVar4) = uVar2;
                *(undefined2 *)(&DAT_803b2b72 + iVar4) = uVar2;
                *(undefined2 *)(&DAT_803b2baa + iVar4) = uVar2;
                *(undefined2 *)(&DAT_803b2be2 + iVar4) = uVar2;
                *(undefined2 *)(&DAT_803b2c1a + iVar4) = uVar2;
                *(undefined2 *)(&DAT_803b2c52 + iVar4) = uVar2;
                *(undefined2 *)(&DAT_803b2c8a + iVar4) = uVar2;
                *(undefined2 *)(&DAT_803b2cc2 + iVar4) = uVar2;
                *(undefined2 *)(&DAT_803b2cfa + iVar4) = uVar2;
                *(undefined2 *)(&DAT_803b2d32 + iVar4) = uVar2;
                *(undefined2 *)(&DAT_803b2d6a + iVar4) = uVar2;
                *(undefined2 *)(&DAT_803b2da2 + iVar4) = uVar2;
                *(undefined2 *)(&DAT_803b2dda + iVar4) = uVar2;
                *(undefined2 *)(&DAT_803b2e12 + iVar4) = uVar2;
              }
              else {
                iVar4 = (uVar7 & 0x7fffffff) * 0x1868;
                (&DAT_803b248a)[iVar4] = (&DAT_803b248a)[iVar4] | 0x20;
                *(undefined2 *)(&DAT_803b2488 + iVar4) = uVar2;
              }
            }
          }
          *param_2 = param_1[2];
        }
      }
    }
  }
  else {
    iVar4 = uVar3 * 0x1868;
    uVar7 = param_1[1];
    *(uint *)(iVar4 + -0x7fc4db9c) = *param_1;
    *(uint *)(iVar4 + -0x7fc4db98) = uVar7;
    uVar7 = param_1[3];
    *(uint *)(iVar4 + -0x7fc4db94) = param_1[2];
    *(uint *)(iVar4 + -0x7fc4db90) = uVar7;
    uVar7 = param_1[5];
    *(uint *)(iVar4 + -0x7fc4db8c) = param_1[4];
    *(uint *)(iVar4 + -0x7fc4db88) = uVar7;
    uVar7 = param_1[7];
    *(uint *)(iVar4 + -0x7fc4db84) = param_1[6];
    *(uint *)(&DAT_803b2480 + iVar4) = uVar7;
    uVar7 = param_1[9];
    *(uint *)(&DAT_803b2484 + iVar4) = param_1[8];
    *(uint *)(&DAT_803b2488 + iVar4) = uVar7;
    *(undefined *)(iVar4 + -0x7fc4db70) = 1;
    *(uint **)(iVar4 + -0x7fc4db74) = param_2;
    (&DAT_803b248a)[iVar4] = (&DAT_803b248a)[iVar4] & 0xfb;
    *param_2 = *param_1 | 0x80000000;
  }
  return;
}

