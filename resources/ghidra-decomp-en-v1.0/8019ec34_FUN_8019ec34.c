// Function: FUN_8019ec34
// Entry: 8019ec34
// Size: 1908 bytes

void FUN_8019ec34(void)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  char cVar7;
  int iVar5;
  undefined4 uVar6;
  int iVar8;
  int iVar9;
  bool bVar10;
  double dVar11;
  float local_48;
  undefined4 local_44;
  undefined2 local_40;
  undefined2 local_3e;
  undefined2 local_3c;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  double local_28;
  
  iVar2 = FUN_802860d4();
  iVar8 = *(int *)(iVar2 + 0x4c);
  iVar9 = *(int *)(iVar2 + 0xb8);
  iVar3 = FUN_8002b9ec();
  FUN_8002b9ac();
  iVar4 = FUN_8001ffb4((int)*(short *)(iVar8 + 0x22));
  if (iVar4 != 0) {
    *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
    *(byte *)(iVar9 + 0x22c) = *(byte *)(iVar9 + 0x22c) & 0xfe;
    FUN_8002ce88(iVar2);
    FUN_80036fa4(iVar2,0x20);
    FUN_80036fa4(iVar2,3);
  }
  if ((*(int *)(iVar9 + 0x230) == 2) && (iVar4 = FUN_8001ffb4(0x66), iVar4 != 0)) {
    (**(code **)(*DAT_803dca54 + 0x48))(6,iVar2,0xffffffff);
    (**(code **)(*DAT_803dca68 + 0x60))();
  }
  else {
    iVar4 = FUN_80080150(iVar9);
    if (iVar4 == 0) {
      *(byte *)(iVar2 + 0xaf) = *(byte *)(iVar2 + 0xaf) | 8;
      if (*(int *)(iVar9 + 0x230) == 0) {
        local_44 = 0x19;
        cVar7 = (**(code **)(*DAT_803dca9c + 0x8c))
                          ((double)FLOAT_803e424c,iVar9 + 0x124,iVar2,&local_44,0);
        if (cVar7 == '\0') {
          *(undefined4 *)(iVar9 + 0x230) = 1;
          FUN_8008016c(iVar9 + 0x238);
        }
      }
      else {
        iVar4 = FUN_80080100(500);
        if (iVar4 != 0) {
          iVar4 = FUN_800221a0(0,3);
          FUN_80039270(iVar2,iVar9 + 0x6c,*(undefined2 *)(*(int *)(iVar9 + 0x240) + iVar4 * 2));
        }
        FUN_80038f38(iVar2,iVar9 + 0x6c);
        if ((*(int *)(iVar9 + 0x230) == 1) || (*(int *)(iVar9 + 0x230) == 2)) {
          dVar11 = (double)*(float *)(iVar9 + 0x23c);
          FUN_80222358(dVar11,(double)(float)((double)FLOAT_803e4238 * dVar11),
                       (double)(float)((double)FLOAT_803e4250 * dVar11),iVar2,iVar9 + 0x124,1);
          FUN_80222550((double)FLOAT_803e4238,(double)FLOAT_803e4254,iVar2,iVar2 + 0x24,0x1e);
          FUN_8002b95c((double)*(float *)(iVar2 + 0x24),(double)*(float *)(iVar2 + 0x28),
                       (double)*(float *)(iVar2 + 0x2c),iVar2);
          if (*(int *)(iVar9 + 0x230) == 1) {
            if ((*(int *)(iVar9 + 0x234) != -1) &&
               (iVar3 = FUN_8001ffb4(*(int *)(iVar9 + 0x234) + 0xb2a), iVar3 != 0)) {
              *(undefined4 *)(iVar9 + 0x230) = 2;
              FUN_800200e8(0x66,0);
              (**(code **)(*DAT_803dca68 + 0x58))
                        (*(undefined4 *)(&DAT_80322b28 + *(int *)(iVar9 + 0x234) * 4),0x5d1);
              FUN_80080178(iVar9 + 0x238,
                           (int)(short)*(undefined4 *)(&DAT_80322b28 + *(int *)(iVar9 + 0x234) * 4))
              ;
            }
            FUN_8019e3f4(iVar2);
            goto LAB_8019f390;
          }
          if (*(int *)(iVar9 + 0x230) == 2) {
            iVar4 = FUN_80036e58(3,iVar2,0);
            if ((iVar4 == 0) ||
               (dVar11 = (double)FUN_80021704(iVar4 + 0x18,iVar9 + 0x18),
               (double)FLOAT_803dbe38 <= dVar11)) {
              if (iVar4 != 0) {
                uVar6 = FUN_8002b9ec();
                FUN_8014c66c(iVar4,uVar6);
              }
            }
            else {
              FUN_8019e568(iVar2,iVar4,iVar9,0);
              iVar5 = FUN_8002b9ec();
              dVar11 = (double)FUN_80021704(iVar5 + 0x18,iVar4 + 0x18);
              if (dVar11 <= (double)FLOAT_803dbe3c) {
                uVar6 = FUN_8002b9ec();
                FUN_8014c66c(iVar4,uVar6);
              }
              else {
                FUN_8014c66c(iVar4,iVar2);
                if (*(short *)(iVar2 + 0xa0) != 0xd) {
                  FUN_80030334((double)*(float *)(iVar2 + 0x98),iVar2,0xd,0);
                }
                FUN_8002fa48((double)FLOAT_803e422c,(double)FLOAT_803db414,iVar2,0);
              }
            }
            FUN_8019e3f4(iVar2);
          }
        }
        dVar11 = (double)FUN_80021704(iVar2 + 0x18,iVar3 + 0x18);
        local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar8 + 0x1a) / 2 ^ 0x80000000);
        bVar10 = dVar11 < (double)(float)(local_28 - DOUBLE_803e4220);
        if (*(int *)(iVar9 + 0x230) == 2) {
          local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar8 + 0x18) ^ 0x80000000);
          local_48 = (float)(local_28 - DOUBLE_803e4220);
          iVar3 = FUN_80080150(iVar9 + 0x238);
          if (iVar3 != 0) {
            iVar3 = FUN_8002b9ec();
            if (((*(ushort *)(iVar3 + 0xb0) & 0x1000) == 0) &&
               (iVar3 = FUN_800801a8(iVar9 + 0x238), iVar3 != 0)) {
              (**(code **)(*DAT_803dca54 + 0x48))(6,iVar2,0xffffffff);
              (**(code **)(*DAT_803dca68 + 0x60))();
              goto LAB_8019f390;
            }
            local_28 = (double)(longlong)(int)*(float *)(iVar9 + 0x238);
            (**(code **)(*DAT_803dca68 + 0x5c))((int)*(float *)(iVar9 + 0x238));
          }
          if ((!bVar10) && (iVar3 = FUN_80036e58(3,iVar2,&local_48), iVar3 != 0)) {
            bVar10 = true;
          }
          iVar3 = FUN_8001ffb4(*(int *)(iVar9 + 0x234) + 0xb2e);
          if (iVar3 != 0) {
            *(undefined4 *)(iVar9 + 0x230) = 3;
            (**(code **)(*DAT_803dca68 + 0x60))();
            FUN_8000bb18(iVar2,0x109);
            FUN_8008016c(iVar9 + 0x238);
          }
        }
        else {
          *(byte *)(iVar2 + 0xaf) = *(byte *)(iVar2 + 0xaf) & 0xf7;
          iVar4 = *(int *)(iVar2 + 0xb8);
          iVar3 = FUN_8002b9ec();
          iVar5 = *(int *)(iVar2 + 0x4c);
          bVar1 = false;
          dVar11 = (double)FUN_80021704(iVar3 + 0x18,iVar2 + 0x18);
          local_28 = (double)CONCAT44(0x43300000,(int)*(short *)(iVar5 + 0x1a) ^ 0x80000000);
          if (((dVar11 < (double)(float)(local_28 - DOUBLE_803e4220)) &&
              (*(int *)(iVar4 + 0x230) == 3)) && ((*(ushort *)(iVar2 + 0xb0) & 0x1000) == 0)) {
            bVar1 = true;
          }
          if (bVar1) {
            *(byte *)(iVar2 + 0xaf) = *(byte *)(iVar2 + 0xaf) & 0xef;
          }
          else {
            *(byte *)(iVar2 + 0xaf) = *(byte *)(iVar2 + 0xaf) | 0x10;
          }
        }
        if (*(int *)(iVar9 + 0x230) == 3) {
          if (*(char *)(iVar9 + 0x244) < '\0') {
            if (bVar10) {
              (**(code **)(*DAT_803dca54 + 0x48))(1,iVar2,0xffffffff);
              *(undefined4 *)(iVar9 + 0xb0) = 1;
            }
            uVar6 = FUN_8002b9ec();
            FUN_8019e568(iVar2,uVar6,iVar9,1);
            iVar3 = FUN_8002fa48((double)*(float *)(iVar9 + 0xa8),(double)FLOAT_803db414,iVar2,0);
            if (iVar3 != 0) {
              iVar3 = FUN_80080100(2);
              if (iVar3 == 0) {
                FUN_80030334((double)FLOAT_803e4218,iVar2,0,0);
              }
              else {
                FUN_80030334((double)FLOAT_803e4218,iVar2,2,0);
              }
            }
          }
          else {
            local_34 = *(undefined4 *)(iVar8 + 8);
            local_30 = *(undefined4 *)(iVar8 + 0xc);
            local_2c = *(undefined4 *)(iVar8 + 0x10);
            local_40 = *(undefined2 *)(iVar9 + 0xd0);
            local_3e = 0;
            local_3c = 0;
            *(undefined2 *)(iVar2 + 2) = 0;
            *(undefined2 *)(iVar2 + 4) = 0;
            iVar3 = FUN_801147bc((double)FLOAT_803dbe40,iVar2,&local_40,0xffffffff,&FLOAT_803dbe44,
                                 &DAT_803dbe48);
            if (iVar3 != 0) {
              *(byte *)(iVar9 + 0x244) = *(byte *)(iVar9 + 0x244) & 0x7f | 0x80;
              FUN_800200e8(0x66,0);
            }
            FUN_8002fa48((double)FLOAT_803dbe44,(double)FLOAT_803db414,iVar2,0);
          }
        }
      }
    }
    else {
      *(byte *)(iVar9 + 0x22c) = *(byte *)(iVar9 + 0x22c) | 1;
      *(undefined4 *)(iVar9 + 0xc4) = 0;
      if (*(int *)(iVar2 + 0xf4) < 0) {
        if (*(short *)(iVar8 + 0x22) != -1) {
          FUN_800200e8((int)*(short *)(iVar8 + 0x22),1);
        }
        FUN_80035f00(iVar2);
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
        *(byte *)(iVar9 + 0x22c) = *(byte *)(iVar9 + 0x22c) & 0xfe;
        FUN_8002ce88(iVar2);
        FUN_80036fa4(iVar2,0x20);
        FUN_80036fa4(iVar2,3);
        *(ushort *)(iVar2 + 6) = *(ushort *)(iVar2 + 6) | 0x4000;
      }
      else {
        *(int *)(iVar2 + 0xf4) = *(int *)(iVar2 + 0xf4) + -1;
      }
    }
  }
LAB_8019f390:
  FUN_80286120();
  return;
}

