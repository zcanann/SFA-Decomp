// Function: FUN_80166f2c
// Entry: 80166f2c
// Size: 1228 bytes

void FUN_80166f2c(void)

{
  char cVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  short sVar5;
  int *piVar6;
  int iVar7;
  int iVar8;
  double dVar9;
  float local_90;
  float local_8c;
  float local_88;
  float local_84;
  undefined auStack128 [80];
  char local_30;
  undefined4 local_28;
  uint uStack36;
  
  iVar2 = FUN_802860dc();
  iVar8 = *(int *)(iVar2 + 0x4c);
  iVar7 = *(int *)(iVar2 + 0xb8);
  piVar6 = *(int **)(iVar7 + 0x40c);
  iVar3 = FUN_8002b9ec();
  local_90 = FLOAT_803e3034;
  if ((*piVar6 == 0) && (*(undefined *)(piVar6 + 0x24) = 6, *(byte *)((int)piVar6 + 0x92) >> 4 != 0)
     ) {
    iVar4 = FUN_800380e0(iVar2,0x4ad,&local_90);
    *piVar6 = iVar4;
    if (iVar4 != 0) {
      (**(code **)(**(int **)(*piVar6 + 0x68) + 0x20))(*piVar6,piVar6 + 0x12,(int)piVar6 + 0x91);
      *(undefined *)(piVar6 + 0x24) = 5;
    }
    *(byte *)((int)piVar6 + 0x92) =
         ((*(byte *)((int)piVar6 + 0x92) >> 4) - 1) * '\x10' | *(byte *)((int)piVar6 + 0x92) & 0xf;
  }
  if (*(int *)(iVar2 + 0xf4) == 0) {
    if (*(int *)(iVar2 + 0xf8) == 0) {
      *(undefined4 *)(iVar2 + 0xc) = *(undefined4 *)(iVar8 + 8);
      *(undefined4 *)(iVar2 + 0x10) = *(undefined4 *)(iVar8 + 0xc);
      *(undefined4 *)(iVar2 + 0x14) = *(undefined4 *)(iVar8 + 0x10);
      (**(code **)(*DAT_803dca54 + 0x48))((int)*(char *)(iVar8 + 0x2e),iVar2,0xffffffff);
      *(undefined4 *)(iVar2 + 0xf8) = 1;
    }
    else {
      iVar8 = (**(code **)(*DAT_803dcab8 + 0x30))(iVar2,iVar7,0);
      if (iVar8 != 0) {
        if (((*(byte *)((int)piVar6 + 0x92) >> 1 & 1) == 0) &&
           (iVar8 = FUN_80037ef0(iVar2,iVar3,FUN_80167550), iVar8 != 0)) {
          *(byte *)((int)piVar6 + 0x92) = *(byte *)((int)piVar6 + 0x92) & 0xfd | 2;
        }
        FUN_8002fa48((double)(float)piVar6[0x11],(double)FLOAT_803db414,iVar2,0);
        if (*(short *)(iVar7 + 0x402) != 1) {
          uStack36 = (uint)*(ushort *)(iVar7 + 0x3fe);
          local_28 = 0x43300000;
          iVar8 = (**(code **)(*DAT_803dcab8 + 0x48))
                            ((double)(float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e3040
                                            ),iVar2,iVar7,0x8000);
          if (iVar8 != 0) {
            (**(code **)(*DAT_803dcab8 + 0x28))
                      (iVar2,iVar7,iVar7 + 0x35c,(int)*(short *)(iVar7 + 0x3f4),0,0,1,0,0xffffffff);
            *(int *)(iVar7 + 0x2d0) = iVar8;
            *(undefined *)(iVar7 + 0x349) = 0;
            *(undefined2 *)(iVar7 + 0x402) = 1;
            *(undefined *)(iVar7 + 0x405) = 2;
          }
          if ((*(int *)(iVar7 + 0x2d0) != 0) && (*(short *)(iVar7 + 0x402) == 2)) {
            uStack36 = (uint)*(ushort *)(iVar7 + 0x3fe);
            local_28 = 0x43300000;
            if (*(float *)(iVar7 + 0x2c0) <=
                (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e3040)) {
              *(undefined2 *)(iVar7 + 0x402) = 1;
            }
          }
        }
        iVar8 = *(int *)(iVar7 + 0x2d0);
        if (iVar8 != 0) {
          local_8c = *(float *)(iVar8 + 0x18) - *(float *)(iVar2 + 0x18);
          local_88 = *(float *)(iVar8 + 0x1c) - *(float *)(iVar2 + 0x1c);
          local_84 = *(float *)(iVar8 + 0x20) - *(float *)(iVar2 + 0x20);
          dVar9 = (double)FUN_802931a0((double)(local_84 * local_84 +
                                               local_8c * local_8c + local_88 * local_88));
          *(float *)(iVar7 + 0x2c0) = (float)dVar9;
        }
        (**(code **)(*DAT_803dcab8 + 0x54))
                  (iVar2,iVar7,iVar7 + 0x35c,(int)*(short *)(iVar7 + 0x3f4),0,0,0,0);
        cVar1 = *(char *)(iVar7 + 0x354);
        if (('\0' < cVar1) &&
           ((**(code **)(*DAT_803dcab8 + 0x50))
                      (iVar2,iVar7,iVar7 + 0x35c,(int)*(short *)(iVar7 + 0x3f4),&DAT_803202e8,
                       &DAT_80320360,0,&DAT_803ac638), *(char *)(iVar7 + 0x354) < cVar1)) {
          (**(code **)(**(int **)(*(int *)(iVar3 + 200) + 0x68) + 0x50))();
          DAT_803ac644 = *(undefined4 *)(iVar2 + 0xc);
          DAT_803ac648 = *(undefined4 *)(iVar2 + 0x10);
          DAT_803ac64c = *(undefined4 *)(iVar2 + 0x14);
          FUN_8009a1dc((double)FLOAT_803e3038,iVar2,&DAT_803ac638,1,0);
        }
        (**(code **)(*DAT_803dcab8 + 0x2c))((double)FLOAT_803e2fdc,iVar2,iVar7,0xffffffff);
        *(undefined4 *)(iVar7 + 0x3e0) = *(undefined4 *)(iVar2 + 0xc0);
        *(undefined4 *)(iVar2 + 0xc0) = 0;
        (**(code **)(*DAT_803dca8c + 8))
                  ((double)FLOAT_803db414,(double)FLOAT_803db414,iVar2,iVar7,&DAT_803ac650,
                   &DAT_803dda88);
        *(undefined4 *)(iVar2 + 0xc0) = *(undefined4 *)(iVar7 + 0x3e0);
        if (((*(byte *)((int)piVar6 + 0x92) & 1) == 0) && (*(char *)(piVar6 + 0x24) == '\x06')) {
          iVar2 = FUN_800640cc((double)FLOAT_803e3030,iVar2 + 0x80,iVar2 + 0xc,0,auStack128,iVar2,
                               0xffffff84,0xffffffff,0xff,0);
          if ((iVar2 != 0) && (local_30 == '\r')) {
            *(byte *)((int)piVar6 + 0x92) = *(byte *)((int)piVar6 + 0x92) & 0xfe | 1;
            sVar5 = FUN_800221a0(10,0xf);
            *(short *)((int)piVar6 + 0x8e) = sVar5 * 0x3c;
          }
        }
      }
    }
  }
  FUN_80286128();
  return;
}

