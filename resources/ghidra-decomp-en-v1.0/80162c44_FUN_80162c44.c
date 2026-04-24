// Function: FUN_80162c44
// Entry: 80162c44
// Size: 672 bytes

void FUN_80162c44(int param_1)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0xb8);
  iVar3 = *(int *)(iVar4 + 0x40c);
  iVar2 = *(int *)(param_1 + 0x4c);
  if (*(int *)(param_1 + 0xf4) == 0) {
    if (*(int *)(iVar3 + 0x34) == 0) {
      FUN_801627f4();
    }
    else {
      (**(code **)(*DAT_803dca8c + 8))
                ((double)FLOAT_803e2ebc,(double)FLOAT_803e2ebc,param_1,iVar4,&DAT_803ac610,
                 &DAT_803ac5f8);
      (**(code **)(**(int **)(*(int *)(iVar3 + 0x38) + 0x68) + 0x24))
                ((double)*(float *)(iVar3 + 0x48),*(int *)(iVar3 + 0x38),param_1 + 0xc,
                 param_1 + 0x10,param_1 + 0x14);
      (**(code **)(*DAT_803dcab8 + 0x54))
                (param_1,iVar4,iVar4 + 0x35c,(int)*(short *)(iVar4 + 0x3f4),iVar4 + 0x405,0,0,0);
      iVar2 = (**(code **)(*DAT_803dcab8 + 0x50))
                        (param_1,iVar4,iVar4 + 0x35c,(int)*(short *)(iVar4 + 0x3f4),&DAT_803200e0,
                         &DAT_80320158,3,0);
      if (iVar2 == 0xe) {
        *(undefined *)(iVar4 + 0x405) = 2;
        uVar1 = FUN_8002b9ec();
        *(undefined4 *)(iVar4 + 0x2d0) = uVar1;
      }
      if ((*(int *)(iVar4 + 0x2d0) == 0) && (*(char *)(iVar4 + 0x354) != '\0')) {
        *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
             *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) & 0xfffe;
        iVar2 = (**(code **)(*DAT_803dcab8 + 0x48))
                          ((double)(float)((double)CONCAT44(0x43300000,
                                                            (uint)*(ushort *)(iVar4 + 0x3fe)) -
                                          DOUBLE_803e2f10),param_1,iVar4,0x8000);
        if (iVar2 != 0) {
          *(int *)(iVar4 + 0x2d0) = iVar2;
          *(undefined *)(iVar4 + 0x349) = 0;
        }
      }
      else {
        *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) =
             *(ushort *)(*(int *)(param_1 + 0x54) + 0x60) | 1;
        iVar2 = (**(code **)(*DAT_803dcab8 + 0x44))
                          ((double)(float)((double)CONCAT44(0x43300000,
                                                            (uint)*(ushort *)(iVar4 + 0x3fe)) -
                                          DOUBLE_803e2f10),param_1,iVar4,1);
        if (iVar2 != 0) {
          *(undefined4 *)(iVar4 + 0x2d0) = 0;
        }
      }
    }
  }
  else {
    iVar3 = (**(code **)(*DAT_803dcaac + 0x68))(*(undefined4 *)(iVar2 + 0x14));
    if (iVar3 != 0) {
      (**(code **)(*DAT_803dcab8 + 0x58))
                ((double)FLOAT_803e2f28,param_1,iVar2,iVar4,10,6,0x10e,0x36);
      *(undefined2 *)(iVar4 + 0x270) = 1;
      *(undefined *)(iVar4 + 0x27b) = 1;
      *(undefined *)(param_1 + 0x36) = 0;
    }
  }
  return;
}

