// Function: FUN_801630f0
// Entry: 801630f0
// Size: 672 bytes

void FUN_801630f0(short *param_1)

{
  undefined4 uVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  
  iVar4 = *(int *)(param_1 + 0x5c);
  iVar3 = *(int *)(iVar4 + 0x40c);
  iVar2 = *(int *)(param_1 + 0x26);
  if (*(int *)(param_1 + 0x7a) == 0) {
    if (*(int *)(iVar3 + 0x34) == 0) {
      FUN_80162ca0(param_1);
    }
    else {
      (**(code **)(*DAT_803dd70c + 8))
                ((double)FLOAT_803e3b54,(double)FLOAT_803e3b54,param_1,iVar4,&DAT_803ad270,
                 &DAT_803ad258);
      (**(code **)(**(int **)(*(int *)(iVar3 + 0x38) + 0x68) + 0x24))
                ((double)*(float *)(iVar3 + 0x48),*(int *)(iVar3 + 0x38),param_1 + 6,param_1 + 8,
                 param_1 + 10);
      (**(code **)(*DAT_803dd738 + 0x54))
                (param_1,iVar4,iVar4 + 0x35c,(int)*(short *)(iVar4 + 0x3f4),iVar4 + 0x405,0,0,0);
      iVar2 = (**(code **)(*DAT_803dd738 + 0x50))
                        (param_1,iVar4,iVar4 + 0x35c,(int)*(short *)(iVar4 + 0x3f4),&DAT_80320d30,
                         &DAT_80320da8,3,0);
      if (iVar2 == 0xe) {
        *(undefined *)(iVar4 + 0x405) = 2;
        uVar1 = FUN_8002bac4();
        *(undefined4 *)(iVar4 + 0x2d0) = uVar1;
      }
      if ((*(int *)(iVar4 + 0x2d0) == 0) && (*(char *)(iVar4 + 0x354) != '\0')) {
        *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) & 0xfffe;
        iVar2 = (**(code **)(*DAT_803dd738 + 0x48))
                          ((double)(float)((double)CONCAT44(0x43300000,
                                                            (uint)*(ushort *)(iVar4 + 0x3fe)) -
                                          DOUBLE_803e3ba8),param_1,iVar4,0x8000);
        if (iVar2 != 0) {
          *(int *)(iVar4 + 0x2d0) = iVar2;
          *(undefined *)(iVar4 + 0x349) = 0;
        }
      }
      else {
        *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) =
             *(ushort *)(*(int *)(param_1 + 0x2a) + 0x60) | 1;
        iVar2 = (**(code **)(*DAT_803dd738 + 0x44))
                          ((double)(float)((double)CONCAT44(0x43300000,
                                                            (uint)*(ushort *)(iVar4 + 0x3fe)) -
                                          DOUBLE_803e3ba8),param_1,iVar4,1);
        if (iVar2 != 0) {
          *(undefined4 *)(iVar4 + 0x2d0) = 0;
        }
      }
    }
  }
  else {
    iVar3 = (**(code **)(*DAT_803dd72c + 0x68))(*(undefined4 *)(iVar2 + 0x14));
    if (iVar3 != 0) {
      (**(code **)(*DAT_803dd738 + 0x58))
                ((double)FLOAT_803e3bc0,param_1,iVar2,iVar4,10,6,0x10e,0x36);
      *(undefined2 *)(iVar4 + 0x270) = 1;
      *(undefined *)(iVar4 + 0x27b) = 1;
      *(undefined *)(param_1 + 0x1b) = 0;
    }
  }
  return;
}

