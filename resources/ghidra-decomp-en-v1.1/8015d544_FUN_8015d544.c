// Function: FUN_8015d544
// Entry: 8015d544
// Size: 484 bytes

void FUN_8015d544(int param_1,int param_2,int param_3)

{
  int iVar1;
  uint uVar2;
  
  FUN_80035ff8(param_1);
  if ((*(byte *)(param_2 + 0x404) & 4) == 0) {
    if ((*(byte *)(param_2 + 0x404) & 8) == 0) {
      iVar1 = (**(code **)(*DAT_803dd738 + 0x48))
                        ((double)(float)((double)CONCAT44(0x43300000,
                                                          (uint)*(ushort *)(param_2 + 0x3fe)) -
                                        DOUBLE_803e39a0),param_1,param_3,0x8000);
    }
    else {
      iVar1 = (**(code **)(*DAT_803dd738 + 0x48))
                        ((double)(FLOAT_803e39bc *
                                 (float)((double)CONCAT44(0x43300000,
                                                          (uint)*(ushort *)(param_2 + 0x3fe)) -
                                        DOUBLE_803e39a0)),param_1,param_3,0x8000);
    }
  }
  else {
    iVar1 = (**(code **)(*DAT_803dd738 + 0x48))((double)FLOAT_803e39ec,param_1,param_3,0x8000);
  }
  if (iVar1 != 0) {
    (**(code **)(*DAT_803dd70c + 0x30))((double)FLOAT_803dc074,param_1,param_3,4);
    uVar2 = (**(code **)(*DAT_803dd738 + 0x18))((double)FLOAT_803e3998,param_1,param_3);
    if ((uVar2 & 1) == 0) {
      iVar1 = 0;
    }
  }
  if (iVar1 != 0) {
    (**(code **)(*DAT_803dd738 + 0x28))
              (param_1,param_3,param_2 + 0x35c,(int)*(short *)(param_2 + 0x3f4),0,0,0,8,0xffffffff);
    *(int *)(param_3 + 0x2d0) = iVar1;
    *(undefined *)(param_3 + 0x349) = 0;
    *(undefined2 *)(param_2 + 0x402) = 1;
  }
  return;
}

