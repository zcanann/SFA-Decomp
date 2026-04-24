// Function: FUN_8015d27c
// Entry: 8015d27c
// Size: 324 bytes

void FUN_8015d27c(int param_1,int param_2,int param_3)

{
  undefined2 uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_2 + 0x40c);
  *(ushort *)(iVar2 + 0x46) = *(short *)(iVar2 + 0x46) + (ushort)DAT_803db410;
  if (299 < *(ushort *)(iVar2 + 0x46)) {
    uVar1 = FUN_800221a0(0,200);
    *(undefined2 *)(iVar2 + 0x46) = uVar1;
    if ((*(short *)(param_3 + 0x274) == 7) || (*(short *)(param_3 + 0x274) == 8)) {
      FUN_8000bb18(param_1,0x26c);
    }
  }
  if ((*(byte *)(param_2 + 0x404) & 2) == 0) {
    (**(code **)(*DAT_803dcab8 + 0x2c))((double)FLOAT_803e2db0,param_1,param_3,0xffffffff);
  }
  else {
    (**(code **)(*DAT_803dcab8 + 0x2c))((double)FLOAT_803e2d14,param_1,param_3,0xffffffff);
  }
  *(undefined4 *)(param_2 + 0x3e0) = *(undefined4 *)(param_1 + 0xc0);
  *(undefined4 *)(param_1 + 0xc0) = 0;
  (**(code **)(*DAT_803dca8c + 8))
            ((double)FLOAT_803db414,(double)FLOAT_803db414,param_1,param_3,&DAT_803ac548,
             &DAT_803ac528);
  *(undefined4 *)(param_1 + 0xc0) = *(undefined4 *)(param_2 + 0x3e0);
  return;
}

