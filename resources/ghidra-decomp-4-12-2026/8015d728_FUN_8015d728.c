// Function: FUN_8015d728
// Entry: 8015d728
// Size: 324 bytes

void FUN_8015d728(uint param_1,int param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_2 + 0x40c);
  *(ushort *)(iVar2 + 0x46) = *(short *)(iVar2 + 0x46) + (ushort)DAT_803dc070;
  if (299 < *(ushort *)(iVar2 + 0x46)) {
    uVar1 = FUN_80022264(0,200);
    *(short *)(iVar2 + 0x46) = (short)uVar1;
    if ((*(short *)(param_3 + 0x274) == 7) || (*(short *)(param_3 + 0x274) == 8)) {
      FUN_8000bb38(param_1,0x26c);
    }
  }
  if ((*(byte *)(param_2 + 0x404) & 2) == 0) {
    (**(code **)(*DAT_803dd738 + 0x2c))((double)FLOAT_803e3a48,param_1,param_3,0xffffffff);
  }
  else {
    (**(code **)(*DAT_803dd738 + 0x2c))((double)FLOAT_803e39ac,param_1,param_3,0xffffffff);
  }
  *(undefined4 *)(param_2 + 0x3e0) = *(undefined4 *)(param_1 + 0xc0);
  *(undefined4 *)(param_1 + 0xc0) = 0;
  (**(code **)(*DAT_803dd70c + 8))
            ((double)FLOAT_803dc074,(double)FLOAT_803dc074,param_1,param_3,&DAT_803ad1a8,
             &DAT_803ad188);
  *(undefined4 *)(param_1 + 0xc0) = *(undefined4 *)(param_2 + 0x3e0);
  return;
}

