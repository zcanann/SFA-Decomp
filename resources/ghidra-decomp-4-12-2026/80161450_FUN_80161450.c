// Function: FUN_80161450
// Entry: 80161450
// Size: 252 bytes

void FUN_80161450(int param_1,int param_2,int param_3)

{
  uint uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  uVar1 = 0x16;
  if (param_3 != 0) {
    uVar1 = 0x17;
  }
  if ((*(byte *)(param_2 + 0x2b) & 1) == 0) {
    uVar1 = uVar1 | 8;
  }
  *(short *)(param_1 + 2) = (short)((int)*(char *)(param_2 + 0x28) << 8);
  *(short *)(param_1 + 4) = (short)((int)*(char *)(param_2 + 0x27) << 8);
  (**(code **)(*DAT_803dd738 + 0x58))((double)FLOAT_803e3b40,param_1,param_2,iVar2,4,6,0x82,uVar1);
  *(code **)(param_1 + 0xbc) = FUN_80160e68;
  (**(code **)(*DAT_803dd70c + 0x14))(param_1,iVar2,0);
  *(undefined2 *)(iVar2 + 0x270) = 0;
  if (*(ushort *)(iVar2 + 0x3fe) < 0x32) {
    *(undefined2 *)(iVar2 + 0x3fe) = 0x32;
  }
  return;
}

