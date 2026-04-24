// Function: FUN_8015bbf4
// Entry: 8015bbf4
// Size: 164 bytes

undefined4 FUN_8015bbf4(int param_1,int param_2)

{
  undefined4 uVar1;
  
  if (*(char *)(param_2 + 0x354) < '\x01') {
    uVar1 = 3;
  }
  else {
    if (*(char *)(param_2 + 0x346) != '\0') {
      if (*(short *)(param_2 + 0x274) != 0xc) {
        return 8;
      }
      if (*(byte *)(*(int *)(param_1 + 0xb8) + 0x406) < 0x33) {
        (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,1);
      }
      else {
        (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,0);
      }
    }
    uVar1 = 0;
  }
  return uVar1;
}

