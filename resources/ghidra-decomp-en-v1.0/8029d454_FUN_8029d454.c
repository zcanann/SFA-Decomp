// Function: FUN_8029d454
// Entry: 8029d454
// Size: 108 bytes

undefined4 FUN_8029d454(int param_1,int param_2)

{
  undefined4 uVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  *(undefined *)(param_2 + 0x34d) = 3;
  if (**(char **)(iVar2 + 0x35c) < '\x01') {
    uVar1 = 0;
  }
  else {
    FUN_80030334((double)FLOAT_803e7ea4,param_1,200,0);
    *(undefined4 *)(param_2 + 0x308) = 0;
    uVar1 = 0xffffffdf;
  }
  return uVar1;
}

