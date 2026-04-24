// Function: FUN_8005faf8
// Entry: 8005faf8
// Size: 204 bytes

void FUN_8005faf8(int param_1,undefined4 param_2)

{
  undefined auStack104 [12];
  float local_5c;
  float local_4c;
  float local_3c;
  undefined auStack56 [48];
  
  FUN_8025d0a8(param_2,0);
  FUN_80246e80(param_2,auStack104);
  local_5c = FLOAT_803debcc;
  local_4c = FLOAT_803debcc;
  local_3c = FLOAT_803debcc;
  FUN_8025d0e4(auStack104,0);
  FUN_80246eb4(&DAT_803967f0,param_2,auStack56);
  FUN_8025d160(auStack56,0x24,0);
  FUN_80257e74(9,*(undefined4 *)(param_1 + 0x58),6);
  FUN_80257e74(0xb,*(undefined4 *)(param_1 + 0x5c),2);
  FUN_80257e74(0xd,*(undefined4 *)(param_1 + 0x60),4);
  FUN_80257e74(0xe,*(undefined4 *)(param_1 + 0x60),4);
  return;
}

