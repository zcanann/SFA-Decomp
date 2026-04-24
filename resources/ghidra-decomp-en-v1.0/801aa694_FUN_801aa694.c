// Function: FUN_801aa694
// Entry: 801aa694
// Size: 160 bytes

void FUN_801aa694(short *param_1,int param_2)

{
  int iVar1;
  undefined4 local_18;
  undefined2 local_14;
  undefined4 local_10;
  undefined2 local_c;
  
  iVar1 = *(int *)(param_1 + 0x5c);
  local_10 = DAT_803e4650;
  local_c = DAT_803e4654;
  local_18 = DAT_803e4658;
  local_14 = DAT_803e465c;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  FUN_80114f64(param_1,iVar1,0x71c7,0x3555,3);
  FUN_8011507c(iVar1,600,0xf0);
  FUN_80113f9c(iVar1,&local_18,&local_10,3);
  *(byte *)(iVar1 + 0x611) = *(byte *)(iVar1 + 0x611) | 10;
  return;
}

