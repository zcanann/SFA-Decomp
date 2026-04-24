// Function: FUN_801aac48
// Entry: 801aac48
// Size: 160 bytes

void FUN_801aac48(short *param_1,int param_2)

{
  undefined4 *puVar1;
  undefined4 local_18;
  undefined2 local_14;
  undefined4 local_10;
  undefined2 local_c;
  
  puVar1 = *(undefined4 **)(param_1 + 0x5c);
  local_10 = DAT_803e52e8;
  local_c = DAT_803e52ec;
  local_18 = DAT_803e52f0;
  local_14 = DAT_803e52f4;
  *param_1 = (ushort)*(byte *)(param_2 + 0x1a) << 8;
  FUN_80115200((int)param_1,puVar1,0x71c7,0x3555,3);
  FUN_80115318((int)puVar1,600,0xf0);
  FUN_80114238((int)puVar1,(wchar_t *)&local_18,(wchar_t *)&local_10);
  *(byte *)((int)puVar1 + 0x611) = *(byte *)((int)puVar1 + 0x611) | 10;
  return;
}

