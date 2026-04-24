// Function: FUN_8006f400
// Entry: 8006f400
// Size: 256 bytes

void FUN_8006f400(double param_1)

{
  undefined *puVar1;
  undefined4 *puVar2;
  uint uVar3;
  int iVar4;
  double local_18;
  double local_10;
  
  puVar2 = &DAT_80392de0;
  puVar1 = &DAT_80391de0;
  iVar4 = 0x100;
  do {
    uVar3 = (uint)*(byte *)((int)puVar2 + 0x33);
    if (uVar3 != 0) {
      local_18 = (double)CONCAT44(0x43300000,uVar3);
      if (FLOAT_803dee20 < (float)((double)(float)(local_18 - DOUBLE_803dee30) - param_1)) {
        local_18 = (double)CONCAT44(0x43300000,uVar3);
        *(char *)((int)puVar2 + 0x33) =
             (char)(int)((double)(float)(local_18 - DOUBLE_803dee30) - param_1);
      }
      else {
        *(undefined *)((int)puVar2 + 0x33) = 0;
      }
    }
    uVar3 = (uint)(byte)puVar1[0xe];
    if (uVar3 != 0) {
      local_10 = (double)CONCAT44(0x43300000,uVar3);
      if (FLOAT_803dee20 < (float)((double)(float)(local_10 - DOUBLE_803dee30) - param_1)) {
        local_10 = (double)CONCAT44(0x43300000,uVar3);
        puVar1[0xe] = (char)(int)((double)(float)(local_10 - DOUBLE_803dee30) - param_1);
      }
      else {
        puVar1[0xe] = 0;
      }
    }
    puVar2 = puVar2 + 0xe;
    puVar1 = puVar1 + 0x10;
    iVar4 = iVar4 + -1;
  } while (iVar4 != 0);
  return;
}

