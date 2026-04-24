// Function: FUN_80212c18
// Entry: 80212c18
// Size: 268 bytes

int FUN_80212c18(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  int local_18 [5];
  
  iVar2 = *(int *)(param_1 + 0x4c);
  if (*(char *)(param_2 + 0x27b) == '\0') {
    fVar1 = (float)DAT_803ddd54[1] - FLOAT_803db414;
    DAT_803ddd54[1] = fVar1;
    if (fVar1 < FLOAT_803e67b8) {
      DAT_803ddd54[1] = FLOAT_803e67b8;
    }
    if ((*(char *)(param_2 + 0x346) != '\0') && ((float)DAT_803ddd54[1] <= FLOAT_803e67b8)) {
      local_18[0] = 0;
      iVar2 = FUN_800138b4(*DAT_803ddd54);
      if (iVar2 == 0) {
        FUN_800138e0(*DAT_803ddd54,local_18);
      }
      return local_18[0] + 1;
    }
  }
  else {
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,4);
    DAT_803ddd54[1] =
         (float)((double)CONCAT44(0x43300000,
                                  (uint)*(ushort *)
                                         (iVar2 + (uint)*(byte *)((int)DAT_803ddd54 + 0xfd) * 2 +
                                         0x44)) - DOUBLE_803e67e0);
  }
  return 0;
}

