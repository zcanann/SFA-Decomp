// Function: FUN_80213290
// Entry: 80213290
// Size: 268 bytes

int FUN_80213290(int param_1,int param_2)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  int local_18 [5];
  
  iVar3 = *(int *)(param_1 + 0x4c);
  if (*(char *)(param_2 + 0x27b) == '\0') {
    fVar1 = (float)DAT_803de9d4[1] - FLOAT_803dc074;
    DAT_803de9d4[1] = fVar1;
    if (fVar1 < FLOAT_803e7450) {
      DAT_803de9d4[1] = FLOAT_803e7450;
    }
    if ((*(char *)(param_2 + 0x346) != '\0') && ((float)DAT_803de9d4[1] <= FLOAT_803e7450)) {
      local_18[0] = 0;
      uVar2 = FUN_800138d4((short *)*DAT_803de9d4);
      if (uVar2 == 0) {
        FUN_80013900((short *)*DAT_803de9d4,(uint)local_18);
      }
      return local_18[0] + 1;
    }
  }
  else {
    (**(code **)(*DAT_803dd70c + 0x14))(param_1,param_2,4);
    DAT_803de9d4[1] =
         (float)((double)CONCAT44(0x43300000,
                                  (uint)*(ushort *)
                                         (iVar3 + (uint)*(byte *)((int)DAT_803de9d4 + 0xfd) * 2 +
                                         0x44)) - DOUBLE_803e7478);
  }
  return 0;
}

