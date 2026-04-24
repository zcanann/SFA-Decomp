// Function: FUN_8015b7ec
// Entry: 8015b7ec
// Size: 460 bytes

undefined4 FUN_8015b7ec(int param_1,int param_2)

{
  float fVar1;
  uint uVar2;
  int iVar3;
  
  fVar1 = FLOAT_803e2d14;
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(int *)(param_2 + 0x2d0) != 0) {
    if (*(char *)(param_2 + 0x27b) != '\0') {
      *(float *)(param_2 + 0x284) = FLOAT_803e2d14;
      *(float *)(param_2 + 0x280) = fVar1;
      if (*(byte *)(iVar3 + 0x406) < 0x33) {
        (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,1);
      }
      else if ((*(float *)(param_2 + 0x2c0) <
                FLOAT_803e2d24 *
                (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar3 + 0x3fe)) -
                       DOUBLE_803e2d08)) || ((*(byte *)(iVar3 + 0x404) & 2) != 0)) {
        (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,0);
      }
      else {
        (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,1);
      }
    }
    if (*(char *)(param_2 + 0x346) != '\0') {
      (**(code **)(*DAT_803dca8c + 0x30))((double)FLOAT_803db414,param_1,param_2,4);
      uVar2 = (**(code **)(*DAT_803dcab8 + 0x18))((double)FLOAT_803e2d00,param_1,param_2);
      if ((uVar2 & 1) == 0) {
        return 5;
      }
      if ((FLOAT_803e2d24 *
           (float)((double)CONCAT44(0x43300000,(uint)*(ushort *)(iVar3 + 0x3fe)) - DOUBLE_803e2d08)
           <= *(float *)(param_2 + 0x2c0)) && ((*(byte *)(iVar3 + 0x404) & 2) == 0)) {
        return 7;
      }
      return 8;
    }
  }
  return 0;
}

