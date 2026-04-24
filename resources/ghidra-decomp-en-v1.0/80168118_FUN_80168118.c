// Function: FUN_80168118
// Entry: 80168118
// Size: 260 bytes

undefined4 FUN_80168118(int param_1,int param_2)

{
  bool bVar1;
  int iVar2;
  
  iVar2 = *(int *)(param_1 + 0xb8);
  bVar1 = *(char *)(param_2 + 0x27a) == '\0';
  if (bVar1) {
    if (*(char *)(param_2 + 0x346) != '\0') {
      *(undefined2 *)(iVar2 + 0x402) = 1;
    }
  }
  else {
    if (!bVar1) {
      FUN_80030334((double)FLOAT_803e3060,param_1,4,0);
      *(undefined *)(param_2 + 0x346) = 0;
    }
    FUN_80169360(param_1,1);
    *(undefined *)(param_2 + 0x25f) = 1;
    FUN_800200e8((int)*(short *)(iVar2 + 0x3f4),1);
    *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
    *(undefined *)(param_1 + 0x36) = 0xff;
    *(undefined *)(param_2 + 0x34d) = 1;
    *(float *)(param_2 + 0x2a0) =
         FLOAT_803e3098 +
         (float)((double)CONCAT44(0x43300000,(uint)*(byte *)(iVar2 + 0x406)) - DOUBLE_803e3068) /
         FLOAT_803e309c;
    FUN_80035f20(param_1);
  }
  return 0;
}

