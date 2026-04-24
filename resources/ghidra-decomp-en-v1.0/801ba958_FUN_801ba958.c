// Function: FUN_801ba958
// Entry: 801ba958
// Size: 300 bytes

undefined4 FUN_801ba958(int param_1,int param_2)

{
  float fVar1;
  int iVar2;
  
  if (*(char *)(param_2 + 0x27a) != '\0') {
    *(undefined2 *)(param_1 + 0xa2) = 0xffff;
    fVar1 = FLOAT_803e4bd8;
    *(float *)(param_2 + 0x280) = FLOAT_803e4bd8;
    *(float *)(param_2 + 0x284) = fVar1;
    *(float *)(param_2 + 0x2a0) = FLOAT_803e4c00;
    iVar2 = FUN_800221a0(0,1);
    if (iVar2 == 0) {
      if (*(char *)(param_2 + 0x27a) != '\0') {
        FUN_80030334((double)FLOAT_803e4bd8,param_1,0xc,0);
        *(undefined *)(param_2 + 0x346) = 0;
      }
    }
    else if (*(char *)(param_2 + 0x27a) != '\0') {
      FUN_80030334((double)FLOAT_803e4bd8,param_1,0xd,0);
      *(undefined *)(param_2 + 0x346) = 0;
    }
  }
  (**(code **)(*DAT_803dca8c + 0x34))(param_1,param_2,0,0,&DAT_80325aa0);
  (**(code **)(*DAT_803dca8c + 0x34))(param_1,param_2,7,1,&DAT_80325aa0);
  return 0;
}

