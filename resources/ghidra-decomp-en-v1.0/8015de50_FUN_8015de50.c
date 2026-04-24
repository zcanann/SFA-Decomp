// Function: FUN_8015de50
// Entry: 8015de50
// Size: 100 bytes

undefined4 FUN_8015de50(int param_1,int param_2)

{
  float fVar1;
  float *pfVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0xb8);
  if (*(char *)(param_2 + 0x27b) != '\0') {
    (**(code **)(*DAT_803dca8c + 0x14))(param_1,param_2,1);
    fVar1 = FLOAT_803e2dc8;
    pfVar2 = *(float **)(iVar3 + 0x40c);
    *pfVar2 = FLOAT_803e2dc8;
    pfVar2[1] = fVar1;
  }
  return 0;
}

