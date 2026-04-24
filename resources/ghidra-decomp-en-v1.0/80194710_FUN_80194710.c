// Function: FUN_80194710
// Entry: 80194710
// Size: 300 bytes

void FUN_80194710(int param_1)

{
  int iVar1;
  int *piVar2;
  int iVar3;
  float local_18 [4];
  
  piVar2 = *(int **)(param_1 + 0xb8);
  iVar3 = *(int *)(param_1 + 0x4c);
  *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 8;
  if (-1 < (char)*(byte *)(piVar2 + 1)) {
    if (*piVar2 < 3000) {
      iVar3 = FUN_8002b9ac();
      if (iVar3 == 0) {
        *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) | 0x10;
      }
      else {
        local_18[0] = FLOAT_803e3ffc;
        iVar1 = FUN_80036e58(5,param_1,local_18);
        if (iVar1 == 0) {
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xef;
          *(byte *)(param_1 + 0xaf) = *(byte *)(param_1 + 0xaf) & 0xf7;
          if ((*(byte *)(param_1 + 0xaf) & 4) != 0) {
            (**(code **)(**(int **)(iVar3 + 0x68) + 0x28))(iVar3,param_1,1,1);
          }
          FUN_80041018(param_1);
        }
      }
    }
    else {
      *(byte *)(piVar2 + 1) = *(byte *)(piVar2 + 1) & 0x7f | 0x80;
      FUN_800200e8((int)*(short *)(iVar3 + 0x18),1);
      FUN_8000bb18(param_1,0x109);
    }
  }
  return;
}

