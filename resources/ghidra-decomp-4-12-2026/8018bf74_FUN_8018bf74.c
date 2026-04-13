// Function: FUN_8018bf74
// Entry: 8018bf74
// Size: 196 bytes

void FUN_8018bf74(int param_1)

{
  int iVar1;
  char cVar2;
  float *pfVar3;
  
  pfVar3 = *(float **)(param_1 + 0xb8);
  iVar1 = FUN_8003811c(param_1);
  if ((iVar1 != 0) && (cVar2 = FUN_80133868(), cVar2 == '\0')) {
    *pfVar3 = FLOAT_803e4918;
  }
  if (FLOAT_803e491c < *pfVar3) {
    if ((*(byte *)(param_1 + 0xaf) & 4) == 0) {
      *pfVar3 = FLOAT_803e491c;
    }
    else {
      *pfVar3 = *pfVar3 - FLOAT_803dc074;
      FUN_8012f288(*(undefined2 *)
                    (*(int *)(param_1 + 0x50) + (uint)*(byte *)(*(int *)(param_1 + 0x4c) + 0x19) * 2
                    + 0x7c));
    }
  }
  if ((*(uint *)(*(int *)(param_1 + 0x50) + 0x44) & 1) != 0) {
    FUN_80041110();
  }
  return;
}

