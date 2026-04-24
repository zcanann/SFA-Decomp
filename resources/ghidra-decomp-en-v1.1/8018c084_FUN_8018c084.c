// Function: FUN_8018c084
// Entry: 8018c084
// Size: 252 bytes

void FUN_8018c084(int param_1)

{
  int iVar1;
  byte bVar2;
  char cVar3;
  float *pfVar4;
  
  pfVar4 = *(float **)(param_1 + 0xb8);
  iVar1 = FUN_8002bac4();
  if (*(char *)(pfVar4 + 1) == '\0') {
    bVar2 = FUN_80296434(iVar1);
    if (bVar2 != 0) {
      *(undefined *)(pfVar4 + 1) = 1;
    }
  }
  else {
    bVar2 = FUN_80296434(iVar1);
    if (bVar2 == 0) {
      *(undefined *)(pfVar4 + 1) = 0;
    }
  }
  FUN_8002b738(param_1,(ushort)*(byte *)(pfVar4 + 1));
  FUN_8002b95c(param_1,(uint)*(byte *)(pfVar4 + 1));
  iVar1 = FUN_8003811c(param_1);
  if ((iVar1 != 0) && (cVar3 = FUN_80133868(), cVar3 == '\0')) {
    *pfVar4 = FLOAT_803e4920;
  }
  if (FLOAT_803e4924 < *pfVar4) {
    if ((*(byte *)(param_1 + 0xaf) & 4) == 0) {
      *pfVar4 = FLOAT_803e4924;
    }
    else {
      *pfVar4 = *pfVar4 - FLOAT_803dc074;
      FUN_8012f288(*(undefined2 *)
                    (*(int *)(param_1 + 0x50) + (uint)*(byte *)(pfVar4 + 1) * 2 + 0x7c));
    }
  }
  return;
}

