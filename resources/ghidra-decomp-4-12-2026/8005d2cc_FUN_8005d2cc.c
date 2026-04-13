// Function: FUN_8005d2cc
// Entry: 8005d2cc
// Size: 288 bytes

void FUN_8005d2cc(int param_1,int param_2,int param_3)

{
  int iVar1;
  uint uVar2;
  float *pfVar3;
  float local_28;
  undefined4 local_24;
  float local_20;
  
  if (DAT_803ddab0 == 1000) {
    FUN_8005dcb4();
    DAT_803ddab0 = 0;
  }
  if (*(int *)(param_1 + 0x30) == 0) {
    local_28 = *(float *)(param_1 + 0x18) - FLOAT_803dda58;
    local_24 = *(undefined4 *)(param_1 + 0x1c);
    local_20 = *(float *)(param_1 + 0x20) - FLOAT_803dda5c;
  }
  else {
    local_28 = *(float *)(param_1 + 0x18);
    local_24 = *(undefined4 *)(param_1 + 0x1c);
    local_20 = *(float *)(param_1 + 0x20);
  }
  pfVar3 = (float *)FUN_8000f56c();
  FUN_80247bf8(pfVar3,&local_28,&local_28);
  iVar1 = DAT_803ddab0;
  uVar2 = (int)-local_20 + param_3;
  if ((int)uVar2 < 0) {
    uVar2 = 0;
  }
  else if (0x7ffffff < (int)uVar2) {
    uVar2 = 0x7ffffff;
  }
  (&DAT_8037ed20)[DAT_803ddab0 * 4] = param_1;
  (&DAT_8037ed28)[iVar1 * 4] = uVar2 | param_2 << 0x1b;
  return;
}

