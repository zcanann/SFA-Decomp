// Function: FUN_8005d150
// Entry: 8005d150
// Size: 288 bytes

void FUN_8005d150(int param_1,int param_2,int param_3)

{
  int iVar1;
  uint uVar2;
  undefined4 uVar3;
  float local_28;
  undefined4 local_24;
  float local_20;
  
  if (DAT_803dce30 == 1000) {
    FUN_8005db38();
    DAT_803dce30 = 0;
  }
  if (*(int *)(param_1 + 0x30) == 0) {
    local_28 = *(float *)(param_1 + 0x18) - FLOAT_803dcdd8;
    local_24 = *(undefined4 *)(param_1 + 0x1c);
    local_20 = *(float *)(param_1 + 0x20) - FLOAT_803dcddc;
  }
  else {
    local_28 = *(float *)(param_1 + 0x18);
    local_24 = *(undefined4 *)(param_1 + 0x1c);
    local_20 = *(float *)(param_1 + 0x20);
  }
  uVar3 = FUN_8000f54c();
  FUN_80247494(uVar3,&local_28,&local_28);
  iVar1 = DAT_803dce30;
  uVar2 = (int)-local_20 + param_3;
  if ((int)uVar2 < 0) {
    uVar2 = 0;
  }
  else if (0x7ffffff < (int)uVar2) {
    uVar2 = 0x7ffffff;
  }
  (&DAT_8037e0c0)[DAT_803dce30 * 4] = param_1;
  (&DAT_8037e0c8)[iVar1 * 4] = uVar2 | param_2 << 0x1b;
  return;
}

