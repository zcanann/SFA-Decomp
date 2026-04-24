// Function: FUN_80220728
// Entry: 80220728
// Size: 216 bytes

void FUN_80220728(undefined2 *param_1,int param_2)

{
  int iVar1;
  undefined4 *puVar2;
  byte *pbVar3;
  
  pbVar3 = *(byte **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x20));
  if (iVar1 == 0) {
    *pbVar3 = *pbVar3 & 0x7f;
    puVar2 = (undefined4 *)FUN_800394ac(param_1,0,0);
    if (puVar2 != (undefined4 *)0x0) {
      *puVar2 = 0;
    }
  }
  else {
    *pbVar3 = *pbVar3 & 0x7f | 0x80;
    FUN_8000bb18(param_1,0x30c);
    puVar2 = (undefined4 *)FUN_800394ac(param_1,0,0);
    if (puVar2 != (undefined4 *)0x0) {
      *puVar2 = 0x100;
    }
  }
  param_1[0x58] = param_1[0x58] | 0x6000;
  return;
}

