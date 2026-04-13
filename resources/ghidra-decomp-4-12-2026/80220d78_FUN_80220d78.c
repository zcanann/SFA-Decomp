// Function: FUN_80220d78
// Entry: 80220d78
// Size: 216 bytes

void FUN_80220d78(undefined2 *param_1,int param_2)

{
  uint uVar1;
  undefined4 *puVar2;
  byte *pbVar3;
  
  pbVar3 = *(byte **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x20));
  if (uVar1 == 0) {
    *pbVar3 = *pbVar3 & 0x7f;
    puVar2 = (undefined4 *)FUN_800395a4((int)param_1,0);
    if (puVar2 != (undefined4 *)0x0) {
      *puVar2 = 0;
    }
  }
  else {
    *pbVar3 = *pbVar3 & 0x7f | 0x80;
    FUN_8000bb38((uint)param_1,0x30c);
    puVar2 = (undefined4 *)FUN_800395a4((int)param_1,0);
    if (puVar2 != (undefined4 *)0x0) {
      *puVar2 = 0x100;
    }
  }
  param_1[0x58] = param_1[0x58] | 0x6000;
  return;
}

