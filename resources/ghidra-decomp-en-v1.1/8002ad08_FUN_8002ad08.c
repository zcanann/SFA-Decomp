// Function: FUN_8002ad08
// Entry: 8002ad08
// Size: 256 bytes

void FUN_8002ad08(undefined4 param_1,undefined4 param_2,undefined4 param_3,undefined4 param_4,
                 undefined4 param_5,uint param_6)

{
  int iVar1;
  int iVar2;
  int iVar3;
  undefined8 uVar4;
  
  uVar4 = FUN_80286834();
  iVar1 = (int)((ulonglong)uVar4 >> 0x20);
  *(short *)(iVar1 + 0xe6) = (short)uVar4;
  *(byte *)(iVar1 + 0xe5) = *(byte *)(iVar1 + 0xe5) & 0xfb;
  *(byte *)(iVar1 + 0xe5) = *(byte *)(iVar1 + 0xe5) | 2;
  *(char *)(iVar1 + 0xec) = (char)param_3;
  *(char *)(iVar1 + 0xed) = (char)param_4;
  *(char *)(iVar1 + 0xee) = (char)param_5;
  if ((int)uVar4 == 10000) {
    *(byte *)(iVar1 + 0xe5) = *(byte *)(iVar1 + 0xe5) | 8;
  }
  else {
    *(byte *)(iVar1 + 0xe5) = *(byte *)(iVar1 + 0xe5) & 0xf7;
  }
  if ((param_6 & 0xff) == 0) {
    *(undefined *)(iVar1 + 0xef) = 0;
  }
  else {
    *(undefined *)(iVar1 + 0xef) = 0x7f;
  }
  iVar3 = iVar1;
  for (iVar2 = 0; iVar2 < (int)(uint)*(byte *)(iVar1 + 0xeb); iVar2 = iVar2 + 1) {
    FUN_8002ad08(*(undefined4 *)(iVar3 + 200),(int)uVar4,param_3,param_4,param_5,param_6);
    iVar3 = iVar3 + 4;
  }
  FUN_80286880();
  return;
}

