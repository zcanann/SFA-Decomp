// Function: FUN_8019d8b4
// Entry: 8019d8b4
// Size: 308 bytes

void FUN_8019d8b4(undefined2 *param_1,int param_2)

{
  short sVar1;
  int iVar2;
  short *psVar3;
  
  psVar3 = *(short **)(param_1 + 0x5c);
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  *psVar3 = *(short *)(param_2 + 0x1e);
  sVar1 = *psVar3;
  if (sVar1 == 0x55) {
    psVar3[1] = 0x52;
    *(undefined *)(psVar3 + 2) = 1;
    FUN_8002b884(param_1,2);
  }
  else if (sVar1 < 0x55) {
    if (0x53 < sVar1) {
      psVar3[1] = 0x51;
      *(undefined *)(psVar3 + 2) = 0;
    }
  }
  else if (sVar1 < 0x57) {
    psVar3[1] = 0x53;
    *(undefined *)(psVar3 + 2) = 2;
    FUN_8002b884(param_1,1);
  }
  *(code **)(param_1 + 0x5e) = FUN_8019d578;
  FUN_80037964(param_1,2);
  iVar2 = FUN_8001ffb4((int)psVar3[1]);
  if (iVar2 == 0) {
    *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 0x10;
  }
  else {
    *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) & 0xef;
  }
  iVar2 = FUN_8001ffb4((int)*psVar3);
  if (iVar2 != 0) {
    *(byte *)((int)param_1 + 0xaf) = *(byte *)((int)param_1 + 0xaf) | 8;
    *(undefined4 *)(param_1 + 0x7a) = 1;
  }
  return;
}

