// Function: FUN_801ccecc
// Entry: 801ccecc
// Size: 208 bytes

void FUN_801ccecc(int param_1)

{
  char cVar1;
  undefined4 uVar2;
  int iVar3;
  
  iVar3 = *(int *)(param_1 + 0x4c);
  if (*(char *)(iVar3 + 0x19) == '\0') {
    uVar2 = 1;
  }
  else {
    uVar2 = 3;
  }
  FUN_80035df4(param_1,0xe,uVar2,0);
  cVar1 = *(char *)(iVar3 + 0x19);
  if (cVar1 == '\x01') {
    FUN_800066e0(param_1,param_1,0x203,0,0,0);
  }
  else if (cVar1 == '\x02') {
    FUN_800066e0(param_1,param_1,0x204,0,0,0);
  }
  else {
    FUN_800066e0(param_1,param_1,0x201,0,0,0);
  }
  return;
}

