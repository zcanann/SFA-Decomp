// Function: FUN_80013d94
// Entry: 80013d94
// Size: 184 bytes

int * FUN_80013d94(int param_1,int param_2)

{
  int *piVar1;
  
  piVar1 = (int *)FUN_80023d8c(param_1 * (param_2 + 2U) + 0x14,0x1a);
  *piVar1 = (int)(piVar1 + 5);
  *(char *)(piVar1 + 3) = (char)param_2;
  *(char *)((int)piVar1 + 0xd) = (char)(param_2 + 2U >> 1);
  piVar1[1] = *piVar1;
  piVar1[2] = *piVar1 + param_1 * (uint)*(byte *)((int)piVar1 + 0xd) * 2;
  FUN_800033a8(*piVar1,0xff,param_1 * (uint)*(byte *)((int)piVar1 + 0xd) * 2);
  return piVar1;
}

