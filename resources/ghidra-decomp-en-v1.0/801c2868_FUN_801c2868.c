// Function: FUN_801c2868
// Entry: 801c2868
// Size: 164 bytes

void FUN_801c2868(int param_1,int param_2)

{
  int iVar1;
  undefined4 *puVar2;
  undefined2 *puVar3;
  
  puVar3 = *(undefined2 **)(param_1 + 0xb8);
  *(code **)(param_1 + 0xbc) = FUN_801c26e0;
  iVar1 = FUN_8001ffb4((int)*(short *)(param_2 + 0x22));
  if (iVar1 == 0) {
    *(undefined *)((int)puVar3 + 3) = 0;
  }
  else {
    *(undefined *)((int)puVar3 + 3) = 2;
  }
  puVar2 = (undefined4 *)FUN_800394ac(param_1,0,0);
  if (puVar2 != (undefined4 *)0x0) {
    if (*(char *)((int)puVar3 + 3) == '\x02') {
      *puVar2 = 1;
    }
    else {
      *puVar2 = 0;
    }
  }
  *puVar3 = 0;
  return;
}

