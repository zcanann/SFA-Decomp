// Function: FUN_801c2e1c
// Entry: 801c2e1c
// Size: 164 bytes

void FUN_801c2e1c(int param_1,int param_2)

{
  uint uVar1;
  undefined4 *puVar2;
  undefined2 *puVar3;
  
  puVar3 = *(undefined2 **)(param_1 + 0xb8);
  *(code **)(param_1 + 0xbc) = FUN_801c2c94;
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x22));
  if (uVar1 == 0) {
    *(undefined *)((int)puVar3 + 3) = 0;
  }
  else {
    *(undefined *)((int)puVar3 + 3) = 2;
  }
  puVar2 = (undefined4 *)FUN_800395a4(param_1,0);
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

