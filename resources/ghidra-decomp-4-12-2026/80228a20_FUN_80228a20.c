// Function: FUN_80228a20
// Entry: 80228a20
// Size: 248 bytes

void FUN_80228a20(undefined2 *param_1,int param_2,int param_3)

{
  char cVar3;
  uint uVar1;
  undefined4 *puVar2;
  
  *(code **)(param_1 + 0x5e) = FUN_80228874;
  *(undefined *)((int)param_1 + 0xad) = *(undefined *)(param_2 + 0x19);
  if (*(char *)(*(int *)(param_1 + 0x28) + 0x55) <= *(char *)((int)param_1 + 0xad)) {
    *(undefined *)((int)param_1 + 0xad) = 0;
  }
  *param_1 = (short)((int)*(char *)(param_2 + 0x18) << 8);
  if ((param_3 == 0) &&
     (cVar3 = (**(code **)(*DAT_803dd72c + 0x40))((int)*(char *)(param_1 + 0x56)), cVar3 == '\x02'))
  {
    *(float *)(param_1 + 8) = *(float *)(param_1 + 8) + FLOAT_803e7aac;
  }
  uVar1 = FUN_80020078((int)*(short *)(param_2 + 0x1e));
  if (uVar1 != 0) {
    puVar2 = (undefined4 *)FUN_800395a4((int)param_1,0);
    if (puVar2 != (undefined4 *)0x0) {
      *puVar2 = 0x100;
    }
    *(undefined4 *)(param_1 + 0x7a) = 1;
  }
  return;
}

