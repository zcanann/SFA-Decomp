// Function: FUN_80241ad8
// Entry: 80241ad8
// Size: 172 bytes

uint * FUN_80241ad8(uint *param_1,uint *param_2)

{
  uint *puVar1;
  uint *puVar2;
  
  puVar1 = (uint *)0x0;
  for (puVar2 = param_1; (puVar2 != (uint *)0x0 && (puVar2 < param_2)); puVar2 = (uint *)puVar2[1])
  {
    puVar1 = puVar2;
  }
  param_2[1] = (uint)puVar2;
  *param_2 = (uint)puVar1;
  if (puVar2 != (uint *)0x0) {
    *puVar2 = (uint)param_2;
    if ((uint *)((int)param_2 + param_2[2]) == puVar2) {
      param_2[2] = param_2[2] + puVar2[2];
      puVar2 = (uint *)puVar2[1];
      param_2[1] = (uint)puVar2;
      if (puVar2 != (uint *)0x0) {
        *puVar2 = (uint)param_2;
      }
    }
  }
  if (puVar1 == (uint *)0x0) {
    return param_2;
  }
  puVar1[1] = (uint)param_2;
  if ((uint *)((int)puVar1 + puVar1[2]) != param_2) {
    return param_1;
  }
  puVar1[2] = puVar1[2] + param_2[2];
  puVar1[1] = (uint)puVar2;
  if (puVar2 == (uint *)0x0) {
    return param_1;
  }
  *puVar2 = (uint)puVar1;
  return param_1;
}

