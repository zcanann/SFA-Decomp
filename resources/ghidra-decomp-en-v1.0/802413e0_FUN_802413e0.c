// Function: FUN_802413e0
// Entry: 802413e0
// Size: 172 bytes

uint ** FUN_802413e0(uint **param_1,uint **param_2)

{
  uint **ppuVar1;
  uint **ppuVar2;
  
  ppuVar1 = (uint **)0x0;
  for (ppuVar2 = param_1; (ppuVar2 != (uint **)0x0 && (ppuVar2 < param_2));
      ppuVar2 = (uint **)ppuVar2[1]) {
    ppuVar1 = ppuVar2;
  }
  param_2[1] = (uint *)ppuVar2;
  *param_2 = (uint *)ppuVar1;
  if (ppuVar2 != (uint **)0x0) {
    *ppuVar2 = (uint *)param_2;
    if ((uint **)((int)param_2 + (int)param_2[2]) == ppuVar2) {
      param_2[2] = (uint *)((int)param_2[2] + (int)ppuVar2[2]);
      ppuVar2 = (uint **)ppuVar2[1];
      param_2[1] = (uint *)ppuVar2;
      if (ppuVar2 != (uint **)0x0) {
        *ppuVar2 = (uint *)param_2;
      }
    }
  }
  if (ppuVar1 == (uint **)0x0) {
    return param_2;
  }
  ppuVar1[1] = (uint *)param_2;
  if ((uint **)((int)ppuVar1 + (int)ppuVar1[2]) != param_2) {
    return param_1;
  }
  ppuVar1[2] = (uint *)((int)ppuVar1[2] + (int)param_2[2]);
  ppuVar1[1] = (uint *)ppuVar2;
  if (ppuVar2 == (uint **)0x0) {
    return param_1;
  }
  *ppuVar2 = (uint *)ppuVar1;
  return param_1;
}

