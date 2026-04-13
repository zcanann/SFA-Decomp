// Function: FUN_80291db4
// Entry: 80291db4
// Size: 296 bytes

int FUN_80291db4(uint *param_1,uint *param_2)

{
  int iVar1;
  int iVar2;
  uint uVar3;
  uint uVar4;
  
  uVar3 = (uint)*(byte *)param_1;
  if (uVar3 - *(byte *)param_2 != 0) {
    return uVar3 - *(byte *)param_2;
  }
  uVar4 = (uint)param_1 & 3;
  if (((uint)param_2 & 3) == uVar4) {
    if (uVar4 != 0) {
      if (uVar3 == 0) {
        return 0;
      }
      for (iVar1 = 3 - uVar4; iVar1 != 0; iVar1 = iVar1 + -1) {
        param_1 = (uint *)((int)param_1 + 1);
        param_2 = (uint *)((int)param_2 + 1);
        iVar2 = (uint)*(byte *)param_1 - (uint)*(byte *)param_2;
        if (iVar2 != 0) {
          return iVar2;
        }
        if (*(byte *)param_1 == 0) {
          return 0;
        }
      }
      param_1 = (uint *)((int)param_1 + 1);
      param_2 = (uint *)((int)param_2 + 1);
    }
    uVar4 = *param_2;
    uVar3 = *param_1;
    while ((uVar3 + 0xfefefeff & 0x80808080) == 0) {
      if (uVar3 != uVar4) {
        if (uVar4 < uVar3) {
          return 1;
        }
        return -1;
      }
      param_1 = param_1 + 1;
      param_2 = param_2 + 1;
      uVar4 = *param_2;
      uVar3 = *param_1;
    }
    uVar3 = (uint)*(byte *)param_1;
    if (uVar3 - *(byte *)param_2 != 0) {
      return uVar3 - *(byte *)param_2;
    }
  }
  if (uVar3 == 0) {
    return 0;
  }
  do {
    param_1 = (uint *)((int)param_1 + 1);
    param_2 = (uint *)((int)param_2 + 1);
    iVar1 = (uint)*(byte *)param_1 - (uint)*(byte *)param_2;
    if (iVar1 != 0) {
      return iVar1;
    }
  } while (*(byte *)param_1 != 0);
  return 0;
}

