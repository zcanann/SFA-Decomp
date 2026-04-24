// Function: FUN_8013db3c
// Entry: 8013db3c
// Size: 332 bytes

undefined FUN_8013db3c(int param_1,int param_2)

{
  byte bVar1;
  int iVar2;
  undefined uVar3;
  double dVar4;
  float local_18 [3];
  
  local_18[0] = FLOAT_803e242c;
  bVar1 = *(byte *)(param_2 + 0x58) >> 1 & 0xf;
  uVar3 = bVar1 != 0;
  if ((bool)uVar3) {
    *(byte *)(param_2 + 0x58) = (bVar1 - 1) * '\x02' & 0x1e | *(byte *)(param_2 + 0x58) & 0xe1;
  }
  iVar2 = FUN_80036e58(0x53,param_1,local_18);
  if (iVar2 == 0) {
    if ((*(char *)(param_2 + 0xd) != '\x03') &&
       ((*(ushort *)(*(int *)(param_2 + 4) + 0xb0) & 0x1000) != 0)) {
      iVar2 = FUN_8005afac((double)*(float *)(param_1 + 0xc),(double)*(float *)(param_1 + 0x14));
      if (iVar2 == 0x38) {
        iVar2 = FUN_8001ffb4(0x385);
        if (((iVar2 == 0) && (iVar2 = FUN_8001ffb4(900), iVar2 != 0)) &&
           ((iVar2 = FUN_8001ffb4(0xc1), iVar2 != 0 || (iVar2 = FUN_8001ffb4(0x12e), iVar2 != 0))))
        {
          uVar3 = true;
        }
      }
      else {
        *(byte *)(param_2 + 0x58) = *(byte *)(param_2 + 0x58) & 0xe1 | 0x1e;
        uVar3 = true;
      }
    }
    if (((bool)uVar3 == true) &&
       (dVar4 = (double)FUN_800216d0(*(int *)(param_2 + 4) + 0x18,param_1 + 0x18),
       dVar4 < (double)FLOAT_803e24c4)) {
      uVar3 = 2;
    }
  }
  else {
    uVar3 = 0;
  }
  return uVar3;
}

