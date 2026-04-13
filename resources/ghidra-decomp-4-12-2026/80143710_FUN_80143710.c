// Function: FUN_80143710
// Entry: 80143710
// Size: 296 bytes

undefined4 FUN_80143710(int param_1,int *param_2)

{
  int iVar1;
  bool bVar2;
  int iVar3;
  
  iVar1 = FUN_80144994(param_1,param_2);
  if (iVar1 == 0) {
    for (iVar1 = 0; iVar1 < *(char *)((int)param_2 + 0x827); iVar1 = iVar1 + 1) {
      if ((((*(char *)((int)param_2 + iVar1 + 0x81f) == '\0') &&
           (iVar3 = *(int *)(param_1 + 0xb8), (*(byte *)(iVar3 + 0x58) >> 6 & 1) == 0)) &&
          ((0x2f < *(short *)(param_1 + 0xa0) || (*(short *)(param_1 + 0xa0) < 0x29)))) &&
         (bVar2 = FUN_8000b598(param_1,0x10), !bVar2)) {
        FUN_800394f0(param_1,iVar3 + 0x3a8,0x357,0,0xffffffff,0);
      }
    }
    iVar1 = FUN_80144994(param_1,param_2);
    if (((iVar1 == 0) && ((param_2[0x15] & 0x8000000U) != 0)) &&
       (param_2[8] == (int)*(short *)(param_1 + 0xa0))) {
      *(undefined *)((int)param_2 + 10) = 0;
    }
  }
  return 1;
}

