// Function: FUN_80008f38
// Entry: 80008f38
// Size: 208 bytes

void FUN_80008f38(uint param_1,undefined4 param_2,uint param_3)

{
  int iVar1;
  int iVar2;
  
  iVar2 = DAT_803dd438 + 1;
  iVar1 = DAT_803dd438 * 0x30;
  DAT_803dd438 = iVar2;
  if (0xf < iVar2) {
    DAT_803dd438 = 0;
  }
  if ((param_3 & 0x1f) != 0) {
    param_3 = (param_3 | 0x1f) + 1;
  }
  FUN_802420e0(param_1,param_3);
  DAT_803dd43c = 0;
  FUN_802514c8((undefined4 *)(&DAT_803365a0 + iVar1),100,0,1,param_1,param_2,param_3,-0x7fff6ff8);
  do {
  } while (DAT_803dd43c == 0);
  return;
}

