// Function: FUN_802837b4
// Entry: 802837b4
// Size: 44 bytes

void FUN_802837b4(int param_1,uint param_2)

{
  int iVar1;
  
  iVar1 = DAT_803de344 + param_1 * 0xf4;
  *(undefined2 *)(iVar1 + 0xce) = *(undefined2 *)(&DAT_803dc620 + (param_2 & 0xff) * 2);
  *(uint *)(iVar1 + 0x24) = *(uint *)(iVar1 + 0x24) | 0x80;
  return;
}

