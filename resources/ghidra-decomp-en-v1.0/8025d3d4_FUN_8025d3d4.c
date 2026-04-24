// Function: FUN_8025d3d4
// Entry: 8025d3d4
// Size: 80 bytes

void FUN_8025d3d4(int *param_1,int *param_2,int *param_3,int *param_4)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  
  uVar3 = *(uint *)(DAT_803dc5a8 + 0xfc);
  uVar1 = (*(uint *)(DAT_803dc5a8 + 0xf8) & 0x7ff000) >> 0xc;
  uVar2 = *(uint *)(DAT_803dc5a8 + 0xf8) & 0x7ff;
  *param_1 = uVar1 - 0x156;
  *param_2 = uVar2 - 0x156;
  *param_3 = (((uVar3 & 0x7ff000) >> 0xc) - uVar1) + 1;
  *param_4 = ((uVar3 & 0x7ff) - uVar2) + 1;
  return;
}

