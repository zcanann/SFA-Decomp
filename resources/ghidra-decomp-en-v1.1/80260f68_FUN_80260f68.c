// Function: FUN_80260f68
// Entry: 80260f68
// Size: 172 bytes

void FUN_80260f68(int param_1,short *param_2,undefined4 param_3)

{
  param_2[2] = param_2[2] + 1;
  FUN_80261278((ushort *)(param_2 + 2),0x1ffc,param_2,param_2 + 1);
  FUN_80242114((uint)param_2,0x2000);
  *(undefined4 *)(&DAT_803aff18 + param_1 * 0x110) = param_3;
  FUN_8025f378(param_1,*(int *)(&DAT_803afe4c + param_1 * 0x110) *
                       ((uint)((int)param_2 - (&DAT_803afec0)[param_1 * 0x44]) >> 0xd),-0x7fd9f314);
  return;
}

