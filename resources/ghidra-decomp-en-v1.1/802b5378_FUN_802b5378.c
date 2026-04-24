// Function: FUN_802b5378
// Entry: 802b5378
// Size: 456 bytes

/* WARNING: Removing unreachable block (ram,0x802b5520) */
/* WARNING: Removing unreachable block (ram,0x802b5388) */

void FUN_802b5378(undefined8 param_1,short *param_2,uint *param_3)

{
  char cVar1;
  undefined auStack_58 [64];
  
  param_3[0xa9] = (uint)FLOAT_803e8b4c;
  param_3[0xa4] = param_3[0x1b7];
  param_3[0xa3] = param_3[0x1b6];
  param_3[199] = (uint)*(ushort *)((int)param_3 + 0x6e2);
  param_3[0xc6] = (uint)*(ushort *)(param_3 + 0x1b8);
  *(undefined *)(*(int *)(param_2 + 0x2a) + 0x6e) = 0;
  *(undefined *)(*(int *)(param_2 + 0x2a) + 0x6f) = 0;
  *(undefined *)(*(int *)(param_2 + 0x2a) + 0x6c) = 0;
  *(undefined *)(*(int *)(param_2 + 0x2a) + 0x6d) = 0;
  *(undefined *)((int)param_3 + 0x25f) = 1;
  param_3[1] = param_3[1] & 0xf7efffff;
  FUN_80062bac((int)param_2);
  *(undefined *)((int)param_3 + 0x8c5) = 0;
  param_3[0xd8] = param_3[0xd8] & 0xffffdfff;
  *param_3 = *param_3 | 0x1000000;
  FUN_802b1604(param_2,(int)param_3,(int)param_3);
  cVar1 = FUN_802a7c04(param_2,param_3,(int)param_3,auStack_58,0x60);
  if (cVar1 == '\b') {
    param_3[0xb4] = 0;
    *(undefined *)((int)param_3 + 0x349) = 0;
    (**(code **)(*DAT_803dd6d0 + 0x48))(0);
    if ((DAT_803df0cc != 0) && ((*(byte *)(param_3 + 0xfd) >> 6 & 1) != 0)) {
      *(undefined *)(param_3 + 0x22d) = 1;
      *(byte *)(param_3 + 0xfd) = *(byte *)(param_3 + 0xfd) & 0xf7 | 8;
    }
    (**(code **)(*DAT_803dd70c + 0x14))(param_2,param_3,10);
    param_3[0xc1] = 0;
  }
  (**(code **)(*DAT_803dd70c + 8))(param_1,param_1,param_2,param_3,&DAT_803dbc28,&DAT_803df138);
  *param_3 = *param_3 & 0xfeffffff;
  return;
}

