// Function: FUN_8025ef74
// Entry: 8025ef74
// Size: 436 bytes

undefined4 FUN_8025ef74(int param_1,int param_2,int param_3)

{
  byte bVar1;
  int iVar2;
  uint uVar3;
  int iVar4;
  uint uVar5;
  undefined4 uVar6;
  
  FUN_80243e74();
  iVar4 = param_1 * 0x110;
  if ((&DAT_803afe40)[param_1 * 0x44] == 0) {
    uVar6 = 0xfffffffd;
    goto LAB_8025f108;
  }
  if (param_2 != 0) {
    *(int *)(&DAT_803aff08 + iVar4) = param_2;
  }
  if (param_3 != 0) {
    *(int *)(&DAT_803aff0c + iVar4) = param_3;
  }
  *(undefined **)(&DAT_803aff1c + iVar4) = &LAB_8025ee64;
  iVar2 = FUN_80254c34(param_1,0,-0x7fda174c);
  if (iVar2 == 0) {
    uVar6 = 0xffffffff;
    goto LAB_8025f108;
  }
  *(undefined4 *)(&DAT_803aff1c + iVar4) = 0;
  iVar2 = FUN_80254534(param_1,0,4);
  if (iVar2 == 0) {
    FUN_80254d28(param_1);
    uVar6 = 0xfffffffd;
    goto LAB_8025f108;
  }
  FUN_8024173c((int *)(&DAT_803aff20 + iVar4));
  bVar1 = (&DAT_803afed4)[iVar4];
  if (bVar1 != 0xf3) {
    if (bVar1 < 0xf3) {
      if (bVar1 == 0xf1) {
LAB_8025f0a0:
        uVar3 = *(uint *)(&DAT_803afe4c + iVar4);
        uVar5 = (DAT_800000f8 >> 2) * 2;
        uVar3 = ((int)uVar3 >> 0xd) + (uint)((int)uVar3 < 0 && (uVar3 & 0x1fff) != 0);
        iVar2 = ((int)uVar3 >> 0x1f) * uVar5 + (int)((ulonglong)uVar3 * (ulonglong)uVar5 >> 0x20);
        FUN_802416d4((undefined4 *)(&DAT_803aff20 + iVar4),iVar2,iVar2,uVar3 * uVar5,&LAB_8025eb94);
      }
      else if (0xf0 < bVar1) {
        FUN_802416d4((undefined4 *)(&DAT_803aff20 + iVar4),0x10624dd3,0,(DAT_800000f8 / 4000) * 100,
                     &LAB_8025eb94);
      }
    }
    else if (bVar1 < 0xf5) goto LAB_8025f0a0;
  }
  uVar6 = 0;
LAB_8025f108:
  FUN_80243e9c();
  return uVar6;
}

