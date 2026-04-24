// Function: FUN_800d7568
// Entry: 800d7568
// Size: 1288 bytes

void FUN_800d7568(void)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  uint uVar4;
  uint uVar5;
  int iVar6;
  undefined in_r6;
  undefined in_r7;
  undefined in_r8;
  uint uVar7;
  uint uVar8;
  uint uVar9;
  uint uVar10;
  uint uVar11;
  uint uVar12;
  uint local_a8;
  undefined4 local_a4;
  undefined4 local_a0;
  undefined4 local_9c;
  undefined4 local_98;
  uint local_94;
  uint local_90;
  uint local_8c;
  uint local_88;
  uint local_84;
  uint local_80;
  uint local_7c;
  uint local_78;
  uint local_74;
  uint local_70;
  uint local_6c;
  uint local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  int local_54;
  int local_50;
  int local_4c;
  int local_48 [2];
  double local_40;
  double local_38;
  
  FUN_802860c8();
  FUN_8025d3d4(&local_58,&local_5c,&local_60,&local_64);
  FUN_8000f3d8(local_48,&local_4c,&local_50,&local_54);
  uVar5 = local_54 - local_4c & 0xffff;
  if (FLOAT_803dd420 <= FLOAT_803e0540) {
    uVar12 = (uint)(FLOAT_803e0544 * FLOAT_803dd420);
    uVar11 = 0;
  }
  else {
    uVar12 = 0xff;
    uVar11 = (uint)(FLOAT_803dd420 - FLOAT_803e0540);
  }
  uVar1 = (local_50 - local_48[0] & 0xffffU) >> 1;
  local_40 = (double)CONCAT44(0x43300000,(uVar11 & 0xffff) * uVar1 ^ 0x80000000);
  uVar7 = (uint)((float)(local_40 - DOUBLE_803e0550) * FLOAT_803e0548);
  local_38 = (double)(longlong)(int)uVar7;
  uVar7 = uVar7 & 0xffff;
  if (uVar7 == uVar1) {
    FUN_8025d3d4(&local_a4,&local_a0,&local_9c,&local_98);
    FUN_8025d324(0,0,0x280,0x1e0);
    local_38 = (double)(longlong)(int)FLOAT_803dd420;
    local_a8 = (int)FLOAT_803dd420 & 0xffU | (uint)CONCAT21(CONCAT11(in_r6,in_r8),in_r7) << 8;
    local_94 = local_a8;
    FUN_800753b8(local_a4,local_a0,local_9c,local_98,&local_94);
    FUN_8025d324(local_a4,local_a0,local_9c,local_98);
  }
  else {
    uVar10 = uVar1 - uVar7 & 0xffff;
    uVar8 = uVar1 + uVar7 & 0xffff;
    uVar7 = (uVar1 - 1) - uVar7 & 0xffff;
    FUN_8025d324();
    local_68 = uVar12 & 0xff | 0xffffff00;
    local_6c = local_68;
    FUN_800753b8(local_48[0] + uVar7 + 1,local_4c,local_48[0] + uVar8,local_54,&local_6c);
    uVar4 = uVar10 / (uVar1 / 6) & 0xff;
    if (uVar4 == 0) {
      uVar4 = 1;
    }
    uVar2 = uVar12 & 0xff;
    for (uVar9 = 0; uVar3 = uVar9 & 0xffff, (int)uVar3 < (int)(uVar10 - uVar4);
        uVar9 = uVar9 + uVar4) {
      local_68 = (int)(uVar2 * (uVar1 - uVar3)) / (int)uVar1 & 0xffU | 0xffffff00;
      local_70 = local_68;
      iVar6 = local_48[0] + (uVar8 & 0xffff);
      FUN_800753b8(iVar6,local_4c,uVar4 + iVar6,local_54,&local_70);
      local_74 = local_68;
      iVar6 = local_48[0] + (uVar7 & 0xffff);
      FUN_800753b8((iVar6 - uVar4) + 1,local_4c,iVar6 + 1,local_54,&local_74);
      uVar8 = uVar8 + uVar4;
      uVar7 = uVar7 - uVar4;
    }
    local_68 = (int)(uVar2 * (uVar1 - uVar3)) / (int)uVar1 & 0xffU | 0xffffff00;
    local_78 = local_68;
    FUN_800753b8(local_48[0] + (uVar8 & 0xffff),local_4c,local_50,local_54,&local_78);
    local_7c = local_68;
    FUN_800753b8(local_48[0],local_4c,local_48[0] + (uVar7 & 0xffff) + 1,local_54,&local_7c);
    uVar7 = uVar5 >> 1;
    local_38 = (double)CONCAT44(0x43300000,(uVar11 & 0xffff) * uVar7 ^ 0x80000000);
    uVar11 = (uint)((float)(local_38 - DOUBLE_803e0550) * FLOAT_803e0548);
    local_40 = (double)(longlong)(int)uVar11;
    uVar11 = uVar11 & 0xffff;
    uVar1 = uVar7 - uVar11 & 0xffff;
    uVar10 = uVar7 + uVar11 & 0xffff;
    uVar11 = (uVar7 - 1) - uVar11 & 0xffff;
    local_68 = uVar12 & 0xff | 0xffffff00;
    local_80 = local_68;
    FUN_800753b8(local_48[0],local_4c + uVar11 + 1,local_50,local_4c + uVar10,&local_80);
    uVar5 = uVar1 / (uVar5 >> 4) & 0xff;
    if (uVar5 == 0) {
      uVar5 = 1;
    }
    for (uVar12 = 0; uVar8 = uVar12 & 0xffff, (int)uVar8 < (int)(uVar1 - uVar5);
        uVar12 = uVar12 + uVar5) {
      local_68 = (int)(uVar2 * (uVar7 - uVar8)) / (int)uVar7 & 0xffU | 0xffffff00;
      local_84 = local_68;
      iVar6 = local_4c + (uVar10 & 0xffff);
      FUN_800753b8(local_48[0],iVar6,local_50,uVar5 + iVar6,&local_84);
      local_88 = local_68;
      iVar6 = local_4c + (uVar11 & 0xffff);
      FUN_800753b8(local_48[0],(iVar6 - uVar5) + 1,local_50,iVar6 + 1,&local_88);
      uVar10 = uVar10 + uVar5;
      uVar11 = uVar11 - uVar5;
    }
    local_68 = (int)(uVar2 * (uVar7 - uVar8)) / (int)uVar7 & 0xffU | 0xffffff00;
    local_8c = local_68;
    FUN_800753b8(local_48[0],local_4c + (uVar10 & 0xffff),local_50,local_54,&local_8c);
    local_90 = local_68;
    FUN_800753b8(local_48[0],local_4c,local_50,local_4c + (uVar11 & 0xffff) + 1,&local_90);
    FUN_8025d324(local_58,local_5c,local_60,local_64);
  }
  FUN_80286114();
  return;
}

