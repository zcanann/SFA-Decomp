// Function: FUN_800d77f4
// Entry: 800d77f4
// Size: 1288 bytes

void FUN_800d77f4(void)

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
  undefined4 local_a8;
  int local_a4;
  int local_a0;
  int local_9c;
  int local_98;
  undefined4 local_94;
  undefined4 local_90;
  undefined4 local_8c;
  undefined4 local_88;
  undefined4 local_84;
  undefined4 local_80;
  undefined4 local_7c;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  int local_64;
  int local_60;
  int local_5c;
  int local_58;
  int local_54;
  uint local_50;
  int local_4c;
  int local_48 [2];
  undefined8 local_40;
  undefined8 local_38;
  
  FUN_8028682c();
  FUN_8025db38(&local_58,&local_5c,&local_60,&local_64);
  FUN_8000f3f8(local_48,&local_4c,&local_50,&local_54);
  uVar5 = local_54 - local_4c & 0xffff;
  if (FLOAT_803de0a0 <= FLOAT_803e11c0) {
    uVar12 = (uint)(FLOAT_803e11c4 * FLOAT_803de0a0);
    uVar11 = 0;
  }
  else {
    uVar12 = 0xff;
    uVar11 = (uint)(FLOAT_803de0a0 - FLOAT_803e11c0);
  }
  uVar1 = (local_50 - local_48[0] & 0xffff) >> 1;
  local_40 = (double)CONCAT44(0x43300000,(uVar11 & 0xffff) * uVar1 ^ 0x80000000);
  uVar7 = (uint)((float)(local_40 - DOUBLE_803e11d0) * FLOAT_803e11c8);
  local_38 = (double)(longlong)(int)uVar7;
  uVar7 = uVar7 & 0xffff;
  if (uVar7 == uVar1) {
    FUN_8025db38(&local_a4,&local_a0,&local_9c,&local_98);
    FUN_8025da88(0,0,0x280,0x1e0);
    local_38 = (double)(longlong)(int)FLOAT_803de0a0;
    local_a8 = CONCAT31(CONCAT21(CONCAT11(in_r6,in_r8),in_r7),(char)(int)FLOAT_803de0a0);
    local_94 = local_a8;
    FUN_80075534(local_a4,local_a0,local_9c,local_98,&local_94);
    FUN_8025da88(local_a4,local_a0,local_9c,local_98);
  }
  else {
    uVar10 = uVar1 - uVar7 & 0xffff;
    uVar8 = uVar1 + uVar7 & 0xffff;
    uVar7 = (uVar1 - 1) - uVar7 & 0xffff;
    FUN_8025da88(local_48[0],local_4c,local_50 - local_48[0],local_54 - local_4c);
    local_68 = CONCAT31(0xffffff,(char)uVar12);
    local_6c = local_68;
    FUN_80075534(local_48[0] + uVar7 + 1,local_4c,local_48[0] + uVar8,local_54,&local_6c);
    uVar4 = uVar10 / (uVar1 / 6) & 0xff;
    if (uVar4 == 0) {
      uVar4 = 1;
    }
    uVar2 = uVar12 & 0xff;
    for (uVar9 = 0; uVar3 = uVar9 & 0xffff, (int)uVar3 < (int)(uVar10 - uVar4);
        uVar9 = uVar9 + uVar4) {
      local_68 = CONCAT31(0xffffff,(char)((int)(uVar2 * (uVar1 - uVar3)) / (int)uVar1));
      local_70 = local_68;
      iVar6 = local_48[0] + (uVar8 & 0xffff);
      FUN_80075534(iVar6,local_4c,uVar4 + iVar6,local_54,&local_70);
      local_74 = local_68;
      iVar6 = local_48[0] + (uVar7 & 0xffff);
      FUN_80075534((iVar6 - uVar4) + 1,local_4c,iVar6 + 1,local_54,&local_74);
      uVar8 = uVar8 + uVar4;
      uVar7 = uVar7 - uVar4;
    }
    local_68 = CONCAT31(0xffffff,(char)((int)(uVar2 * (uVar1 - uVar3)) / (int)uVar1));
    local_78 = local_68;
    FUN_80075534(local_48[0] + (uVar8 & 0xffff),local_4c,local_50,local_54,&local_78);
    local_7c = local_68;
    FUN_80075534(local_48[0],local_4c,local_48[0] + (uVar7 & 0xffff) + 1,local_54,&local_7c);
    uVar7 = uVar5 >> 1;
    local_38 = (double)CONCAT44(0x43300000,(uVar11 & 0xffff) * uVar7 ^ 0x80000000);
    uVar11 = (uint)((float)(local_38 - DOUBLE_803e11d0) * FLOAT_803e11c8);
    local_40 = (double)(longlong)(int)uVar11;
    uVar11 = uVar11 & 0xffff;
    uVar1 = uVar7 - uVar11 & 0xffff;
    uVar10 = uVar7 + uVar11 & 0xffff;
    uVar11 = (uVar7 - 1) - uVar11 & 0xffff;
    local_68 = CONCAT31(0xffffff,(char)uVar12);
    local_80 = local_68;
    FUN_80075534(local_48[0],local_4c + uVar11 + 1,local_50,local_4c + uVar10,&local_80);
    uVar5 = uVar1 / (uVar5 >> 4) & 0xff;
    if (uVar5 == 0) {
      uVar5 = 1;
    }
    for (uVar12 = 0; uVar8 = uVar12 & 0xffff, (int)uVar8 < (int)(uVar1 - uVar5);
        uVar12 = uVar12 + uVar5) {
      local_68 = CONCAT31(0xffffff,(char)((int)(uVar2 * (uVar7 - uVar8)) / (int)uVar7));
      local_84 = local_68;
      iVar6 = local_4c + (uVar10 & 0xffff);
      FUN_80075534(local_48[0],iVar6,local_50,uVar5 + iVar6,&local_84);
      local_88 = local_68;
      iVar6 = local_4c + (uVar11 & 0xffff);
      FUN_80075534(local_48[0],(iVar6 - uVar5) + 1,local_50,iVar6 + 1,&local_88);
      uVar10 = uVar10 + uVar5;
      uVar11 = uVar11 - uVar5;
    }
    local_68 = CONCAT31(0xffffff,(char)((int)(uVar2 * (uVar7 - uVar8)) / (int)uVar7));
    local_8c = local_68;
    FUN_80075534(local_48[0],local_4c + (uVar10 & 0xffff),local_50,local_54,&local_8c);
    local_90 = local_68;
    FUN_80075534(local_48[0],local_4c,local_50,local_4c + (uVar11 & 0xffff) + 1,&local_90);
    FUN_8025da88(local_58,local_5c,local_60,local_64);
  }
  FUN_80286878();
  return;
}

