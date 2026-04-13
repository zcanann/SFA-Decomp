// Function: FUN_8003dd48
// Entry: 8003dd48
// Size: 1040 bytes

void FUN_8003dd48(void)

{
  byte bVar1;
  ushort uVar2;
  bool bVar3;
  int iVar4;
  uint uVar5;
  uint uVar6;
  int iVar7;
  int iVar8;
  undefined4 *puVar9;
  int *piVar10;
  byte *pbVar11;
  int iVar12;
  undefined8 uVar13;
  uint local_68;
  uint local_64;
  uint local_60;
  uint local_5c;
  uint local_58;
  uint local_54;
  uint local_50;
  uint local_4c;
  uint local_48;
  undefined4 local_44;
  int local_40;
  undefined4 local_3c [15];
  
  uVar13 = FUN_80286840();
  iVar12 = (int)((ulonglong)uVar13 >> 0x20);
  iVar4 = (int)uVar13;
  local_40 = 0;
  DAT_803dd8dc = 0;
  bVar1 = *(byte *)(iVar12 + 0x24);
  if ((bVar1 & 0x10) == 0) {
    iVar8 = 0;
  }
  else {
    iVar8 = 4;
  }
  if ((*(ushort *)(iVar12 + 0xe2) & 2) == 0) {
    FUN_8001e9b8(0);
    FUN_8001e6cc(iVar8,0,(uint)((bVar1 & 2) != 0));
    uVar2 = *(ushort *)(iVar12 + 0xe2);
    if ((uVar2 & 9) == 0) {
      if ((uVar2 & 0xc) == 0) {
        uVar6 = 6;
        uVar5 = (uint)*(byte *)(*(int *)(iVar4 + 0x50) + 0x8d);
        if (uVar5 == 0) {
          FUN_80089bfc((uint)*(byte *)(iVar4 + 0xf2));
          FUN_80089ba8((uint)*(byte *)(iVar4 + 0xf2),(undefined *)&local_44,
                       (undefined *)((int)&local_44 + 1),(undefined *)((int)&local_44 + 2));
        }
        else {
          FUN_8001f07c(uVar5,(undefined *)&local_44,(undefined *)((int)&local_44 + 1),
                       (undefined *)((int)&local_44 + 2));
        }
        local_44 = local_44 & 0xffffff00;
        local_50 = local_44;
        FUN_8025a2ec(iVar8,&local_50);
      }
      else {
        uVar6 = 2;
        local_4c = DAT_803dc0cc;
        FUN_8025a2ec(iVar8,&local_4c);
      }
      uVar5 = (uint)*(byte *)(*(int *)(iVar4 + 0x50) + 0x8c);
      if (uVar5 != 0) {
        FUN_8001ed58(iVar4,local_3c,uVar5,&local_40,uVar6);
      }
      if (local_40 == 0) {
        local_54 = DAT_803dc0cc;
        FUN_8025a454(iVar8,&local_54);
      }
      else {
        local_58 = DAT_803dc0c8;
        FUN_8025a454(iVar8,&local_58);
      }
      puVar9 = local_3c;
      for (iVar7 = 0; iVar7 < local_40; iVar7 = iVar7 + 1) {
        FUN_8001e568(iVar8,*puVar9,iVar4);
        puVar9 = puVar9 + 1;
      }
    }
    else if ((uVar2 & 1) == 0) {
      local_60 = DAT_803dc0cc;
      FUN_8025a454(iVar8,&local_60);
    }
    else {
      local_5c = DAT_803dc0c8;
      FUN_8025a454(iVar8,&local_5c);
    }
    if (*(byte *)(iVar12 + 0xfa) != 0) {
      FUN_8001ed58(iVar4,&DAT_803dd8e4,(uint)*(byte *)(iVar12 + 0xfa),&DAT_803dd8dc,8);
      if (((*(byte *)(*(int *)(iVar4 + 0x50) + 0x5f) & 4) != 0) || (DAT_803dd8cc != '\0')) {
        DAT_803dd8dc = 0;
      }
      bVar3 = false;
      piVar10 = &DAT_803dd8e4;
      pbVar11 = &DAT_803dd8e0;
      for (iVar12 = 0; iVar12 < DAT_803dd8dc; iVar12 = iVar12 + 1) {
        iVar8 = FUN_8001dbe0(*piVar10);
        if ((bVar3) || (iVar8 != 1)) {
          if (iVar12 == 0) {
            *pbVar11 = 2;
          }
          else {
            *pbVar11 = 3;
          }
        }
        else {
          *pbVar11 = 1;
          bVar3 = true;
        }
        FUN_8001e6cc((uint)*pbVar11,2,0);
        FUN_8001e568((uint)*pbVar11,*piVar10,iVar4);
        local_64 = DAT_803dc0d0;
        FUN_8025a2ec((uint)*pbVar11,&local_64);
        local_68 = DAT_803dc0c8;
        FUN_8025a454((uint)*pbVar11,&local_68);
        piVar10 = piVar10 + 1;
        pbVar11 = pbVar11 + 1;
      }
    }
    FUN_8001e6f8();
    bVar1 = *(byte *)(*(int *)(iVar4 + 0x50) + 0x5f);
    if (((bVar1 & 4) == 0) && (DAT_803dd8cc == '\0')) {
      if ((bVar1 & 0x11) != 0) {
        DAT_803dd8dc = 1;
      }
    }
    else {
      DAT_803dd8dc = 2;
    }
  }
  else if (((bVar1 & 2) == 0) && ((bVar1 & 0x10) == 0)) {
    FUN_8025a608(4,0,0,0,0,0,2);
    FUN_8025a608(5,0,0,0,0,0,2);
    FUN_8025a5bc(0);
  }
  else {
    DAT_803dd8d4 = DAT_803dd8d4 & 0xffffff00;
    local_48 = DAT_803dd8d4;
    FUN_8025a2ec(iVar8,&local_48);
    FUN_8025a608(0,1,0,1,0,0,2);
    FUN_8025a608(2,0,0,1,0,0,2);
    FUN_8025a5bc(1);
  }
  FUN_8028688c();
  return;
}

