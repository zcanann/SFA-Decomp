// Function: FUN_8003dc50
// Entry: 8003dc50
// Size: 1040 bytes

void FUN_8003dc50(void)

{
  byte bVar1;
  char cVar2;
  ushort uVar3;
  bool bVar4;
  int iVar5;
  undefined4 uVar6;
  int iVar7;
  undefined4 uVar8;
  undefined4 *puVar9;
  undefined1 *puVar10;
  int iVar11;
  undefined8 uVar12;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  uint local_50;
  undefined4 local_4c;
  uint local_48;
  undefined4 local_44;
  int local_40;
  undefined4 local_3c [15];
  
  uVar12 = FUN_802860dc();
  iVar11 = (int)((ulonglong)uVar12 >> 0x20);
  iVar5 = (int)uVar12;
  local_40 = 0;
  DAT_803dcc5c = 0;
  bVar1 = *(byte *)(iVar11 + 0x24);
  if ((bVar1 & 0x10) == 0) {
    uVar8 = 0;
  }
  else {
    uVar8 = 4;
  }
  if ((*(ushort *)(iVar11 + 0xe2) & 2) == 0) {
    FUN_8001e8f4(0);
    FUN_8001e608(uVar8,0,(bVar1 & 2) != 0);
    uVar3 = *(ushort *)(iVar11 + 0xe2);
    if ((uVar3 & 9) == 0) {
      if ((uVar3 & 0xc) == 0) {
        uVar6 = 6;
        cVar2 = *(char *)(*(int *)(iVar5 + 0x50) + 0x8d);
        if (cVar2 == '\0') {
          FUN_80089970(*(undefined *)(iVar5 + 0xf2));
          FUN_8008991c(*(undefined *)(iVar5 + 0xf2),&local_44,(int)&local_44 + 1,(int)&local_44 + 2)
          ;
        }
        else {
          FUN_8001efb8(cVar2,&local_44,(int)&local_44 + 1,(int)&local_44 + 2);
        }
        local_44 = local_44 & 0xffffff00;
        local_50 = local_44;
        FUN_80259b88(uVar8,&local_50);
      }
      else {
        uVar6 = 2;
        local_4c = DAT_803db46c;
        FUN_80259b88(uVar8,&local_4c);
      }
      cVar2 = *(char *)(*(int *)(iVar5 + 0x50) + 0x8c);
      if (cVar2 != '\0') {
        FUN_8001ec94(iVar5,local_3c,cVar2,&local_40,uVar6);
      }
      if (local_40 == 0) {
        local_54 = DAT_803db46c;
        FUN_80259cf0(uVar8,&local_54);
      }
      else {
        local_58 = DAT_803db468;
        FUN_80259cf0(uVar8,&local_58);
      }
      puVar9 = local_3c;
      for (iVar7 = 0; iVar7 < local_40; iVar7 = iVar7 + 1) {
        FUN_8001e4a4(uVar8,*puVar9,iVar5);
        puVar9 = puVar9 + 1;
      }
    }
    else if ((uVar3 & 1) == 0) {
      local_60 = DAT_803db46c;
      FUN_80259cf0(uVar8,&local_60);
    }
    else {
      local_5c = DAT_803db468;
      FUN_80259cf0(uVar8,&local_5c);
    }
    if (*(char *)(iVar11 + 0xfa) != '\0') {
      FUN_8001ec94(iVar5,&DAT_803dcc64,*(char *)(iVar11 + 0xfa),&DAT_803dcc5c,8);
      if (((*(byte *)(*(int *)(iVar5 + 0x50) + 0x5f) & 4) != 0) || (DAT_803dcc4c != '\0')) {
        DAT_803dcc5c = 0;
      }
      bVar4 = false;
      puVar9 = &DAT_803dcc64;
      puVar10 = &DAT_803dcc60;
      for (iVar11 = 0; iVar11 < DAT_803dcc5c; iVar11 = iVar11 + 1) {
        iVar7 = FUN_8001db1c(*puVar9);
        if ((bVar4) || (iVar7 != 1)) {
          if (iVar11 == 0) {
            *puVar10 = 2;
          }
          else {
            *puVar10 = 3;
          }
        }
        else {
          *puVar10 = 1;
          bVar4 = true;
        }
        FUN_8001e608(*puVar10,2,0);
        FUN_8001e4a4(*puVar10,*puVar9,iVar5);
        local_64 = DAT_803db470;
        FUN_80259b88(*puVar10,&local_64);
        local_68 = DAT_803db468;
        FUN_80259cf0(*puVar10,&local_68);
        puVar9 = puVar9 + 1;
        puVar10 = puVar10 + 1;
      }
    }
    FUN_8001e634();
    bVar1 = *(byte *)(*(int *)(iVar5 + 0x50) + 0x5f);
    if (((bVar1 & 4) == 0) && (DAT_803dcc4c == '\0')) {
      if ((bVar1 & 0x11) != 0) {
        DAT_803dcc5c = 1;
      }
    }
    else {
      DAT_803dcc5c = 2;
    }
  }
  else if (((bVar1 & 2) == 0) && ((bVar1 & 0x10) == 0)) {
    FUN_80259ea4(4,0,0,0,0,0,2);
    FUN_80259ea4(5,0,0,0,0,0,2);
    FUN_80259e58(0);
  }
  else {
    DAT_803dcc54 = DAT_803dcc54 & 0xffffff00;
    local_48 = DAT_803dcc54;
    FUN_80259b88(uVar8,&local_48);
    FUN_80259ea4(0,1,0,1,0,0,2);
    FUN_80259ea4(2,0,0,1,0,0,2);
    FUN_80259e58(1);
  }
  FUN_80286128();
  return;
}

