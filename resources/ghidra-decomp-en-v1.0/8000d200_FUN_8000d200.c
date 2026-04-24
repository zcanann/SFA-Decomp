// Function: FUN_8000d200
// Entry: 8000d200
// Size: 860 bytes

void FUN_8000d200(void)

{
  bool bVar1;
  int iVar2;
  uint uVar3;
  undefined4 uVar4;
  int iVar5;
  int iVar6;
  ushort *puVar7;
  undefined8 uVar8;
  undefined auStack104 [64];
  undefined4 local_28;
  uint uStack36;
  
  uVar8 = FUN_802860d4();
  iVar2 = DAT_803dc854;
  puVar7 = DAT_803dc850;
  uVar3 = (uint)((ulonglong)uVar8 >> 0x20);
  iVar6 = -1;
  if (uVar3 == 0x4cc) {
    uVar4 = 0;
  }
  else {
    if (uVar3 == 0x526) {
      FUN_8000a518(0xa8,0);
      FUN_8000a518(0xf4,1);
    }
    iVar5 = FUN_8000a188(8);
    if (iVar5 == 0) {
      for (; iVar2 != 0; iVar2 = iVar2 + -1) {
        if (*puVar7 == uVar3) {
          iVar2 = ((int)puVar7 - (int)DAT_803dc850) / 0x16 +
                  ((int)puVar7 - (int)DAT_803dc850 >> 0x1f);
          iVar6 = (iVar2 - (iVar2 >> 0x1f)) + 1;
          break;
        }
        puVar7 = puVar7 + 0xb;
      }
      if (iVar6 == -1) {
        uVar4 = 0;
      }
      else if (DAT_803dc849 == '\0') {
        DAT_803dc849 = '\0';
        iVar2 = FUN_8000a200(auStack104,0x40,s__streams__802c5df4,puVar7 + 3,&DAT_803db254);
        if (iVar2 == 0) {
          uVar4 = 0;
        }
        else {
          iVar2 = FUN_80248b9c(auStack104,&DAT_80336cd0);
          if (iVar2 == 0) {
            uVar4 = 0;
          }
          else {
            if (DAT_803dc868 == 0) {
              DAT_803dc848 = '\0';
            }
            else {
              FUN_8024fa90(0);
              FUN_8024fabc(0);
              iVar2 = FUN_8024afd8(&DAT_80336c40,FUN_8000cfe4);
              if (iVar2 == 0) {
                FUN_8007d6dc(s_WARNING_DVDCancelStreamAsync_ret_802c5dc4);
                DAT_803dc848 = '\0';
              }
              DAT_803dc874 = 0;
              DAT_803dc870 = 0;
              DAT_803dc868 = 0;
              DAT_803dc86c = 0;
              DAT_803dc7c8 = 0;
            }
            uStack36 = (uint)puVar7[2];
            local_28 = 0x43300000;
            FLOAT_803dc84c =
                 (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803de5e0) / FLOAT_803de5d4;
            if (FLOAT_803de5d0 == FLOAT_803dc84c) {
              FLOAT_803dc84c = FLOAT_803de5d8;
            }
            DAT_803dc860 = (uint)(*(int *)(&DAT_802c5db8 + (uint)(*(byte *)(puVar7 + 1) >> 6) * 4)
                                 != 0);
            DAT_803dc85c = (uint)(*(int *)(&DAT_802c5db8 + (*(byte *)(puVar7 + 1) >> 4 & 3) * 4) !=
                                 0);
            if ((*(byte *)(puVar7 + 1) >> 2 & 3) != 0) {
              FUN_8000b624();
            }
            if (*(char *)((int)puVar7 + 3) < '\0') {
              DAT_803dc7c8 = 4;
            }
            else {
              DAT_803dc7c8 = 0;
            }
            bVar1 = false;
            while (DAT_803dc848 != '\0') {
              FUN_80014f40();
              FUN_800202cc();
              if (bVar1) {
                FUN_800234ec(0);
                FUN_8004a868();
              }
              FUN_80015624();
              if (bVar1) {
                FUN_80019c24();
                FUN_8004a43c(1,0);
              }
              if (DAT_803dc950 != '\0') {
                bVar1 = true;
                DAT_803dc848 = '\0';
              }
            }
            uVar3 = (int)(((*(byte *)((int)puVar7 + 3) & 0x7f) + 1) * (uint)DAT_803db253) >> 7 &
                    0xff;
            DAT_803db250 = (undefined)uVar3;
            DAT_803db251 = DAT_803db250;
            FUN_8024fa90(uVar3);
            FUN_8024fabc(uVar3);
            DAT_803dc849 = '\x01';
            DAT_803dc864 = (int)uVar8;
            DAT_803dc870 = iVar6;
            FUN_802490d8(&DAT_80336cd0,0,0,FUN_8000d5dc);
            FUN_8024b094(&DAT_80336ca0,0);
            uVar4 = 1;
          }
        }
      }
      else {
        uVar4 = 0;
      }
    }
    else {
      uVar4 = 0;
    }
  }
  FUN_80286120(uVar4);
  return;
}

