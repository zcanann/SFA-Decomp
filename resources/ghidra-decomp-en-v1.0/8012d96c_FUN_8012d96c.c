// Function: FUN_8012d96c
// Entry: 8012d96c
// Size: 936 bytes

void FUN_8012d96c(void)

{
  bool bVar1;
  int iVar2;
  int iVar3;
  int iVar4;
  ushort uVar5;
  char cVar6;
  char cVar7;
  uint uVar8;
  byte bVar9;
  int iVar10;
  byte *pbVar11;
  
  uVar5 = DAT_803dd776;
  if ((DAT_803dd776 != 0) && ((DAT_803dd776 < 0x78 || (0x82 < DAT_803dd776)))) {
    DAT_803dd776 = 0x78;
    if ((short)uVar5 < 0x1e) {
      iVar10 = 0;
      pbVar11 = &DAT_803dba94;
      do {
        iVar2 = FUN_8001ffb4(*(undefined2 *)(&DAT_8031b08a + (uint)*pbVar11 * 0x1c));
        if (iVar2 != 0) {
          cVar7 = (&DAT_803dba94)[iVar10];
          goto LAB_8012da0c;
        }
        pbVar11 = pbVar11 + 1;
        iVar10 = iVar10 + 1;
      } while (iVar10 < 5);
      cVar7 = -1;
LAB_8012da0c:
      iVar10 = FUN_8001ffb4(0x63c);
      iVar2 = FUN_8001ffb4(0x4e9);
      iVar3 = FUN_8001ffb4(0x5f3);
      iVar4 = FUN_8001ffb4(0x5f4);
      iVar2 = iVar2 + iVar10 + iVar3 + iVar4;
      iVar10 = FUN_8001ffb4(0x123);
      if (iVar10 != 0) {
        iVar2 = iVar2 + 1;
      }
      iVar10 = FUN_8001ffb4(0x2e8);
      if (iVar10 != 0) {
        iVar2 = iVar2 + 1;
      }
      iVar10 = FUN_8001ffb4(0x83b);
      if (iVar10 != 0) {
        iVar2 = iVar2 + 1;
      }
      iVar10 = FUN_8001ffb4(0x83c);
      if (iVar10 != 0) {
        iVar2 = iVar2 + 1;
      }
      bVar9 = DAT_803dba94;
      if ((((iVar2 < (int)(uint)(byte)(&DAT_8031b08c)[(uint)DAT_803dba94 * 0x1c]) &&
           (bVar9 = bRam803dba95,
           iVar2 < (int)(uint)(byte)(&DAT_8031b08c)[(uint)bRam803dba95 * 0x1c])) &&
          (bVar9 = bRam803dba96, iVar2 < (int)(uint)(byte)(&DAT_8031b08c)[(uint)bRam803dba96 * 0x1c]
          )) && ((bVar9 = bRam803dba97,
                 iVar2 < (int)(uint)(byte)(&DAT_8031b08c)[(uint)bRam803dba97 * 0x1c] &&
                 (bVar9 = bRam803dba98,
                 iVar2 < (int)(uint)(byte)(&DAT_8031b08c)[(uint)bRam803dba98 * 0x1c])))) {
        bVar9 = 0xff;
      }
      uVar5 = FUN_800ea2bc();
      bVar1 = 0xad < uVar5;
      uVar8 = (uint)DAT_803dd77a;
      if ((uVar8 == 2) && (bVar1)) {
        iVar10 = 0x51e4;
      }
      else if (((int)cVar7 == uVar8) && ((int)(char)bVar9 != uVar8)) {
        iVar10 = *(int *)(&DAT_8031b07c + uVar8 * 0x1c);
      }
      else if (uVar8 == 2) {
        cVar6 = (**(code **)(*DAT_803dcaac + 0x40))(0xd);
        if ((cVar6 != '\x02') || (bVar1)) {
          if ((int)cVar7 == (int)(char)bVar9) {
            iVar2 = (char)bVar9 * 0x1c;
            iVar10 = FUN_8001ffb4(*(undefined2 *)(&DAT_8031b08e + iVar2));
            if (iVar10 == 0) {
              iVar10 = *(int *)(&DAT_8031b084 + iVar2);
            }
            else {
              iVar10 = 0x51e6;
            }
          }
          else {
            iVar10 = *(int *)(&DAT_8031b080 + (uint)DAT_803dd77a * 0x1c);
          }
        }
        else {
          iVar10 = 0x51e5;
        }
      }
      else if (((uVar8 != 0) || (cVar7 = (**(code **)(*DAT_803dcaac + 0x40))(0xd), cVar7 != '\x02'))
              || (bVar1)) {
        iVar10 = *(int *)(&DAT_8031b080 + (uint)DAT_803dd77a * 0x1c);
      }
      else {
        iVar10 = 0x51e2;
      }
      if (iVar10 != 0) {
        FUN_8000d200(iVar10,FUN_8000d138);
      }
    }
    if (0xff < DAT_803dd776) {
      DAT_803dd776 = 0;
    }
  }
  return;
}

