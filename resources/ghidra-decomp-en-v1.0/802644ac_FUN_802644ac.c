// Function: FUN_802644ac
// Entry: 802644ac
// Size: 580 bytes

char FUN_802644ac(int param_1,int param_2,int param_3,int param_4,int param_5)

{
  byte bVar1;
  bool bVar2;
  uint uVar3;
  char *pcVar4;
  byte *pbVar5;
  char cVar6;
  byte **ppbVar7;
  
  if (param_1 == 0) {
    cVar6 = '\x19';
  }
  else if (((param_2 == 0) || (param_3 == 0)) || (param_4 == 0)) {
    cVar6 = '\x1b';
  }
  else if (param_5 == 0) {
    cVar6 = '\x1a';
  }
  else {
    uVar3 = FUN_80240384();
    if ((uVar3 & 0x10000000) == 0) {
      cVar6 = '\x1c';
    }
    else if (DAT_803de214 == 0) {
      cVar6 = '\x1d';
    }
    else {
      DAT_803de210 = param_5 + 0x1fU & 0xffffffe0;
      DAT_803de20c = DAT_803de210 + 0x6bc;
      FUN_80241ab0(DAT_803de210,0x6bc);
      *(undefined4 *)(DAT_803de210 + 0x6a4) = 0x21;
      bVar2 = false;
      *(undefined2 *)(DAT_803de210 + 0x698) = 0;
      *(int *)(DAT_803de210 + 0x69c) = param_1;
      do {
        pcVar4 = *(char **)(DAT_803de210 + 0x69c);
        *(char **)(DAT_803de210 + 0x69c) = pcVar4 + 1;
        if (*pcVar4 != -1) {
          return '\x03';
        }
        while( true ) {
          ppbVar7 = (byte **)(DAT_803de210 + 0x69c);
          pbVar5 = *(byte **)(DAT_803de210 + 0x69c);
          if (*pbVar5 != 0xff) break;
          *ppbVar7 = *ppbVar7 + 1;
        }
        *ppbVar7 = pbVar5 + 1;
        bVar1 = *pbVar5;
        if (bVar1 < 0xd8) {
          if (bVar1 == 0xc4) {
            cVar6 = FUN_80264d48();
          }
          else {
            if (bVar1 != 0xc0) {
              return '\v';
            }
            cVar6 = FUN_80264734();
          }
joined_r0x802645d8:
          if (cVar6 != '\0') {
            return cVar6;
          }
        }
        else if ((bVar1 < 0xd8) || (0xdf < bVar1)) {
          if (bVar1 >= 0xe0) {
            if (((bVar1 < 0xe0) || (0xef < bVar1)) && (bVar1 != 0xfe)) {
              return '\v';
            }
            *(uint *)(DAT_803de210 + 0x69c) =
                 (int)*(ushort **)(DAT_803de210 + 0x69c) + (uint)**(ushort **)(DAT_803de210 + 0x69c)
            ;
          }
        }
        else if (bVar1 == 0xdd) {
          FUN_8026523c();
        }
        else {
          if (bVar1 == 0xdb) {
            cVar6 = FUN_8026498c();
            goto joined_r0x802645d8;
          }
          if (bVar1 == 0xda) {
            cVar6 = FUN_80264870();
            if (cVar6 != '\0') {
              return cVar6;
            }
            bVar2 = true;
          }
          else if (bVar1 != 0xd8) {
            return '\v';
          }
        }
      } while (!bVar2);
      FUN_802646f0();
      FUN_802654dc(param_2,param_3,param_4);
      cVar6 = '\0';
    }
  }
  return cVar6;
}

