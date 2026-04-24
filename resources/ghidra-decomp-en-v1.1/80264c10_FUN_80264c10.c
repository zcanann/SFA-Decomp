// Function: FUN_80264c10
// Entry: 80264c10
// Size: 580 bytes

uint FUN_80264c10(int param_1,int param_2,int param_3,int param_4,int param_5)

{
  byte bVar1;
  bool bVar2;
  uint uVar3;
  char *pcVar4;
  byte *pbVar5;
  int *piVar6;
  
  if (param_1 == 0) {
    uVar3 = 0x19;
  }
  else if (((param_2 == 0) || (param_3 == 0)) || (param_4 == 0)) {
    uVar3 = 0x1b;
  }
  else if (param_5 == 0) {
    uVar3 = 0x1a;
  }
  else {
    uVar3 = FUN_80240a7c();
    if ((uVar3 & 0x10000000) == 0) {
      uVar3 = 0x1c;
    }
    else if (DAT_803dee94 == 0) {
      uVar3 = 0x1d;
    }
    else {
      DAT_803dee90 = param_5 + 0x1fU & 0xffffffe0;
      DAT_803dee8c = DAT_803dee90 + 0x6bc;
      FUN_802421a8(DAT_803dee90,0x6bc);
      *(undefined4 *)(DAT_803dee90 + 0x6a4) = 0x21;
      bVar2 = false;
      *(undefined2 *)(DAT_803dee90 + 0x698) = 0;
      *(int *)(DAT_803dee90 + 0x69c) = param_1;
      do {
        pcVar4 = *(char **)(DAT_803dee90 + 0x69c);
        *(char **)(DAT_803dee90 + 0x69c) = pcVar4 + 1;
        if (*pcVar4 != -1) {
          return 3;
        }
        while( true ) {
          piVar6 = (int *)(DAT_803dee90 + 0x69c);
          pbVar5 = *(byte **)(DAT_803dee90 + 0x69c);
          if (*pbVar5 != 0xff) break;
          *piVar6 = *piVar6 + 1;
        }
        *piVar6 = (int)(pbVar5 + 1);
        bVar1 = *pbVar5;
        if (bVar1 < 0xd8) {
          if (bVar1 == 0xc4) {
            uVar3 = FUN_802654ac();
          }
          else {
            if (bVar1 != 0xc0) {
              return 0xb;
            }
            uVar3 = FUN_80264e98();
          }
joined_r0x80264d3c:
          if ((uVar3 & 0xff) != 0) {
LAB_80264e2c:
            return uVar3 & 0xff;
          }
        }
        else if ((bVar1 < 0xd8) || (0xdf < bVar1)) {
          if (bVar1 >= 0xe0) {
            if (((bVar1 < 0xe0) || (0xef < bVar1)) && (bVar1 != 0xfe)) {
              return 0xb;
            }
            *(uint *)(DAT_803dee90 + 0x69c) =
                 (int)*(ushort **)(DAT_803dee90 + 0x69c) + (uint)**(ushort **)(DAT_803dee90 + 0x69c)
            ;
          }
        }
        else if (bVar1 == 0xdd) {
          FUN_802659a0();
        }
        else {
          if (bVar1 == 0xdb) {
            uVar3 = FUN_802650f0();
            goto joined_r0x80264d3c;
          }
          if (bVar1 == 0xda) {
            uVar3 = FUN_80264fd4();
            if ((uVar3 & 0xff) != 0) goto LAB_80264e2c;
            bVar2 = true;
          }
          else if (bVar1 != 0xd8) {
            return 0xb;
          }
        }
      } while (!bVar2);
      FUN_80264e54();
      FUN_80265c40(param_2,param_3,param_4);
      uVar3 = 0;
    }
  }
  return uVar3;
}

