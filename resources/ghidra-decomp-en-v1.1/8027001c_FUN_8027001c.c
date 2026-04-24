// Function: FUN_8027001c
// Entry: 8027001c
// Size: 980 bytes

uint FUN_8027001c(undefined2 param_1,int param_2,undefined4 param_3,undefined4 param_4,uint param_5,
                 byte param_6,uint param_7,uint param_8,byte param_9,undefined param_10,
                 ushort param_11,undefined2 param_12,int param_13,undefined param_14,
                 undefined param_15,int param_16)

{
  ushort uVar1;
  byte bVar2;
  uint uVar3;
  uint uVar4;
  ushort *puVar5;
  uint uVar6;
  uint uVar7;
  int iVar8;
  int iVar9;
  uint uVar10;
  uint uVar11;
  short sVar12;
  uint unaff_r29;
  uint unaff_r31;
  undefined4 local_64;
  short local_60;
  byte local_5e;
  uint local_5c;
  uint local_58;
  int local_54;
  uint local_50;
  
  uVar11 = 0xffffffff;
  local_5e = param_6;
  puVar5 = (ushort *)FUN_8027588c(param_1,&local_60);
  if (puVar5 != (ushort *)0x0) {
    local_58 = param_7 & 0xff;
    uVar3 = param_5 & 0x7f;
    local_5c = (uint)local_5e;
    uVar4 = param_5 & 0x80;
    local_50 = 0x8000;
    local_54 = -0x7efdfbf7;
    for (; local_60 != 0; local_60 = local_60 + -1) {
      if (((*puVar5 != 0xffff) && (*(byte *)(puVar5 + 1) <= uVar3)) &&
         (uVar3 <= *(byte *)((int)puVar5 + 3))) {
        uVar6 = uVar3 + (int)*(char *)(puVar5 + 2);
        if ((int)uVar6 < 0x80) {
          if ((int)uVar6 < 0) {
            uVar6 = 0;
          }
        }
        else {
          uVar6 = 0x7f;
        }
        if ((*puVar5 & 0xc000) == 0) {
          uVar7 = FUN_80282288(0x41,param_8,(uint)param_9);
          if ((uVar7 & 0xffff) < 0x1f81) {
            unaff_r29 = 0xffffffff;
            uVar7 = 1;
          }
          else {
            unaff_r29 = uVar6 & 0x7f;
            param_8 = FUN_8026fd94((byte)unaff_r29,(char)param_8,param_9,0,&local_64);
            uVar7 = countLeadingZeros(local_64);
            uVar7 = uVar7 >> 5;
          }
          if (uVar7 != 0) {
            if (unaff_r29 == 0xffffffff) goto LAB_80270170;
            goto LAB_80270314;
          }
        }
        else {
LAB_80270170:
          if ((*(byte *)(puVar5 + 4) & 0x80) == 0) {
            uVar7 = (*(byte *)(puVar5 + 4) - 0x40) + local_58;
            if ((int)uVar7 < 0) {
              uVar7 = 0;
            }
            else if (0x7f < (int)uVar7) {
              uVar7 = 0x7f;
            }
          }
          else {
            uVar7 = 0x80;
          }
          iVar8 = local_5c * *(byte *)((int)puVar5 + 5);
          iVar8 = (int)((ulonglong)((longlong)local_54 * (longlong)iVar8) >> 0x20) + iVar8;
          sVar12 = (short)param_2 + puVar5[3];
          bVar2 = (char)(iVar8 >> 6) - (char)(iVar8 >> 0x1f);
          if (sVar12 < 0x100) {
            if (sVar12 < 0) {
              sVar12 = 0;
            }
          }
          else {
            sVar12 = 0xff;
          }
          uVar1 = *puVar5;
          param_2 = (int)sVar12;
          uVar10 = uVar1 & 0xc000;
          if (uVar10 == 0x4000) {
            unaff_r29 = FUN_802703f0(uVar1,sVar12,param_3,param_4,uVar6 | uVar4,bVar2,uVar7 & 0xff,
                                     param_8,param_9,param_10,param_11,param_12,0,param_14,param_15,
                                     param_16);
          }
          else if (uVar10 < 0x4000) {
            if ((uVar1 & 0xc000) == 0) {
              unaff_r29 = FUN_802792f8((uint)uVar1,(byte)sVar12,(byte)param_3,(short)param_4,
                                       (byte)uVar6 | (byte)uVar4,bVar2,(char)uVar7,param_8,param_9,
                                       param_10,param_11,(char)param_12,0,param_14,param_15,param_16
                                      );
            }
          }
          else if (uVar10 == local_50) {
            unaff_r29 = FUN_8027001c(uVar1,param_2,param_3,param_4,uVar6 | uVar4,bVar2,uVar7 & 0xff,
                                     param_8,param_9,param_10,param_11,param_12,0,param_14,param_15,
                                     param_16);
          }
          if (unaff_r29 != 0xffffffff) {
LAB_80270314:
            if (uVar11 == 0xffffffff) {
              unaff_r31 = unaff_r29;
              uVar11 = unaff_r29;
              if (param_13 != 0) {
                uVar11 = FUN_80279af0(DAT_803deee8 + (unaff_r29 & 0xff) * 0x404);
              }
            }
            else {
              *(uint *)(DAT_803deee8 + (unaff_r31 & 0xff) * 0x404 + 0xec) = unaff_r29;
              *(uint *)(DAT_803deee8 + (unaff_r29 & 0xff) * 0x404 + 0xf0) = unaff_r31;
              unaff_r31 = unaff_r29;
            }
            while( true ) {
              iVar9 = (unaff_r31 & 0xff) * 0x404;
              iVar8 = DAT_803deee8 + iVar9;
              if (*(int *)(iVar8 + 0xec) == -1) break;
              *(undefined *)(iVar8 + 0x11c) = 1;
              unaff_r31 = *(uint *)(DAT_803deee8 + iVar9 + 0xec);
            }
            *(undefined *)(iVar8 + 0x11c) = 1;
          }
        }
      }
      puVar5 = puVar5 + 6;
    }
  }
  return uVar11;
}

