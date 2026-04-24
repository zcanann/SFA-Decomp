// Function: FUN_8026f8b8
// Entry: 8026f8b8
// Size: 980 bytes

uint FUN_8026f8b8(undefined4 param_1,uint param_2,undefined4 param_3,undefined4 param_4,uint param_5
                 ,byte param_6,uint param_7,undefined4 param_8,undefined param_9,undefined param_10,
                 undefined2 param_11,undefined2 param_12,int param_13,undefined param_14,
                 undefined param_15,undefined4 param_16)

{
  uint uVar1;
  uint uVar2;
  uint uVar3;
  ushort *puVar4;
  uint uVar5;
  ushort uVar6;
  int iVar7;
  int iVar8;
  uint uVar9;
  uint uVar10;
  short sVar11;
  uint unaff_r29;
  uint unaff_r31;
  undefined4 local_64;
  short local_60;
  byte local_5e;
  uint local_5c;
  uint local_58;
  int local_54;
  uint local_50;
  
  uVar10 = 0xffffffff;
  local_5e = param_6;
  puVar4 = (ushort *)FUN_80275128(param_1,&local_60);
  if (puVar4 != (ushort *)0x0) {
    local_58 = param_7 & 0xff;
    uVar1 = param_5 & 0x7f;
    local_5c = (uint)local_5e;
    param_5 = param_5 & 0x80;
    local_50 = 0x8000;
    local_54 = -0x7efdfbf7;
    for (; local_60 != 0; local_60 = local_60 + -1) {
      if (((*puVar4 != 0xffff) && (*(byte *)(puVar4 + 1) <= uVar1)) &&
         (uVar1 <= *(byte *)((int)puVar4 + 3))) {
        uVar5 = uVar1 + (int)*(char *)(puVar4 + 2);
        if ((int)uVar5 < 0x80) {
          if ((int)uVar5 < 0) {
            uVar5 = 0;
          }
        }
        else {
          uVar5 = 0x7f;
        }
        if ((*puVar4 & 0xc000) == 0) {
          uVar6 = FUN_80281b24(0x41,param_8,param_9);
          if (uVar6 < 0x1f81) {
            unaff_r29 = 0xffffffff;
            uVar3 = 1;
          }
          else {
            unaff_r29 = FUN_8026f630(uVar5 & 0x7f,param_8,param_9,0,&local_64);
            uVar3 = countLeadingZeros(local_64);
            uVar3 = uVar3 >> 5;
          }
          if (uVar3 != 0) {
            if (unaff_r29 == 0xffffffff) goto LAB_8026fa0c;
            goto LAB_8026fbb0;
          }
        }
        else {
LAB_8026fa0c:
          if ((*(byte *)(puVar4 + 4) & 0x80) == 0) {
            uVar3 = (*(byte *)(puVar4 + 4) - 0x40) + local_58;
            if ((int)uVar3 < 0) {
              uVar3 = 0;
            }
            else if (0x7f < (int)uVar3) {
              uVar3 = 0x7f;
            }
          }
          else {
            uVar3 = 0x80;
          }
          iVar7 = local_5c * *(byte *)((int)puVar4 + 5);
          iVar7 = (int)((ulonglong)((longlong)local_54 * (longlong)iVar7) >> 0x20) + iVar7;
          sVar11 = (short)param_2 + puVar4[3];
          uVar2 = (iVar7 >> 6) - (iVar7 >> 0x1f) & 0xff;
          if (sVar11 < 0x100) {
            if (sVar11 < 0) {
              sVar11 = 0;
            }
          }
          else {
            sVar11 = 0xff;
          }
          uVar6 = *puVar4;
          param_2 = (uint)sVar11;
          uVar9 = uVar6 & 0xc000;
          if (uVar9 == 0x4000) {
            unaff_r29 = FUN_8026fc8c(uVar6,param_2,param_3,param_4,uVar5 | param_5,uVar2,
                                     uVar3 & 0xff,param_8,param_9,param_10,param_11,param_12,0,
                                     param_14,param_15,param_16);
          }
          else if (uVar9 < 0x4000) {
            if ((uVar6 & 0xc000) == 0) {
              unaff_r29 = FUN_80278b94(uVar6,param_2 & 0xff,param_3,param_4,uVar5 | param_5,uVar2,
                                       uVar3 & 0xff,param_8,param_9,param_10,param_11,param_12,0,
                                       param_14,param_15,param_16);
            }
          }
          else if (uVar9 == local_50) {
            unaff_r29 = FUN_8026f8b8(uVar6,param_2,param_3,param_4,uVar5 | param_5,uVar2,
                                     uVar3 & 0xff,param_8,param_9,param_10,param_11,param_12,0,
                                     param_14,param_15,param_16);
          }
          if (unaff_r29 != 0xffffffff) {
LAB_8026fbb0:
            if (uVar10 == 0xffffffff) {
              unaff_r31 = unaff_r29;
              uVar10 = unaff_r29;
              if (param_13 != 0) {
                uVar10 = FUN_8027938c(DAT_803de268 + (unaff_r29 & 0xff) * 0x404);
              }
            }
            else {
              *(uint *)(DAT_803de268 + (unaff_r31 & 0xff) * 0x404 + 0xec) = unaff_r29;
              *(uint *)(DAT_803de268 + (unaff_r29 & 0xff) * 0x404 + 0xf0) = unaff_r31;
              unaff_r31 = unaff_r29;
            }
            while( true ) {
              iVar8 = (unaff_r31 & 0xff) * 0x404;
              iVar7 = DAT_803de268 + iVar8;
              if (*(int *)(iVar7 + 0xec) == -1) break;
              *(undefined *)(iVar7 + 0x11c) = 1;
              unaff_r31 = *(uint *)(DAT_803de268 + iVar8 + 0xec);
            }
            *(undefined *)(iVar7 + 0x11c) = 1;
          }
        }
      }
      puVar4 = puVar4 + 6;
    }
  }
  return uVar10;
}

