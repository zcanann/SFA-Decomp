// Function: FUN_802703f0
// Entry: 802703f0
// Size: 608 bytes

void FUN_802703f0(undefined2 param_1,short param_2,undefined4 param_3,undefined4 param_4,
                 uint param_5,byte param_6,uint param_7,uint param_8,byte param_9,undefined param_10
                 ,ushort param_11,undefined2 param_12,uint param_13,undefined param_14,
                 undefined param_15,int param_16)

{
  ushort uVar1;
  int iVar2;
  int iVar3;
  uint uVar4;
  uint uVar5;
  uint uVar6;
  uint uVar7;
  short sVar8;
  ushort *puVar9;
  undefined4 local_4c [2];
  
  iVar3 = FUN_8027581c(param_1);
  if (iVar3 != 0) {
    iVar2 = (param_5 & 0x7f) * 8;
    if (*(short *)(iVar3 + iVar2) != -1) {
      puVar9 = (ushort *)(iVar3 + iVar2);
      uVar1 = *puVar9;
      if ((uVar1 & 0xc000) != 0x4000) {
        if ((*(byte *)((int)puVar9 + 3) & 0x80) == 0) {
          uVar7 = (*(byte *)(iVar3 + (param_5 & 0xff) * 8 + 3) - 0x40) + (param_7 & 0xff);
          if ((int)uVar7 < 0) {
            uVar7 = 0;
          }
          else if ((int)uVar7 < 0x80) {
            uVar7 = uVar7 & 0xff;
          }
          else {
            uVar7 = 0x7f;
          }
        }
        else {
          uVar7 = 0x80;
        }
        uVar6 = (param_5 & 0x7f) + (int)*(char *)(iVar3 + iVar2 + 2);
        if ((int)uVar6 < 0x80) {
          if ((int)uVar6 < 0) {
            uVar6 = 0;
          }
        }
        else {
          uVar6 = 0x7f;
        }
        sVar8 = param_2 + *(short *)(iVar3 + iVar2 + 4);
        if (sVar8 < 0x100) {
          if (sVar8 < 0) {
            sVar8 = 0;
          }
        }
        else {
          sVar8 = 0xff;
        }
        if ((uVar1 & 0xc000) == 0) {
          uVar4 = FUN_80282288(0x41,param_8,(uint)param_9);
          if ((uVar4 & 0xffff) < 0x1f81) {
            uVar5 = 0xffffffff;
            uVar4 = 1;
          }
          else {
            uVar5 = uVar6 & 0x7f;
            param_8 = FUN_8026fd94((byte)uVar5,(char)param_8,param_9,param_13,local_4c);
            uVar4 = countLeadingZeros(local_4c[0]);
            uVar4 = uVar4 >> 5;
          }
          if ((uVar4 != 0) && (uVar5 == 0xffffffff)) {
            FUN_802792f8((uint)*puVar9,(byte)sVar8,(byte)param_3,(short)param_4,
                         (byte)uVar6 | (byte)param_5 & 0x80,param_6,(char)uVar7,param_8,param_9,
                         param_10,param_11,(char)param_12,(byte)param_13,param_14,param_15,param_16)
            ;
          }
        }
        else {
          FUN_8027001c(uVar1,(int)sVar8,param_3,param_4,uVar6 | param_5 & 0x80,param_6,uVar7,param_8
                       ,param_9,param_10,param_11,param_12,param_13 & 0xff,param_14,param_15,
                       param_16);
        }
      }
    }
  }
  return;
}

