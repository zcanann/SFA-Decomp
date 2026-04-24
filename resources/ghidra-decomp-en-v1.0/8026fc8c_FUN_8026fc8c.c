// Function: FUN_8026fc8c
// Entry: 8026fc8c
// Size: 608 bytes

int FUN_8026fc8c(undefined4 param_1,short param_2,undefined4 param_3,undefined4 param_4,uint param_5
                ,undefined4 param_6,uint param_7,undefined4 param_8,undefined param_9,
                undefined param_10,undefined2 param_11,undefined2 param_12,uint param_13,
                undefined param_14,undefined param_15,undefined4 param_16)

{
  int iVar1;
  uint uVar2;
  int iVar3;
  ushort uVar4;
  uint uVar5;
  uint uVar6;
  ushort *puVar7;
  undefined4 local_4c [2];
  
  iVar3 = FUN_802750b8();
  if (iVar3 != 0) {
    iVar1 = (param_5 & 0x7f) * 8;
    if (*(short *)(iVar3 + iVar1) != -1) {
      puVar7 = (ushort *)(iVar3 + iVar1);
      uVar4 = *puVar7;
      if ((uVar4 & 0xc000) != 0x4000) {
        if ((*(byte *)((int)puVar7 + 3) & 0x80) == 0) {
          uVar6 = (*(byte *)(iVar3 + (param_5 & 0xff) * 8 + 3) - 0x40) + (param_7 & 0xff);
          if ((int)uVar6 < 0) {
            uVar6 = 0;
          }
          else if ((int)uVar6 < 0x80) {
            uVar6 = uVar6 & 0xff;
          }
          else {
            uVar6 = 0x7f;
          }
        }
        else {
          uVar6 = 0x80;
        }
        uVar5 = (param_5 & 0x7f) + (int)*(char *)(iVar3 + iVar1 + 2);
        if ((int)uVar5 < 0x80) {
          if ((int)uVar5 < 0) {
            uVar5 = 0;
          }
        }
        else {
          uVar5 = 0x7f;
        }
        param_2 = param_2 + *(short *)(iVar3 + iVar1 + 4);
        if (param_2 < 0x100) {
          if (param_2 < 0) {
            param_2 = 0;
          }
        }
        else {
          param_2 = 0xff;
        }
        if ((uVar4 & 0xc000) == 0) {
          uVar4 = FUN_80281b24(0x41,param_8,param_9);
          if (uVar4 < 0x1f81) {
            iVar3 = -1;
            uVar2 = 1;
          }
          else {
            iVar3 = FUN_8026f630(uVar5 & 0x7f,param_8,param_9,param_13,local_4c);
            uVar2 = countLeadingZeros(local_4c[0]);
            uVar2 = uVar2 >> 5;
          }
          if (uVar2 == 0) {
            return -1;
          }
          if (iVar3 != -1) {
            return iVar3;
          }
          iVar3 = FUN_80278b94(*puVar7,(int)param_2 & 0xff,param_3,param_4,uVar5 | param_5 & 0x80,
                               param_6,uVar6,param_8,param_9,param_10,param_11,param_12,
                               param_13 & 0xff,param_14,param_15,param_16);
          return iVar3;
        }
        iVar3 = FUN_8026f8b8(uVar4,(int)param_2,param_3,param_4,uVar5 | param_5 & 0x80,param_6,uVar6
                             ,param_8,param_9,param_10,param_11,param_12,param_13 & 0xff,param_14,
                             param_15,param_16);
        return iVar3;
      }
    }
  }
  return -1;
}

