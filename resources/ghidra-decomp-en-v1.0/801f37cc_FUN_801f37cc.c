// Function: FUN_801f37cc
// Entry: 801f37cc
// Size: 1112 bytes

void FUN_801f37cc(void)

{
  int iVar1;
  ushort uVar2;
  undefined2 *puVar3;
  int iVar4;
  int iVar5;
  int iVar6;
  int *piVar7;
  double dVar8;
  undefined8 uVar9;
  undefined4 local_78;
  undefined4 local_74;
  undefined4 local_70;
  undefined4 local_6c;
  undefined4 local_68;
  undefined4 local_64;
  undefined4 local_60;
  undefined4 local_5c;
  undefined4 local_58;
  undefined4 local_54;
  undefined4 local_50;
  undefined local_4c;
  undefined4 local_48;
  uint uStack68;
  longlong local_40;
  undefined4 local_38;
  uint uStack52;
  longlong local_30;
  undefined4 local_28;
  uint uStack36;
  longlong local_20;
  
  uVar9 = FUN_802860dc();
  puVar3 = (undefined2 *)((ulonglong)uVar9 >> 0x20);
  iVar5 = (int)uVar9;
  piVar7 = *(int **)(puVar3 + 0x5c);
  local_78 = DAT_802c2488;
  local_74 = DAT_802c248c;
  local_70 = DAT_802c2490;
  local_6c = DAT_802c2494;
  local_68 = DAT_802c2498;
  local_64 = DAT_802c249c;
  local_60 = DAT_802c24a0;
  local_5c = DAT_802c24a4;
  local_58 = DAT_802c24a8;
  local_54 = DAT_802c24ac;
  local_50 = DAT_802c24b0;
  local_4c = DAT_802c24b4;
  *puVar3 = (short)(((int)*(char *)(iVar5 + 0x18) & 0x3fU) << 10);
  if (*(short *)(iVar5 + 0x1a) < 1) {
    *(float *)(puVar3 + 4) = FLOAT_803e5e24;
  }
  else {
    uStack68 = (int)*(short *)(iVar5 + 0x1a) ^ 0x80000000;
    local_48 = 0x43300000;
    *(float *)(puVar3 + 4) =
         (float)((double)CONCAT44(0x43300000,uStack68) - DOUBLE_803e5e48) / FLOAT_803e5e20;
  }
  *(undefined *)(piVar7 + 5) = *(undefined *)(iVar5 + 0x19);
  piVar7[4] = (int)*(short *)(iVar5 + 0x1e);
  *(undefined *)((int)piVar7 + 0x15) = 1;
  if ((*(ushort *)(iVar5 + 0x1c) & 0x20) == 0) {
    *(undefined *)((int)piVar7 + 0x16) = 3;
  }
  else {
    *(undefined *)((int)piVar7 + 0x16) = 0;
  }
  if ((*(byte *)(iVar5 + 0x22) & 1) == 0) {
    *(undefined *)((int)piVar7 + 0x19) = 0;
  }
  else {
    *(undefined *)((int)piVar7 + 0x19) = 1;
  }
  if (*(char *)(piVar7 + 5) == '\0') {
    *(undefined *)((int)piVar7 + 0x17) = 1;
    uVar2 = *(ushort *)(iVar5 + 0x1c);
    if ((uVar2 & 4) == 0) {
      if ((uVar2 & 8) == 0) {
        if ((uVar2 & 0x10) == 0) {
          if ((uVar2 & 1) != 0) {
            *(undefined *)((int)piVar7 + 0x16) = 6;
          }
        }
        else {
          *(undefined *)((int)piVar7 + 0x15) = 6;
        }
      }
      else {
        *(undefined *)((int)piVar7 + 0x15) = 8;
      }
    }
    else {
      *(undefined *)((int)piVar7 + 0x15) = 4;
    }
  }
  if ((*(ushort *)(iVar5 + 0x1c) & 0x40) == 0) {
    *piVar7 = 0;
  }
  else {
    if (*piVar7 == 0) {
      iVar4 = FUN_8001f4c8(puVar3,1);
      *piVar7 = iVar4;
      if (*piVar7 != 0) {
        FUN_8001db2c(*piVar7,2);
      }
    }
    if (*piVar7 != 0) {
      if ((puVar3[0x23] == 0x705) || (puVar3[0x23] == 0x712)) {
        dVar8 = (double)FLOAT_803e5e0c;
        FUN_8001dd88(dVar8,dVar8,dVar8);
      }
      else {
        FUN_8001dd88((double)FLOAT_803e5e0c,(double)FLOAT_803e5e28,(double)FLOAT_803e5e0c);
      }
      iVar4 = (uint)*(byte *)((int)piVar7 + 0x15) * 3;
      FUN_8001daf0(*piVar7,*(undefined *)((int)&local_78 + iVar4),
                   *(undefined *)((int)&local_78 + iVar4 + 1),
                   *(undefined *)((int)&local_78 + iVar4 + 2),0xff);
      iVar4 = (uint)*(byte *)((int)piVar7 + 0x15) * 3;
      FUN_8001da18(*piVar7,*(undefined *)((int)&local_78 + iVar4),
                   *(undefined *)((int)&local_78 + iVar4 + 1),
                   *(undefined *)((int)&local_78 + iVar4 + 2),0xff);
      FUN_8001dc38((double)FLOAT_803e5e2c,(double)FLOAT_803e5e30,*piVar7);
      FUN_8001db6c((double)FLOAT_803e5e0c,*piVar7,1);
      FUN_8001d620(*piVar7,1,3);
      iVar6 = (uint)*(byte *)((int)piVar7 + 0x15) * 3;
      uStack68 = (uint)*(byte *)((int)&local_78 + iVar6);
      local_48 = 0x43300000;
      iVar4 = (int)(FLOAT_803e5e34 *
                   (float)((double)CONCAT44(0x43300000,(uint)*(byte *)((int)&local_78 + iVar6)) -
                          DOUBLE_803e5e50));
      local_40 = (longlong)iVar4;
      uStack52 = (uint)*(byte *)((int)&local_78 + iVar6 + 1);
      local_38 = 0x43300000;
      iVar1 = (int)(FLOAT_803e5e34 *
                   (float)((double)CONCAT44(0x43300000,uStack52) - DOUBLE_803e5e50));
      local_30 = (longlong)iVar1;
      uStack36 = (uint)*(byte *)((int)&local_78 + iVar6 + 2);
      local_28 = 0x43300000;
      iVar6 = (int)(FLOAT_803e5e34 *
                   (float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e5e50));
      local_20 = (longlong)iVar6;
      FUN_8001dab8(*piVar7,iVar4,iVar1,iVar6,0xff);
      FUN_8001db54(*piVar7,1);
      if ((*(ushort *)(iVar5 + 0x1c) & 0x80) != 0) {
        if ((puVar3[0x23] == 0x705) || (puVar3[0x23] == 0x712)) {
          iVar4 = (uint)*(byte *)((int)piVar7 + 0x15) * 3;
          FUN_8001d730((double)(FLOAT_803e5e38 * FLOAT_803e5e3c * *(float *)(puVar3 + 4)),*piVar7,0,
                       *(undefined *)((int)&local_78 + iVar4),
                       *(undefined *)((int)&local_78 + iVar4 + 1),
                       *(undefined *)((int)&local_78 + iVar4 + 2),0x8c);
        }
        else {
          iVar4 = (uint)*(byte *)((int)piVar7 + 0x15) * 3;
          FUN_8001d730((double)(FLOAT_803e5e3c * *(float *)(puVar3 + 4)),*piVar7,0,
                       *(undefined *)((int)&local_78 + iVar4),
                       *(undefined *)((int)&local_78 + iVar4 + 1),
                       *(undefined *)((int)&local_78 + iVar4 + 2),0x8c);
        }
        FUN_8001d714((double)FLOAT_803e5e40,*piVar7);
      }
    }
  }
  if ((*(ushort *)(iVar5 + 0x1c) & 2) != 0) {
    *(undefined *)((int)piVar7 + 0x15) = 0;
  }
  puVar3[0x58] = puVar3[0x58] | 0x2000;
  piVar7[1] = (int)FLOAT_803e5e10;
  piVar7[2] = (int)FLOAT_803e5e08;
  FUN_80286128();
  return;
}

