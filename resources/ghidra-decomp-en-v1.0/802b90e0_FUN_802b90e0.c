// Function: FUN_802b90e0
// Entry: 802b90e0
// Size: 1576 bytes

void FUN_802b90e0(undefined4 param_1,undefined4 param_2,int param_3)

{
  int iVar1;
  undefined2 uVar4;
  uint uVar2;
  int iVar3;
  undefined4 uVar5;
  undefined4 *puVar6;
  int iVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_802860dc();
  iVar1 = (int)((ulonglong)uVar8 >> 0x20);
  iVar3 = (int)uVar8;
  iVar7 = *(int *)(iVar1 + 0xb8);
  uVar5 = 0x16;
  if (param_3 != 0) {
    uVar5 = 0x17;
  }
  (**(code **)(*DAT_803dcab8 + 0x58))((double)FLOAT_803e8228,iVar1,iVar3,iVar7,5,3,0x108,uVar5);
  *(code **)(iVar1 + 0xbc) = FUN_802b8864;
  *(undefined2 *)(iVar7 + 0x274) = 0;
  *(undefined2 *)(iVar7 + 0x270) = 0;
  *(ushort *)(iVar1 + 0xb0) = *(ushort *)(iVar1 + 0xb0) | 0x2000;
  puVar6 = *(undefined4 **)(iVar7 + 0x40c);
  *(undefined2 *)((int)puVar6 + 0x26) = 0xffff;
  *(undefined2 *)(puVar6 + 10) = *(undefined2 *)((int)puVar6 + 0x26);
  *(ushort *)(iVar1 + 0xb0) = *(ushort *)(iVar1 + 0xb0) | (short)*(char *)(iVar3 + 0x28) & 7U;
  if (*(short *)(iVar3 + 0x1a) == 0x64c) {
    *(undefined2 *)(iVar7 + 0x274) = 2;
    *(undefined2 *)(iVar7 + 0x270) = 1;
    FUN_80035f00(iVar1);
    uVar4 = FUN_800221a0(0,3);
    *(undefined2 *)(puVar6 + 9) = uVar4;
    *(undefined2 *)(puVar6 + 10) = 0x6f1;
    *puVar6 = &DAT_803dc6f0;
    puVar6[1] = &DAT_803dc6f4;
    *(byte *)(iVar1 + 0xaf) = *(byte *)(iVar1 + 0xaf) | 8;
    *(undefined4 *)(iVar1 + 0xf8) = 0;
    goto LAB_802b966c;
  }
  iVar3 = *(int *)(iVar3 + 0x14);
  if (iVar3 == 0x46a51) {
    iVar3 = FUN_8001ffb4(0xc52);
    if (iVar3 != 0) {
      *(byte *)(iVar1 + 0xaf) = *(byte *)(iVar1 + 0xaf) | 8;
    }
    *puVar6 = &DAT_80334ee8;
    puVar6[1] = &DAT_80334ef8;
    goto LAB_802b966c;
  }
  if (iVar3 < 0x46a51) {
    if (iVar3 == 0x3433f) {
      *puVar6 = &DAT_80334f18;
      puVar6[1] = &DAT_80334f28;
      *(byte *)(iVar1 + 0xaf) = *(byte *)(iVar1 + 0xaf) | 8;
      uVar2 = FUN_800221a0(0,99);
      *(float *)(iVar1 + 0x98) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e8198) /
           FLOAT_803e817c;
      goto LAB_802b966c;
    }
    if (iVar3 < 0x3433f) {
      if (iVar3 == 0x33e3c) {
        *puVar6 = &DAT_803dc6f0;
        puVar6[1] = &DAT_803dc6f4;
        *(undefined2 *)(puVar6 + 10) = 0x6f1;
        *(byte *)(iVar1 + 0xaf) = *(byte *)(iVar1 + 0xaf) | 8;
        uVar2 = FUN_800221a0(0,99);
        *(float *)(iVar1 + 0x98) =
             (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e8198) /
             FLOAT_803e817c;
        goto LAB_802b966c;
      }
      if (iVar3 < 0x33e3c) {
        if (iVar3 == 0x33e34) {
          *puVar6 = &DAT_803dc6fc;
          puVar6[1] = &DAT_803dc700;
          *(undefined2 *)(puVar6 + 10) = 0x6f1;
          *(byte *)(iVar1 + 0xaf) = *(byte *)(iVar1 + 0xaf) | 8;
          uVar2 = FUN_800221a0(0,99);
          *(float *)(iVar1 + 0x98) =
               (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e8198) /
               FLOAT_803e817c;
          goto LAB_802b966c;
        }
      }
      else if (iVar3 == 0x34316) {
        *puVar6 = &DAT_803dc714;
        puVar6[1] = &DAT_803dc718;
        FUN_80035f00(iVar1);
        *(byte *)(iVar1 + 0xaf) = *(byte *)(iVar1 + 0xaf) | 8;
        uVar2 = FUN_800221a0(0,99);
        *(float *)(iVar1 + 0x98) =
             (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e8198) /
             FLOAT_803e817c;
        goto LAB_802b966c;
      }
    }
    else {
      if (iVar3 == 0x460b6) {
        *puVar6 = &DAT_803dc720;
        puVar6[1] = &DAT_803dc724;
        FUN_80035f00(iVar1);
        *(byte *)(iVar1 + 0xaf) = *(byte *)(iVar1 + 0xaf) | 8;
        uVar2 = FUN_800221a0(0,99);
        *(float *)(iVar1 + 0x98) =
             (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e8198) /
             FLOAT_803e817c;
        goto LAB_802b966c;
      }
      if ((iVar3 < 0x460b6) && (iVar3 == 0x45c47)) {
        *puVar6 = &DAT_803dc708;
        puVar6[1] = &DAT_803dc70c;
        FUN_80035f00(iVar1);
        *(undefined2 *)(puVar6 + 10) = 0x6f2;
        *(byte *)(iVar1 + 0xaf) = *(byte *)(iVar1 + 0xaf) | 8;
        uVar2 = FUN_800221a0(0,99);
        *(float *)(iVar1 + 0x98) =
             (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e8198) /
             FLOAT_803e817c;
        goto LAB_802b966c;
      }
    }
  }
  else {
    if (iVar3 == 0x499ac) {
LAB_802b95c8:
      *(undefined2 *)(iVar7 + 0x270) = 2;
      *puVar6 = &DAT_80334f18;
      puVar6[1] = &DAT_80334f28;
      uVar2 = FUN_800221a0(0x78,0xb4);
      puVar6[5] = (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e8198);
      uVar2 = FUN_800221a0(0,99);
      *(float *)(iVar1 + 0x98) =
           (float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e8198) /
           FLOAT_803e817c;
      goto LAB_802b966c;
    }
    if (iVar3 < 0x499ac) {
      if (iVar3 == 0x49928) {
        iVar3 = FUN_8001ffb4(0xc54);
        if (iVar3 != 0) {
          *(byte *)(iVar1 + 0xaf) = *(byte *)(iVar1 + 0xaf) | 8;
        }
        *puVar6 = &DAT_80334ee8;
        puVar6[1] = &DAT_80334ef8;
        goto LAB_802b966c;
      }
      if ((iVar3 < 0x49928) && (iVar3 == 0x46a55)) {
        iVar3 = FUN_8001ffb4(0xc53);
        if (iVar3 != 0) {
          *(byte *)(iVar1 + 0xaf) = *(byte *)(iVar1 + 0xaf) | 8;
        }
        *puVar6 = &DAT_80334ee8;
        puVar6[1] = &DAT_80334ef8;
        goto LAB_802b966c;
      }
    }
    else if (iVar3 < 0x499b5) {
      if ((iVar3 < 0x499b3) && (0x499ad < iVar3)) goto LAB_802b95c8;
    }
    else if (iVar3 < 0x499b7) {
      *(undefined4 *)(iVar1 + 0xf4) = 1;
      *puVar6 = &DAT_80334f18;
      puVar6[1] = &DAT_80334f28;
      goto LAB_802b966c;
    }
  }
  *puVar6 = &DAT_80334ee8;
  puVar6[1] = &DAT_80334ef8;
LAB_802b966c:
  FUN_802b84d0(iVar1);
  uVar2 = FUN_800221a0(0,99);
  FUN_80030304((double)((float)((double)CONCAT44(0x43300000,uVar2 ^ 0x80000000) - DOUBLE_803e8198) /
                       FLOAT_803e817c),iVar1);
  iVar3 = FUN_800221a0(0,1);
  if (iVar3 == 0) {
    uVar4 = 0x134;
  }
  else {
    uVar4 = 0x133;
  }
  *(undefined2 *)((int)puVar6 + 0x2a) = uVar4;
  puVar6[3] = FLOAT_803e81c0;
  if (*(int *)(iVar1 + 0xf4) != 0) {
    FUN_80035f00(iVar1);
  }
  FUN_80286128();
  return;
}

