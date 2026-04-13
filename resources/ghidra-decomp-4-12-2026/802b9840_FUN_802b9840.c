// Function: FUN_802b9840
// Entry: 802b9840
// Size: 1576 bytes

void FUN_802b9840(undefined4 param_1,undefined4 param_2,int param_3)

{
  undefined2 uVar1;
  undefined2 *puVar2;
  uint uVar3;
  int iVar4;
  undefined4 uVar5;
  undefined4 *puVar6;
  int iVar7;
  undefined8 uVar8;
  
  uVar8 = FUN_80286840();
  puVar2 = (undefined2 *)((ulonglong)uVar8 >> 0x20);
  iVar4 = (int)uVar8;
  iVar7 = *(int *)(puVar2 + 0x5c);
  uVar5 = 0x16;
  if (param_3 != 0) {
    uVar5 = 0x17;
  }
  (**(code **)(*DAT_803dd738 + 0x58))((double)FLOAT_803e8ec0,puVar2,iVar4,iVar7,5,3,0x108,uVar5);
  *(code **)(puVar2 + 0x5e) = FUN_802b8fc4;
  *(undefined2 *)(iVar7 + 0x274) = 0;
  *(undefined2 *)(iVar7 + 0x270) = 0;
  puVar2[0x58] = puVar2[0x58] | 0x2000;
  puVar6 = *(undefined4 **)(iVar7 + 0x40c);
  *(undefined2 *)((int)puVar6 + 0x26) = 0xffff;
  *(undefined2 *)(puVar6 + 10) = *(undefined2 *)((int)puVar6 + 0x26);
  puVar2[0x58] = puVar2[0x58] | (short)*(char *)(iVar4 + 0x28) & 7U;
  if (*(short *)(iVar4 + 0x1a) == 0x64c) {
    *(undefined2 *)(iVar7 + 0x274) = 2;
    *(undefined2 *)(iVar7 + 0x270) = 1;
    FUN_80035ff8((int)puVar2);
    uVar3 = FUN_80022264(0,3);
    *(short *)(puVar6 + 9) = (short)uVar3;
    *(undefined2 *)(puVar6 + 10) = 0x6f1;
    *puVar6 = &DAT_803dd358;
    puVar6[1] = &DAT_803dd35c;
    *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) | 8;
    *(undefined4 *)(puVar2 + 0x7c) = 0;
    goto LAB_802b9dcc;
  }
  iVar4 = *(int *)(iVar4 + 0x14);
  if (iVar4 == 0x46a51) {
    uVar3 = FUN_80020078(0xc52);
    if (uVar3 != 0) {
      *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) | 8;
    }
    *puVar6 = &DAT_80335b48;
    puVar6[1] = &DAT_80335b58;
    goto LAB_802b9dcc;
  }
  if (iVar4 < 0x46a51) {
    if (iVar4 == 0x3433f) {
      *puVar6 = &DAT_80335b78;
      puVar6[1] = &DAT_80335b88;
      *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) | 8;
      uVar3 = FUN_80022264(0,99);
      *(float *)(puVar2 + 0x4c) =
           (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e8e30) /
           FLOAT_803e8e14;
      goto LAB_802b9dcc;
    }
    if (iVar4 < 0x3433f) {
      if (iVar4 == 0x33e3c) {
        *puVar6 = &DAT_803dd358;
        puVar6[1] = &DAT_803dd35c;
        *(undefined2 *)(puVar6 + 10) = 0x6f1;
        *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) | 8;
        uVar3 = FUN_80022264(0,99);
        *(float *)(puVar2 + 0x4c) =
             (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e8e30) /
             FLOAT_803e8e14;
        goto LAB_802b9dcc;
      }
      if (iVar4 < 0x33e3c) {
        if (iVar4 == 0x33e34) {
          *puVar6 = &DAT_803dd364;
          puVar6[1] = &DAT_803dd368;
          *(undefined2 *)(puVar6 + 10) = 0x6f1;
          *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) | 8;
          uVar3 = FUN_80022264(0,99);
          *(float *)(puVar2 + 0x4c) =
               (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e8e30) /
               FLOAT_803e8e14;
          goto LAB_802b9dcc;
        }
      }
      else if (iVar4 == 0x34316) {
        *puVar6 = &DAT_803dd37c;
        puVar6[1] = &DAT_803dd380;
        FUN_80035ff8((int)puVar2);
        *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) | 8;
        uVar3 = FUN_80022264(0,99);
        *(float *)(puVar2 + 0x4c) =
             (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e8e30) /
             FLOAT_803e8e14;
        goto LAB_802b9dcc;
      }
    }
    else {
      if (iVar4 == 0x460b6) {
        *puVar6 = &DAT_803dd388;
        puVar6[1] = &DAT_803dd38c;
        FUN_80035ff8((int)puVar2);
        *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) | 8;
        uVar3 = FUN_80022264(0,99);
        *(float *)(puVar2 + 0x4c) =
             (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e8e30) /
             FLOAT_803e8e14;
        goto LAB_802b9dcc;
      }
      if ((iVar4 < 0x460b6) && (iVar4 == 0x45c47)) {
        *puVar6 = &DAT_803dd370;
        puVar6[1] = &DAT_803dd374;
        FUN_80035ff8((int)puVar2);
        *(undefined2 *)(puVar6 + 10) = 0x6f2;
        *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) | 8;
        uVar3 = FUN_80022264(0,99);
        *(float *)(puVar2 + 0x4c) =
             (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e8e30) /
             FLOAT_803e8e14;
        goto LAB_802b9dcc;
      }
    }
  }
  else {
    if (iVar4 == 0x499ac) {
LAB_802b9d28:
      *(undefined2 *)(iVar7 + 0x270) = 2;
      *puVar6 = &DAT_80335b78;
      puVar6[1] = &DAT_80335b88;
      uVar3 = FUN_80022264(0x78,0xb4);
      puVar6[5] = (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e8e30);
      uVar3 = FUN_80022264(0,99);
      *(float *)(puVar2 + 0x4c) =
           (float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e8e30) /
           FLOAT_803e8e14;
      goto LAB_802b9dcc;
    }
    if (iVar4 < 0x499ac) {
      if (iVar4 == 0x49928) {
        uVar3 = FUN_80020078(0xc54);
        if (uVar3 != 0) {
          *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) | 8;
        }
        *puVar6 = &DAT_80335b48;
        puVar6[1] = &DAT_80335b58;
        goto LAB_802b9dcc;
      }
      if ((iVar4 < 0x49928) && (iVar4 == 0x46a55)) {
        uVar3 = FUN_80020078(0xc53);
        if (uVar3 != 0) {
          *(byte *)((int)puVar2 + 0xaf) = *(byte *)((int)puVar2 + 0xaf) | 8;
        }
        *puVar6 = &DAT_80335b48;
        puVar6[1] = &DAT_80335b58;
        goto LAB_802b9dcc;
      }
    }
    else if (iVar4 < 0x499b5) {
      if ((iVar4 < 0x499b3) && (0x499ad < iVar4)) goto LAB_802b9d28;
    }
    else if (iVar4 < 0x499b7) {
      *(undefined4 *)(puVar2 + 0x7a) = 1;
      *puVar6 = &DAT_80335b78;
      puVar6[1] = &DAT_80335b88;
      goto LAB_802b9dcc;
    }
  }
  *puVar6 = &DAT_80335b48;
  puVar6[1] = &DAT_80335b58;
LAB_802b9dcc:
  FUN_802b8c30(puVar2);
  uVar3 = FUN_80022264(0,99);
  FUN_800303fc((double)((float)((double)CONCAT44(0x43300000,uVar3 ^ 0x80000000) - DOUBLE_803e8e30) /
                       FLOAT_803e8e14),(int)puVar2);
  uVar3 = FUN_80022264(0,1);
  if (uVar3 == 0) {
    uVar1 = 0x134;
  }
  else {
    uVar1 = 0x133;
  }
  *(undefined2 *)((int)puVar6 + 0x2a) = uVar1;
  puVar6[3] = FLOAT_803e8e58;
  if (*(int *)(puVar2 + 0x7a) != 0) {
    FUN_80035ff8((int)puVar2);
  }
  FUN_8028688c();
  return;
}

