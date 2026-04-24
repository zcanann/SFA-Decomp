// Function: FUN_802113f8
// Entry: 802113f8
// Size: 1560 bytes

/* WARNING: Removing unreachable block (ram,0x802119f0) */

void FUN_802113f8(short *param_1)

{
  char cVar1;
  float fVar2;
  undefined uVar3;
  int iVar4;
  int *piVar5;
  int *piVar6;
  undefined4 uVar7;
  undefined8 uVar8;
  double dVar9;
  undefined8 in_f31;
  double dVar10;
  float local_48;
  short local_44;
  undefined2 local_42;
  undefined2 local_40;
  float local_3c;
  float local_38;
  float local_34;
  float local_30;
  undefined4 local_28;
  uint uStack36;
  undefined auStack8 [8];
  
  uVar7 = 0;
  __psq_st0(auStack8,(int)((ulonglong)in_f31 >> 0x20),0);
  __psq_st1(auStack8,(int)in_f31,0);
  piVar6 = *(int **)(param_1 + 0x5c);
  if (piVar6[1] != 0) {
    FUN_8001d6b0();
  }
  if (*(int *)(param_1 + 0x62) != 0) {
    *piVar6 = *(int *)(param_1 + 0x62);
    *(undefined4 *)(param_1 + 0x62) = 0;
  }
  iVar4 = FUN_80080150(piVar6 + 10);
  if (iVar4 != 0) {
    *(float *)(param_1 + 4) = (float)piVar6[3] * FLOAT_803db414 + *(float *)(param_1 + 4);
    if (*piVar6 != 0) {
      iVar4 = FUN_8005a194();
      if (iVar4 == 0) {
        *(undefined4 *)(param_1 + 6) = *(undefined4 *)(*piVar6 + 0xc);
        *(undefined4 *)(param_1 + 8) = *(undefined4 *)(*piVar6 + 0x10);
        *(undefined4 *)(param_1 + 10) = *(undefined4 *)(*piVar6 + 0x14);
      }
      else {
        FUN_8003842c(*piVar6,*(undefined4 *)(param_1 + 0x7a),param_1 + 6,param_1 + 8,param_1 + 10,0)
        ;
      }
    }
    iVar4 = FUN_800801a8(piVar6 + 10);
    if (iVar4 != 0) {
      if (*(char *)(piVar6 + 0xb) == '\x02') {
        FUN_800658a4((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                     (double)*(float *)(param_1 + 10),param_1,&local_48,0);
        *(float *)(param_1 + 8) = *(float *)(param_1 + 8) - local_48;
        FUN_8000bb18(param_1,0x2e6);
        FUN_8000bb18(param_1,0x2e8);
      }
      else {
        FUN_8000bb18(param_1,0x2e7);
        FUN_8000bb18(param_1,0x2e9);
      }
    }
    if (piVar6[1] == 0) {
      iVar4 = FUN_8001cc9c(param_1,0xff,0,0,0);
      piVar6[1] = iVar4;
      piVar5 = (int *)FUN_800394ac(param_1,0,0);
      if (piVar5 == (int *)0x0) {
        uVar3 = 0;
      }
      else {
        iVar4 = *piVar5 + 0x10 >> 0x1f;
        *piVar5 = (iVar4 * 0x200 | (uint)((*piVar5 + 0x10) * 0x800000 + iVar4) >> 0x17) - iVar4;
        uVar3 = (undefined)((uint)*piVar5 >> 8);
      }
      if (piVar6[1] != 0) {
        *(undefined *)(piVar6[1] + 0x4c) = uVar3;
        FUN_8001d730((double)FLOAT_803dc234,piVar6[1],0,0xff,0,0,DAT_803dc238);
        FUN_8001dd88((double)FLOAT_803e6768,(double)*(float *)(param_1 + 0x54),
                     (double)FLOAT_803e6768,piVar6[1]);
      }
    }
    goto LAB_802119f0;
  }
  iVar4 = FUN_80080150(piVar6 + 7);
  if (iVar4 != 0) {
    FUN_8000bb18(param_1,0xef);
    if (piVar6[1] == 0) {
      iVar4 = FUN_8001cc9c(param_1,0xff,0,0,0);
      piVar6[1] = iVar4;
      if (piVar6[1] != 0) {
        FUN_8001d730((double)FLOAT_803dc23c,piVar6[1],0,0xff,0,0,DAT_803dc240);
        FUN_8001dd88((double)FLOAT_803e6768,(double)*(float *)(param_1 + 0x54),
                     (double)FLOAT_803e6768,piVar6[1]);
      }
    }
    iVar4 = FUN_800801a8(piVar6 + 7);
    if (iVar4 != 0) {
      FUN_802110f8(param_1);
      goto LAB_802119f0;
    }
  }
  cVar1 = *(char *)(piVar6 + 0xb);
  if (cVar1 == '\x01') {
LAB_802117f8:
    iVar4 = FUN_800801a8(piVar6 + 6);
    fVar2 = FLOAT_803e6768;
    if (iVar4 != 0) {
      iVar4 = *(int *)(param_1 + 0x5c);
      *(float *)(param_1 + 0x14) = FLOAT_803e6768;
      *(float *)(param_1 + 0x12) = fVar2;
      *(float *)(param_1 + 0x16) = fVar2;
      *(undefined *)(iVar4 + 0x2c) = 0;
      FUN_8008016c(iVar4 + 0x1c);
      FUN_80080178(iVar4 + 0x1c,1);
      FUN_80080178(iVar4 + 0x14,10);
      goto LAB_802119f0;
    }
    if (FLOAT_803e6784 < *(float *)(param_1 + 0x14)) {
      *(float *)(param_1 + 0x14) = FLOAT_803e6788 * FLOAT_803db414 + *(float *)(param_1 + 0x14);
    }
    *param_1 = *param_1 + (ushort)DAT_803db410 * 0x400;
    param_1[1] = param_1[1] + (ushort)DAT_803db410 * 0x700;
    *(float *)(param_1 + 6) = *(float *)(param_1 + 0x12) * FLOAT_803db414 + *(float *)(param_1 + 6);
    *(float *)(param_1 + 8) = *(float *)(param_1 + 0x14) * FLOAT_803db414 + *(float *)(param_1 + 8);
    *(float *)(param_1 + 10) =
         *(float *)(param_1 + 0x16) * FLOAT_803db414 + *(float *)(param_1 + 10);
    *(undefined4 *)(param_1 + 0xc) = *(undefined4 *)(param_1 + 6);
    *(undefined4 *)(param_1 + 0xe) = *(undefined4 *)(param_1 + 8);
    *(undefined4 *)(param_1 + 0x10) = *(undefined4 *)(param_1 + 10);
LAB_802118ec:
    (**(code **)(*DAT_803dca88 + 8))(param_1,0x51c,0,1,0xffffffff,0);
    iVar4 = FUN_800801a8(piVar6 + 8);
    if (iVar4 != 0) {
      FUN_80035f20(param_1);
    }
    FUN_80035df4(param_1,0xd,1,0);
    if (piVar6[1] == 0) {
      *(undefined *)(piVar6 + 0xc) = 0;
    }
    else {
      if ((*(char *)(piVar6[1] + 0x4c) != '\0') && (*(char *)(piVar6 + 0xc) == '\0')) {
        FUN_8000bb18(param_1,0x42e);
      }
      *(undefined *)(piVar6 + 0xc) = *(undefined *)(piVar6[1] + 0x4c);
    }
  }
  else if (cVar1 < '\x01') {
    if (cVar1 == -1) {
      iVar4 = FUN_8002b9ec();
      uVar8 = FUN_80021690(param_1 + 0xc,iVar4 + 0x18);
      *(undefined *)(piVar6 + 0xb) = 1;
      *(float *)(param_1 + 0x12) = FLOAT_803e6768;
      dVar9 = (double)FUN_802931a0();
      *(float *)(param_1 + 0x14) =
           FLOAT_803e677c * FLOAT_803dc248 + (float)(dVar9 / (double)FLOAT_803dc244);
      dVar9 = (double)FUN_802931a0(uVar8);
      *(float *)(param_1 + 0x16) =
           FLOAT_803e6780 * FLOAT_803dc248 - (float)(dVar9 / (double)FLOAT_803dc244);
      local_38 = FLOAT_803e6768;
      local_34 = FLOAT_803e6768;
      local_30 = FLOAT_803e6768;
      local_3c = FLOAT_803e6778;
      local_40 = 0;
      local_42 = 0;
      local_44 = *param_1;
      FUN_80021ac8(&local_44,param_1 + 0x12);
      FUN_8000bb18(param_1,0xf0);
      goto LAB_802117f8;
    }
    if (-2 < cVar1) {
      FUN_8000b7bc(param_1,0x40);
      iVar4 = FUN_800801a8(piVar6 + 5);
      if (iVar4 != 0) {
        FUN_8002cbc4(param_1);
        goto LAB_802119f0;
      }
    }
  }
  else if (cVar1 == '\x03') {
    uStack36 = (int)*(short *)(*(int *)(param_1 + 0x26) + 0x1a) ^ 0x80000000;
    local_28 = 0x43300000;
    dVar10 = (double)(float)((double)CONCAT44(0x43300000,uStack36) - DOUBLE_803e6790);
    iVar4 = FUN_8002b9ec();
    dVar9 = (double)FUN_80021704(param_1 + 0xc,iVar4 + 0x18);
    if (dVar9 < dVar10) {
      *(undefined *)(piVar6 + 0xb) = 2;
      FUN_80080178(piVar6 + 7,0x78);
    }
  }
  else if (cVar1 < '\x03') goto LAB_802118ec;
  iVar4 = FUN_80080150(piVar6 + 5);
  if ((iVar4 == 0) &&
     (iVar4 = FUN_8005b2fc((double)*(float *)(param_1 + 6),(double)*(float *)(param_1 + 8),
                           (double)*(float *)(param_1 + 10)), fVar2 = FLOAT_803e6768, iVar4 == -1))
  {
    iVar4 = *(int *)(param_1 + 0x5c);
    *(float *)(param_1 + 0x14) = FLOAT_803e6768;
    *(float *)(param_1 + 0x12) = fVar2;
    *(float *)(param_1 + 0x16) = fVar2;
    *(undefined *)(iVar4 + 0x2c) = 0;
    FUN_8008016c(iVar4 + 0x1c);
    FUN_80080178(iVar4 + 0x1c,1);
    FUN_80080178(iVar4 + 0x14,10);
  }
LAB_802119f0:
  __psq_l0(auStack8,uVar7);
  __psq_l1(auStack8,uVar7);
  return;
}

