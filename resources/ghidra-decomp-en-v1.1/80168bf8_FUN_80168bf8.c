// Function: FUN_80168bf8
// Entry: 80168bf8
// Size: 1076 bytes

void FUN_80168bf8(undefined8 param_1,double param_2,double param_3,double param_4,undefined8 param_5
                 ,undefined8 param_6,undefined8 param_7,undefined8 param_8,undefined4 param_9,
                 undefined4 param_10,int param_11)

{
  float fVar1;
  undefined2 *puVar2;
  undefined4 uVar3;
  int iVar4;
  uint uVar5;
  int iVar6;
  int *piVar7;
  double dVar8;
  undefined8 uVar9;
  undefined auStack_48 [2];
  undefined auStack_46 [2];
  short local_44 [2];
  float local_40;
  float local_3c;
  float local_38;
  undefined4 local_34;
  undefined4 local_30;
  undefined4 local_2c;
  undefined4 local_28;
  longlong local_20;
  
  uVar9 = FUN_80286840();
  puVar2 = (undefined2 *)((ulonglong)uVar9 >> 0x20);
  iVar6 = (int)uVar9;
  piVar7 = *(int **)(iVar6 + 0x40c);
  local_34 = DAT_802c2990;
  local_30 = DAT_802c2994;
  local_2c = DAT_802c2998;
  local_28 = DAT_802c299c;
  uVar3 = FUN_8002bac4();
  iVar4 = *(int *)(param_11 + 0x2d0);
  if (iVar4 != 0) {
    local_40 = *(float *)(iVar4 + 0x18) - *(float *)(puVar2 + 0xc);
    param_4 = (double)local_40;
    local_3c = *(float *)(iVar4 + 0x1c) - *(float *)(puVar2 + 0xe);
    param_3 = (double)local_3c;
    local_38 = *(float *)(iVar4 + 0x20) - *(float *)(puVar2 + 0x10);
    param_2 = (double)(local_38 * local_38);
    dVar8 = FUN_80293900((double)(float)(param_2 +
                                        (double)((float)(param_4 * param_4) +
                                                (float)(param_3 * param_3))));
    *(float *)(param_11 + 0x2c0) = (float)dVar8;
  }
  (**(code **)(*DAT_803dd738 + 0x54))
            (puVar2,param_11,iVar6 + 0x35c,(int)*(short *)(iVar6 + 0x3f4),0,0,0,4);
  (**(code **)(*DAT_803dd738 + 0x14))(puVar2,uVar3,4,local_44,auStack_46,auStack_48);
  if ((local_44[0] == 1) || (local_44[0] == 2)) {
    iVar4 = (**(code **)(*DAT_803dd738 + 0x50))
                      (puVar2,param_11,iVar6 + 0x35c,(int)*(short *)(iVar6 + 0x3f4),0,0,1,
                       &DAT_803ad2c8);
    if (iVar4 != 0) {
      if ((iVar4 != 0x10) && (iVar4 != 0x11)) {
        FUN_8009a468(puVar2,&DAT_803ad2c8,3,(int *)0x0);
        (**(code **)(*DAT_803dd70c + 0x14))(puVar2,param_11,4);
        *(char *)(param_11 + 0x354) = *(char *)(param_11 + 0x354) + -1;
        FUN_8002ad08(puVar2,0xf,200,0,0,1);
        FUN_8000bb38((uint)puVar2,0x22);
      }
      if (*(char *)(param_11 + 0x354) < '\x01') {
        *(undefined2 *)(param_11 + 0x270) = 2;
      }
    }
  }
  else {
    iVar4 = (**(code **)(*DAT_803dd738 + 0x50))
                      (puVar2,param_11,iVar6 + 0x35c,(int)*(short *)(iVar6 + 0x3f4),0,0,1,
                       &DAT_803ad2c8);
    if (iVar4 != 0) {
      if (iVar4 == 0x11) {
        if (*(short *)(param_11 + 0x270) != 1) {
          (**(code **)(*DAT_803dd70c + 0x14))(puVar2,param_11,6);
          *(undefined *)(param_11 + 0x27b) = 1;
          *(undefined *)(param_11 + 0x27a) = 1;
          *(undefined2 *)(param_11 + 0x270) = 1;
          FUN_8009a468(puVar2,&DAT_803ad2c8,1,(int *)0x0);
          FUN_8000bb38((uint)puVar2,0x22);
          FUN_8000bb38((uint)puVar2,0x3ac);
        }
      }
      else if ((iVar4 != 0x10) && ((double)(float)piVar7[0x10] < (double)FLOAT_803e3d58)) {
        FUN_801686c8((double)(float)piVar7[0x10],param_2,param_3,param_4,param_5,param_6,param_7,
                     param_8,(uint)puVar2,piVar7);
        DAT_803ad2d0 = FLOAT_803e3d10;
        DAT_803ad2cc = 0;
        DAT_803ad2ca = 0;
        DAT_803ad2c8 = 0;
        (**(code **)(*DAT_803de710 + 4))(0,1,&DAT_803ad2c8,0x401,0xffffffff,&local_34);
        FUN_8029695c(uVar3,2);
        (**(code **)(*DAT_803dd70c + 0x14))(puVar2,param_11,5);
        FUN_8009a468(puVar2,&DAT_803ad2c8,4,(int *)0x0);
        FUN_8000bb38((uint)puVar2,0x255);
      }
    }
    if (*(char *)(param_11 + 0x354) < '\x01') {
      *(undefined2 *)(param_11 + 0x270) = 2;
    }
  }
  fVar1 = FLOAT_803e3cf8;
  if (*piVar7 != 0) {
    if (FLOAT_803e3cf8 < (float)piVar7[0x10]) {
      uVar5 = (uint)(float)piVar7[0x10];
      local_20 = (longlong)(int)uVar5;
      uVar5 = FUN_80022264(0,uVar5 & 0xff);
      *(char *)(*piVar7 + 0x36) = (char)uVar5;
      *(undefined2 *)(*piVar7 + 4) = puVar2[2];
      *(undefined2 *)(*piVar7 + 2) = puVar2[1];
      *(undefined2 *)*piVar7 = *puVar2;
      piVar7[0x10] = (int)-(FLOAT_803e3d5c * FLOAT_803dc074 - (float)piVar7[0x10]);
    }
    else {
      *(undefined *)(*piVar7 + 0x36) = 0;
      piVar7[0x10] = (int)fVar1;
    }
  }
  FUN_8028688c();
  return;
}

